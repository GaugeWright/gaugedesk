import {
    newIdempotencyKey,
    type EngagementId,
    type FileEntry,
    type MergeAction,
    type MergeState,
    type StreamEvent,
} from "@gaugewright/control-plane-client";

import type {
    EdgeUsage,
    EmbedQueuedTurn,
    EmbedSessionApi,
    TurnObservation,
} from "./session-api";
import { TURN_ACTIVITIES } from "./session-api";
import {
    observeBrowserLatency,
    relayServerLatency,
    type LatencyObserver,
} from "./latency";

interface EdgeState {
    readonly session_id: string;
    readonly release_id: string;
    readonly cursor: number;
    readonly transcript: StreamEvent[];
    readonly files: { path: string }[];
    readonly queue?: EmbedQueuedTurn[];
    readonly active_turn?: { readonly activity?: string };
}

type PendingTurn = {
    text: string;
    images: { media_type: string; data_base64: string }[];
    resolve: (value: unknown) => void;
    reject: (reason: unknown) => void;
};

type PendingAck = {
    resolve: () => void;
    reject: (reason: unknown) => void;
};

type PendingQueueOperation = PendingAck & {
    payload: Record<string, unknown>;
};

/** A stop is keyed by the turn it aims at, and carries the operation id the
 *  host echoes back on a refusal — the only thread tying that refusal to this
 *  request. */
type PendingStop = PendingAck & {
    operationId: string;
};

export interface EmbedChatControls {
    create(): Promise<void>;
    open?(chat: string): Promise<void>;
    erase?(chat: string): Promise<void>;
}

/** The overwhelmingly common reconnect is one dropped frame on a live session,
 * so the first retry stays fast enough that a visitor never feels it. */
const RECONNECT_BASE_MS = 100;

/** A rejected upgrade is not always transient, and the client cannot read the
 * status a failed WebSocket handshake returned. Without a ceiling, one session
 * the deployment refuses becomes ten upgrade attempts a second for as long as
 * the tab stays open — a self-inflicted flood that never resolves and buries
 * the real error in console noise. Doubling to this ceiling keeps a genuine
 * blip invisible while a persistent refusal settles into a slow poll. */
const RECONNECT_CEILING_MS = 30_000;

/** One canonical, cursor-resumable WebSocket to the engagement's Session DO. */
export class EdgeSessionApi implements EmbedSessionApi {
    private socket: WebSocket | null = null;
    private openPromise: Promise<WebSocket> | null = null;
    private readonly listeners = new Set<(event: StreamEvent) => void>();
    private readonly pendingTurns = new Map<string, PendingTurn>();
    private readonly pendingStops = new Map<string, PendingStop>();
    private readonly pendingQueueOperations = new Map<string, PendingQueueOperation>();
    private readonly queueListeners = new Set<(queue: readonly EmbedQueuedTurn[]) => void>();
    private readonly activityListeners = new Set<(activity: TurnObservation) => void>();
    private readonly assistantText = new Map<string, string>();
    private readonly acceptedMessages = new Set<string>();
    private readonly receivedRequests = new Set<string>();
    private readonly receivedFirstText = new Set<string>();
    private readonly renderedFirstText = new Set<string>();
    private readonly awaitingFirstTextRender: string[] = [];
    private readonly sentRequests = new Set<string>();
    private snapshot: EdgeState | null = null;
    private lastUsage: EdgeUsage | null = null;
    private turnQueue: EmbedQueuedTurn[] = [];
    private turnActivity: TurnObservation = { state: "idle" };
    private cursor = 0;
    private disposed = false;
    private refreshPromise: Promise<void> | null = null;
    private refreshTimer: ReturnType<typeof setTimeout> | null = null;
    private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
    private reconnectAttempts = 0;
    private terminalRecoveryStarted = false;
    /** Whether a refused probe has already been answered with a capability
     *  refresh. A second refusal after a refresh that reported success means the
     *  routes disagree about this session, and one more attempt would only
     *  resume the loop this flag exists to end. */
    private refusalRecoveryAttempted = false;

    constructor(
        private readonly deploymentBase: string,
        private readonly sessionId: EngagementId,
        private readonly resumeCapability: string,
        private connectionCapability: string,
        private connectionExpiresAtUnixMs: number,
        private readonly audienceAssertion: string | null,
        private readonly whiteLabel: boolean,
        private readonly latencyObserver?: LatencyObserver,
        private readonly chatControls?: EmbedChatControls,
    ) {
        this.scheduleCapabilityRefresh();
    }

    get embedAudience(): boolean {
        return this.audienceAssertion !== null;
    }

    private observeLatency(
        phase: Parameters<typeof observeBrowserLatency>[1],
        fields?: Parameters<typeof observeBrowserLatency>[2],
    ): void {
        observeBrowserLatency(this.latencyObserver, phase, fields);
    }

    private projection(path: "state" | "files"): string {
        return new URL(
            `${this.deploymentBase}/sessions/${encodeURIComponent(this.sessionId)}/${path}`,
        ).toString();
    }

    private projectionHeaders(): HeadersInit {
        return { "x-gw-connection-capability": this.connectionCapability };
    }

    private socketUrl(): string {
        const url = new URL(
            `${this.deploymentBase}/sessions/${encodeURIComponent(this.sessionId)}/socket`,
        );
        url.searchParams.set("cap", this.connectionCapability);
        if (this.cursor > 0) url.searchParams.set("after", String(this.cursor));
        url.protocol = url.protocol === "https:" ? "wss:" : "ws:";
        return url.toString();
    }

    private async refreshState(): Promise<void> {
        const response = await fetch(this.projection("state"), {
            headers: this.projectionHeaders(),
            credentials: "omit",
            cache: "no-store",
        });
        if (!response.ok) {
            throw new Error(`read session state: ${response.status}`);
        }
        const snapshot = (await response.json()) as Partial<EdgeState>;
        if (
            snapshot.session_id !== this.sessionId ||
            !Number.isSafeInteger(snapshot.cursor) ||
            !Array.isArray(snapshot.transcript) ||
            !Array.isArray(snapshot.files)
        ) {
            throw new Error("session state projection was inconsistent");
        }
        const cursor = Number(snapshot.cursor);
        if (cursor >= this.cursor) {
            this.snapshot = snapshot as EdgeState;
            this.cursor = cursor;
            this.setTurnQueue(this.snapshot.queue ?? []);
            this.setTurnActivity(this.snapshot.active_turn?.activity);
        }
    }

    private connect(): Promise<WebSocket> {
        if (this.openPromise) return this.openPromise;
        if (this.socket?.readyState === WebSocket.OPEN) return Promise.resolve(this.socket);
        if (Date.now() >= this.connectionExpiresAtUnixMs - 30_000) {
            return this.refreshConnectionCapability().then(() => this.connect());
        }
        this.observeLatency("socket_connect_start");
        this.openPromise = new Promise<WebSocket>((resolve, reject) => {
            const socket = new WebSocket(this.socketUrl());
            this.socket = socket;
            let ready = false;
            socket.addEventListener(
                "error",
                () => {
                    if (!ready) this.openPromise = null;
                    reject(new Error("Session DO WebSocket failed to open"));
                },
                { once: true },
            );
            socket.addEventListener("message", (event) => {
                const type = this.receive(String(event.data));
                if (type === "cursor_gap") {
                    socket.close();
                    return;
                }
                if (type === "session_ready" && !ready) {
                    ready = true;
                    this.openPromise = null;
                    // A connection that reached ready is the only evidence the
                    // backoff should start over from; an upgrade that merely
                    // succeeded is not, since the session can still be refused
                    // after the socket opens.
                    this.reconnectAttempts = 0;
                    this.observeLatency("session_ready_received", {
                        sequence: this.cursor,
                    });
                    this.resendPending(socket);
                    resolve(socket);
                }
            });
            socket.addEventListener("close", () => {
                this.socket = null;
                this.openPromise = null;
                if (!ready) reject(new Error("Session DO WebSocket closed before ready"));
                for (const pending of this.pendingStops.values()) {
                    pending.reject(
                        new Error("Session DO WebSocket closed before stop was admitted"),
                    );
                }
                this.pendingStops.clear();
                for (const pending of this.pendingQueueOperations.values()) {
                    pending.reject(
                        new Error("Session DO WebSocket closed before queue command was admitted"),
                    );
                }
                this.pendingQueueOperations.clear();
                if (
                    !this.disposed &&
                    (this.chatControls ||
                        this.listeners.size > 0 ||
                        this.queueListeners.size > 0 ||
                        this.pendingTurns.size > 0 ||
                        this.pendingQueueOperations.size > 0)
                ) {
                    this.scheduleReconnect();
                }
            });
        });
        return this.openPromise;
    }

    private scheduleReconnect(): void {
        if (this.reconnectTimer || this.terminalRecoveryStarted) return;
        const delay = Math.min(
            RECONNECT_CEILING_MS,
            RECONNECT_BASE_MS * 2 ** this.reconnectAttempts,
        );
        this.reconnectAttempts += 1;
        this.reconnectTimer = globalThis.setTimeout(() => {
            this.reconnectTimer = null;
            void this.recoverOrReconnect();
        }, delay);
    }

    /** Distinguish a transient transport loss from a session the deployment has
     * terminally removed. WebSocket does not expose its failed HTTP upgrade
     * status, so the scoped state projection is the authoritative probe — which
     * is why every public route must agree about whether a session is still
     * usable. When the projection disagreed with the socket, this probe read a
     * refused session as transient and reconnected against it forever. */
    private async recoverOrReconnect(): Promise<void> {
        let unavailable = false;
        let refused = false;
        try {
            const response = await fetch(this.projection("state"), {
                headers: this.projectionHeaders(),
                credentials: "omit",
                cache: "no-store",
            });
            unavailable = response.status === 404 || response.status === 410;
            refused = response.status === 401 || response.status === 403;
        } catch {
            // A failed probe is transport uncertainty, not terminal authority.
        }
        if (this.disposed) return;
        // A refusal says the capability this client holds is not one the
        // deployment will honour, and that has two causes which look identical
        // here. The capability may simply have expired while the tab slept,
        // which a refresh repairs. Or the session behind it is gone — a
        // deployment cutover ends live sessions — and no capability for it will
        // ever be honoured again.
        //
        // Refreshing distinguishes them, because the refresh insists on being
        // handed back this same session. When it cannot be, the session is the
        // thing that ended rather than the credential, and this client must
        // start another instead of asking a second time.
        //
        // Treating a refusal as transient is what produced the failure this
        // handles: a panel whose session had been ended by a cutover reconnected
        // against it every few seconds for as long as the tab stayed open,
        // showing a visitor a permanent outage where a new session was
        // available for the asking.
        if (refused && !unavailable) {
            if (this.refusalRecoveryAttempted) {
                unavailable = true;
            } else {
                this.refusalRecoveryAttempted = true;
                try {
                    await this.refreshConnectionCapability();
                } catch {
                    unavailable = true;
                }
                if (this.disposed) return;
            }
        }
        if (unavailable) {
            this.terminalRecoveryStarted = true;
            const error = new Error("public session is no longer available");
            for (const pending of this.pendingTurns.values()) {
                pending.reject(error);
            }
            this.pendingTurns.clear();
            if (this.chatControls) {
                await this.chatControls.create().catch(() => undefined);
            }
            return;
        }
        void this.connect().catch((error) => {
            for (const pending of this.pendingTurns.values()) {
                pending.reject(error);
            }
            this.pendingTurns.clear();
        });
    }

    private scheduleCapabilityRefresh(): void {
        if (this.refreshTimer) clearTimeout(this.refreshTimer);
        const delay = Math.max(
            1_000,
            this.connectionExpiresAtUnixMs - Date.now() - 60_000,
        );
        this.refreshTimer = setTimeout(() => {
            void this.refreshConnectionCapability().catch(() => undefined);
        }, delay);
    }

    private refreshConnectionCapability(): Promise<void> {
        if (this.refreshPromise) return this.refreshPromise;
        this.refreshPromise = fetch(`${this.deploymentBase}/bootstrap`, {
            method: "POST",
            headers: { "content-type": "application/json" },
            credentials: "omit",
            body: JSON.stringify({
                resume_capability: this.resumeCapability,
                ...(this.audienceAssertion
                    ? { audience_assertion: this.audienceAssertion }
                    : {}),
            }),
        })
            .then(async (response) => {
                if (!response.ok) {
                    throw new Error(`session capability refresh: ${response.status}`);
                }
                const value = (await response.json()) as {
                    session_id?: string;
                    connection_capability?: string;
                    connection_expires_at_unix_ms?: number;
                };
                if (
                    value.session_id !== this.sessionId ||
                    typeof value.connection_capability !== "string" ||
                    !Number.isSafeInteger(value.connection_expires_at_unix_ms)
                ) {
                    throw new Error("session capability refresh was inconsistent");
                }
                this.connectionCapability = value.connection_capability;
                this.connectionExpiresAtUnixMs = Number(
                    value.connection_expires_at_unix_ms,
                );
                this.scheduleCapabilityRefresh();
            })
            .finally(() => {
                this.refreshPromise = null;
            });
        return this.refreshPromise;
    }

    private receive(raw: string): string | null {
        let message: Record<string, unknown>;
        try {
            message = JSON.parse(raw) as Record<string, unknown>;
        } catch {
            return null;
        }
        if (message.type === "latency") {
            return relayServerLatency(this.latencyObserver, message)
                ? "latency"
                : null;
        }
        if (message.type === "session_ready") {
            const snapshot = message.snapshot;
            if (snapshot && typeof snapshot === "object" && !Array.isArray(snapshot)) {
                this.snapshot = snapshot as unknown as EdgeState;
                this.cursor = Math.max(this.cursor, Number(this.snapshot.cursor) || 0);
                this.setTurnQueue(this.snapshot.queue ?? []);
                this.setTurnActivity(this.snapshot.active_turn?.activity);
            }
            return "session_ready";
        }
        // An unrecognized activity is dropped rather than rendered: the runtime
        // may publish a state this client predates, and holding the last known
        // state is the safe reading — it never invents a label and never pins
        // the composer busy on a word we cannot show.
        if (message.type === "turn_activity" && typeof message.activity === "string") {
            this.setTurnActivity(
                message.activity,
                typeof message.tool === "string" ? message.tool : undefined,
            );
            return "turn_activity";
        }
        const sequence = Number(message.sequence);
        if (Number.isSafeInteger(sequence)) {
            if (sequence <= this.cursor) return String(message.type ?? "");
            if (sequence !== this.cursor + 1) return "cursor_gap";
            this.cursor = sequence;
        }
        const requestId =
            typeof message.request_id === "string"
                ? message.request_id
                : undefined;
        if (requestId && !this.receivedRequests.has(requestId)) {
            this.receivedRequests.add(requestId);
            this.observeLatency("first_event_received", {
                request_id: requestId,
                ...(Number.isSafeInteger(sequence) ? { sequence } : {}),
            });
        }
        if (
            message.type === "message_accepted" &&
            message.role === "user" &&
            typeof message.text === "string"
        ) {
            const requestId =
                typeof message.request_id === "string"
                    ? message.request_id
                    : `sequence:${sequence}`;
            if (!this.acceptedMessages.has(requestId) && this.snapshot) {
                this.acceptedMessages.add(requestId);
                this.snapshot = {
                    ...this.snapshot,
                    transcript: [
                        ...this.snapshot.transcript,
                        { type: "user", text: message.text },
                    ],
                };
            }
            if (typeof message.parent_request_id === "string") {
                for (const listener of this.listeners) {
                    listener({ type: "user", text: message.text });
                }
            }
            return "message_accepted";
        }
        if (message.type === "text_delta" && typeof message.delta === "string") {
            const textRequestId =
                typeof message.request_id === "string"
                    ? message.request_id
                    : typeof message.command_id === "string"
                      ? message.command_id
                      : "active-turn";
            if (!this.receivedFirstText.has(textRequestId)) {
                this.receivedFirstText.add(textRequestId);
                this.awaitingFirstTextRender.push(textRequestId);
                this.observeLatency("first_text_received", {
                    request_id: textRequestId,
                    ...(Number.isSafeInteger(sequence) ? { sequence } : {}),
                });
            }
            this.assistantText.set(
                textRequestId,
                `${this.assistantText.get(textRequestId) ?? ""}${message.delta}`,
            );
            for (const listener of this.listeners) {
                listener({ type: "text", delta: message.delta });
            }
            return "text_delta";
        }
        if (
            (message.type === "turn_stop_requested" || message.type === "turn_stopped") &&
            typeof message.request_id === "string"
        ) {
            this.pendingStops.get(message.request_id)?.resolve();
            this.pendingStops.delete(message.request_id);
            return String(message.type);
        }
        if (message.type === "turn_queue_changed" && Array.isArray(message.queue)) {
            this.setTurnQueue(message.queue);
            const operationId =
                typeof message.operation_id === "string" ? message.operation_id : undefined;
            if (operationId) {
                this.pendingQueueOperations.get(operationId)?.resolve();
                this.pendingQueueOperations.delete(operationId);
            }
            return "turn_queue_changed";
        }
        if (
            message.type === "turn_command_applied" &&
            message.kind === "compact" &&
            typeof message.request_id === "string"
        ) {
            for (const [operationId, pending] of this.pendingQueueOperations) {
                if (pending.payload.type !== "compact") continue;
                if (pending.payload.request_id !== message.request_id) continue;
                pending.resolve();
                this.pendingQueueOperations.delete(operationId);
            }
            return "turn_command_applied";
        }
        if (
            message.type === "tool_call" &&
            typeof message.tool === "string" &&
            typeof message.call_id === "string"
        ) {
            const args =
                message.arguments === undefined
                    ? undefined
                    : JSON.stringify(message.arguments);
            const target =
                message.arguments &&
                typeof message.arguments === "object" &&
                !Array.isArray(message.arguments) &&
                typeof (message.arguments as { path?: unknown }).path === "string"
                    ? (message.arguments as { path: string }).path
                    : undefined;
            for (const listener of this.listeners) {
                listener({
                    type: "tool",
                    tool: message.tool,
                    mediated: true,
                    call_id: message.call_id,
                    ...(target ? { target } : {}),
                    ...(args ? { args } : {}),
                });
            }
            return "tool_call";
        }
        if (
            message.type === "tool_result" &&
            typeof message.call_id === "string" &&
            typeof message.ok === "boolean"
        ) {
            for (const listener of this.listeners) {
                listener({
                    type: "toolresult",
                    call_id: message.call_id,
                    ok: message.ok,
                    ...(typeof message.result === "string"
                        ? { result: message.result }
                        : {}),
                });
            }
            return "tool_result";
        }
        if (message.type === "workspace_snapshot" && Array.isArray(message.files)) {
            const files = message.files
                .filter(
                    (file): file is { path: string } =>
                        !!file &&
                        typeof file === "object" &&
                        !Array.isArray(file) &&
                        typeof (file as { path?: unknown }).path === "string",
                )
                .map((file) => ({ path: file.path }));
            if (this.snapshot) this.snapshot = { ...this.snapshot, files };
            return "workspace_snapshot";
        }
        if (
            message.type === "usage" &&
            message.usage &&
            typeof message.usage === "object" &&
            !Array.isArray(message.usage)
        ) {
            const usage = message.usage as Partial<EdgeUsage>;
            if (
                typeof usage.usage_ref === "string" &&
                Number.isSafeInteger(usage.input_tokens) &&
                Number.isSafeInteger(usage.cached_input_tokens) &&
                Number.isSafeInteger(usage.output_tokens)
            ) {
                this.lastUsage = usage as EdgeUsage;
            }
            return "usage";
        }
        if (message.type === "error" && typeof message.operation_id === "string") {
            const pending = this.pendingQueueOperations.get(message.operation_id);
            if (pending) {
                this.pendingQueueOperations.delete(message.operation_id);
                pending.reject(new Error(String(message.error ?? "queue command failed")));
            }
            // A refused stop arrives the same way — an `error` carrying only the
            // operation id it was sent with. Matched here or its promise waits
            // forever, and a caller waiting forever reports nothing at all.
            for (const [requestId, stop] of this.pendingStops) {
                if (stop.operationId !== message.operation_id) continue;
                this.pendingStops.delete(requestId);
                stop.reject(new Error(String(message.error ?? "the turn could not be stopped")));
            }
            return "error";
        }
        if (
            (message.type === "turn_terminal" || message.type === "error") &&
            typeof message.request_id === "string"
        ) {
            this.setTurnActivity("idle");
            const pending = this.pendingTurns.get(message.request_id);
            if (!pending) return String(message.type);
            this.observeLatency("terminal_received", {
                request_id: message.request_id,
                ...(Number.isSafeInteger(sequence) ? { sequence } : {}),
            });
            this.pendingTurns.delete(message.request_id);
            const status = Number(message.status);
            const assistant = this.assistantText.get(message.request_id) ?? "";
            this.assistantText.delete(message.request_id);
            if (status >= 200 && status < 300) {
                if (assistant && this.snapshot) {
                    this.snapshot = {
                        ...this.snapshot,
                        transcript: [
                            ...this.snapshot.transcript,
                            { type: "assistant", text: assistant },
                        ],
                    };
                }
                pending.resolve(message.body);
            } else {
                // The runtime says why in the terminal body — a policy
                // refusal, a provider failure, a missing credential. A bare
                // status hides all of them behind one number, and the person
                // reading it cannot tell a broken deployment from a broken
                // network.
                const body = message.body as { error?: unknown } | undefined;
                const reason =
                    body && typeof body.error === "string" && body.error.trim()
                        ? `: ${body.error.trim()}`
                        : "";
                pending.reject(new Error(`public turn failed: ${status}${reason}`));
            }
        }
        return typeof message.type === "string" ? message.type : null;
    }

    private sendTurn(socket: WebSocket, requestId: string, turn: PendingTurn): void {
        socket.send(
            JSON.stringify({
                type: "send_message",
                request_id: requestId,
                after: this.cursor,
                text: turn.text,
                ...(turn.images.length > 0 ? { images: turn.images } : {}),
            }),
        );
        if (!this.sentRequests.has(requestId)) {
            this.sentRequests.add(requestId);
            this.observeLatency("command_sent", { request_id: requestId });
        }
    }

    /** A reconnect is a retry of the same durable runtime command, never a new
     * turn. The Session DO resolves the stable request id against WhippleScript
     * effect/receipt authority. */
    private resendPending(socket: WebSocket): void {
        for (const [requestId, turn] of this.pendingTurns) {
            this.sendTurn(socket, requestId, turn);
        }
        for (const pending of this.pendingQueueOperations.values()) {
            socket.send(JSON.stringify(pending.payload));
        }
    }

    private setTurnQueue(value: unknown[]): void {
        this.turnQueue = value.flatMap((candidate) => {
            if (!candidate || typeof candidate !== "object" || Array.isArray(candidate)) {
                return [];
            }
            const item = candidate as Partial<EmbedQueuedTurn>;
            if (
                typeof item.command_id !== "string" ||
                typeof item.text !== "string" ||
                !Number.isFinite(item.position)
            ) {
                return [];
            }
            return [{
                command_id: item.command_id,
                text: item.text,
                position: Number(item.position),
            }];
        });
        for (const listener of this.queueListeners) listener(this.turnQueue);
    }

    private setTurnActivity(activity: string | undefined, tool?: string): void {
        const state = (TURN_ACTIVITIES as readonly string[]).includes(activity ?? "idle")
            ? ((activity ?? "idle") as TurnObservation["state"])
            : undefined;
        if (state === undefined) return;
        if (state === this.turnActivity.state && tool === this.turnActivity.tool) return;
        this.turnActivity = tool ? { state, tool } : { state };
        for (const listener of this.activityListeners) listener(this.turnActivity);
    }

    private async queueOperation(payload: Record<string, unknown>): Promise<void> {
        const operationId = newIdempotencyKey().replaceAll("-", "_");
        const socket = await this.connect();
        const command = { ...payload, operation_id: operationId, after: this.cursor };
        const admitted = new Promise<void>((resolve, reject) => {
            this.pendingQueueOperations.set(operationId, { payload: command, resolve, reject });
        });
        socket.send(JSON.stringify(command));
        return admitted;
    }

    async ready(): Promise<void> {
        await this.connect();
    }

    /** Wait until a freshly bootstrapped session can be adopted by its host.
     * A client which fails before that point was never bound into the element's
     * teardown chain, so leaving it alive creates an orphan reconnect loop.
     * Dispose that unowned client while preserving `ready()` for callers which
     * deliberately want to ride out an initial transport failure. */
    async readyForAdoption(): Promise<void> {
        try {
            await this.ready();
        } catch (error) {
            this.dispose();
            throw error;
        }
    }

    async getTranscript(_id: EngagementId): Promise<StreamEvent[]> {
        await this.refreshState();
        await this.connect();
        return this.snapshot?.transcript ?? [];
    }

    getUsage(): EdgeUsage | null {
        return this.lastUsage;
    }

    /** Ask the host to end the running turn, and wait for it to say whether it
     *  did.
     *
     *  The stop carries an `operation_id` for the same reason every queue
     *  command does: a host that refuses answers `{type: "error"}` with no
     *  `request_id` — the runtime rejects a cancellation for anything that is
     *  not `running` — and without the id there is nothing to match that error
     *  to. The promise then never settled at all, so the caller's `.catch` never
     *  ran, and a Stop the host had refused was indistinguishable from one it
     *  had honoured. Silence is the one answer an interrupt must never give. */
    async stopTurn(): Promise<void> {
        const requestId = this.pendingTurns.keys().next().value as string | undefined;
        if (!requestId) throw new Error("session has no active turn");
        const operationId = newIdempotencyKey().replaceAll("-", "_");
        const socket = await this.connect();
        const admitted = new Promise<void>((resolve, reject) => {
            this.pendingStops.set(requestId, { resolve, reject, operationId });
        });
        socket.send(
            JSON.stringify({
                type: "stop",
                request_id: requestId,
                operation_id: operationId,
                after: this.cursor,
            }),
        );
        return admitted;
    }

    /** Ask WhippleScript to run the turn's selected compactor at its next model
     * boundary. The request id is durable and replay-safe; this promise settles
     * only when the runtime publishes the applied-command acknowledgement. */
    compactTurn(): Promise<void> {
        return this.queueOperation({
            type: "compact",
            request_id: newIdempotencyKey().replaceAll("-", "_"),
        });
    }

    getTurnQueue(): readonly EmbedQueuedTurn[] {
        return this.turnQueue;
    }

    getTurnActivity(): TurnObservation {
        return this.turnActivity;
    }

    subscribeTurnActivity(listener: (activity: TurnObservation) => void): () => void {
        this.activityListeners.add(listener);
        return () => this.activityListeners.delete(listener);
    }

    subscribeTurnQueue(listener: (queue: readonly EmbedQueuedTurn[]) => void): () => void {
        this.queueListeners.add(listener);
        listener(this.turnQueue);
        return () => this.queueListeners.delete(listener);
    }

    followUpTurn(
        text: string,
        images: { data: string; mimeType: string }[] = [],
    ): Promise<void> {
        return this.queueOperation({
            type: "follow_up",
            request_id: newIdempotencyKey().replaceAll("-", "_"),
            text,
            images: images.map((image) => ({
                media_type: image.mimeType,
                data_base64: image.data,
            })),
        });
    }

    steerTurn(
        text: string,
        images: { data: string; mimeType: string }[] = [],
    ): Promise<void> {
        return this.queueOperation({
            type: "steer",
            request_id: newIdempotencyKey().replaceAll("-", "_"),
            text,
            images: images.map((image) => ({
                media_type: image.mimeType,
                data_base64: image.data,
            })),
        });
    }

    editQueuedTurn(commandId: string, text: string): Promise<void> {
        return this.queueOperation({ type: "queue_edit", command_id: commandId, text });
    }

    removeQueuedTurn(commandId: string): Promise<void> {
        return this.queueOperation({ type: "queue_remove", command_id: commandId });
    }

    reorderQueuedTurns(commandIds: readonly string[]): Promise<void> {
        return this.queueOperation({ type: "queue_reorder", command_ids: [...commandIds] });
    }

    promoteQueuedTurn(commandId: string): Promise<void> {
        return this.queueOperation({ type: "queue_promote", command_id: commandId });
    }

    subscribe(
        _id: EngagementId,
        onEvent: (event: StreamEvent) => void,
        onOpen?: () => void,
    ): () => void {
        this.listeners.add(onEvent);
        void this.connect().then(() => onOpen?.()).catch(() => undefined);
        return () => this.listeners.delete(onEvent);
    }

    async runEmbedTurn(
        _id: EngagementId,
        prompt: string,
        images: { data: string; mimeType: string }[] = [],
    ): Promise<unknown> {
        const requestId = newIdempotencyKey().replaceAll("-", "_");
        this.observeLatency("prompt_submitted", { request_id: requestId });
        const socket = await this.connect();
        const result = new Promise<unknown>((resolve, reject) => {
            this.pendingTurns.set(requestId, {
                text: prompt,
                images: images.map((image) => ({
                    media_type: image.mimeType,
                    data_base64: image.data,
                })),
                resolve,
                reject,
            });
        });
        this.sendTurn(socket, requestId, this.pendingTurns.get(requestId)!);
        return result;
    }

    recordFirstTextRendered(): void {
        const requestId = this.awaitingFirstTextRender.shift();
        if (!requestId || this.renderedFirstText.has(requestId)) return;
        this.renderedFirstText.add(requestId);
        this.observeLatency("first_text_rendered", { request_id: requestId });
    }

    runTask(
        id: EngagementId,
        prompt: string,
        images: { data: string; mimeType: string }[] = [],
    ): Promise<unknown> {
        return this.runEmbedTurn(id, prompt, images);
    }

    async getTree(_id: EngagementId): Promise<FileEntry[]> {
        await this.connect();
        return (this.snapshot?.files ?? []).map((file) => ({
            path: file.path,
            isDir: false,
        }));
    }

    async getFile(_id: EngagementId, path: string): Promise<string> {
        const response = await fetch(
            (() => {
                const url = new URL(this.projection("files"));
                url.searchParams.set("path", path);
                return url.toString();
            })(),
            {
                headers: this.projectionHeaders(),
                credentials: "omit",
                cache: "no-store",
            },
        );
        if (!response.ok) throw new Error(`read ${path}: ${response.status}`);
        return response.text();
    }

    async getFileWithCut(
        id: EngagementId,
        path: string,
    ): Promise<{ content: string; cut: string | null }> {
        return { content: await this.getFile(id, path), cut: null };
    }

    putFile(): Promise<void> {
        return Promise.reject(new Error("public session files are read-only"));
    }

    engagementDiff(): Promise<string> {
        return Promise.resolve("");
    }

    getMerge(): Promise<MergeState> {
        return Promise.resolve({ phase: "Clean" } as MergeState);
    }

    mergeCommand(_id: EngagementId, _action: MergeAction): Promise<MergeState> {
        return this.getMerge();
    }

    embedMyChats(): Promise<{ chat: string; title: string }[]> {
        if (!this.audienceAssertion) return Promise.resolve([]);
        return fetch(`${this.deploymentBase}/audience/sessions`, {
            method: "POST",
            headers: { "content-type": "application/json" },
            credentials: "omit",
            body: JSON.stringify({ audience_assertion: this.audienceAssertion }),
        }).then(async (response) => {
            if (!response.ok) throw new Error(`my chats: ${response.status}`);
            const value = (await response.json()) as {
                sessions?: { session_id: string; created_at_unix_ms: number }[];
            };
            return (value.sessions ?? []).map((session) => ({
                chat: session.session_id,
                title: new Date(session.created_at_unix_ms).toLocaleString(),
            }));
        });
    }

    embedOpenChat(chat: string): Promise<void> {
        if (!this.audienceAssertion || !this.chatControls?.open) {
            return Promise.reject(new Error("authenticated audience is required"));
        }
        return this.chatControls.open(chat);
    }

    embedNewChat(): Promise<void> {
        if (!this.chatControls) {
            return Promise.reject(new Error("session lifecycle is unavailable"));
        }
        return this.chatControls.create();
    }

    embedEraseChat(chat: string): Promise<void> {
        if (!this.audienceAssertion || !this.chatControls?.erase) {
            return Promise.reject(new Error("authenticated audience is required"));
        }
        return this.chatControls.erase(chat);
    }

    embedGetConfig(): Promise<{ white_label: boolean }> {
        return Promise.resolve({ white_label: this.whiteLabel });
    }

    dispose(): void {
        this.disposed = true;
        if (this.refreshTimer) clearTimeout(this.refreshTimer);
        this.refreshTimer = null;
        if (this.reconnectTimer) clearTimeout(this.reconnectTimer);
        this.reconnectTimer = null;
        this.socket?.close(1000, "panel disconnected");
        this.socket = null;
    }
}
