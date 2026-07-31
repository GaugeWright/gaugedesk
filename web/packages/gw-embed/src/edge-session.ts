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
    EmbedSessionApi,
} from "./session-api";
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
}

type PendingTurn = {
    text: string;
    resolve: (value: unknown) => void;
    reject: (reason: unknown) => void;
};

type PendingAck = {
    resolve: () => void;
    reject: (reason: unknown) => void;
};

export interface AudienceChatControls {
    open(chat: string): Promise<void>;
    create(): Promise<void>;
    erase(chat: string): Promise<void>;
}

/** One canonical, cursor-resumable WebSocket to the engagement's Session DO. */
export class EdgeSessionApi implements EmbedSessionApi {
    private socket: WebSocket | null = null;
    private openPromise: Promise<WebSocket> | null = null;
    private readonly listeners = new Set<(event: StreamEvent) => void>();
    private readonly pendingTurns = new Map<string, PendingTurn>();
    private readonly pendingStops = new Map<string, PendingAck>();
    private readonly assistantText = new Map<string, string>();
    private readonly acceptedMessages = new Set<string>();
    private readonly receivedRequests = new Set<string>();
    private readonly receivedFirstText = new Set<string>();
    private readonly renderedFirstText = new Set<string>();
    private readonly awaitingFirstTextRender: string[] = [];
    private readonly sentRequests = new Set<string>();
    private snapshot: EdgeState | null = null;
    private lastUsage: EdgeUsage | null = null;
    private cursor = 0;
    private disposed = false;
    private refreshPromise: Promise<void> | null = null;
    private refreshTimer: ReturnType<typeof setTimeout> | null = null;

    constructor(
        private readonly deploymentBase: string,
        private readonly sessionId: EngagementId,
        private readonly resumeCapability: string,
        private connectionCapability: string,
        private connectionExpiresAtUnixMs: number,
        private readonly audienceAssertion: string | null,
        private readonly whiteLabel: boolean,
        private readonly latencyObserver?: LatencyObserver,
        private readonly audienceControls?: AudienceChatControls,
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
        const url = new URL(
            `${this.deploymentBase}/sessions/${encodeURIComponent(this.sessionId)}/${path}`,
        );
        url.searchParams.set("cap", this.connectionCapability);
        return url.toString();
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
                if (!this.disposed && (this.listeners.size > 0 || this.pendingTurns.size > 0)) {
                    globalThis.setTimeout(() => {
                        void this.connect().catch((error) => {
                            for (const pending of this.pendingTurns.values()) {
                                pending.reject(error);
                            }
                            this.pendingTurns.clear();
                        });
                    }, 100);
                }
            });
        });
        return this.openPromise;
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
            }
            return "session_ready";
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
            message.type === "turn_stopped" &&
            typeof message.request_id === "string"
        ) {
            this.pendingStops.get(message.request_id)?.resolve();
            this.pendingStops.delete(message.request_id);
            return "turn_stopped";
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
        if (
            (message.type === "turn_terminal" || message.type === "error") &&
            typeof message.request_id === "string"
        ) {
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
                pending.reject(new Error(`public turn failed: ${status}`));
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
    }

    async ready(): Promise<void> {
        await this.connect();
    }

    async getTranscript(_id: EngagementId): Promise<StreamEvent[]> {
        await this.refreshState();
        await this.connect();
        return this.snapshot?.transcript ?? [];
    }

    getUsage(): EdgeUsage | null {
        return this.lastUsage;
    }

    async stopTurn(): Promise<void> {
        const requestId = this.pendingTurns.keys().next().value as string | undefined;
        if (!requestId) throw new Error("session has no active turn");
        const socket = await this.connect();
        const admitted = new Promise<void>((resolve, reject) => {
            this.pendingStops.set(requestId, { resolve, reject });
        });
        socket.send(
            JSON.stringify({
                type: "stop",
                request_id: requestId,
                after: this.cursor,
            }),
        );
        return admitted;
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

    async runEmbedTurn(_id: EngagementId, prompt: string): Promise<unknown> {
        const requestId = newIdempotencyKey().replaceAll("-", "_");
        this.observeLatency("prompt_submitted", { request_id: requestId });
        const socket = await this.connect();
        const result = new Promise<unknown>((resolve, reject) => {
            this.pendingTurns.set(requestId, { text: prompt, resolve, reject });
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

    runTask(id: EngagementId, prompt: string): Promise<unknown> {
        return this.runEmbedTurn(id, prompt);
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
            { credentials: "omit", cache: "no-store" },
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
        if (!this.audienceAssertion || !this.audienceControls) {
            return Promise.reject(new Error("authenticated audience is required"));
        }
        return this.audienceControls.open(chat);
    }

    embedNewChat(): Promise<void> {
        if (!this.audienceAssertion || !this.audienceControls) {
            return Promise.reject(new Error("authenticated audience is required"));
        }
        return this.audienceControls.create();
    }

    embedEraseChat(chat: string): Promise<void> {
        if (!this.audienceAssertion || !this.audienceControls) {
            return Promise.reject(new Error("authenticated audience is required"));
        }
        return this.audienceControls.erase(chat);
    }

    embedGetConfig(): Promise<{ white_label: boolean }> {
        return Promise.resolve({ white_label: this.whiteLabel });
    }

    dispose(): void {
        this.disposed = true;
        if (this.refreshTimer) clearTimeout(this.refreshTimer);
        this.refreshTimer = null;
        this.socket?.close(1000, "panel disconnected");
        this.socket = null;
    }
}
