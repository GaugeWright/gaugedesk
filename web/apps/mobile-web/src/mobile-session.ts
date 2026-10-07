/**
 * The mobile {@link Session} adapter — the seam that lets the phone render the
 * **shared `ChatPanel`** instead of a composer of its own (`mobile-client.md`,
 * *Shape*; [ADR 0076]).
 *
 * This is the same shape `gw-embed`'s `createRemoteSession` proves for an
 * embedded panel: the desktop builds its Session inline over many signals, an
 * embed builds one over a Session DO client, and the phone builds one here over
 * `MobileControlPlane`. Projection-first (`INV-5`): everything exposed is a view
 * or a scoped command, never authority.
 *
 * Unlike the embed adapter this one does **not** own the transcript or the event
 * subscription. `MobileApp` already folds the SSE into the shared `Transcript`
 * and retires the subscription as the selected chat changes, so the adapter
 * reads the host's accessors rather than opening a second stream against the
 * same chat. It owns only what the panel needs and the host does not already
 * have: dispatch state, the capability declaration, and the two commands.
 *
 * **A stated limitation.** `busy` reflects a turn *this client dispatched*, not
 * every turn running on the addressed Home. A turn started from the desktop
 * streams into the transcript here — visibly — but does not raise `busy`, so the
 * activity line stays idle for it. That is exactly the desktop's own reading and
 * is preserved deliberately: the alternative is inferring liveness from an open
 * text line, which never closes if a turn's last event is a delta, and a
 * composer stuck showing Stop forever is worse than one that misses a remote
 * turn's caption.
 */
import { createSignal, type Accessor } from "solid-js";
import {
    turnStopped,
    type EngagementId,
    type FileEntry,
    type StopTurnResult,
} from "@gaugewright/control-plane-client";
import {
    localTurnActivity,
    type Session,
    type SessionApi,
} from "@gaugewright/workbench-ui/session-context";
import { attachTaskCommandAttempt, createTaskCommandLedger, type TaskCommandLedger, sameTaskAddress, taskCommandAddress, type ComposerCapabilities } from "@gaugewright/workbench-ui/session-composer-controller";
import { canSendOnConnection } from "@gaugewright/workbench-ui/connection-banner";
import { type ConnectionStatus } from "@gaugewright/workbench-ui/connection";
import { type Transcript } from "@gaugewright/workbench-ui/transcript";

/**
 * What a phone admits into the shared composer.
 *
 * Declared here rather than reached for from the shared defaults because it is
 * this Environment's own statement, and because neither shared constant is
 * honest about a phone: `UNIVERSAL` claims a runtime queue and steering the
 * mobile control plane has no route for, and `BASIC` claims attachments it has
 * no picker or upload path for. Claiming a capability that resolves to nothing
 * is how a control becomes silently dead.
 *
 * `stop` is real — `MobileControlPlane.stopTurn` exists and the retired
 * `MobileChat` offered it. `review` is carried by the controller's controlled
 * review value rather than by a capability flag.
 */
export const MOBILE_COMPOSER_CAPABILITIES: ComposerCapabilities = Object.freeze({
    queue: false,
    steer: false,
    stop: true,
    hold: false,
    fork: false,
    attachments: [] as const,
});

/** The narrow slice of `MobileControlPlane` this adapter commands. Declared
 *  structurally so the account-scoped proxy `MobileApp` builds satisfies it as
 *  readily as the direct client does. */
export interface MobileSessionApi {
    getTranscript?(id: EngagementId): Promise<import("@gaugewright/control-plane-client").StreamEvent[]>;
    taskIdentity?(): Promise<{ home_id: string; actor_id: string }>;
    runTask(
        id: EngagementId,
        text: string,
        images?: { data: string; mimeType: string }[],
        composedId?: string,
    ): Promise<unknown>;
    stopTurn(id: EngagementId): Promise<StopTurnResult>;
    getTree(id: EngagementId): Promise<FileEntry[]>;
    getFile(id: EngagementId, path: string): Promise<string>;
}

export interface MobileSessionOptions {
    readonly api: MobileSessionApi;
    readonly taskCommands?: TaskCommandLedger;
    readonly project?: Accessor<string | null>;
    /** The open chat, or null. The host owns selection and its subscription. */
    readonly engagementId: Accessor<EngagementId | null>;
    /** The host's fold of the durable snapshot plus live SSE. */
    readonly transcript: Accessor<Transcript>;
    /** The same admitted fold with a locally pending user send shown until the
     *  next snapshot reconciles it. Registration checks still read `transcript`. */
    readonly visibleTranscript?: Accessor<Transcript>;
    /** The addressed Home's connection status (MOB-018). Its `canCommand`
     *  reading becomes the Session's, so the composer's refusal and the
     *  connection banner provably share one predicate. */
    readonly connection: Accessor<ConnectionStatus>;
    readonly selectedFile: Accessor<string | null>;
    readonly selectFile: (path: string | null) => void;
    /** Bumped by the host when the worktree may have changed. */
    readonly worktreeRev: Accessor<unknown>;
    /** A turn settled: re-derive the sibling task-queue and files projections. */
    readonly onSettled: (id: EngagementId) => void | Promise<void>;
    /** Compatibility slot for older hosts. Addressed task failure recovery belongs
     *  to the original outbox row; restoring text alone would mint a second identity. */
    readonly onSendFailed?: (text: string) => void;
    readonly onStatus: (message: string) => void;
}

/** How long a Stop keeps asking while the turn it aims at is still registering.
 *  Matches the workbench's window: the same gap, for the same reason. */
const STOP_REGISTRATION_GRACE_MS = 1500;

/** The turn this client has in flight, as far as it can know one.
 *
 *  `stopTurn` carries only the engagement id, so a retry cannot name the turn it
 *  aims at; the identity is held locally instead, so the grace loop can stop
 *  asking the moment it no longer knows that the turn it aimed at is the one a
 *  second ask would reach. `seq` separates successive local turns, and `lines` is
 *  the transcript length at dispatch — the first event of this turn is the
 *  registration the grace window waits for, so observing one also closes it. */
interface DispatchedTurn {
    readonly seq: number;
    readonly lines: number;
}

export function createMobileSession(options: MobileSessionOptions): Session {
    const { api } = options;
    const taskCommands = options.taskCommands ?? createTaskCommandLedger();
    const [dispatched, setDispatched] = createSignal<DispatchedTurn | null>(null);
    let dispatches = 0;
    const busy = () => dispatched() !== null;

    // The phone reads files but has no write route: `MobileControlPlane` serves
    // no putFile. Refusing explicitly beats a silent no-op — nothing in the chat
    // stop calls it, and a future editor should fail loudly rather than appear
    // to save (the explicit-outcome rule, `mobile-client.md`).
    const sessionApi: SessionApi = {
        getFile: (id, path) => api.getFile(id, path),
        getTree: (id) => api.getTree(id),
        putFile: () =>
            Promise.reject(new Error("This mobile session cannot write files.")),
    };

    // `images` is ignored rather than dropped silently: the capability set above
    // declares no attachments, so the shared composer never offers a way to
    // produce one and this parameter is always empty.
    const [taskScope, setTaskScope] = createSignal<import("@gaugewright/workbench-ui/session-composer-controller").TaskCommandScope>();
    const send: Session["send"] = async (text, _images, composedId, bindTask) => {
        const id = options.engagementId();
        if (id === null) throw new Error("Open a chat before sending.");
        const requestId = composedId ?? crypto.randomUUID();
        const project = options.project?.() ?? null;
        setDispatched({ seq: ++dispatches, lines: options.transcript().lines.length });
        const authority = api.taskIdentity ? await api.taskIdentity().catch(() => undefined) : undefined;
        const scope = { home: api, chat: String(id), authority, project };
        setTaskScope(scope);
        const attempt = taskCommands.begin(scope, requestId, text, options.transcript().lines.length);
        const assertSelection = () => {
            if (options.engagementId() !== id || (options.project?.() ?? null) !== project) throw new Error("Task mobile selection changed");
        };
        const verify = async () => {
            assertSelection();
            if (!authority) return;
            const current = await api.taskIdentity!();
            assertSelection();
            if (current.home_id !== authority.home_id || current.actor_id !== authority.actor_id) throw new Error("Task Home actor changed");
        };
        options.onStatus(`send: ${text}`);
        try {
            assertSelection();
            if (bindTask) await bindTask(attempt);
            assertSelection();
            if (authority) await verify();
            const result = await api.runTask(id, text, [], requestId);
            assertSelection();
            if (authority) await verify();
            taskCommands.observe(scope, result);
            options.onStatus("turn complete");
            return attempt;
        } catch (cause) {
            try { await verify(); taskCommands.observe(scope, cause); } catch { /* Different actor remains unknown. */ }
            taskCommands.uncertain(scope, requestId);
            // A stopped turn is not a failed send. Handing the text back is
            // right for a dropped relay and wrong here: the reader cancelled
            // this message, and refilling the composer with it proposes the very
            // thing they just called off. The turn still settled, so the sibling
            // projections are re-derived exactly as they are for a completed one.
            if (turnStopped(cause)) {
                options.onStatus("turn stopped");
                throw attachTaskCommandAttempt(cause, attempt);
            }
            options.onStatus(`turn error: ${String(cause)}`);
            throw attachTaskCommandAttempt(cause, attempt);
        } finally {
            try {
                await options.onSettled(id);
            } finally {
                // The ledger retires only an addressed authority observation, never finally.
                setDispatched(null);
            }
        }
    };

    return {
        api: sessionApi,
        taskCommands,
        taskScope,
        recoverTask: async (address) => {
            if (!api.taskIdentity || !api.getTranscript || options.engagementId() !== address.chat_id
                || (options.project?.() ?? null) !== address.project_id) return undefined;
            const authority = await api.taskIdentity();
            const scope = { home: api, chat: address.chat_id, project: options.project?.() ?? null, authority };
            if (!sameTaskAddress(address, taskCommandAddress(scope))) return undefined;
            const events = await api.getTranscript(address.chat_id as EngagementId);
            const after = await api.taskIdentity();
            if (options.engagementId() !== address.chat_id || (options.project?.() ?? null) !== address.project_id
                || after.home_id !== authority.home_id || after.actor_id !== authority.actor_id) return undefined;
            setTaskScope(scope);
            return { scope, events };
        },
        appliesComposedIdOnce: true,
        engagementId: options.engagementId,
        worktreeRev: options.worktreeRev,
        selectedFile: options.selectedFile,
        selectFile: options.selectFile,
        transcript: options.visibleTranscript ?? options.transcript,
        busy,
        turnActivity: localTurnActivity(busy, options.transcript),
        composerCapabilities: () => MOBILE_COMPOSER_CAPABILITIES,
        // The one predicate the connection banner reads (MOB-028), so a degraded
        // connection always both shows the notice and refuses the send.
        canCommand: () => canSendOnConnection(options.connection()),
        // The phone reviews inline through its own approval card (MOB-031) and
        // has no merge surface, so these engagement projections are constant.
        // They are Session members the chat stop never reads.
        diff: () => "",
        mergePhase: () => null,
        mergeConflicted: () => false,
        chatKind: () => "work",
        methodName: () => "",
        merge: () => undefined,
        onContentSaved: () => undefined,
        send,
        // Stop says whether it landed.
        //
        // This was a best-effort abort inherited from the retired composer: it
        // discarded the `{ stopped }` answer and swallowed every error, so a
        // refused Stop was indistinguishable from an honoured one on the surface
        // with the least room for a person to check by other means. The shared
        // controller reports a rejection on the composer's own error line, which
        // is the only place a phone has to say it.
        //
        // A stop can also outrun the turn it aims at: this Session reads as busy
        // from the moment the task request goes out, while the runtime registers
        // the turn a little later, so a fast tap can arrive before there is
        // anything to interrupt. Ask again across that gap — bounded, and bound
        // to the turn the tap was aimed at.
        //
        // Local request liveness alone is not that binding. A stop that races a
        // natural completion is answered `nothing running` after the runtime has
        // released the turn while this client's task request is still pending, so
        // this Session still reads as busy — and `stopTurn` names only the chat,
        // so a later iteration would interrupt whatever turn is running by then,
        // including one another client started during the window. The retry
        // therefore also requires that not one event of the aimed-at turn has
        // been seen: before registration there is nothing to have ended, and the
        // first event both proves the turn registered and ends the ambiguity.
        stop: async () => {
            const id = options.engagementId();
            if (id === null) return;
            const aimedAt = dispatched();
            const deadline = Date.now() + STOP_REGISTRATION_GRACE_MS;
            for (;;) {
                const result = await api.stopTurn(id);
                if (result.stopped) return;
                const sameUnregisteredTurn = aimedAt !== null
                    && dispatched()?.seq === aimedAt.seq
                    && options.transcript().lines.length === aimedAt.lines;
                const worthRetrying = Date.now() < deadline
                    && options.engagementId() === id
                    && sameUnregisteredTurn;
                if (!worthRetrying) {
                    throw new Error("nothing is running to stop");
                }
                await new Promise((settle) => setTimeout(settle, 100));
            }
        },
    };
}
