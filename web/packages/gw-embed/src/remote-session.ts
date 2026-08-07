/**
 * A {@link Session} projection over one EDGE-5 browser connection for a single
 * hosted engagement. This is the adapter that makes the shared panels
 * context-portable:
 * the desktop's Session is built inline in `App.tsx` over its many signals; an
 * embed's is built here over one Session DO client + one fixed engagement.
 *
 * It owns its OWN engagement projection — the transcript snapshot+live, the event
 * subscription, and the diff/merge projections — exactly the per-engagement
 * machinery the desktop keeps in its shell, condensed to one chat. Projection-first
 * (`INV-5`): everything exposed is a view or a scoped command, never authority.
 *
 * Must be created inside a Solid reactive root (the `<gw-session>` element's
 * render owns it). The returned `dispose` closes the event subscription.
 */
import { createResource, createSignal } from "solid-js";
import { type EngagementId, type MergeAction } from "@gaugewright/control-plane-client";
import {
    empty,
    fromSnapshot,
    reduce,
    type Transcript,
} from "@gaugewright/workbench-ui/transcript";
import { type Session } from "@gaugewright/workbench-ui/session-context";
import { type ImageRef } from "@gaugewright/workbench-ui/attachments";
import { type EmbedSessionApi } from "./session-api";
import { type TurnObservation } from "./session-api";
import { UNIVERSAL_COMPOSER_CAPABILITIES } from "@gaugewright/workbench-ui/session-composer-controller";

export interface RemoteSessionOptions {
    /** The canonical EDGE-5 client, scoped to one hosted deployment. */
    readonly api: EmbedSessionApi;
    /** The single engagement this embedded session is bound to. */
    readonly engagementId: EngagementId;
}

export function createRemoteSession(opts: RemoteSessionOptions): { session: Session; dispose: () => void } {
    const { api } = opts;
    const id = opts.engagementId;
    const [engagementId] = createSignal<EngagementId | null>(id);
    const [selectedFile, setSelectedFile] = createSignal<string | null>(null);
    const [worktreeRev, setWorktreeRev] = createSignal(0);
    const [dispatching, setDispatching] = createSignal(false);
    const [turnActivity, setTurnActivity] = createSignal<TurnObservation>(
        api.getTurnActivity?.() ?? { state: "idle" },
    );
    const unsubscribeActivity = api.subscribeTurnActivity?.((observation) =>
        setTurnActivity(observation),
    );
    const busy = () => dispatching() || turnActivity().state !== "idle";
    const [turnQueue, setTurnQueue] = createSignal(
        (api.getTurnQueue?.() ?? []).map((item) => ({
            id: item.command_id,
            text: item.text,
        })),
    );
    const unsubscribeQueue = api.subscribeTurnQueue?.((queue) => {
        setTurnQueue(queue.map((item) => ({ id: item.command_id, text: item.text })));
    });
    const composerCapabilities = {
        ...UNIVERSAL_COMPOSER_CAPABILITIES,
        queue: Boolean(api.followUpTurn),
        steer: Boolean(api.steerTurn),
        stop: Boolean(api.stopTurn),
    };
    const composerRuntime =
        api.followUpTurn &&
        api.steerTurn &&
        api.editQueuedTurn &&
        api.removeQueuedTurn &&
        api.reorderQueuedTurns &&
        api.promoteQueuedTurn
            ? {
                queue: turnQueue,
                followUp: (text: string, images: readonly ImageRef[]) =>
                    api.followUpTurn!(text, [...images]),
                steer: (text: string, images: readonly ImageRef[]) =>
                    api.steerTurn!(text, [...images]),
                edit: (commandId: string, text: string) =>
                    api.editQueuedTurn!(commandId, text),
                remove: (commandId: string) => api.removeQueuedTurn!(commandId),
                reorder: (commandIds: readonly string[]) =>
                    api.reorderQueuedTurns!(commandIds),
                promote: (commandId: string) => api.promoteQueuedTurn!(commandId),
            }
            : undefined;
    const bumpWorktree = () => setWorktreeRev((n) => n + 1);

    // Transcript: durable snapshot of admitted records + live WebSocket events
    // reduced into the in-progress turn (`transcript.ts`) — repairable from the
    // snapshot.
    const [snapshot, setSnapshot] = createSignal<Transcript>(empty);
    const [live, setLive] = createSignal<Transcript>(empty);
    const transcript = (): Transcript => ({
        lines: [...snapshot().lines, ...live().lines],
        openText: live().openText,
    });
    async function loadSnapshot() {
        try {
            setSnapshot(fromSnapshot(await api.getTranscript(id)));
            setLive(empty);
        } catch {
            /* a fresh engagement has no snapshot yet */
        }
    }
    void loadSnapshot();
    const unsubscribe = api.subscribe(id, (ev) => {
        setLive((t) => reduce(t, ev));
        if (ev.type !== "text" || !api.recordFirstTextRendered) return;
        const record = () => api.recordFirstTextRendered?.();
        if (typeof globalThis.requestAnimationFrame === "function") {
            globalThis.requestAnimationFrame(record);
        } else {
            globalThis.queueMicrotask(record);
        }
    });

    // Engagement-scoped read projections (the desktop's `createResource`s, here for
    // one fixed engagement).
    // Audience panels do not receive owner merge/diff authority. Their files/viewer projections
    // are read-only and their sole command is the admitted public turn.
    const ownerEngagement = (): EngagementId | false => false;
    const [diff, { refetch: refetchDiff }] = createResource(ownerEngagement, (eid) => api.engagementDiff(eid));
    const [merge, { refetch: refetchMerge }] = createResource(ownerEngagement, (eid) => api.getMerge(eid));

    // On a turn/merge settling, re-read durable truth (retiring the optimistic echo)
    // and bump the worktree rev so the files panel refetches.
    async function settle() {
        await Promise.allSettled([loadSnapshot(), refetchDiff(), refetchMerge()]);
        bumpWorktree();
    }

    async function send(text: string, images: readonly ImageRef[] = []): Promise<void> {
        const t = text.trim();
        if (!t) throw new Error("A message is required.");
        if (busy()) throw new Error("A turn is already running.");
        setDispatching(true);
        // Optimistic echo: show the user's line the instant the turn starts; the
        // snapshot re-read in settle() retires it (a failed turn drops it).
        setLive((tr) => reduce(tr, { type: "user", text: t }));
        // The Session DO admits the stable command and streams its durable
        // observations over the same WebSocket while this promise is pending.
        try {
            await api.runEmbedTurn(id, t, [...images]);
            await settle();
        } catch (error) {
            await loadSnapshot();
            throw error;
        } finally {
            setDispatching(false);
        }
    }

    const session: Session = {
        api,
        engagementId,
        worktreeRev,
        selectedFile,
        selectFile: (path) => setSelectedFile(path),
        diff: () => diff() ?? "",
        mergePhase: () => merge()?.phase ?? null,
        mergeConflicted: () => merge()?.phase === "Rejected" && merge()?.git_outcome === "Conflict",
        // An embedded end-user chat is a work chat; method-edit vocabulary/lineage is
        // a desktop-owner affordance, not exposed to the audience (kept as a default).
        chatKind: () => "work",
        methodName: () => "",
        transcript,
        busy,
        turnActivity,
        composerCapabilities: () => composerCapabilities,
        // The EDGE-5 client owns one socket and re-establishes it on demand
        // rather than exposing an up/down state the panel reads, so from here a
        // command is always issuable — a send during a reconnect waits on the
        // socket instead of being refused. If that client later projects its
        // transport state, this is where the panel starts believing it.
        canCommand: () => true,
        composerRuntime,
        merge: (action: MergeAction) => void api.mergeCommand(id, action).then(() => settle()),
        onContentSaved: () => void Promise.allSettled([refetchDiff(), refetchMerge()]),
        send,
        stop: api.stopTurn ? () => api.stopTurn!() : undefined,
    };
    return {
        session,
        dispose: () => {
            unsubscribe();
            unsubscribeQueue?.();
            unsubscribeActivity?.();
        },
    };
}
