import { createComputed, createEffect, createMemo, createSignal, on, type Accessor, type JSX } from "solid-js";
import { alreadyApplied } from "@gaugewright/control-plane-client";
import {
    buildOutgoing,
    classifyAttachment,
    extractDocumentAttachment,
    fileToBase64,
    type Attachment,
    type ImageRef,
} from "./attachments";
import type { ComposerMode, ComposerQueueItem } from "./ChatComposer";
import {
    createMemoryOutboxStore,
    newOutboxId,
    type OutboxRow,
    type OutboxStore,
} from "./composer-outbox";

export type ComposerAttachmentCapability = "image" | "text" | "document";

/** Commands an Environment admits into the shared chat-composer controller.
 * Presentation identity (desktop/audience/embed) is deliberately absent. */
export interface ComposerCapabilities {
    readonly queue: boolean;
    readonly steer: boolean;
    readonly stop: boolean;
    /** Can a queued message be kept out of the running order indefinitely?
     *
     *  Holding is a client act (ADR 0137): a held row is one the outbox has not
     *  submitted, so no transport verb is involved and any surface with a queue
     *  can offer it. This stays a declared capability because *offering* stashing
     *  is still a product choice, not because the mechanism varies. */
    readonly hold: boolean;
    /** Can a composed message start a new line of the conversation? Distinct from
     *  `Session.forkAt`, which branches from an existing transcript entry: this
     *  is fork-at-head carrying the draft, and an Environment that can read a
     *  fork tree cannot necessarily mint one. */
    readonly fork: boolean;
    readonly attachments: readonly ComposerAttachmentCapability[];
}

export const UNIVERSAL_COMPOSER_CAPABILITIES: ComposerCapabilities = Object.freeze({
    queue: true,
    steer: true,
    stop: true,
    hold: true,
    fork: true,
    attachments: ["image", "text", "document"] as const,
});

export const BASIC_COMPOSER_CAPABILITIES: ComposerCapabilities = Object.freeze({
    queue: false,
    steer: false,
    stop: false,
    hold: false,
    fork: false,
    attachments: ["image", "text", "document"] as const,
});

export interface ComposerRuntimeQueueItem extends ComposerQueueItem {
    readonly id: string;
    /** The attachments the host holds for this row.
     *
     *  Undefined means the queue projection carries text only, which is not the
     *  same as a row with no attachments: the bytes may exist on the host and
     *  simply not be readable here. Withdrawing such a row would delete the
     *  authoritative copy and keep only its words, so the controller refuses it
     *  (see {@link SessionComposerController.holdQueued}). A host whose
     *  projection is complete says so by supplying this, empty included. */
    readonly images?: readonly ImageRef[];
}

/** Optional runtime-owned queue. Environments that supply it get durable
 * Pi-style steer/follow-up semantics; environments without it keep the same
 * controller with its local staged queue. */
export interface ComposerRuntimeCommands {
    readonly queue: Accessor<readonly ComposerRuntimeQueueItem[]>;
    readonly followUp: (text: string, images: readonly ImageRef[]) => Promise<void>;
    readonly steer: (text: string, images: readonly ImageRef[]) => Promise<void>;
    readonly edit: (id: string, text: string) => Promise<void>;
    readonly remove: (id: string) => Promise<void>;
    readonly reorder: (ids: readonly string[]) => Promise<void>;
    readonly promote: (id: string) => Promise<void>;
}

interface ControlledValue<T> {
    readonly value: Accessor<T>;
    readonly set: (value: T) => void;
}

export interface SessionComposerControllerOptions {
    /** Queue/draft scope. Changing it retires client-only staged state. */
    readonly scope: Accessor<string>;
    readonly busy: Accessor<boolean>;
    readonly capabilities: Accessor<ComposerCapabilities>;
    /** The Session's momentary command admission. Omitted means always able —
     * the honest default for a host whose transport is local. */
    readonly canCommand?: Accessor<boolean>;
    /** `composedId` is the outbox id this message was composed under, so the
     *  host can apply it once (ADR 0137 §3). The controller always supplies it;
     *  what a host does with it is the host's business. */
    readonly send: (
        text: string,
        images: readonly ImageRef[],
        composedId: string,
    ) => Promise<void>;
    readonly stop?: () => Promise<void>;
    readonly runtime?: ComposerRuntimeCommands;
    /** Where composed messages live before they are sent (ADR 0137). Defaults to
     *  a session-scoped store, so every surface has the tier and durability is a
     *  store swap rather than a second code path. Owner surfaces pass a durable
     *  one; the audience embed should keep the default. */
    readonly outbox?: OutboxStore;
    /** The mode a chat opens in — a standing user preference, not chat state.
     *  The mode itself is per chat (see {@link SessionComposerController.mode});
     *  this is only what a chat you have not touched starts as. Hosts that do not
     *  persist a preference leave it undefined and every chat opens steering. */
    readonly defaultMode?: Accessor<ComposerMode>;
    readonly draft?: ControlledValue<string>;
    /** Preserve a host-owned draft across Session selection changes. Useful when
     * navigation and immediate typing can overlap; queued/attached state still retires. */
    readonly retainDraftOnScopeChange?: boolean;
    /** `stacked` asks for the compact expander's labelled-row form. */
    readonly modelToolbar?: (stacked?: boolean) => JSX.Element;
    /** `false` is authoritative; undefined remains runtime-permissive. */
    readonly acceptsImages?: Accessor<boolean | undefined>;
    /** Does {@link send} apply a composed id at most once (ADR 0137 §3)?
     *
     *  This is what licenses **resending** a message whose dispatch never
     *  settled. Without the guarantee, a resend is the one action that can run a
     *  turn twice, so an in-flight row is set aside for a person instead — which
     *  is safe but costs the message its automatic recovery.
     *
     *  Default `false`, deliberately: a host that has not said it applies the id
     *  once is assumed not to, because the failure of guessing wrong in that
     *  direction is a duplicate turn and the failure in the other is a row that
     *  waits for a click. Opt in only when the transport really carries the id
     *  through to a server-side receipt. */
    readonly appliesComposedIdOnce?: Accessor<boolean>;
    readonly onStatus?: (message: string) => void;
}

export interface SessionComposerController {
    readonly draft: Accessor<string>;
    readonly setDraft: (value: string) => void;
    readonly queue: Accessor<readonly ComposerQueueItem[]>;
    readonly attachments: Accessor<readonly Attachment[]>;
    readonly busy: Accessor<boolean>;
    /** The transport cannot presently carry a standing command. Distinct from
     * `canSubmit` (is there anything to send?) and from `busy` (is a turn
     * already running?), because the repair is different for each and the
     * composer says so differently. */
    readonly blocked: Accessor<boolean>;
    /** Where a composed message goes when you just press Enter. Kept per chat, so
     *  jotting in one conversation cannot silently redirect the next one; a chat
     *  you have not chosen for rests in {@link SessionComposerControllerOptions.defaultMode}. */
    readonly mode: Accessor<ComposerMode>;
    readonly setMode: (mode: ComposerMode) => void;
    /** Whether this Environment can keep a queued message out of the running
     *  order — which is what both stashing and the per-row hold do. Reads the
     *  declared capability: an Environment whose queue it cannot hold says so
     *  there, so the controls never appear rather than appearing and doing
     *  nothing. */
    readonly canHold: Accessor<boolean>;
    readonly canSubmit: Accessor<boolean>;
    readonly error: Accessor<string>;
    readonly attaching: Accessor<boolean>;
    readonly capabilities: Accessor<ComposerCapabilities>;
    /** `stacked` asks for the compact expander's labelled-row form. */
    readonly modelToolbar?: (stacked?: boolean) => JSX.Element;
    readonly submit: () => void;
    readonly steer: () => void;
    /** Put the draft in the queue, held. Nothing runs it until it is released. */
    readonly stash: () => void;
    /** Lift the composed message out of the box for a host that will deliver it
     *  somewhere this controller does not reach — forking into a new chat is the
     *  case that exists. Clears the box like any other destination would, and
     *  hands back a `restore` so a host whose delivery *fails* can put the
     *  message back rather than eat it. Null when there is nothing composed. */
    readonly takeComposed: () => {
        readonly text: string;
        readonly images: readonly ImageRef[];
        readonly restore: () => void;
    } | null;
    readonly stop: () => void;
    /** Move one queued message between ready and held. Releasing the head of the
     *  line starts it, which is what "release" has to mean. */
    readonly holdQueued: (id: number | string, held: boolean) => void;
    readonly attachFiles: (files: readonly File[]) => Promise<void>;
    readonly removeAttachment: (index: number) => void;
    readonly reorderQueue: (from: number, to: number) => void;
    readonly editQueued: (id: number | string, text: string) => void;
    readonly removeQueued: (id: number | string) => void;
    readonly sendNowQueued: (id: number | string) => void;
}

function failureMessage(error: unknown): string {
    if (error instanceof Error && error.message.trim()) return error.message;
    const message = String(error).trim();
    return message || "The turn failed.";
}

/** One client-only controller for every Session-backed chat composer. Runtime
 * truth remains in Session; this owns only drafts, staged commands, and their
 * explicit settlement-driven orchestration. */
export function createSessionComposerController(
    options: SessionComposerControllerOptions,
): SessionComposerController {
    const [internalDraft, setInternalDraft] = createSignal("");
    const draft = options.draft?.value ?? internalDraft;
    const setDraft = options.draft?.set ?? setInternalDraft;
    const store = options.outbox ?? createMemoryOutboxStore();
    const [rows, setRows] = createSignal<readonly OutboxRow[]>([]);
    // Rows handed to the transport but not yet acknowledged. They stay in the
    // store until the send resolves — losing a message because the send failed is
    // the quiet loss the outbox exists to stop — but they leave the *queue* the
    // moment they are dispatched, because a message that is running is the turn,
    // not something waiting behind it.
    const [sending, setSending] = createSignal<ReadonlySet<string>>(new Set());
    const markSending = (id: string, active: boolean) => {
        setSending((current) => {
            const next = new Set(current);
            if (active) next.add(id);
            else next.delete(id);
            return next;
        });
    };
    let nextSeq = 1;
    /** Submitted rows in the host's order, then unsubmitted rows in creation
     *  order (ADR 0137 §4). The two regions never interleave, which is what makes
     *  a reorder across the boundary refusable rather than ambiguous. */
    /** A host row can be withdrawn only where the outbox can hold the whole
     *  message. The queue projection is the only description of it available
     *  here, so a projection that carries no attachments cannot say whether the
     *  row had any, and withdrawing it would delete the host's copy and keep the
     *  words alone (ADR 0137 §5). */
    const canWithdraw = (item: ComposerRuntimeQueueItem) => item.images !== undefined;
    const queue = createMemo<readonly ComposerQueueItem[]>(() => [
        ...(options.runtime?.queue() ?? []).map((item) => ({
            id: item.id,
            text: item.text,
            held: false,
            canHold: canWithdraw(item),
        })),
        ...rows()
            .filter((row) => !sending().has(row.id))
            .map((row) => ({ id: row.id, text: row.text, held: row.held })),
    ]);
    const isRuntimeRow = (id: number | string) =>
        (options.runtime?.queue() ?? []).some((item) => item.id === id);
    const [attachments, setAttachments] = createSignal<Attachment[]>([]);
    // Mode is per chat, so a stashing spell in one conversation cannot quietly
    // redirect the next one. Keyed by scope rather than retired with the rest of
    // the scoped state because coming back to a chat should find it as you left
    // it — unlike the queue, a mode costs nothing to remember.
    const [modes, setModes] = createSignal<ReadonlyMap<string, ComposerMode>>(new Map());
    const defaultMode = (): ComposerMode => options.defaultMode?.() ?? "steer";
    const mode = (): ComposerMode => modes().get(options.scope()) ?? defaultMode();
    const setMode = (next: ComposerMode) => {
        const scope = options.scope();
        setModes((current) => new Map(current).set(scope, next));
    };
    const canHold = () => options.capabilities().hold;
    const [dispatchingScopes, setDispatchingScopes] = createSignal<ReadonlySet<string>>(new Set());
    const [attaching, setAttaching] = createSignal(false);
    const [error, setError] = createSignal("");

    const busy = () => options.busy() || dispatchingScopes().has(options.scope());
    const blocked = () => options.canCommand?.() === false;
    const markDispatching = (scope: string, active: boolean) => {
        setDispatchingScopes((current) => {
            const next = new Set(current);
            if (active) next.add(scope);
            else next.delete(scope);
            return next;
        });
    };
    const canSubmit = () => draft().trim().length > 0 || attachments().length > 0;
    const report = (message: string) => {
        setError(message);
        options.onStatus?.(message);
    };

    /** The signal is the working copy the composer renders; the store is where
     *  it survives. Writes are **awaitable** and chained per row: awaitable
     *  because nothing may be handed to the transport before it is durable, and
     *  chained because two writes to one row must reach the store in the order
     *  they were made. A failed write is reported rather than swallowed,
     *  because losing durability silently would leave the queue looking safe
     *  when it is not. */
    const writes = new Map<string, Promise<boolean>>();
    const after = <T>(id: string, work: () => Promise<T>): Promise<T> => {
        const queued = writes.get(id);
        return queued ? queued.then(work, work) : work();
    };
    const track = (id: string, settled: Promise<boolean>) => {
        writes.set(id, settled);
        void settled.then(() => {
            if (writes.get(id) === settled) writes.delete(id);
        });
        return settled;
    };
    const persist = (row: OutboxRow): Promise<boolean> =>
        track(row.id, after(row.id, () => store.put(row)).then(
            () => true,
            () => {
                report("This message is queued, but could not be saved for later.");
                return false;
            },
        ));
    const forget = (id: string) => {
        void track(id, after(id, () => store.remove(id)).then(() => true, () => false));
    };

    // Only the newest hydration may write. Opening two chats quickly otherwise
    // races, and the loser would repopulate the queue of a chat you have left.
    let hydration = 0;
    /** Scopes whose stored rows have arrived. The drain stands still until the
     *  scope it would send from is in here: the oldest ready row cannot be
     *  chosen from half the set, and sending a message composed just now ahead
     *  of ones still loading is precisely the order reversal creation order
     *  promises not to do (ADR 0137 §4). */
    const hydrated = new Set<string>();
    const hydrate = (scope: string) => {
        const token = ++hydration;
        hydrated.delete(scope);
        void store.load(scope)
            .then((found) => {
                let loaded: readonly OutboxRow[] = found;
                if (token !== hydration) return;
                nextSeq = loaded.reduce((high, row) => Math.max(high, row.seq), 0) + 1;
                // A row that was in flight when the client died has an unknown
                // fate: the host may have taken it.
                //
                // Where the host applies a composed id once, the recovery is to
                // ask — resend it under the same id and let the host say whether
                // it already ran. The row stays ready and the drain does exactly
                // that. Where the host offers no such guarantee, resending is the
                // one outcome that can run a turn twice, so the row is set aside
                // for a person to judge instead. See ADR 0137 §3.
                if (!options.appliesComposedIdOnce?.()) {
                    for (const row of loaded) {
                        if (!row.dispatched) continue;
                        const settled = { ...row, dispatched: false, held: true };
                        loaded = loaded.map((other) => (other.id === row.id ? settled : other));
                        persist(settled);
                    }
                }
                // Anything composed while the load was in flight is already in the
                // store and simply newer, so it wins. This is not a merge of two
                // sources — there is one store, and this only keeps the read from
                // clobbering a write that overtook it.
                const inFlight = sending();
                const byId = new Map(loaded.map((row) => [row.id, row]));
                for (const row of rows()) {
                    if (inFlight.has(row.id)) {
                        byId.set(row.id, row);
                        continue;
                    }
                    // Those rows were numbered against an empty store, so their
                    // `seq` would seat them in front of rows that are genuinely
                    // older. Creation order is what the number means, so they are
                    // renumbered onto the end of what was loaded.
                    const renumbered = { ...row, seq: nextSeq++ };
                    byId.set(row.id, renumbered);
                    persist(renumbered);
                }
                setRows([...byId.values()].sort((a, b) => a.seq - b.seq));
                hydrated.add(scope);
                queueMicrotask(drain);
            })
            .catch(() => {
                // A read that failed will not arrive later, and holding the drain
                // shut until it does would strand every new message behind a store
                // this browser cannot read. The scope opens on what is in memory.
                if (token === hydration) hydrated.add(scope);
                report("Could not read messages saved for later.");
                queueMicrotask(drain);
            });
    };

    const resetScopedState = () => {
        if (!options.retainDraftOnScopeChange) setDraft("");
        // The outbox is not retired with the rest of the scoped state — that is
        // the point of it. The rows are dropped from *this* view and reloaded for
        // the chat being opened; nothing is deleted.
        setRows([]);
        setSending(() => new Set<string>());
        setAttachments([]);
        setError("");
        hydrate(options.scope());
    };
    // Scope retirement must precede interaction with the newly selected Session.
    // A deferred effect can otherwise erase text entered immediately after a chat
    // opens (the stream-ready edge and the effect scheduler are independent).
    createComputed(on(options.scope, resetScopedState, { defer: true }));
    hydrate(options.scope());

    // The drain takes the next *ready* message and steps over held ones. It does
    // not consult the mode: the mode says where a new message goes, not whether
    // the line moves. That distinction is the whole reason a stashed thought no
    // longer freezes the messages you did mean to run.
    const drop = (id: string) => {
        setRows((current) => current.filter((row) => row.id !== id));
        forget(id);
    };

    /** A send that failed leaves the message **held** rather than gone.
     *
     *  Before the outbox the row was removed before the send and a failure simply
     *  lost it. Keeping it is the point of durability — but keeping it *ready*
     *  would make the drain offer the same failing row forever. Held, it is
     *  visible, recoverable, and retried only when a person releases it, which is
     *  also the honest reading: this one did not go, it is set aside for you. */
    const setAside = (id: string) => {
        setRows((current) => current.map((row) => {
            if (row.id !== id) return row;
            const next = { ...row, held: true, dispatched: false };
            persist(next);
            return next;
        }));
    };

    const drain = () => {
        if (blocked()) return;
        // Nothing may be sent from a scope whose stored rows have not arrived.
        // Hydration re-drains, so this defers the send rather than dropping it.
        if (!hydrated.has(options.scope())) return;
        const next = rows().find((row) => !row.held && !sending().has(row.id));
        if (!next) return;
        // A runtime can take a follow-up while its turn is still running; without
        // one, the row waits for settlement. Either way the row leaves the outbox
        // only once the host has it. The choice is made here rather than after the
        // write, so the row is delivered the way it was picked.
        const asFollowUp = busy();
        if (asFollowUp && !options.runtime) return;
        const dispatchScope = options.scope();
        markSending(next.id, true);
        // Marked before the write, not after it: the composer reads as busy from
        // the moment the row is committed to the transport, and a slow store must
        // not open a window where nothing looks like it is happening.
        if (!asFollowUp) markDispatching(dispatchScope, true);
        // Durable *before* the transport sees it. The draft was cleared when the
        // row was composed, so a row handed to `send` whose write never landed is
        // recoverable from nowhere if the tab dies mid-request: the exact loss
        // this outbox exists to prevent. A write that fails refuses the dispatch
        // and sets the row aside instead.
        void persist({ ...next, dispatched: true }).then((stored) => {
            if (stored) {
                deliver(next, asFollowUp, dispatchScope);
                return;
            }
            if (!asFollowUp) markDispatching(dispatchScope, false);
            markSending(next.id, false);
            // Held in the signal without a further write: the store has just
            // said it cannot take one, and a second doomed attempt would only
            // replace this refusal with a vaguer message about durability.
            setRows((current) => current.map((row) => (
                row.id === next.id ? { ...row, held: true, dispatched: false } : row
            )));
            report("This message was not sent, because it could not be saved first. It is held here.");
        });
    };

    const deliver = (next: OutboxRow, asFollowUp: boolean, dispatchScope: string) => {
        const finish = () => {
            markSending(next.id, false);
            queueMicrotask(drain);
        };
        if (asFollowUp) {
            void options.runtime!.followUp(next.text, next.images)
                .then(() => drop(next.id))
                .catch((cause) => {
                    setAside(next.id);
                    report(`Could not queue: ${failureMessage(cause)}`);
                })
                .finally(finish);
            return;
        }
        void options.send(next.text, next.images, next.id)
            .then(() => drop(next.id))
            .catch((cause) => {
                // A host that refuses this send because it already applied the
                // composed id has not failed — it has answered the question the
                // resend was asked to ask (ADR 0137 §3). The turn ran; exactly one
                // attempt ran it; the row is done. Reporting it as an error would
                // teach the reader to distrust a mechanism that just worked.
                if (alreadyApplied(cause)) {
                    drop(next.id);
                    return;
                }
                setAside(next.id);
                report(failureMessage(cause));
            })
            .finally(() => {
                markDispatching(dispatchScope, false);
                finish();
            });
    };
    const pump = drain;

    // A resumed Session can already be busy before this controller exists. When
    // that authoritative turn settles, drain anything the visitor queued locally.
    createEffect(on(options.busy, (now, previous) => {
        if (previous && !now) queueMicrotask(pump);
    }));

    // A transport that recovers drains what was staged while it was down. Without
    // this, anything queued during an outage waits for the next unrelated pump
    // and reads as silently swallowed — the outcome `blocked` exists to prevent.
    createEffect(on(blocked, (now, previous) => {
        if (previous && !now) queueMicrotask(pump);
    }));

    /** Lift the draft out of the box as a durable row. `at` puts it at the head
     *  of the unsubmitted region — steering and send-now both need that — and
     *  nothing else reorders on composition. */
    const compose = (held: boolean, position: "back" | "front" = "back"): OutboxRow | null => {
        const outgoing = buildOutgoing(draft(), [...attachments()]);
        if (!outgoing.message.trim()) return null;
        setDraft("");
        setAttachments([]);
        const seq = position === "front"
            ? rows().reduce((low, row) => Math.min(low, row.seq), nextSeq) - 1
            : nextSeq++;
        const row: OutboxRow = {
            id: newOutboxId(),
            scope: options.scope(),
            text: outgoing.message,
            images: outgoing.images,
            held,
            seq,
            at: Date.now(),
        };
        persist(row);
        setRows((current) => [...current, row].sort((a, b) => a.seq - b.seq));
        return row;
    };

    const submit = () => {
        // An Environment with no queue has nowhere to hold a message, so it still
        // refuses one it cannot run right now. Everywhere else the message lands
        // durably and waits — including while the transport is down, which is the
        // whole point of composing offline (ADR 0137).
        if (!options.capabilities().queue && (busy() || blocked())) return;
        if (!compose(false)) return;
        setError("");
        drain();
    };

    const steer = () => {
        // Steering is a live command by definition — "run this instead, now". It
        // is the one destination the outbox cannot stand in for, so a dead
        // transport refuses it and leaves the text where the writer can see it.
        if (blocked()) return;
        if (!options.capabilities().steer || (!options.runtime && !options.stop)) return;
        if (busy() && options.runtime) {
            const outgoing = compose(false, "front");
            if (!outgoing) return;
            setError("");
            // Handed straight to the runtime; the row exists only long enough to
            // survive a failure between composing and admitting.
            markSending(outgoing.id, true);
            void options.runtime.steer(outgoing.text, outgoing.images)
                .then(() => drop(outgoing.id))
                .catch((cause) => {
                    setAside(outgoing.id);
                    report(`Could not steer: ${failureMessage(cause)}`);
                })
                .finally(() => markSending(outgoing.id, false));
            return;
        }
        const outgoing = compose(false, "front");
        if (!outgoing) return;
        setError("");
        if (!busy()) {
            drain();
            return;
        }
        void options.stop!().catch((cause) => report(`Could not steer: ${failureMessage(cause)}`));
    };

    /** Jot the draft down. It joins the same line every other message is in, held,
     *  and nothing drains after — a stash that ran would not be a stash. Held is
     *  simply *unsubmitted*, so this needs no transport and works offline. */
    const stash = () => {
        if (!canHold()) return;
        if (!compose(true)) return;
        setError("");
    };

    const takeComposed = () => {
        const previous = { draft: draft(), attachments: attachments() };
        const row = compose(false);
        if (!row) return null;
        // Taken out of the outbox as well as the box: the host is delivering it
        // somewhere this controller does not reach.
        drop(row.id);
        return {
            text: row.text,
            images: row.images,
            restore: () => {
                setDraft(previous.draft);
                setAttachments([...previous.attachments]);
            },
        };
    };

    const stop = () => {
        // Stop is a standing command too, so a dead transport cannot deliver it.
        if (blocked() || !options.stop || !busy()) return;
        setError("");
        void options.stop().catch((cause) => report(`Could not stop: ${failureMessage(cause)}`));
    };

    /** Hold a row out of the running order, or release it back into one.
     *
     *  For a row the host already has, holding is a **withdraw** (ADR 0137 §5):
     *  take it out of the host's queue and put it back in the outbox. There is no
     *  host-side held state to set. It also fails honestly — a row that has
     *  already run cannot be removed, and the refusal is the truthful answer
     *  rather than a hold that arrives too late to mean anything. */
    const holdQueued = (id: number | string, held: boolean) => {
        if (!canHold()) return;
        if (isRuntimeRow(id)) {
            // Already in the running order; there is nothing to release it into.
            if (!held || !options.runtime) return;
            const item = options.runtime.queue().find((row) => row.id === id);
            if (!item) return;
            // Withdrawing deletes the host's row and recreates it here, so it is
            // only offered where this side can hold the whole message. A
            // text-only projection cannot, and quietly dropping someone's images
            // to honour a hold would be the worse answer.
            if (!canWithdraw(item)) {
                report("This message cannot be held here without losing what was attached to it.");
                return;
            }
            const withdrawn = item.text;
            const attached = item.images ?? [];
            void options.runtime.remove(String(id))
                .then(() => {
                    const row: OutboxRow = {
                        id: newOutboxId(),
                        scope: options.scope(),
                        text: withdrawn,
                        images: attached,
                        held: true,
                        seq: nextSeq++,
                        at: Date.now(),
                    };
                    persist(row);
                    setRows((current) => [...current, row].sort((a, b) => a.seq - b.seq));
                })
                .catch(() => report("That message has already run — it cannot be held now."));
            return;
        }
        setRows((current) => current.map((row) => {
            if (row.id !== id) return row;
            const next = { ...row, held };
            persist(next);
            return next;
        }));
        // Releasing the row at the head of the line has to start it, or "release"
        // would mean nothing until the next unrelated turn settled.
        if (!held) queueMicrotask(drain);
    };

    const attachFiles = async (files: readonly File[]) => {
        const admitted = new Set(options.capabilities().attachments);
        if (admitted.size === 0 || files.length === 0) return;
        setAttaching(true);
        setError("");
        const next: Attachment[] = [];
        const failures: string[] = [];
        try {
            for (const file of files) {
                const kind = classifyAttachment(file);
                try {
                    if (kind === "image" && admitted.has("image")) {
                        if (options.acceptsImages?.() === false) {
                            failures.push(`${file.name}: this model cannot read images`);
                        } else {
                            next.push({
                                kind: "image",
                                name: file.name || "attached image",
                                mimeType: file.type,
                                data: await fileToBase64(file),
                            });
                        }
                    } else if (kind === "text" && admitted.has("text")) {
                        next.push({ kind: "text", name: file.name, text: await file.text() });
                    } else if (kind === "document" && admitted.has("document")) {
                        next.push(await extractDocumentAttachment(file));
                    } else {
                        failures.push(`${file.name}: unsupported attachment`);
                    }
                } catch (cause) {
                    failures.push(`${file.name}: ${failureMessage(cause)}`);
                }
            }
            if (next.length > 0) setAttachments((current) => [...current, ...next]);
            if (failures.length > 0) report(failures.join("; "));
        } finally {
            setAttaching(false);
        }
    };

    /** Reordering happens *within* a region, never across one (ADR 0137 §4). The
     *  host orders what it holds and the outbox orders what it has not sent; a
     *  row dragged from one into the other has no defined destination, so the
     *  move is refused rather than half-applied. */
    /** Reordering happens *within* a region, never across one (ADR 0137 §4). The
     *  host orders what it holds and the outbox orders what it has not sent; a
     *  row dragged from one into the other has no defined destination, so the
     *  move is refused rather than half-applied.
     *
     *  Positions are resolved through the rendered queue and then by **id**, not
     *  by arithmetic on the caller's indices. The queue hides rows that are in
     *  flight, so a displayed index is not an index into the stored rows, and
     *  offsetting one to reach the other is how this went wrong before. */
    const reorderQueue = (from: number, to: number) => {
        const shown = queue();
        const moving = shown[from];
        const target = shown[to];
        if (!moving || !target || moving.id === target.id) return;
        const fromHost = isRuntimeRow(moving.id);
        if (fromHost !== isRuntimeRow(target.id)) return;

        if (fromHost && options.runtime) {
            const ids = options.runtime.queue().map((item) => item.id);
            const at = ids.indexOf(String(moving.id));
            const onto = ids.indexOf(String(target.id));
            if (at < 0 || onto < 0) return;
            ids.splice(at, 1);
            ids.splice(onto, 0, String(moving.id));
            void options.runtime.reorder(ids).catch((cause) => report(failureMessage(cause)));
            return;
        }

        setRows((current) => {
            const at = current.findIndex((row) => row.id === moving.id);
            const onto = current.findIndex((row) => row.id === target.id);
            if (at < 0 || onto < 0) return current;
            const next = current.slice();
            const [moved] = next.splice(at, 1);
            next.splice(onto, 0, moved);
            // Creation order is what `seq` means everywhere else, so a deliberate
            // reorder rewrites it rather than layering a second ordering on top.
            const renumbered = next.map((row, index) => ({ ...row, seq: index + 1 }));
            nextSeq = renumbered.length + 1;
            for (const row of renumbered) persist(row);
            return renumbered;
        });
    };

    const editQueued = (id: number | string, text: string) => {
        const trimmed = text.trim();
        if (isRuntimeRow(id) && options.runtime) {
            const operation = trimmed
                ? options.runtime.edit(String(id), trimmed)
                : options.runtime.remove(String(id));
            void operation.catch((cause) => report(failureMessage(cause)));
            return;
        }
        setRows((current) => current.flatMap((row) => {
            if (row.id !== id) return [row];
            if (!trimmed) {
                forget(row.id);
                return [];
            }
            const next = { ...row, text: trimmed };
            persist(next);
            return [next];
        }));
    };

    const removeQueued = (id: number | string) => {
        if (isRuntimeRow(id) && options.runtime) {
            void options.runtime.remove(String(id)).catch((cause) => report(failureMessage(cause)));
            return;
        }
        drop(String(id));
    };

    const sendNowQueued = (id: number | string) => {
        if (blocked()) return;
        if (isRuntimeRow(id) && options.runtime) {
            void options.runtime.promote(String(id)).catch((cause) => report(failureMessage(cause)));
            return;
        }
        const row = rows().find((candidate) => candidate.id === id);
        if (!row) return;
        // Released as well as promoted: a held row sent to the front that the
        // drain then stepped over would be the worst of both readings.
        const promoted: OutboxRow = {
            ...row,
            held: false,
            seq: rows().reduce((low, other) => Math.min(low, other.seq), row.seq) - 1,
        };
        persist(promoted);
        setRows((current) => current
            .map((other) => (other.id === row.id ? promoted : other))
            .sort((a, b) => a.seq - b.seq));
        setError("");
        // Without a runtime, cutting the line means ending the turn in front of
        // it; the drain picks this row up when the stop settles.
        if (busy() && !options.runtime && options.capabilities().steer && options.stop) {
            void options.stop().catch((cause) => report(`Could not steer: ${failureMessage(cause)}`));
            return;
        }
        drain();
    };

    return {
        draft,
        setDraft,
        queue,
        attachments,
        busy,
        blocked,
        mode,
        setMode,
        canHold,
        canSubmit,
        error,
        attaching,
        capabilities: options.capabilities,
        modelToolbar: options.modelToolbar,
        submit,
        steer,
        stash,
        takeComposed,
        stop,
        holdQueued,
        attachFiles,
        removeAttachment: (index) => setAttachments((current) => current.filter((_, at) => at !== index)),
        reorderQueue,
        editQueued,
        removeQueued,
        sendNowQueued,
    };
}
