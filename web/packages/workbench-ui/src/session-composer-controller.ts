import { createComputed, createEffect, createMemo, createSignal, on, type Accessor, type JSX } from "solid-js";
import {
    buildOutgoing,
    classifyAttachment,
    extractDocumentAttachment,
    fileToBase64,
    type Attachment,
    type ImageRef,
} from "./attachments";
import type { ComposerQueueItem } from "./ChatComposer";

export type ComposerAttachmentCapability = "image" | "text" | "document";

/** Commands an Environment admits into the shared chat-composer controller.
 * Presentation identity (desktop/audience/embed) is deliberately absent. */
export interface ComposerCapabilities {
    readonly queue: boolean;
    readonly steer: boolean;
    readonly stop: boolean;
    readonly stage: boolean;
    readonly attachments: readonly ComposerAttachmentCapability[];
}

export const UNIVERSAL_COMPOSER_CAPABILITIES: ComposerCapabilities = Object.freeze({
    queue: true,
    steer: true,
    stop: true,
    stage: true,
    attachments: ["image", "text", "document"] as const,
});

export const BASIC_COMPOSER_CAPABILITIES: ComposerCapabilities = Object.freeze({
    queue: false,
    steer: false,
    stop: false,
    stage: false,
    attachments: ["image", "text", "document"] as const,
});

export interface ComposerTurnOptions {
    readonly review?: boolean;
}

interface QueuedTurn extends ComposerQueueItem {
    readonly images: readonly ImageRef[];
}

export interface ComposerRuntimeQueueItem extends ComposerQueueItem {
    readonly id: string;
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
    readonly send: (
        text: string,
        images: readonly ImageRef[],
        options: ComposerTurnOptions,
    ) => Promise<void>;
    readonly stop?: () => Promise<void>;
    readonly runtime?: ComposerRuntimeCommands;
    readonly draft?: ControlledValue<string>;
    /** Preserve a host-owned draft across Session selection changes. Useful when
     * navigation and immediate typing can overlap; queued/attached state still retires. */
    readonly retainDraftOnScopeChange?: boolean;
    readonly review?: ControlledValue<boolean>;
    readonly modelToolbar?: () => JSX.Element;
    /** `false` is authoritative; undefined remains runtime-permissive. */
    readonly acceptsImages?: Accessor<boolean | undefined>;
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
    readonly gated: Accessor<boolean>;
    readonly reviewNext: Accessor<boolean>;
    readonly canSubmit: Accessor<boolean>;
    readonly error: Accessor<string>;
    readonly attaching: Accessor<boolean>;
    readonly capabilities: Accessor<ComposerCapabilities>;
    readonly modelToolbar?: () => JSX.Element;
    readonly submit: () => void;
    readonly steer: () => void;
    readonly stop: () => void;
    readonly toggleGate: () => void;
    readonly toggleReview?: () => void;
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
    const [internalReview, setInternalReview] = createSignal(false);
    const reviewNext = options.review?.value ?? internalReview;
    const setReviewNext = options.review?.set ?? setInternalReview;
    const [stagedQueue, setStagedQueue] = createSignal<QueuedTurn[]>([]);
    const queue = createMemo<readonly ComposerQueueItem[]>(() => [
        ...(options.runtime?.queue() ?? []),
        ...stagedQueue(),
    ]);
    const [attachments, setAttachments] = createSignal<Attachment[]>([]);
    const [gated, setGated] = createSignal(false);
    const [dispatchingScopes, setDispatchingScopes] = createSignal<ReadonlySet<string>>(new Set());
    const [attaching, setAttaching] = createSignal(false);
    const [error, setError] = createSignal("");
    let nextQueueId = 1;

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

    const resetScopedState = () => {
        if (!options.retainDraftOnScopeChange) setDraft("");
        setStagedQueue([]);
        setGated(false);
        setReviewNext(false);
        setAttachments([]);
        setError("");
    };
    // Scope retirement must precede interaction with the newly selected Session.
    // A deferred effect can otherwise erase text entered immediately after a chat
    // opens (the stream-ready edge and the effect scheduler are independent).
    createComputed(on(options.scope, resetScopedState, { defer: true }));

    const pump = () => {
        if (busy() || gated() || blocked()) return;
        const next = stagedQueue()[0];
        if (!next) return;
        setStagedQueue((current) => current.slice(1));
        const dispatchScope = options.scope();
        markDispatching(dispatchScope, true);
        void options.send(next.text, next.images, { review: next.review })
            .catch((cause) => report(failureMessage(cause)))
            .finally(() => {
                markDispatching(dispatchScope, false);
                queueMicrotask(pump);
            });
    };

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

    const takeOutgoing = (): QueuedTurn | null => {
        const outgoing = buildOutgoing(draft(), [...attachments()]);
        if (!outgoing.message.trim()) return null;
        setDraft("");
        setAttachments([]);
        const review = reviewNext();
        setReviewNext(false);
        return {
            id: nextQueueId++,
            text: outgoing.message,
            images: outgoing.images,
            review,
        };
    };

    const submit = () => {
        // Refuse before `takeOutgoing`, which clears the draft: a send that cannot
        // be carried must leave the text where the writer can still see it.
        if (blocked()) return;
        if (!options.capabilities().queue && busy()) return;
        const outgoing = takeOutgoing();
        if (!outgoing) return;
        setError("");
        if (busy() && !gated() && options.runtime) {
            void options.runtime.followUp(outgoing.text, outgoing.images)
                .catch((cause) => report(`Could not queue: ${failureMessage(cause)}`));
            return;
        }
        setStagedQueue((current) => [...current, outgoing]);
        pump();
    };

    const steer = () => {
        if (blocked()) return;
        if (!options.capabilities().steer || (!options.runtime && !options.stop)) return;
        const outgoing = takeOutgoing();
        if (!outgoing) return;
        setError("");
        if (!busy()) {
            setStagedQueue((current) => [outgoing, ...current]);
            pump();
            return;
        }
        if (options.runtime) {
            void options.runtime.steer(outgoing.text, outgoing.images)
                .catch((cause) => report(`Could not steer: ${failureMessage(cause)}`));
            return;
        }
        setStagedQueue((current) => [outgoing, ...current]);
        void options.stop!().catch((cause) => report(`Could not steer: ${failureMessage(cause)}`));
    };

    const stop = () => {
        // Stop is a standing command too, so a dead transport cannot deliver it.
        if (blocked() || !options.stop || !busy()) return;
        setError("");
        void options.stop().catch((cause) => report(`Could not stop: ${failureMessage(cause)}`));
    };

    const toggleGate = () => {
        if (!options.capabilities().stage) return;
        const releasing = gated();
        setGated(!releasing);
        if (releasing) queueMicrotask(pump);
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

    const reorderQueue = (from: number, to: number) => {
        const runtimeItems = options.runtime?.queue() ?? [];
        if (from < runtimeItems.length && to < runtimeItems.length && options.runtime) {
            const ids = runtimeItems.map((item) => item.id);
            const [moved] = ids.splice(from, 1);
            ids.splice(to, 0, moved);
            void options.runtime.reorder(ids).catch((cause) => report(failureMessage(cause)));
            return;
        }
        const localFrom = from - runtimeItems.length;
        const localTo = to - runtimeItems.length;
        setStagedQueue((current) => {
            if (localFrom < 0 || localTo < 0 || localFrom >= current.length || localTo >= current.length) return current;
            const next = current.slice();
            const [moved] = next.splice(localFrom, 1);
            next.splice(localTo, 0, moved);
            return next;
        });
    };
    const editQueued = (id: number | string, text: string) => {
        const trimmed = text.trim();
        if (typeof id === "string" && options.runtime) {
            const operation = trimmed
                ? options.runtime.edit(id, trimmed)
                : options.runtime.remove(id);
            void operation.catch((cause) => report(failureMessage(cause)));
            return;
        }
        setStagedQueue((current) => current.flatMap((item) =>
            item.id !== id ? [item] : trimmed ? [{ ...item, text: trimmed }] : [],
        ));
    };
    const removeQueued = (id: number | string) => {
        if (typeof id === "string" && options.runtime) {
            void options.runtime.remove(id).catch((cause) => report(failureMessage(cause)));
            return;
        }
        setStagedQueue((current) => current.filter((item) => item.id !== id));
    };
    const sendNowQueued = (id: number | string) => {
        if (blocked()) return;
        const item = queue().find((candidate) => candidate.id === id);
        if (!item) return;
        if (typeof id === "string" && options.runtime) {
            void options.runtime.promote(id).catch((cause) => report(failureMessage(cause)));
            return;
        }
        if (busy()) {
            setStagedQueue((current) => [
                item as QueuedTurn,
                ...current.filter((candidate) => candidate.id !== id),
            ]);
            if (options.capabilities().steer && options.stop) {
                void options.stop().catch((cause) => report(`Could not steer: ${failureMessage(cause)}`));
            }
            return;
        }
        setStagedQueue((current) => current.filter((candidate) => candidate.id !== id));
        const dispatchScope = options.scope();
        markDispatching(dispatchScope, true);
        setError("");
        void options.send(item.text, (item as QueuedTurn).images, { review: item.review })
            .catch((cause) => report(failureMessage(cause)))
            .finally(() => {
                markDispatching(dispatchScope, false);
                queueMicrotask(pump);
            });
    };

    return {
        draft,
        setDraft,
        queue,
        attachments,
        busy,
        blocked,
        gated,
        reviewNext,
        canSubmit,
        error,
        attaching,
        capabilities: options.capabilities,
        modelToolbar: options.modelToolbar,
        submit,
        steer,
        stop,
        toggleGate,
        toggleReview: options.review ? () => setReviewNext(!reviewNext()) : undefined,
        attachFiles,
        removeAttachment: (index) => setAttachments((current) => current.filter((_, at) => at !== index)),
        reorderQueue,
        editQueued,
        removeQueued,
        sendNowQueued,
    };
}
