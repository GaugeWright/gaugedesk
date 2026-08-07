/**
 * The one chat composer presentation used by every GaugeDesk Environment.
 *
 * An Environment supplies the commands it is allowed to expose. The desktop
 * supplies queue/steer/review/attachment controls; an audience Environment
 * supplies send only. Capability changes therefore remove controls from this
 * shared composer instead of selecting a second, lesser UI.
 */
import { createEffect, createSignal, For, onCleanup, onMount, Show, type JSX } from "solid-js";
import { IMAGE_MIMES, type Attachment } from "./attachments";
import { Icon } from "./icons";

export interface ComposerQueueItem {
    readonly id: number | string;
    readonly text: string;
    readonly review?: boolean;
}

export interface ChatComposerProps {
    readonly draft: string;
    readonly placeholder: string;
    readonly queue?: readonly ComposerQueueItem[];
    readonly attachments?: readonly Attachment[];
    readonly busy: boolean;
    readonly gated?: boolean;
    readonly reviewNext?: boolean;
    readonly canSubmit: boolean;
    /** The Session cannot presently carry a standing command. Disables the
     *  command controls and *only* those — the draft stays editable, because
     *  composing while unable to deliver is the point of an offline client. The
     *  Environment shows why elsewhere (mobile's connection banner), so this is
     *  a refusal with a stated reason rather than a dead control. */
    readonly blocked?: boolean;
    readonly error?: string;
    readonly attaching?: boolean;
    /** Marks the public custom-element contract without changing presentation. */
    readonly audience?: boolean;
    /** The no-selection desktop on-ramp that mints a chat on first send. */
    readonly quickStart?: boolean;
    readonly modelToolbar?: JSX.Element;
    readonly onDraft: (value: string) => void;
    readonly onSubmit: () => void;
    readonly onSteer?: () => void;
    readonly onStop?: () => void;
    readonly onToggleGate?: () => void;
    readonly onToggleReview?: () => void;
    readonly onAttachInput?: JSX.EventHandler<HTMLInputElement, Event>;
    /** Image files pasted into the textarea. Text paste remains native. */
    readonly onPasteFiles?: (files: readonly File[]) => void | Promise<void>;
    readonly onRemoveAttachment?: (index: number) => void;
    readonly onReorderQueue?: (from: number, to: number) => void;
    readonly onEditQueue?: (id: number | string, text: string) => void;
    readonly onRemoveQueue?: (id: number | string) => void;
    readonly onSendNow?: (id: number | string) => void;
    readonly inputRef?: (element: HTMLTextAreaElement) => void;
}

export function ChatComposer(props: ChatComposerProps): JSX.Element {
    let attachInput: HTMLInputElement | undefined;
    let messageInput: HTMLTextAreaElement | undefined;
    const queue = () => props.queue ?? [];
    const attachments = () => props.attachments ?? [];
    const hasQueueCommands = () =>
        props.onReorderQueue && props.onEditQueue && props.onRemoveQueue && props.onSendNow;
    const audienceBusy = () => props.busy && !props.onSteer && !hasQueueCommands();
    const resizeMessage = () => {
        const element = messageInput;
        // ChatPanel marks its own sizing boundary for embedded/audience mounts.
        // Desktop mounts the panel body bare, so retain the workbench shell as a
        // fallback without making every shared composer depend on that shell.
        const panel = element?.closest<HTMLElement>("[data-chat-panel], .panel.run");
        if (!element || !panel) return;
        const maximum = Math.floor(panel.clientHeight / 2);
        element.style.height = "auto";
        element.style.maxHeight = `${maximum}px`;
        element.style.height = `${Math.min(element.scrollHeight, maximum)}px`;
        element.style.overflowY = element.scrollHeight > maximum ? "auto" : "hidden";
    };
    createEffect(() => {
        props.draft;
        queueMicrotask(resizeMessage);
    });
    onMount(() => {
        const panel = messageInput?.closest<HTMLElement>("[data-chat-panel], .panel.run");
        const observer = panel ? new ResizeObserver(resizeMessage) : undefined;
        if (panel) observer?.observe(panel);
        resizeMessage();
        onCleanup(() => observer?.disconnect());
    });
    return (
        <div
            class="composer-dock"
            data-chat-composer
            data-desktop-composer={props.audience ? undefined : ""}
            data-empty-chat-composer={props.quickStart ? "" : undefined}
        >
            <Show when={queue().length > 0 && hasQueueCommands()}>
                <ComposerQueue
                    items={queue()}
                    onReorder={props.onReorderQueue!}
                    onEdit={props.onEditQueue!}
                    onRemove={props.onRemoveQueue!}
                    onSendNow={props.onSendNow!}
                />
            </Show>

            <Show when={attachments().length > 0 && props.onRemoveAttachment}>
                <div class="composer-attachments" data-attachments>
                    <For each={attachments()}>
                        {(attachment, index) => (
                            <span class="attachment-chip" data-attachment data-kind={attachment.kind}>
                                {attachment.kind === "image" ? (
                                    <img
                                        class="chip-thumb"
                                        src={`data:${attachment.mimeType};base64,${attachment.data}`}
                                        alt=""
                                    />
                                ) : (
                                    <Icon name="paperclip" />
                                )}
                                {attachment.name}
                                <button
                                    class="chip-x"
                                    type="button"
                                    aria-label={`Remove ${attachment.name}`}
                                    onClick={() => props.onRemoveAttachment!(index())}
                                >
                                    ×
                                </button>
                            </span>
                        )}
                    </For>
                </div>
            </Show>

            <Show when={props.error}>
                <div class="composer-error" data-composer-error role="status">
                    {props.error}
                </div>
            </Show>

            <Show when={props.onAttachInput}>
                <input
                    ref={attachInput}
                    type="file"
                    multiple
                    data-attach-input
                    style={{ display: "none" }}
                    onChange={props.onAttachInput}
                />
            </Show>

            <div class="composer-message">
                <textarea
                    ref={(element) => {
                        messageInput = element;
                        props.inputRef?.(element);
                    }}
                    rows="1"
                    data-embed-composer={props.audience ? "" : undefined}
                    aria-label="Message"
                    placeholder={props.placeholder}
                    value={props.draft}
                    disabled={audienceBusy()}
                    onInput={(event) => props.onDraft(event.currentTarget.value)}
                    onPaste={(event) => {
                        if (!props.onPasteFiles) return;
                        const clipboard = event.clipboardData;
                        if (!clipboard) return;
                        const clipboardFiles = Array.from(clipboard.files);
                        const files = clipboardFiles.length > 0
                            ? clipboardFiles
                            : Array.from(clipboard.items)
                                  .filter((item) => item.kind === "file")
                                  .map((item) => item.getAsFile())
                                  .filter((file): file is File => file !== null);
                        const images = files.filter((file) => IMAGE_MIMES.has(file.type));
                        if (images.length === 0) return;
                        event.preventDefault();
                        void props.onPasteFiles(images);
                    }}
                    onKeyDown={(event) => {
                        if (event.key !== "Enter" || event.shiftKey || event.isComposing) return;
                        event.preventDefault();
                        props.onSubmit();
                    }}
                />
            </div>

            <div class="composer-toolbar">
                <Show when={props.modelToolbar}>
                    <div class="composer-models">{props.modelToolbar}</div>
                </Show>
                <div class="composer-actions">
                <Show when={props.onAttachInput}>
                    <button
                        class="composer-action icon-btn attach-btn"
                        type="button"
                        data-attach
                        aria-label="Attach files"
                        disabled={props.attaching}
                        title="Attach file(s) to this message — their text rides along with the agent (not saved to the workspace)"
                        onClick={() => attachInput?.click()}
                    >
                        <Icon name="paperclip" />
                    </button>
                </Show>
                <Show when={!props.busy && props.onToggleReview}>
                    <button
                        class="composer-action review-toggle"
                        classList={{ active: props.reviewNext }}
                        type="button"
                        data-review-next
                        aria-pressed={props.reviewNext}
                        title={props.reviewNext
                            ? "Review is on for this change — click to return to auto-sync"
                            : "Hold the next change for review instead of auto-syncing it"}
                        onClick={props.onToggleReview}
                    >
                        review
                    </button>
                </Show>
                <Show when={!props.busy && props.onToggleGate}>
                    <button
                        class="composer-action queue-gate"
                        classList={{ gated: props.gated }}
                        type="button"
                        data-queue-gate
                        title={props.gated
                            ? "Release queued messages — they run in order"
                            : "Queue messages without running them yet; release them in order when ready"}
                        onClick={props.onToggleGate}
                    >
                        {props.gated
                            ? `▶ Release${queue().length ? ` · ${queue().length}` : ""}`
                            : "Queue"}
                    </button>
                </Show>
                <Show
                    when={props.busy}
                    fallback={
                        <button
                            class="composer-primary send-btn"
                            type="button"
                            data-embed-send={props.audience ? "" : undefined}
                            data-blocked={props.blocked ? "" : undefined}
                            disabled={!props.canSubmit || props.blocked}
                            onClick={props.onSubmit}
                        >
                            <Icon name={props.gated ? "queue" : "send"} />
                            {props.gated ? "Queue" : "Send"}
                        </button>
                    }
                >
                    <Show when={props.onSteer}>
                        <button
                            class="composer-primary steer-btn"
                            type="button"
                            data-testid="steer-turn"
                            title="Steer the running agent before its next model response"
                            disabled={!props.canSubmit || props.blocked}
                            onClick={props.onSteer}
                        >
                            Steer
                        </button>
                    </Show>
                    <Show when={hasQueueCommands()}>
                        <button
                            class="composer-action queue-btn"
                            type="button"
                            data-testid="queue-msg"
                            title="Queue this message — runs after the current turn finishes"
                            disabled={!props.canSubmit || props.blocked}
                            onClick={props.onSubmit}
                        >
                            <Icon name="queue" />
                            Queue ⏎
                        </button>
                    </Show>
                    <Show when={props.onStop}>
                        <button
                            class="composer-action stop-btn"
                            type="button"
                            data-testid="stop-turn"
                            title="Stop the running turn"
                            disabled={props.blocked}
                            onClick={() => props.onStop?.()}
                        >
                            Stop
                        </button>
                    </Show>
                    <Show when={!props.onSteer && !hasQueueCommands() && !props.onStop}>
                        <button
                            class="composer-primary send-btn"
                            type="button"
                            disabled
                        >
                            Working…
                        </button>
                    </Show>
                </Show>
                </div>
            </div>
        </div>
    );
}

function ComposerQueue(props: {
    readonly items: readonly ComposerQueueItem[];
    readonly onReorder: (from: number, to: number) => void;
    readonly onEdit: (id: number | string, text: string) => void;
    readonly onRemove: (id: number | string) => void;
    readonly onSendNow: (id: number | string) => void;
}): JSX.Element {
    const [dragIndex, setDragIndex] = createSignal<number | null>(null);
    const [overIndex, setOverIndex] = createSignal<number | null>(null);
    const [editId, setEditId] = createSignal<number | string | null>(null);

    const commitDrop = () => {
        const from = dragIndex();
        const to = overIndex();
        if (from !== null && to !== null && from !== to) props.onReorder(from, to);
        setDragIndex(null);
        setOverIndex(null);
    };

    return (
        <div class="queue-stack" data-testid="queue-stack">
            <span class="queue-cap">queued · runs after this turn</span>
            <For each={props.items}>
                {(item, index) => (
                    <div
                        class="queue-item"
                        data-testid="queue-item"
                        classList={{
                            dragging: dragIndex() === index(),
                            over: overIndex() === index()
                                && dragIndex() !== null
                                && dragIndex() !== index(),
                        }}
                        draggable={editId() !== item.id}
                        onDragStart={(event) => {
                            setDragIndex(index());
                            event.dataTransfer!.effectAllowed = "move";
                            event.dataTransfer!.setData("text/plain", String(item.id));
                        }}
                        onDragOver={(event) => {
                            event.preventDefault();
                            setOverIndex(index());
                        }}
                        onDrop={(event) => {
                            event.preventDefault();
                            commitDrop();
                        }}
                        onDragEnd={commitDrop}
                    >
                        <span class="queue-grip" title="Drag to reorder">⠿</span>
                        <span class="queue-pos">{index() + 1}</span>
                        <Show when={item.review}>
                            <span class="queue-review" title="This queued change will wait for review">review</span>
                        </Show>
                        <Show
                            when={editId() === item.id}
                            fallback={
                                <span
                                    class="queue-text"
                                    title="Click to edit"
                                    onClick={() => setEditId(item.id)}
                                >
                                    {item.text}
                                </span>
                            }
                        >
                            <input
                                class="queue-edit"
                                value={item.text}
                                ref={(element) => queueMicrotask(() => element.focus())}
                                onKeyDown={(event) => {
                                    if (event.key === "Enter") {
                                        props.onEdit(item.id, event.currentTarget.value);
                                        setEditId(null);
                                    } else if (event.key === "Escape") {
                                        setEditId(null);
                                    }
                                }}
                                onBlur={(event) => {
                                    props.onEdit(item.id, event.currentTarget.value);
                                    setEditId(null);
                                }}
                            />
                        </Show>
                        <button
                            class="queue-send-now"
                            type="button"
                            data-testid="queue-send-now"
                            title="Send this one now — runs immediately, ahead of the rest"
                            onClick={() => props.onSendNow(item.id)}
                        >
                            ▶
                        </button>
                        <button
                            class="queue-remove"
                            type="button"
                            title="Cancel this queued message"
                            onClick={() => props.onRemove(item.id)}
                        >
                            ✕
                        </button>
                    </div>
                )}
            </For>
        </div>
    );
}
