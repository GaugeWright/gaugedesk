/**
 * The one chat composer presentation used by every GaugeDesk Environment.
 *
 * An Environment supplies the commands it is allowed to expose. The desktop
 * supplies queue/steer/attachment controls; an audience Environment supplies
 * send only. Capability changes therefore remove controls from this shared
 * composer instead of selecting a second, lesser UI.
 */
import { createEffect, createSignal, For, onCleanup, onMount, Show, type JSX } from "solid-js";
import { IMAGE_MIMES, type Attachment } from "./attachments";
import { ComposerMenuButton } from "./ComposerMenu";
import { ContextMeter, type ContextUsage } from "./ContextMeter";
import { Icon } from "./icons";

/** Below this field width the rail cannot hold tools, both settings, the meter
 *  and delivery without crushing something, so everything non-essential folds
 *  behind one expander. Measured on the field, not the viewport: a chat panel
 *  can be narrow inside a wide window. */
const COMPACT_RAIL_WIDTH = 430;

/**
 * Where a composed message goes. These are the *only* things that can happen to
 * it, and each one is a destination you can send to directly:
 *
 * - `steer` — now. If a turn is running, "now" means interrupting it, which is
 *             what steering is; with nothing running it simply runs.
 * - `queue` — into the line, to run when the current turn finishes.
 * - `stash` — into the same line, held, so nothing runs it until released.
 * - `fork`  — now, but down a new branch, leaving this chat where it is.
 *
 * `stop` is deliberately absent: it acts on the running turn, not on a message.
 */
export type ComposerDestination = "steer" | "queue" | "stash" | "fork";

/** The modes the composer can rest in — what the primary button and Enter do.
 *  Fork is excluded on purpose: branching every message by default is not a
 *  policy anyone wants, so it stays an explicit alternate route. */
export type ComposerMode = Exclude<ComposerDestination, "fork">;

export const COMPOSER_MODES: readonly {
    readonly id: ComposerMode;
    readonly label: string;
    readonly detail: string;
}[] = [
    { id: "steer", label: "Steer", detail: "Run it now, interrupting any turn in flight" },
    { id: "queue", label: "Queue", detail: "Run after the current turn" },
    { id: "stash", label: "Stash", detail: "Hold it for later" },
];

const MODE_BY_ID = new Map(COMPOSER_MODES.map((entry) => [entry.id, entry]));

/** The glyph each destination answers to. The primary button wears the active
 *  mode's, so the control says what it will do before you read anything. */
const DESTINATION_ICON = {
    steer: "send",
    queue: "queue",
    stash: "stash",
    fork: "fork",
} as const;

/**
 * The keystroke that always reaches a destination, whatever mode the composer is
 * resting in.
 *
 * These never move. ⏎ *does* move — it follows the mode, because that is what a
 * mode is — so a menu that printed ⏎ against `steer` was lying the moment the
 * mode was anything else. Printing both truths in their own places is the whole
 * fix: ⏎ on the row it currently reaches, and a fixed modifier on every row, so
 * muscle memory has something that does not shift under it.
 *
 * Shift+Enter stays a newline; Control is what promotes it to a command.
 */
const STABLE_KEYS: Record<ComposerDestination, string> = {
    steer: "Ctrl Shift ⏎",
    queue: "Ctrl ⏎",
    stash: "Alt ⏎",
    fork: "Ctrl Alt ⏎",
};

export interface ComposerQueueItem {
    readonly id: number | string;
    readonly text: string;
    /** Held items sit in the queue and are stepped over — the runner takes the
     *  next *ready* item. This is what a stashed message becomes, and it is why
     *  jotting one down does not freeze the messages you did mean to run. */
    readonly held?: boolean;
    /** `false` withholds the hold control for this row alone. A row the host
     *  already has can only be held by withdrawing it, and where the whole
     *  message cannot be reconstructed here that would lose part of it, so the
     *  control does not appear rather than appearing and doing damage. */
    readonly canHold?: boolean;
}

export interface ChatComposerProps {
    readonly draft: string;
    readonly placeholder: string;
    readonly queue?: readonly ComposerQueueItem[];
    readonly attachments?: readonly Attachment[];
    readonly busy: boolean;
    /** The mode the composer rests in: what the primary button and Enter do, and
     *  which glyph the primary wears. It is a standing choice about the turn in
     *  flight — where a message written while the agent is working goes — so it
     *  does not follow the moment. Resting in `queue` on an idle chat is how the
     *  *next* turn's follow-up is arranged for in advance. Defaults to `steer`,
     *  and falls back to it only where the Environment cannot honour the chosen
     *  mode at all. */
    readonly mode?: ComposerMode;
    readonly onPickMode?: (mode: ComposerMode) => void;
    /** The mode a chat opens in. Shown in the mode menu so the standing choice is
     *  visible next to the per-chat one, and settable there — the alternative was
     *  a settings screen for a single value. Absent on hosts that do not persist
     *  a preference, which also hides the row. */
    readonly defaultMode?: ComposerMode;
    readonly onSetDefaultMode?: (mode: ComposerMode) => void;
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
    /** Stacked-row rendering of {@link modelToolbar} for the compact expander. */
    readonly modelToolbarStacked?: JSX.Element;
    /** How full the pinned model's context window is. Absent on Environments that
     *  cannot measure it (the audience embed does not see transcript size). */
    readonly context?: ContextUsage;
    readonly onDraft: (value: string) => void;
    /** Dispatch the draft. `send` while a turn is running is a steer. */
    readonly onSubmit: (destination: ComposerDestination) => void;
    readonly onStop?: () => void;
    /** Available only where the runtime can hold a queued message indefinitely. */
    readonly onStash?: () => void;
    /** Flip one queued message between ready and held. */
    readonly onHoldQueued?: (id: number | string, held: boolean) => void;
    /** Send this message down a new line of the conversation, leaving the current
     *  one where it is. Absent on Environments that cannot branch a chat. */
    readonly onFork?: () => void;
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
    let field: HTMLDivElement | undefined;
    const [compact, setCompact] = createSignal(false);
    const [moreOpen, setMoreOpen] = createSignal(false);
    const queue = () => props.queue ?? [];
    const attachments = () => props.attachments ?? [];
    const hasQueueCommands = () =>
        props.onReorderQueue && props.onEditQueue && props.onRemoveQueue && props.onSendNow;
    const audienceBusy = () => props.busy && !hasQueueCommands() && !props.onStop;

    // Queueing is a capability, not a moment. The message joins the same line
    // whenever it is written — behind a running turn, behind a dead transport
    // (ADR 0137), or behind nothing at all, in which case the drain takes it
    // straight out. Gating this on the moment is what made the mode look broken:
    // choosing Queue on an idle chat collapsed back to Steer before the turn it
    // was chosen for ever started, so the one moment the choice matters could
    // never be arranged for in advance.
    const canQueue = () => Boolean(hasQueueCommands());
    const canStash = () => Boolean(props.onStash);
    // The mode is a standing choice about the turn in flight, so it holds
    // wherever the Environment can honour it at all. It falls back to steering
    // only where the destination does not exist here — never merely because this
    // instant does not distinguish it from steering.
    const mode = (): ComposerMode => {
        const chosen = props.mode ?? "steer";
        if (chosen === "queue" && !canQueue()) return "steer";
        if (chosen === "stash" && !canStash()) return "steer";
        return chosen;
    };
    /** The modes this Environment can rest in at all — a capability question, and
     *  now only that. An Environment with no queue commands, or no way to hold a
     *  row back, can never honour those modes, and offering one there is a
     *  control that quietly does nothing. Below two, there is no choice to make. */
    const offeredModes = () => COMPOSER_MODES.filter((entry) =>
        (entry.id !== "queue" || canQueue()) && (entry.id !== "stash" || canStash()));
    // Nothing to command with: no queue, no stop. Say so instead of offering a
    // primary that cannot land.
    const inert = () => props.busy && !hasQueueCommands() && !props.onStop;
    // Steering means the same thing either way — deliver this now — but while a
    // turn is in flight, "now" means cutting into it, and that is worth saying.
    const steerDetail = () =>
        props.busy ? "Run it now, interrupting the turn in flight" : "Run it now";
    // Queueing likewise reaches one destination — the line — and what that costs
    // depends only on whether anything is ahead of it.
    const queueDetail = () =>
        props.blocked === true ? "Wait in the queue until the connection is back"
        : props.busy ? "Run on its own once the current turn finishes"
        : "Join the line — nothing is ahead of it, so it runs";
    const primaryDetail = () =>
        mode() === "steer" ? steerDetail()
        : mode() === "queue" ? queueDetail()
        : MODE_BY_ID.get(mode())!.detail;

    /** The destinations currently reachable.
     *
     *  The active mode's row is always **last**, because the menu opens over the
     *  primary button and the last row is the one that lands on it. With a fixed
     *  order, hovering the stash button and clicking without moving dispatched
     *  *steer* — the row that happened to sit at the bottom — which sends a
     *  message you meant to put away. The row under the pointer has to be the
     *  one the pointer was already aiming at.
     *
     *  For the same reason the rows no longer come and go with the moment: Queue
     *  is listed wherever the Environment has a queue, running or not, so a turn
     *  starting under an open menu cannot slide a row beneath the pointer. */
    const destinations = () => {
        const active = mode();
        const all = [
            ...(props.onFork ? [{ id: "fork" as const, label: "Fork", detail: "Send down a new branch, leaving this chat as it is" }] : []),
            ...(canStash() ? [{ id: "stash" as const, label: "Stash", detail: "Join the queue held — nothing runs it until you release it" }] : []),
            ...(canQueue() ? [{ id: "queue" as const, label: "Queue", detail: queueDetail() }] : []),
            { id: "steer" as const, label: "Steer", detail: steerDetail() },
        ].map((entry) => ({
            ...entry,
            // The shortest key that gets there from here. ⏎ when the mode owns
            // this row; the row's own fixed modifier otherwise — which still
            // works either way, so the tooltip keeps saying so.
            keys: entry.id === active ? "⏎" : STABLE_KEYS[entry.id],
            detail: entry.id === active
                ? `${entry.detail} · also ${STABLE_KEYS[entry.id]}`
                : entry.detail,
        }));
        return [...all.filter((entry) => entry.id !== active), ...all.filter((entry) => entry.id === active)];
    };

    /** A destination the transport has to carry cannot be offered while it is
     *  down; one the outbox can hold can. Used for the control's disabled state
     *  and by `dispatch`, so what a button looks like and what it does cannot
     *  drift apart. */
    const unreachable = (destination: ComposerDestination) =>
        !props.canSubmit
        || (props.blocked === true && destination !== "queue" && destination !== "stash");

    /** Route a dispatch, doing nothing at all for a destination this Environment
     *  cannot reach. The refusals below are capability questions: a destination
     *  that exists here always does its own thing — queueing on an idle chat
     *  joins an empty line, which then runs — and one that does not exist does
     *  nothing rather than quietly falling back to another destination. That
     *  fallback is what once made Ctrl+Enter on an idle chat *steer*. */
    const dispatch = (destination: ComposerDestination) => {
        if (unreachable(destination)) return;
        if (destination === "queue" && !canQueue()) return;
        if (destination === "stash" && !canStash()) return;
        if (destination === "fork" && !props.onFork) return;
        props.onSubmit(destination);
    };

    /** The mode: what the primary button and Enter do. A standing choice, so it
     *  belongs on the settings rail rather than beside the primary, where "what
     *  this click does" and "what it does by default" would be a glyph apart.
     *  No glyphs here — the primary button is already wearing the mode's, and
     *  saying it twice in two registers is not saying it twice as clearly. */
    const modeSetting = (stacked?: boolean) => (
        <Show when={props.onPickMode && offeredModes().length > 1}>
            <ComposerMenuButton
                label={MODE_BY_ID.get(mode())!.label.toLowerCase()}
                title="What the send button and Enter do with the message you are typing"
                testAttr="mode"
                rowLabel="Mode"
                stacked={stacked}
            >
                {(close) => (
                    <>
                    <For each={offeredModes()}>
                        {(entry) => (
                            <button
                                class="composer-menu-item"
                                classList={{ selected: entry.id === mode() }}
                                type="button"
                                role="menuitemradio"
                                aria-checked={entry.id === mode()}
                                data-mode-option={entry.id}
                                title={entry.detail}
                                onClick={() => {
                                    props.onPickMode!(entry.id);
                                    close();
                                }}
                            >
                                <span>{entry.label}</span>
                                {/* The standing choice, marked where the momentary
                                    one is made. Without this the menu can only say
                                    what this chat does, and the preference behind
                                    it is invisible until the next chat opens. */}
                                <Show when={entry.id === props.defaultMode}>
                                    <span class="composer-menu-note">default</span>
                                </Show>
                            </button>
                        )}
                    </For>
                    <Show when={props.onSetDefaultMode && mode() !== props.defaultMode}>
                        <button
                            class="composer-menu-item foot"
                            type="button"
                            data-mode-make-default
                            title={`Open every new chat in ${MODE_BY_ID.get(mode())!.label.toLowerCase()} mode`}
                            onClick={() => {
                                props.onSetDefaultMode!(mode());
                                close();
                            }}
                        >
                            <span>Make {MODE_BY_ID.get(mode())!.label.toLowerCase()} my default</span>
                        </button>
                    </Show>
                    </>
                )}
            </ComposerMenuButton>
        </Show>
    );

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
        // The rail folds on the field's own width. A media query would miss a
        // narrow chat panel sitting in a wide window, which is the desktop's
        // normal split. Measure once directly rather than waiting on the
        // observer's first delivery: ResizeObserver is tied to the rendering
        // lifecycle, so a composer that mounts in a hidden tab or an unpainted
        // panel would otherwise render its wide rail into a narrow field.
        const measureRail = () => {
            if (field) setCompact(field.clientWidth < COMPACT_RAIL_WIDTH);
        };
        measureRail();
        const railObserver = field ? new ResizeObserver(measureRail) : undefined;
        if (field) railObserver?.observe(field);
        onCleanup(() => {
            observer?.disconnect();
            railObserver?.disconnect();
        });
    });
    return (
        <div
            class="composer-dock"
            data-chat-composer
            data-desktop-composer={props.audience ? undefined : ""}
            data-empty-chat-composer={props.quickStart ? "" : undefined}
            /* Escape interrupts the running turn. It is bound here rather than on
               the field so it reaches Stop from anywhere in the composer, and
               here rather than on the window so it cannot fire for a keystroke
               that was aimed at something else entirely. Anything inside that
               owns Escape for itself — an open menu, a queue row being edited —
               stops it propagating, so the innermost thing Escape can dismiss is
               the thing it dismisses. */
            onKeyDown={(event) => {
                if (event.key !== "Escape" || !props.busy || !props.onStop) return;
                if (props.blocked) return;
                event.preventDefault();
                props.onStop();
            }}
        >
            <Show when={queue().length > 0 && hasQueueCommands()}>
                <ComposerQueue
                    items={queue()}
                    onReorder={props.onReorderQueue!}
                    onEdit={props.onEditQueue!}
                    onRemove={props.onRemoveQueue!}
                    onSendNow={props.onSendNow!}
                    onHold={props.onHoldQueued}
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

            {/* One field. The border belongs to the card; the textarea and every
                control inside it are chrome-free, so the composer reads as a
                place to type with things in it rather than a form of boxes. */}
            <div class="composer-field" ref={field} classList={{ compact: compact() }}>
                {/* Delivery rides with the text, not down in the rail: the gate
                    (queue vs. send) and the send/stop control sit at the end of
                    the entry line, so the choice about *this message* is beside
                    the message. Settings and the meter stay on the rail below. */}
                <div class="composer-entry">
                    <textarea
                        class="composer-input"
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
                            if (event.key !== "Enter" || event.isComposing) return;
                            // (Escape is handled on the dock, so it reaches Stop
                            // from anywhere in the composer, not only the field.)
                            const control = event.ctrlKey || event.metaKey;
                            // Shift+Enter stays a newline. Control is what promotes
                            // it to a command, which is the only reason Steer can
                            // have a chord at all without eating the line break.
                            if (event.shiftKey && !control) return;
                            event.preventDefault();
                            // Fixed modifiers name a destination outright; bare
                            // Enter follows the mode.
                            if (control && event.shiftKey) dispatch("steer");
                            else if (control && event.altKey) dispatch("fork");
                            else if (control) dispatch("queue");
                            else if (event.altKey) dispatch("stash");
                            else dispatch(mode());
                        }}
                    />

                    {/* One primary, wearing the active mode's glyph so it says what
                        it will do before you read anything. The rarer routes stack
                        above it on hover or focus, each naming its shortcut so the
                        menu teaches its way out of existence. Stop stays out and
                        apart: it acts on the turn, not on anything you typed. */}
                    <div class="composer-deliver">
                        <Show when={!inert()} fallback={<span class="composer-working">working…</span>}>
                        <div class="deliver-stack">
                            {/* The mode's own row is the last one, and the menu is
                                anchored so that row lands exactly on the button. A
                                menu floating above the button leaves dead space
                                between the two: the pointer crosses un-hovered
                                ground on the way up and the menu closes under it.
                                Growing from the button means the pointer is already
                                inside the menu the moment it opens. */}
                            <Show when={destinations().length > 1}>
                                <div class="deliver-menu" data-deliver-menu>
                                    <For each={destinations()}>
                                        {(entry) => (
                                            <button
                                                class="deliver-option"
                                                classList={{ primary: entry.id === mode() }}
                                                type="button"
                                                data-deliver-option={entry.id}
                                                data-testid={entry.id === mode() ? undefined : `${entry.id}-msg`}
                                                title={entry.detail}
                                                disabled={unreachable(entry.id)}
                                                onClick={() => dispatch(entry.id)}
                                            >
                                                {/* Glyph last, right-aligned onto the
                                                    button's own: the mark you were
                                                    pointing at stays where it was
                                                    when the menu opens. */}
                                                <span>{entry.label}</span>
                                                <kbd>{entry.keys}</kbd>
                                                <Icon name={DESTINATION_ICON[entry.id]} />
                                            </button>
                                        )}
                                    </For>
                                </div>
                            </Show>
                            <button
                                class="composer-icon send-btn"
                                classList={{ holding: mode() === "stash" }}
                                type="button"
                                data-embed-send={props.audience ? "" : undefined}
                                data-blocked={props.blocked ? "" : undefined}
                                data-mode={mode()}
                                data-testid={mode() !== "steer"
                                    ? `${mode()}-msg`
                                    : props.busy ? "steer-turn" : "send-msg"}
                                aria-label={`${MODE_BY_ID.get(mode())!.label} — ${primaryDetail()}`}
                                title={`${MODE_BY_ID.get(mode())!.label} ⏎ — ${primaryDetail()} · also ${STABLE_KEYS[mode()]}`}
                                disabled={unreachable(mode())}
                                onClick={() => dispatch(mode())}
                            >
                                <Icon name={DESTINATION_ICON[mode()]} />
                            </button>
                        </div>
                        </Show>

                        <Show when={props.busy && props.onStop}>
                            <button
                                class="composer-icon stop-btn"
                                type="button"
                                data-testid="stop-turn"
                                aria-label="Stop the running turn"
                                title="Stop the running turn"
                                disabled={props.blocked}
                                onClick={() => props.onStop?.()}
                            >
                                <Icon name="stop" />
                            </button>
                        </Show>
                    </div>
                </div>

                {/* The rail below carries what the turn will run *on*, plus how much
                    of the window it is carrying. No borders, no dividers — one
                    register of quiet text and glyphs.

                    Everything that describes the *next turn* — model, effort, what
                    Enter does, how full the window is — collects at the far end, so
                    it reads as one statement about the run rather than settings
                    scattered either side of an empty middle. Only the message tool
                    stays at the reading start, next to the message. */}
                <div class="composer-rail">
                    <div class="composer-tools">
                        <Show
                            when={compact()}
                            fallback={
                                <>
                                    <Show when={props.onAttachInput}>
                                        <button
                                            class="composer-icon attach-btn"
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
                                    <Show when={props.modelToolbar}>{props.modelToolbar}</Show>
                                </>
                            }
                        >
                            {/* One expander, not a wrapped second row: a narrow rail
                                keeps delivery and the meter, and folds the rest. */}
                            <span
                                class="composer-more-anchor"
                                /* Escape on the anchor, not the menu: opening the
                                   expander leaves focus on its button, and the
                                   dock behind reads Escape as "stop the turn". */
                                onKeyDown={(event) => {
                                    if (event.key !== "Escape" || !moreOpen()) return;
                                    event.stopPropagation();
                                    setMoreOpen(false);
                                }}
                            >
                                <button
                                    class="composer-icon more-btn"
                                    classList={{ on: moreOpen() }}
                                    type="button"
                                    data-composer-more
                                    aria-label="More composer options"
                                    aria-haspopup="menu"
                                    aria-expanded={moreOpen()}
                                    title="Attachments, model, effort"
                                    onClick={() => setMoreOpen((was) => !was)}
                                >
                                    <Icon name="more" />
                                </button>
                                <Show when={moreOpen()}>
                                    <div class="popover-catcher" onClick={() => setMoreOpen(false)} />
                                    <div
                                        class="composer-more"
                                        role="menu"
                                        data-composer-more-menu
                                    >
                                        <Show when={props.onAttachInput}>
                                            <button
                                                class="composer-menu-item"
                                                type="button"
                                                data-attach
                                                disabled={props.attaching}
                                                onClick={() => {
                                                    setMoreOpen(false);
                                                    attachInput?.click();
                                                }}
                                            >
                                                <span>Attach files…</span>
                                            </button>
                                        </Show>
                                        {/* Destinations no longer fold: they live in the
                                            send button's own stack, which costs the
                                            same width at every size. */}
                                        <Show when={props.modelToolbarStacked ?? props.modelToolbar}>
                                            {props.modelToolbarStacked ?? props.modelToolbar}
                                        </Show>
                                    </div>
                                </Show>
                            </span>
                        </Show>
                    </div>

                    {/* What Enter does is about *delivery*, so it keeps company with
                        the send button's end of the field rather than with model and
                        effort — those describe the run, this describes the keystroke. */}
                    <div class="composer-settings">
                        {modeSetting()}
                        <Show when={props.context}>
                            <ContextMeter usage={props.context!} />
                        </Show>
                    </div>
                </div>
            </div>
        </div>
    );
}

/**
 * The queue: one list, two states per row.
 *
 * A held item is what a stashed message *becomes* — it sits in the same line and
 * the runner steps over it, taking the next ready item instead. That is why
 * jotting something down does not freeze the messages you did mean to run, and
 * it gives "what happened to my stashed message" an answer you can point at
 * rather than a caption that changed.
 *
 * The two groups are the whole explanation: what runs next, and what will not
 * run until you say so.
 */
function ComposerQueue(props: {
    readonly items: readonly ComposerQueueItem[];
    readonly onReorder: (from: number, to: number) => void;
    readonly onEdit: (id: number | string, text: string) => void;
    readonly onRemove: (id: number | string) => void;
    readonly onSendNow: (id: number | string) => void;
    readonly onHold?: (id: number | string, held: boolean) => void;
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

    // Rows are rendered per group but reordered against the whole list, so each
    // carries the index it holds in `items` rather than its index in the group.
    const grouped = (held: boolean) =>
        props.items
            .map((item, index) => ({ item, index }))
            .filter((entry) => Boolean(entry.item.held) === held);

    const row = (entry: { item: ComposerQueueItem; index: number }, position: number | null) => (
        <div
            class="queue-item"
            data-testid="queue-item"
            data-held={entry.item.held ? "" : undefined}
            classList={{
                held: entry.item.held,
                dragging: dragIndex() === entry.index,
                over: overIndex() === entry.index
                    && dragIndex() !== null
                    && dragIndex() !== entry.index,
            }}
            draggable={editId() !== entry.item.id}
            onDragStart={(event) => {
                setDragIndex(entry.index);
                event.dataTransfer!.effectAllowed = "move";
                event.dataTransfer!.setData("text/plain", String(entry.item.id));
            }}
            onDragOver={(event) => {
                event.preventDefault();
                setOverIndex(entry.index);
            }}
            onDrop={(event) => {
                event.preventDefault();
                commitDrop();
            }}
            onDragEnd={commitDrop}
        >
            <span class="queue-grip" title="Drag to reorder">
                <Icon name="grip" />
            </span>
            {/* Only ready items are numbered: a held item has no place in the
                running order, and numbering it would promise one. */}
            <span class="queue-pos">{position === null ? "" : position}</span>
            <Show
                when={editId() === entry.item.id}
                fallback={
                    <span
                        class="queue-text"
                        title="Click to edit"
                        onClick={() => setEditId(entry.item.id)}
                    >
                        {entry.item.text}
                    </span>
                }
            >
                <input
                    class="queue-edit"
                    value={entry.item.text}
                    ref={(element) => queueMicrotask(() => element.focus())}
                    onKeyDown={(event) => {
                        if (event.key === "Enter") {
                            props.onEdit(entry.item.id, event.currentTarget.value);
                            setEditId(null);
                        } else if (event.key === "Escape") {
                            // Abandoning an edit is all this Escape does — it must
                            // not carry on to the dock and stop the turn.
                            event.stopPropagation();
                            setEditId(null);
                        }
                    }}
                    onBlur={(event) => {
                        props.onEdit(entry.item.id, event.currentTarget.value);
                        setEditId(null);
                    }}
                />
            </Show>
            {/* Hold/release reuses the composer's own destination glyphs: the box
                puts this row where stashed messages live, the list puts it back
                in the running order. Same mark, same meaning, either place. */}
            <Show when={props.onHold && entry.item.canHold !== false}>
                <button
                    class="queue-icon queue-hold-btn"
                    classList={{ on: entry.item.held }}
                    type="button"
                    data-testid="queue-hold"
                    aria-pressed={entry.item.held}
                    aria-label={entry.item.held ? "Release into the running order" : "Hold this message"}
                    title={entry.item.held
                        ? "Release — puts this back in the running order"
                        : "Hold — keeps this out of the running order until you release it"}
                    onClick={() => props.onHold!(entry.item.id, !entry.item.held)}
                >
                    <Icon name={entry.item.held ? "queue" : "stash"} />
                </button>
            </Show>
            {/* Click-to-edit stays, but it was undiscoverable: the row looked like
                static text and the only hint was a tooltip. The explicit control is
                the affordance; the click is the shortcut for people who found it. */}
            <button
                class="queue-icon queue-edit-btn"
                type="button"
                data-testid="queue-edit"
                aria-label="Edit this queued message"
                title="Edit this queued message"
                onClick={() => setEditId(editId() === entry.item.id ? null : entry.item.id)}
            >
                <Icon name="edit" />
            </button>
            <button
                class="queue-icon queue-send-now"
                type="button"
                data-testid="queue-send-now"
                aria-label="Run this queued message now"
                title="Send this one now — runs immediately, ahead of the rest"
                onClick={() => props.onSendNow(entry.item.id)}
            >
                <Icon name="send" />
            </button>
            <button
                class="queue-icon queue-remove"
                type="button"
                aria-label="Cancel this queued message"
                title="Cancel this queued message"
                onClick={() => props.onRemove(entry.item.id)}
            >
                <Icon name="remove" />
            </button>
        </div>
    );

    return (
        <div class="queue-stack" data-testid="queue-stack">
            <Show when={grouped(false).length > 0}>
                <span class="queue-cap">up next · runs after this turn</span>
                <For each={grouped(false)}>
                    {(entry, position) => row(entry, position() + 1)}
                </For>
            </Show>
            <Show when={grouped(true).length > 0}>
                {/* Warn-toned, because held work is a promise the composer has to
                    keep visible — this is the only place that state now lives. */}
                <span class="queue-cap held" data-testid="queue-held-cap">
                    held · nothing runs these until you release them
                </span>
                <For each={grouped(true)}>{(entry) => row(entry, null)}</For>
            </Show>
        </div>
    );
}
