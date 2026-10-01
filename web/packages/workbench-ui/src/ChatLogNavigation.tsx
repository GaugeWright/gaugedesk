/** A client-only map of the user turns already visible in the shared transcript. */
import { createEffect, createMemo, createSignal, For, onCleanup, onMount, Show, type JSX } from "solid-js";
import { reconcileLines, type TranscriptLine } from "./transcript";

/** At rest every mark is the same short tick. A hovered or focused mark peaks and
    its neighbours fall away exponentially, 6 + 15·e^-|d|: 21, 12, 8, 7, then 6. */
export function tickWidth(index: number, near: number | null): number {
    if (near === null) return 6;
    return Math.round(6 + 15 * Math.exp(-Math.abs(index - near)));
}

export function ChatLogNavigation(props: {
    lines: readonly TranscriptLine[];
    scroller: () => HTMLElement | undefined;
    frame: () => HTMLElement | undefined;
    onJump: (index: number) => void;
}): JSX.Element {
    const messages = createMemo<readonly TranscriptLine[]>(
        (previous) => reconcileLines(previous, props.lines.filter((line) => line.kind === "user")),
        [],
    );
    const [active, setActive] = createSignal(0);
    const [pageSized, setPageSized] = createSignal(false);
    const [pointer, setPointer] = createSignal<number | null>(null);
    const [focused, setFocused] = createSignal<number | null>(null);
    const [previewTop, setPreviewTop] = createSignal(0);
    const selected = () => pointer() ?? focused();
    const previewText = () => {
        const message = messages()[selected() ?? -1]?.text.trim() || "Message with an attachment";
        return message.length > 350 ? `${message.slice(0, 349)}…` : message;
    };
    let ticksEl: HTMLDivElement | undefined;
    let updateQueued = false;
    /** The mark last clicked. A jump near the end of the chat cannot bring its
        message to the reading line, and the end-of-log rule would then name the
        last message instead, so the clicked mark stays current until the reader
        scrolls by hand. */
    let jumped: number | null = null;

    const updateActive = () => {
        updateQueued = false;
        const scroller = props.scroller();
        const rows = scroller?.querySelectorAll<HTMLElement>(".transcript-body .line.user");
        if (!scroller || !rows?.length) return;
        if (jumped !== null && jumped < rows.length) {
            setActive(jumped);
            return;
        }
        const localScroll = scroller.scrollHeight - scroller.clientHeight > 1;
        setPageSized(!localScroll && (props.frame()?.clientHeight ?? 0) > window.innerHeight);
        const threshold = localScroll
            ? scroller.getBoundingClientRect().top + scroller.clientHeight * 0.35
            : window.innerHeight * 0.35;
        let current = 0;
        rows.forEach((row, index) => {
            if (row.getBoundingClientRect().top <= threshold) current = index;
        });
        if (localScroll && scroller.scrollHeight - scroller.clientHeight - scroller.scrollTop <= 24) {
            current = rows.length - 1;
        }
        setActive(current);
    };
    const queueUpdate = () => {
        if (updateQueued) return;
        updateQueued = true;
        requestAnimationFrame(updateActive);
    };
    const positionPreview = (button: HTMLElement) => {
        const frame = props.frame();
        if (!frame) return;
        const rect = frame.getBoundingClientRect();
        const center = button.getBoundingClientRect().top + button.clientHeight / 2 - rect.top;
        // Keep the card inside short chat panels as well as tall desktop lanes.
        const inset = Math.min(80, rect.height / 2);
        setPreviewTop(Math.max(inset, Math.min(center, rect.height - inset)));
    };
    const revealActiveMark = () => {
        if (!ticksEl || selected() !== null) return;
        const button = ticksEl.querySelectorAll<HTMLElement>("button")[active()];
        if (!button) return;
        const top = button.getBoundingClientRect().top - ticksEl.getBoundingClientRect().top + ticksEl.scrollTop;
        if (top < ticksEl.scrollTop) ticksEl.scrollTop = top;
        else if (top + button.offsetHeight > ticksEl.scrollTop + ticksEl.clientHeight) {
            ticksEl.scrollTop = top + button.offsetHeight - ticksEl.clientHeight;
        }
    };
    onMount(() => {
        const scroller = props.scroller();
        if (!scroller) return;
        const release = () => {
            if (jumped === null) return;
            jumped = null;
            queueUpdate();
        };
        const releaseOnKey = (event: KeyboardEvent) => {
            if (["ArrowUp", "ArrowDown", "PageUp", "PageDown", "Home", "End", " "].includes(event.key)) release();
        };
        const readerGestures = ["wheel", "touchstart", "pointerdown"] as const;
        scroller.addEventListener("scroll", queueUpdate, { passive: true });
        window.addEventListener("scroll", queueUpdate, { passive: true });
        for (const gesture of readerGestures) window.addEventListener(gesture, release, { passive: true });
        window.addEventListener("keydown", releaseOnKey);
        const observer = new ResizeObserver(queueUpdate);
        observer.observe(scroller);
        const body = scroller.querySelector(".transcript-body");
        if (body) observer.observe(body);
        queueUpdate();
        onCleanup(() => {
            scroller.removeEventListener("scroll", queueUpdate);
            window.removeEventListener("scroll", queueUpdate);
            for (const gesture of readerGestures) window.removeEventListener(gesture, release);
            window.removeEventListener("keydown", releaseOnKey);
            observer.disconnect();
        });
    });
    createEffect(() => {
        messages().length;
        queueUpdate();
    });
    createEffect(revealActiveMark);

    const focusMark = (index: number) => {
        setFocused(index);
        ticksEl?.querySelectorAll<HTMLButtonElement>("button")[index]?.focus();
    };
    const onKeys: JSX.EventHandlerUnion<HTMLElement, KeyboardEvent> = (event) => {
        const current = selected() ?? active();
        let next = current;
        if (event.key === "ArrowDown") next = Math.min(messages().length - 1, current + 1);
        else if (event.key === "ArrowUp") next = Math.max(0, current - 1);
        else if (event.key === "Home") next = 0;
        else if (event.key === "End") next = messages().length - 1;
        else return;
        event.preventDefault();
        setPointer(null);
        focusMark(next);
    };

    return (
        <Show when={messages().length > 0}>
            <nav class="chat-log-navigation" classList={{ "page-sized": pageSized() }} aria-label="User messages" onMouseLeave={() => setPointer(null)} onKeyDown={onKeys}>
                <div class="chat-log-navigation-ticks" ref={ticksEl}>
                    <For each={messages()}>{(message, index) => {
                        const summary = () => message.text.trim().replace(/\s+/g, " ").slice(0, 90) || "Message with an attachment";
                        return (
                            <button
                                type="button"
                                class="chat-log-navigation-mark"
                                data-chat-message-mark={index()}
                                aria-label={`Jump to user message ${index() + 1}: ${summary()}`}
                                aria-current={active() === index() ? "location" : undefined}
                                tabIndex={active() === index() ? 0 : -1}
                                onMouseEnter={(event) => { setFocused(null); setPointer(index()); positionPreview(event.currentTarget); }}
                                onFocus={(event) => { if (pointer() === null) setFocused(index()); positionPreview(event.currentTarget); }}
                                onBlur={() => setFocused(null)}
                                onClick={() => { jumped = index(); setActive(index()); props.onJump(index()); }}
                            >
                                <span
                                    class="chat-log-navigation-bar"
                                    classList={{ selected: selected() === index() || (selected() === null && active() === index()) }}
                                    style={{ width: `${tickWidth(index(), selected())}px` }}
                                />
                            </button>
                        );
                    }}</For>
                </div>
            </nav>
            <Show when={selected() !== null}>
                <div
                    class="chat-log-navigation-preview"
                    data-chat-message-preview
                    role="tooltip"
                    style={{ top: `${previewTop()}px` }}
                >
                    {previewText()}
                </div>
            </Show>
        </Show>
    );
}
