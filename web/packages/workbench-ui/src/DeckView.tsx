/**
 * The View tab for a PowerPoint deck.
 *
 * A deck is not a document that happens to be wide — it is a sequence of
 * frames, and the person reading one wants to be on a frame, not somewhere in a
 * scroll of them. So this pages: one slide at a time, back and next, the
 * position stated, and a **Present** mode that fills the screen and answers the
 * keys everyone already has in their fingers.
 *
 * Read-only like the rest of the Office surface, and for the reason in
 * {@link OfficeView}: under ADR 0164 a rendered slide is derived state. Present
 * mode shows a document; it never becomes a place to change one.
 */

import { createEffect, createSignal, onCleanup, Show } from "solid-js";
import { deckAction } from "./deck-view";

/** The slice of `PptxViewer` this shell drives. */
interface Deck {
    load(source: ArrayBuffer): Promise<void>;
    nextSlide(): Promise<void>;
    prevSlide(): Promise<void>;
    goToSlide(index: number): Promise<void>;
    fitPage(): Promise<void>;
    destroy(): void;
}

export interface DeckViewProps {
    readonly bytes: Uint8Array;
    readonly path: string;
    /** Shared engine options (resource bounds, worker mode) from OfficeView. */
    readonly options: Record<string, unknown>;
    readonly onFailure: (error: unknown) => void;
}

export function DeckView(props: DeckViewProps) {
    let root!: HTMLDivElement;
    let slide!: HTMLDivElement;
    // `PptxViewer` takes the canvas itself and builds its own wrapper around it.
    let host!: HTMLCanvasElement;
    const [deck, setDeck] = createSignal<Deck | null>(null);
    const [index, setIndex] = createSignal(0);
    const [total, setTotal] = createSignal(0);
    const [presenting, setPresenting] = createSignal(false);

    createEffect(() => {
        const bytes = props.bytes;
        let viewer: Deck | undefined;
        let dropped = false;
        setDeck(null);
        setIndex(0);
        setTotal(0);
        void (async () => {
            try {
                const { PptxViewer } = await import("@silurus/ooxml/pptx");
                viewer = new PptxViewer(host, {
                    ...props.options,
                    // The engine is the authority on where we are: a slide can
                    // change from a hyperlink or a fit as well as from these
                    // buttons, and a locally-tracked index would drift.
                    onSlideChange: (at: number, count: number) => {
                        if (dropped) return;
                        setIndex(at);
                        setTotal(count);
                    },
                }) as unknown as Deck;
                if (dropped) {
                    viewer.destroy();
                    return;
                }
                await viewer.load(new Uint8Array(bytes).buffer);
                if (dropped) return;
                // A slide is a frame: it is either wholly visible or it is not
                // doing its job, so the whole slide is fitted to the pane
                // rather than its width. Without this it renders at whatever
                // size the deck was authored at, adrift in the middle.
                await viewer.fitPage();
                setDeck(() => viewer ?? null);
            } catch (error) {
                if (!dropped) props.onFailure(error);
            }
        })();
        onCleanup(() => {
            dropped = true;
            viewer?.destroy();
        });
    });

    const atFirst = () => index() <= 0;
    const atLast = () => total() > 0 && index() >= total() - 1;
    const go = (move: (d: Deck) => Promise<void>) => {
        const d = deck();
        if (d) void move(d).catch(props.onFailure);
    };
    const next = () => !atLast() && go((d) => d.nextSlide());
    const prev = () => !atFirst() && go((d) => d.prevSlide());

    // Fullscreen is the browser's to own: Escape, the window chrome and the OS
    // can all end it without us. So presenting follows `fullscreenchange`
    // rather than our own click, and the button only asks.
    function onFullscreenChange() {
        const on = document.fullscreenElement === root;
        setPresenting(on);
        // The same rule either way — the pane just changed size.
        go((d) => d.fitPage());
        if (on) root.focus();
    }
    createEffect(() => {
        document.addEventListener("fullscreenchange", onFullscreenChange);
        onCleanup(() => document.removeEventListener("fullscreenchange", onFullscreenChange));
    });

    // The pane is resizable and the window is not the only thing that moves it:
    // a collapsed panel or a dragged splitter changes the frame just as much,
    // and neither raises a window resize.
    createEffect(() => {
        const d = deck();
        if (!d) return;
        const observer = new ResizeObserver(() => void d.fitPage().catch(() => undefined));
        observer.observe(slide);
        onCleanup(() => observer.disconnect());
    });

    async function present() {
        try {
            await root.requestFullscreen();
        } catch (error) {
            // A refused fullscreen (permissions policy, an embedded frame) is
            // not a broken deck. Stay paged and say nothing louder than this.
            props.onFailure(error);
        }
    }

    // Bound to the panel, never to the document: a deck open in one pane must
    // not swallow the arrow keys of a composer in another. Focus is what makes
    // these live, and entering present mode takes focus deliberately. Which
    // keys count is `deckAction`, tested apart from all of this.
    function onKeyDown(event: KeyboardEvent) {
        const action = deckAction(event, presenting());
        if (!action) return;
        event.preventDefault();
        switch (action) {
            case "next":
                next();
                return;
            case "prev":
                prev();
                return;
            case "first":
                go((d) => d.goToSlide(0));
                return;
            case "last":
                if (total() > 0) go((d) => d.goToSlide(total() - 1));
                return;
            case "exit":
                void document.exitFullscreen().catch(() => undefined);
                return;
        }
    }

    return (
        <div
            class="deckview"
            classList={{ presenting: presenting() }}
            data-file-view
            data-file-media="pptx"
            data-presenting={presenting() ? "" : undefined}
            ref={root}
            tabindex="0"
            onKeyDown={onKeyDown}
        >
            <div class="deckview-bar">
                <button
                    class="deckview-step"
                    data-deck-prev
                    disabled={atFirst() || !deck()}
                    aria-label="Previous slide"
                    onClick={prev}
                >
                    ‹ back
                </button>
                <span class="status" data-deck-position>
                    <Show when={total() > 0} fallback="opening the deck…">
                        slide {index() + 1} of {total()}
                    </Show>
                </span>
                <button
                    class="deckview-step"
                    data-deck-next
                    disabled={atLast() || !deck()}
                    aria-label="Next slide"
                    onClick={next}
                >
                    next ›
                </button>
                <div class="deckview-actions">
                    <Show
                        when={presenting()}
                        fallback={
                            <button data-deck-present disabled={!deck()} onClick={present}>
                                present
                            </button>
                        }
                    >
                        <button data-deck-exit onClick={() => void document.exitFullscreen()}>
                            exit
                        </button>
                    </Show>
                </div>
            </div>
            <div class="deckview-slide" ref={slide}>
                <canvas ref={host} />
            </div>
            {/* Said once, where a first-time presenter looks: on the slide they
                are about to present from, not in a manual. */}
            <Show when={presenting()}>
                <div class="deckview-hint" data-deck-hint>
                    arrows or space to move · esc to leave
                </div>
            </Show>
        </div>
    );
}
