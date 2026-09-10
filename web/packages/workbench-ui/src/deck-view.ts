/**
 * What a key means to a deck — the pure half of {@link DeckView}.
 *
 * Presenting is a keyboard surface, and a keyboard surface is exactly the kind
 * of thing that rots quietly: a key stops working, or worse, starts working
 * somewhere it should not. Kept here so the mapping is testable apart from a
 * canvas, a fullscreen request and a WASM engine.
 */

/** What the deck should do about a key press. */
export type DeckAction = "next" | "prev" | "first" | "last" | "exit";

/** The part of a `KeyboardEvent` this decision needs. */
export interface DeckKey {
    readonly key: string;
    readonly altKey?: boolean;
    readonly ctrlKey?: boolean;
    readonly metaKey?: boolean;
}

/**
 * The action a key asks for, or `null` for a key this surface does not claim.
 *
 * `null` matters as much as the actions: anything not claimed here must reach
 * the page untouched, because this handler sits on a panel inside a workbench
 * and not on a slideshow that owns the window.
 *
 * A modified key is never claimed — `Ctrl+Home` and `Cmd+ArrowLeft` belong to
 * the browser and the platform, and stealing them to move a slide would be a
 * small theft the user cannot undo.
 */
export function deckAction(event: DeckKey, presenting: boolean): DeckAction | null {
    if (event.altKey || event.ctrlKey || event.metaKey) return null;
    switch (event.key) {
        case "ArrowRight":
        case "ArrowDown":
        case "PageDown":
        case " ":
        case "Enter":
            return "next";
        case "ArrowLeft":
        case "ArrowUp":
        case "PageUp":
        case "Backspace":
            return "prev";
        case "Home":
            return "first";
        case "End":
            return "last";
        // Only while presenting. Escape has other jobs in a workbench — closing
        // a menu, leaving a field — and a deck that swallowed it whenever it
        // held focus would break them.
        case "Escape":
            return presenting ? "exit" : null;
        default:
            return null;
    }
}
