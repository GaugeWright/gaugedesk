import { describe, expect, it } from "vitest";
import { deckAction, type DeckKey } from "./deck-view";

const key = (k: string, mods: Partial<DeckKey> = {}): DeckKey => ({ key: k, ...mods });

describe("deckAction", () => {
    it("moves forward on every key a presenter reaches for", () => {
        for (const k of ["ArrowRight", "ArrowDown", "PageDown", " ", "Enter"]) {
            expect(deckAction(key(k), false), k).toBe("next");
        }
    });

    it("moves back on the mirror set", () => {
        for (const k of ["ArrowLeft", "ArrowUp", "PageUp", "Backspace"]) {
            expect(deckAction(key(k), false), k).toBe("prev");
        }
    });

    it("jumps to the ends", () => {
        expect(deckAction(key("Home"), false)).toBe("first");
        expect(deckAction(key("End"), false)).toBe("last");
    });

    /** The hint promises Escape, so Escape must be claimed rather than left to
     *  a browser whose behaviour varies by shell. */
    it("leaves present mode on Escape", () => {
        expect(deckAction(key("Escape"), true)).toBe("exit");
    });

    /** And not otherwise: Escape closes menus and leaves fields, and a deck
     *  holding focus in a panel must not eat those. */
    it("does not claim Escape when it is not presenting", () => {
        expect(deckAction(key("Escape"), false)).toBeNull();
    });

    /** A modified key belongs to the browser or the platform. Moving a slide
     *  on Ctrl+Home would quietly break "go to the top of the document". */
    it("never claims a modified key, in either mode", () => {
        for (const mods of [{ ctrlKey: true }, { metaKey: true }, { altKey: true }]) {
            for (const k of ["ArrowRight", "ArrowLeft", "Home", "End", " ", "Escape"]) {
                expect(deckAction(key(k, mods), true), `${JSON.stringify(mods)} ${k}`).toBeNull();
                expect(deckAction(key(k, mods), false), `${JSON.stringify(mods)} ${k}`).toBeNull();
            }
        }
    });

    /** Everything else reaches the page untouched — this handler sits on a
     *  panel in a workbench, not on a slideshow that owns the window. */
    it("claims nothing it was not asked to claim", () => {
        for (const k of ["a", "Z", "0", "Tab", "F5", "Shift", "/", "Delete", "Insert"]) {
            expect(deckAction(key(k), true), k).toBeNull();
        }
    });
});
