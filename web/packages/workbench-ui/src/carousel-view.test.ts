import { describe, expect, it } from "vitest";
import {
    gutterGesture,
    peekNeighbours,
    tapGesture,
    toggleSegments,
} from "./carousel-view";
import { reduce } from "./carousel";
import {
    PANE_ORDER,
    type CarouselState,
    type PaneKind,
    type Selection,
} from "./mobile-layout";

const noChat: Selection = { chatSelected: false, fileSelected: false };
const chatOnly: Selection = { chatSelected: true, fileSelected: false };
const withFile: Selection = { chatSelected: true, fileSelected: true };

function at(current: PaneKind, selection: Selection): CarouselState {
    return { current, selection };
}

describe("toggle segments (the canonical labelled control)", () => {
    it("lists every pane in canonical broad→deep order", () => {
        const segments = toggleSegments(at("nav", withFile));
        expect(segments.map((s) => s.pane)).toEqual([...PANE_ORDER]);
    });

    it("uses environment vocabulary for a repurposed pane", () => {
        const segments = toggleSegments(at("nav", withFile), { files: "Menu" });
        expect(segments.find((segment) => segment.pane === "files")?.label).toBe("Menu");
    });

    it("boxes exactly the current pane", () => {
        const segments = toggleSegments(at("files", withFile));
        expect(segments.filter((s) => s.current).map((s) => s.pane)).toEqual(["files"]);
    });

    it("greys panes unreachable for the selection (no chat → only nav reachable)", () => {
        const reachable = toggleSegments(at("nav", noChat)).filter((s) => s.reachable);
        expect(reachable.map((s) => s.pane)).toEqual(["nav"]);
    });

    it("chat selected, no file → Content greyed, the rest reachable", () => {
        const byPane = Object.fromEntries(
            toggleSegments(at("chat", chatOnly)).map((s) => [s.pane, s.reachable]),
        );
        expect(byPane).toEqual({ nav: true, chat: true, files: true, content: false });
    });
});

describe("edge peek neighbours (chevron rails never lie)", () => {
    it("at nav there is no broader neighbour", () => {
        expect(peekNeighbours(at("nav", withFile)).broader).toBe(null);
    });

    it("at content there is no deeper neighbour", () => {
        expect(peekNeighbours(at("content", withFile)).deeper).toBe(null);
    });

    it("mid-carousel exposes both neighbours when reachable", () => {
        expect(peekNeighbours(at("chat", withFile))).toEqual({ broader: "nav", deeper: "files" });
    });

    it("hides a deeper neighbour that is greyed (files → greyed content)", () => {
        expect(peekNeighbours(at("files", chatOnly)).deeper).toBe(null);
    });

    it("a shown peek is always a gesture the reducer honours", () => {
        for (const selection of [noChat, chatOnly, withFile]) {
            for (const pane of PANE_ORDER) {
                const state = at(pane, selection);
                const peek = peekNeighbours(state);
                if (peek.broader !== null) {
                    expect(reduce(state, gutterGesture("left")).current).toBe(peek.broader);
                }
                if (peek.deeper !== null) {
                    expect(reduce(state, gutterGesture("right")).current).toBe(peek.deeper);
                }
            }
        }
    });
});

describe("gutter and tap gesture mapping", () => {
    it("left gutter pops broader, right gutter advances deeper", () => {
        expect(gutterGesture("left")).toEqual({ kind: "swipe-right" });
        expect(gutterGesture("right")).toEqual({ kind: "swipe-left" });
    });

    it("a toggle tap is a tap gesture to that pane", () => {
        expect(tapGesture("content")).toEqual({ kind: "tap", target: "content" });
    });
});
