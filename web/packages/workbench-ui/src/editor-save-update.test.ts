import { describe, expect, it } from "vitest";
import { editorSaveUpdate } from "./editor-save-update";
import { editorRequestFence } from "./editor-request-fence";

describe("accepted editor revisions", () => {
    const context = {};
    it("keeps text typed during a merged save on its actual old basis", () => {
        const fence = editorRequestFence(() => context);
        const token = fence.beginSave()!;
        fence.change();
        const next = editorSaveUpdate("human edit", {
            kind: "merged", content: "human edit plus agent edit", cut: "accepted-cut", pieces: [],
        }, { draft: "human edit plus later typing", basis: { cut: "original-cut" }, unchanged: fence.unchanged(token) });
        expect(next.accepted).toBe("human edit plus agent edit");
        expect(next.cut).toBe("accepted-cut");
        expect(next.draft).toBe("human edit plus later typing");
        expect(next.basis).toEqual({ cut: "original-cut" });
        expect(next.message).toContain("remain unsaved");
    });

    it("uses accepted merged bytes when the submitted buffer is still current", () => {
        const next = editorSaveUpdate("human edit", {
            kind: "merged", content: "human edit plus agent edit", cut: "accepted-cut", pieces: [],
        }, { draft: "human edit", basis: { cut: "original-cut" }, unchanged: true });
        expect(next.accepted).toBe("human edit plus agent edit");
        expect(next.draft).toBeNull();
        expect(next.basis).toBeNull();
    });

    it("keeps a legacy content basis paired with a newer buffer", () => {
        const next = editorSaveUpdate("first edit", { kind: "saved", cut: null }, {
            draft: "second edit", basis: { content: "original" }, unchanged: false,
        });
        expect(next.accepted).toBe("first edit");
        expect(next.draft).toBe("second edit");
        expect(next.basis).toEqual({ content: "original" });
    });

    it("does not resurrect a discarded draft or claim equal accepted text is unsaved", () => {
        for (const draft of [null, "accepted"]) {
            const next = editorSaveUpdate("accepted", { kind: "saved", cut: "accepted-cut" }, {
                draft, basis: { cut: "old-cut" }, unchanged: false,
            });
            expect(next.draft).toBeNull();
            expect(next.basis).toBeNull();
            expect(next.message).toBe("saved");
            expect(next.cut).toBe("accepted-cut");
        }
    });
});
