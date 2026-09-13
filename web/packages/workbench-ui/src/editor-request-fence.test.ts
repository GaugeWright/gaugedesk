import { describe, expect, it } from "vitest";
import { editorRequestFence } from "./editor-request-fence";

describe("editor callback ownership", () => {
    function setup() {
        let context = { chat: "chat-a", path: "note.txt" };
        return { fence: editorRequestFence(() => context),
            select: (chat: string, path: string) => { context = { chat, path }; } };
    }

    it("keeps a submission attributable while later keystrokes invalidate buffer replacement", () => {
        const { fence } = setup();
        const save = fence.beginSave()!;
        expect(fence.unchanged(save)).toBe(true);
        fence.change();
        expect(fence.belongs(save)).toBe(true);
        expect(fence.unchanged(save)).toBe(false);
        expect(fence.beginSave()).toBeNull();
        fence.finishSave(save);
        expect(fence.beginSave()).not.toBeNull();
    });

    it("cannot revive an old callback by leaving and returning to the same file", () => {
        const { fence, select } = setup();
        const old = fence.beginSave()!;
        select("chat-a", "other.txt");
        select("chat-a", "note.txt");
        const current = fence.beginSave()!;
        expect(fence.belongs(old)).toBe(false);
        fence.finishSave(old);
        expect(fence.saving()).toBe(true);
        expect(fence.unchanged(current)).toBe(true);
    });

    it("separates the same path in different chats and ignores unmounted callbacks", () => {
        const { fence, select } = setup();
        const old = fence.capture();
        select("chat-b", "note.txt");
        expect(fence.belongs(old)).toBe(false);
        const current = fence.beginSave()!;
        fence.dispose();
        expect(fence.belongs(current)).toBe(false);
        expect(fence.beginSave()).toBeNull();
        expect(fence.beginPreview()).toBeNull();
    });

    it("rejects a preview after typing or discarding, even if the text later matches", () => {
        const { fence } = setup();
        const preview = fence.beginPreview()!;
        fence.change();
        fence.change();
        expect(fence.currentPreview(preview)).toBe(false);
    });

    it("allows only the latest preview and invalidates previews when a save starts", () => {
        const { fence } = setup();
        const old = fence.beginPreview()!;
        const latest = fence.beginPreview()!;
        expect(fence.currentPreview(old)).toBe(false);
        expect(fence.currentPreview(latest)).toBe(true);
        const save = fence.beginSave()!;
        expect(fence.currentPreview(latest)).toBe(false);
        expect(fence.beginPreview()).toBeNull();
        fence.finishSave(save);
        expect(fence.currentPreview(latest)).toBe(false);
    });
    it("keeps only the newest baseline read without treating typing as a new baseline", () => {
        const { fence } = setup();
        const old = fence.beginRead();
        const current = fence.beginRead();
        fence.change();
        expect(fence.currentRead(old)).toBe(false);
        expect(fence.currentRead(current)).toBe(true);
    });

    it("prevents a read started before save completion from replacing accepted bytes", () => {
        const { fence } = setup();
        const pending = fence.beginRead();
        fence.invalidateReads();
        expect(fence.currentRead(pending)).toBe(false);
        const newer = fence.beginRead();
        expect(fence.currentRead(newer)).toBe(true);
    });

});
