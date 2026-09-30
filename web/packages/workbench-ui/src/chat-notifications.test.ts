/**
 * DR-0266: a device notifies when a chat's turn ends, worded by how the chat
 * then stands, and only as far as the device's own preference allows.
 */

import { describe, expect, it } from "vitest";
import type { ChatNotice } from "@gaugewright/control-plane-client";
import { NoticeTracker, noticeText, preferenceWants } from "./chat-notifications";

const notice = (chat: string, settle: number, signal: ChatNotice["signal"] = "turn-settled", failed = false): ChatNotice => ({
    chat,
    title: `Chat ${chat}`,
    signal,
    settle,
    failed,
});

describe("NoticeTracker", () => {
    it("learns a Home on its first read instead of raising what was already there", () => {
        const tracker = new NoticeTracker();
        expect(tracker.fresh("home", [notice("a", 3), notice("b", 1, "question")])).toEqual([]);
        expect(tracker.fresh("home", [notice("a", 3), notice("b", 1, "question")])).toEqual([]);
    });

    it("raises a chat once for each turn that ends", () => {
        const tracker = new NoticeTracker();
        tracker.fresh("home", [notice("a", 1)]);
        expect(tracker.fresh("home", [notice("a", 2)])).toEqual([notice("a", 2)]);
        expect(tracker.fresh("home", [notice("a", 2)])).toEqual([]);
        expect(tracker.fresh("home", [notice("a", 3, "question")])).toEqual([notice("a", 3, "question")]);
    });

    it("raises a chat's first ending when it had nothing to say before", () => {
        const tracker = new NoticeTracker();
        tracker.fresh("home", []);
        expect(tracker.fresh("home", [notice("new", 1)])).toEqual([notice("new", 1)]);
    });

    it("does not treat a changed signal without a new ending as one", () => {
        const tracker = new NoticeTracker();
        tracker.fresh("home", []);
        // A question read while its turn still runs, then the settle: once.
        expect(tracker.fresh("home", [notice("a", 0, "question")])).toEqual([]);
        expect(tracker.fresh("home", [notice("a", 1, "question")])).toEqual([notice("a", 1, "question")]);
        // The conflict is repaired, or the question answered elsewhere: no ending.
        expect(tracker.fresh("home", [notice("a", 1)])).toEqual([]);
    });

    it("never counts backwards on a stale read", () => {
        const tracker = new NoticeTracker();
        tracker.fresh("home", [notice("a", 4)]);
        expect(tracker.fresh("home", [notice("a", 3)])).toEqual([]);
        expect(tracker.fresh("home", [notice("a", 4)])).toEqual([]);
    });

    it("keeps each Home's counts apart", () => {
        const tracker = new NoticeTracker();
        tracker.fresh("one", [notice("a", 1)]);
        expect(tracker.fresh("two", [notice("a", 5)])).toEqual([]);
        expect(tracker.fresh("one", [notice("a", 2)])).toEqual([notice("a", 2)]);
    });
});

describe("preferenceWants", () => {
    it("tells an ending apart from a chat that needs its person", () => {
        const finished = notice("a", 1);
        const failed = notice("a", 1, "turn-settled", true);
        const question = notice("a", 1, "question");
        const conflict = notice("a", 1, "conflict");
        expect([finished, failed, question, conflict].map((n) => preferenceWants("all", n))).toEqual([true, true, true, true]);
        expect([finished, failed, question, conflict].map((n) => preferenceWants("needs-me", n))).toEqual([false, true, true, true]);
        expect([finished, failed, question, conflict].map((n) => preferenceWants("off", n))).toEqual([false, false, false, false]);
    });
});

describe("noticeText", () => {
    it("names the chat and why, and nothing it said", () => {
        expect(noticeText(notice("a", 1))).toEqual({ title: "Chat a", body: "Finished." });
        expect(noticeText(notice("a", 1, "turn-settled", true))).toEqual({ title: "Chat a", body: "Stopped on an error." });
        expect(noticeText(notice("a", 1, "question"))).toEqual({ title: "Chat a", body: "Has a question for you." });
        expect(noticeText(notice("a", 1, "conflict"))).toEqual({ title: "Chat a", body: "Has a conflict to repair." });
        expect(noticeText({ ...notice("a", 1), title: "  " }).title).toBe("A chat");
    });
});
