import { describe, expect, it } from "vitest";
import {
    ANCHOR_GAP,
    BOTTOM_SLACK,
    atBottom,
    distanceFromBottom,
    gaugeLines,
    hostAbsorbedSpacer,
    isHistoryLoad,
    isSend,
    pillVisible,
    scrollable,
    spacerAfterReflow,
    spacerHeight,
} from "./transcript-scroll";
import { type TranscriptLine } from "./transcript";

const line = (kind: TranscriptLine["kind"], seq: number): TranscriptLine => ({
    seq,
    tier: "operational",
    kind,
    text: `${kind} ${seq}`,
});
const lines = (...kinds: TranscriptLine["kind"][]) => kinds.map((kind, seq) => line(kind, seq));

describe("bottom detection", () => {
    it("reads the distance in scroll coordinates", () => {
        expect(distanceFromBottom({ scrollTop: 100, scrollHeight: 1000, clientHeight: 400 })).toBe(500);
        expect(distanceFromBottom({ scrollTop: 600, scrollHeight: 1000, clientHeight: 400 })).toBe(0);
    });

    it("counts the slack band as the bottom, and the first pixel past it as away", () => {
        const at = { scrollTop: 600 - BOTTOM_SLACK, scrollHeight: 1000, clientHeight: 400 };
        const away = { scrollTop: 600 - BOTTOM_SLACK - 1, scrollHeight: 1000, clientHeight: 400 };
        expect(atBottom(at)).toBe(true);
        expect(atBottom(away)).toBe(false);
    });

    it("keeps the anchored position inside the bottom band", () => {
        // The anchor scroll stops ANCHOR_GAP short of the spacer-extended
        // bottom; if the gap left the band, the anchored reader would count as
        // scrolled away the moment they arrived.
        expect(ANCHOR_GAP).toBeLessThanOrEqual(BOTTOM_SLACK);
    });
});

describe("the jump pill", () => {
    it("offers a jump exactly when transcript sits below the fold", () => {
        expect(pillVisible({ scrollTop: 0, scrollHeight: 1000, clientHeight: 400 })).toBe(true);
        expect(pillVisible({ scrollTop: 600, scrollHeight: 1000, clientHeight: 400 })).toBe(false);
    });

    it("never appears in a panel that does not scroll", () => {
        // A content-sized embed host: the page is the scroller, not the panel.
        expect(pillVisible({ scrollTop: 0, scrollHeight: 400, clientHeight: 400 })).toBe(false);
        expect(scrollable({ scrollTop: 0, scrollHeight: 400, clientHeight: 400 })).toBe(false);
    });
});

describe("the anchor spacer", () => {
    it("reserves exactly the shortfall between one viewport and the content below the anchor", () => {
        // 500px viewport, 800px of content, anchor at 750: only 50px sits at or
        // below the anchor, so 450px of room is missing.
        expect(spacerHeight(500, 800, 750)).toBe(450);
    });

    it("reserves nothing when the content below the anchor already fills a viewport", () => {
        expect(spacerHeight(500, 800, 200)).toBe(0);
    });

    it("makes the anchor the exact bottom of the extended scroll range", () => {
        // scrollTop can reach (content + spacer) - viewport; the anchor must
        // land there, so the anchored message tops the viewport with only
        // ANCHOR_GAP above it.
        const clientHeight = 500;
        const contentHeight = 800;
        const anchorTop = 750;
        const spacer = spacerHeight(clientHeight, contentHeight, anchorTop);
        expect(contentHeight + spacer - clientHeight).toBe(anchorTop);
    });
});

describe("the content-sized host probe", () => {
    const m = (clientHeight: number, scrollHeight: number) => ({ scrollTop: 0, clientHeight, scrollHeight });

    it("reads a panel that kept its height and gained scroll room as sized", () => {
        // 500px viewport, 120px of content, anchor at 40: a 420px spacer becomes
        // 40px of scroll room and the viewport does not move.
        expect(hostAbsorbedSpacer(m(500, 120), m(500, 540), 420)).toBe(false);
    });

    it("reads a host that grew by the whole spacer as content-sized", () => {
        expect(hostAbsorbedSpacer(m(120, 120), m(540, 540), 420)).toBe(true);
    });

    it("reads a host that grew by only the anchor's offset, without scroll room, as content-sized", () => {
        // A content-sized host with slack below its content grows by just the
        // overflow the spacer creates — here 40px of a 420px spacer — and never
        // scrolls. Read as sized, the spacer would ask for 40px more on every
        // reflow and the host would grow to fit each time.
        expect(hostAbsorbedSpacer(m(500, 120), m(540, 540), 420)).toBe(true);
    });

    it("stays quiet for a first message whose anchor sits at the top", () => {
        // Anchor offset zero: the spacer creates no overflow in either kind of
        // host, and there is nothing to scroll to or feed on.
        expect(hostAbsorbedSpacer(m(500, 80), m(500, 500), 420)).toBe(false);
        expect(hostAbsorbedSpacer(m(500, 80), m(500, 500), 0)).toBe(false);
    });

    it("ignores a pixel of layout noise", () => {
        expect(hostAbsorbedSpacer(m(500, 120), m(501, 541), 420)).toBe(false);
    });
});

describe("the spacer on reflow", () => {
    it("gives back the room a streaming reply has consumed", () => {
        const scrolling = { scrollTop: 0, clientHeight: 500, scrollHeight: 540 };
        expect(spacerAfterReflow(420, 300, scrolling)).toBe(300);
        const flush = { scrollTop: 0, clientHeight: 500, scrollHeight: 500 };
        expect(spacerAfterReflow(420, 300, flush)).toBe(300);
    });

    it("grows with the viewport of a transcript that scrolls", () => {
        const scrolling = { scrollTop: 0, clientHeight: 600, scrollHeight: 640 };
        expect(spacerAfterReflow(420, 520, scrolling)).toBe(520);
    });

    it("never grows on a transcript that does not scroll", () => {
        // A content-sized host answers a taller spacer with a taller
        // transcript, which would ask for a taller spacer again.
        const flush = { scrollTop: 0, clientHeight: 540, scrollHeight: 540 };
        expect(spacerAfterReflow(420, 460, flush)).toBe(420);
    });
});

describe("send detection", () => {
    it("fires on the first message of a new chat", () => {
        expect(isSend(gaugeLines([]), gaugeLines(lines("user")))).toBe(true);
    });

    it("fires on a message sent into a running conversation", () => {
        const before = lines("user", "assistant", "tool");
        const after = [...before, line("user", 3)];
        expect(isSend(gaugeLines(before), gaugeLines(after))).toBe(true);
    });

    it("stays quiet while the agent's turn streams in", () => {
        const before = lines("user");
        const after = lines("user", "assistant", "tool", "text");
        expect(isSend(gaugeLines(before), gaugeLines(after))).toBe(false);
    });

    it("stays quiet across a snapshot settle that rewrites line identity", () => {
        // Settling replaces the whole list, but the user count is unchanged —
        // the anchor must not re-fire on a repaired copy of history.
        const before = lines("user", "assistant", "user", "assistant");
        const settled = before.map((l) => ({ ...l, seq: l.seq + 100 }));
        expect(isSend(gaugeLines(before), gaugeLines(settled))).toBe(false);
    });

    it("stays quiet when a catch-up ends on the agent's lines", () => {
        const before = lines("user", "assistant");
        const after = lines("user", "assistant", "user", "assistant", "run");
        expect(isSend(gaugeLines(before), gaugeLines(after))).toBe(false);
    });
});

describe("history placement", () => {
    it("treats history filling an empty transcript as placement, not a send", () => {
        const history = lines("user", "assistant", "run");
        expect(isHistoryLoad(gaugeLines([]), gaugeLines(history))).toBe(true);
        expect(isSend(gaugeLines([]), gaugeLines(history))).toBe(false);
    });

    it("does not mistake the first send for history", () => {
        expect(isHistoryLoad(gaugeLines([]), gaugeLines(lines("user")))).toBe(false);
    });

    it("never fires once the transcript has content", () => {
        const before = lines("user");
        const after = lines("user", "assistant", "user");
        expect(isHistoryLoad(gaugeLines(before), gaugeLines(after))).toBe(false);
    });
});
