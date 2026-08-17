/**
 * Transcript scroll behavior for the one shared chat panel (ADR 0076): the
 * reading position is the reader's, and the panel only moves it on the two
 * gestures that ask for it.
 *
 * - **Send** anchors the just-sent message to the top of the viewport — a
 *   spacer under the last line reserves exactly the room the anchor needs, and
 *   gives it back as the reply fills in. The reply streams in *below* the
 *   reader's position and never drags it.
 * - **Jump to latest** (the floating pill, or scrolling to the bottom by hand)
 *   latches the viewport to the bottom while new content arrives. Any manual
 *   scroll away releases the latch and the viewport stays where it was put.
 *
 * Everything here is measurement + latch bookkeeping; it owns no truth about
 * the transcript. The pure functions carry the decisions and are unit-tested;
 * `createTranscriptScroll` binds them to the DOM and is exercised in a real
 * browser through e2e, per this workspace's vitest/DOM split.
 */
import { createSignal, type Accessor } from "solid-js";
import { type TranscriptLine } from "./transcript";

/** One reading of the scroller, in the units the decisions are made in. */
export interface ScrollMetrics {
    readonly scrollTop: number;
    readonly scrollHeight: number;
    readonly clientHeight: number;
}

/** Slack under which the reader still counts as at the bottom. Wide enough to
 *  absorb sub-pixel scroll math and the anchor gap, narrow enough that a real
 *  scroll-up leaves it immediately. */
export const BOTTOM_SLACK = 24;

/** Breathing room kept above an anchored message so it does not sit flush
 *  against the panel edge. Must stay under {@link BOTTOM_SLACK}: the anchored
 *  position is the spacer-extended bottom, and the gap must not read as
 *  "scrolled away". */
export const ANCHOR_GAP = 8;

/** How long a wheel/touch/scrollbar gesture keeps counting as the reader's
 *  intent when judging the scroll events it produces. */
export const INTENT_WINDOW_MS = 3000;

/** How long a smooth programmatic glide (anchor, jump) owns the scroll events
 *  it produces before position is judged again. */
export const GLIDE_WINDOW_MS = 1000;

export function distanceFromBottom(m: ScrollMetrics): number {
    return Math.max(0, m.scrollHeight - m.clientHeight - m.scrollTop);
}

export function atBottom(m: ScrollMetrics): boolean {
    return distanceFromBottom(m) <= BOTTOM_SLACK;
}

/** Whether this element actually scrolls. A content-sized panel (an embed host
 *  that opted out of a definite height) never does — there the page is the
 *  scroller and this module keeps its hands off it. */
export function scrollable(m: ScrollMetrics): boolean {
    return m.scrollHeight - m.clientHeight > 1;
}

/** The pill invites a jump exactly when there is transcript below the fold. */
export function pillVisible(m: ScrollMetrics): boolean {
    return scrollable(m) && distanceFromBottom(m) > BOTTOM_SLACK;
}

/** The spacer that lets an anchored message reach the top of the viewport:
 *  exactly the shortfall between one viewport and the content at and below the
 *  anchor, never more — so the anchor works on a short conversation and the
 *  reply consumes the blank space as it streams in. `contentHeight` is the real
 *  content (scrollHeight minus any current spacer); `anchorTop` the anchor's
 *  offset in scroll coordinates. */
export function spacerHeight(clientHeight: number, contentHeight: number, anchorTop: number): number {
    return Math.max(0, Math.round(clientHeight - (contentHeight - anchorTop)));
}

/** What send-detection needs to know about a line list. */
export interface LineGauge {
    readonly count: number;
    readonly users: number;
    readonly lastIsUser: boolean;
}

export function gaugeLines(lines: readonly TranscriptLine[]): LineGauge {
    let users = 0;
    for (const line of lines) if (line.kind === "user") users += 1;
    return {
        count: lines.length,
        users,
        lastIsUser: lines.length > 0 && lines[lines.length - 1].kind === "user",
    };
}

/** A send is a newly *appended* user line: the user count grew and the list now
 *  ends on one. Snapshot repair after a settle rewrites line identities but not
 *  the user count, so it cannot re-trigger the anchor; a turn's own lines end
 *  on the agent's, not the user's. */
export function isSend(prev: LineGauge, next: LineGauge): boolean {
    return next.lastIsUser && next.users > prev.users;
}

/** History filling an empty transcript is placement, not a send — the panel
 *  opens at the bottom. (A single-line load ending on a user message is
 *  indistinguishable from a first send and anchors; that reads correctly too.) */
export function isHistoryLoad(prev: LineGauge, next: LineGauge): boolean {
    return prev.count === 0 && next.count > 1;
}

export interface TranscriptScroll {
    /** Ref for the scrolling `.transcript` element. */
    readonly transcriptRef: (el: HTMLElement) => void;
    /** Ref for the content wrapper whose height growth drives the latch. */
    readonly bodyRef: (el: HTMLElement) => void;
    /** Ref for the anchor spacer element at the end of the transcript. */
    readonly spacerRef: (el: HTMLElement) => void;
    /** Whether the jump-to-latest pill should be offered. */
    readonly pillVisible: Accessor<boolean>;
    /** Scroll to the bottom and latch the viewport to it. */
    readonly jumpToLatest: () => void;
    /** Feed the current line list; detects sends and initial history. */
    readonly observeLines: (lines: readonly TranscriptLine[]) => void;
    /** Forget everything positional — the session or chat changed. */
    readonly reset: () => void;
    /** Release observers and listeners. The panel calls this from onCleanup. */
    readonly dispose: () => void;
}

export function createTranscriptScroll(): TranscriptScroll {
    let transcriptEl: HTMLElement | undefined;
    let spacerEl: HTMLElement | undefined;
    const [pill, setPill] = createSignal(false);

    /** Latched to the bottom: growth keeps the viewport there. */
    let following = false;
    /** Holding the send anchor: reflow keeps the sent message at the top.
     *  A one-shot smooth glide is not enough — the settle that follows a fast
     *  turn swaps the line list mid-glide and the browser abandons or clamps
     *  the animation, so the anchored position is *held* until the reader
     *  scrolls, exactly as the bottom latch is. */
    let anchored = false;
    /** The anchor spacer's current height; > 0 means bottom is blank room, so
     *  landing there must not latch. */
    let spacer = 0;
    let prev: LineGauge | undefined;
    let intentUntil = 0;
    let glideUntil = 0;
    let tickQueued = false;
    let anchorQueued = false;
    const observers: ResizeObserver[] = [];
    const removeListeners: (() => void)[] = [];

    const now = () => Date.now();
    const metrics = (): ScrollMetrics | undefined => {
        const el = transcriptEl;
        if (!el) return undefined;
        return { scrollTop: el.scrollTop, scrollHeight: el.scrollHeight, clientHeight: el.clientHeight };
    };
    const updatePill = (m: ScrollMetrics) => setPill(pillVisible(m));
    const setSpacer = (height: number) => {
        spacer = height;
        if (spacerEl) spacerEl.style.height = height > 0 ? `${height}px` : "";
    };
    const lastUserLine = (): HTMLElement | null => {
        const all = transcriptEl?.querySelectorAll<HTMLElement>(".line.user");
        return all && all.length > 0 ? all[all.length - 1] : null;
    };
    /** An element's top in the transcript's scroll coordinates. Rect-based:
     *  `offsetTop` would answer relative to whatever positioned ancestor the
     *  host mount happens to have. */
    const topWithin = (el: HTMLElement): number => {
        const outer = transcriptEl!.getBoundingClientRect();
        return el.getBoundingClientRect().top - outer.top + transcriptEl!.scrollTop;
    };

    /** One coalesced pass after content or viewport growth: give back spacer
     *  room the reply has consumed, hold the bottom latch, refresh the pill. */
    const tick = () => {
        tickQueued = false;
        const el = transcriptEl;
        const m = metrics();
        if (!el || !m) return;
        // A missing anchor line is left alone rather than acted on: a snapshot
        // repair can swap the line list over a frame, and reacting to that
        // frame would yank the anchored reader upward.
        const anchor = spacer > 0 || anchored ? lastUserLine() : null;
        if (spacer > 0 && anchor) {
            setSpacer(spacerHeight(m.clientHeight, m.scrollHeight - spacer, topWithin(anchor)));
        }
        // While a smooth glide runs, the writes below would snap it short.
        if (now() >= glideUntil) {
            if (anchored && anchor) {
                const desired = Math.max(0, topWithin(anchor) - ANCHOR_GAP);
                if (Math.abs(el.scrollTop - desired) > 1) el.scrollTop = desired;
            } else if (following && distanceFromBottom(m) > 1) {
                el.scrollTop = el.scrollHeight;
            }
        }
        const after = metrics();
        if (after) updatePill(after);
    };
    const queueTick = () => {
        if (tickQueued) return;
        tickQueued = true;
        requestAnimationFrame(tick);
    };

    const onScroll = () => {
        const m = metrics();
        if (!m) return;
        updatePill(m);
        if (now() < glideUntil) return;
        // Position changes only count as the reader's when a gesture is live:
        // the browser's own scroll anchoring emits events on reflow, and those
        // must move neither latch. Latching additionally requires the bottom to
        // be real — the spacer-extended bottom is blank reserved room, not
        // "the latest", and reaching it opts nobody into following.
        if (now() >= intentUntil) return;
        anchored = false;
        if (atBottom(m)) {
            if (spacer === 0) following = true;
        } else {
            following = false;
        }
    };
    /** Hand the viewport to the reader mid-glide. Clearing our window is not
     *  enough: the browser does not abandon an in-flight programmatic smooth
     *  scroll on user input, so the animation keeps dragging the viewport to
     *  its old target and the gesture feels ignored. An instant same-position
     *  write is the documented way to cancel the animation. */
    const haltGlide = () => {
        if (glideUntil === 0) return;
        glideUntil = 0;
        transcriptEl?.scrollTo({ top: transcriptEl.scrollTop, behavior: "auto" });
    };
    // Wheel-up and touch drags release the latch directly: during streaming the
    // latch rewrites scrollTop every frame, so waiting for the scroll event to
    // land off-bottom would fight the reader's gesture.
    const onWheel = (event: WheelEvent) => {
        intentUntil = now() + INTENT_WINDOW_MS;
        if (event.deltaY !== 0) {
            anchored = false;
            haltGlide();
        }
        if (event.deltaY < 0) following = false;
    };
    const onTouchMove = () => {
        intentUntil = now() + INTENT_WINDOW_MS;
        following = false;
        anchored = false;
        haltGlide();
    };
    // A scrollbar grab: halt any glide so the thumb is not fought over, and let
    // the drag's scroll events do the judging.
    const onMouseDown = () => {
        intentUntil = now() + INTENT_WINDOW_MS;
        haltGlide();
    };

    const placeAtBottom = () => {
        requestAnimationFrame(() => {
            const el = transcriptEl;
            if (!el) return;
            setSpacer(0);
            following = true;
            anchored = false;
            el.scrollTop = el.scrollHeight;
            const m = metrics();
            if (m) updatePill(m);
        });
    };

    const anchorToLastSend = () => {
        anchorQueued = false;
        const el = transcriptEl;
        const m = metrics();
        const target = lastUserLine();
        if (!el || !m || !target) return;
        following = false;
        const wanted = spacerHeight(m.clientHeight, m.scrollHeight - spacer, topWithin(target));
        const heightBefore = m.clientHeight;
        setSpacer(wanted);
        requestAnimationFrame(() => {
            const after = metrics();
            if (!after) return;
            // The probe for a content-sized host: a sized panel keeps its
            // clientHeight and turns the spacer into scroll room, while a
            // content-sized one grows by it. (Scroll room itself is not the
            // signal — the overflow a spacer creates equals the anchor's
            // offset, which is legitimately zero for the first message of a
            // chat.) Undo the spacer and let the page's own scroller carry a
            // best-effort anchor. No pill, no latch — the page is the host's.
            if (wanted > 0 && after.clientHeight - heightBefore > wanted / 2) {
                setSpacer(0);
                target.scrollIntoView({ behavior: "smooth", block: "start" });
                return;
            }
            anchored = true;
            glideUntil = now() + GLIDE_WINDOW_MS;
            el.scrollTo({ top: Math.max(0, topWithin(target) - ANCHOR_GAP), behavior: "smooth" });
            // The glide is only the entry animation — a settle can swap the
            // line list mid-flight and the browser abandons the animation, so
            // the hold in tick() re-pins once the glide window closes.
            setTimeout(queueTick, GLIDE_WINDOW_MS + 50);
        });
    };

    return {
        transcriptRef: (el) => {
            transcriptEl = el;
            el.addEventListener("scroll", onScroll, { passive: true });
            el.addEventListener("wheel", onWheel, { passive: true });
            el.addEventListener("touchmove", onTouchMove, { passive: true });
            el.addEventListener("mousedown", onMouseDown, { passive: true });
            removeListeners.push(() => {
                el.removeEventListener("scroll", onScroll);
                el.removeEventListener("wheel", onWheel);
                el.removeEventListener("touchmove", onTouchMove);
                el.removeEventListener("mousedown", onMouseDown);
            });
            const viewport = new ResizeObserver(queueTick);
            viewport.observe(el);
            observers.push(viewport);
        },
        bodyRef: (el) => {
            const content = new ResizeObserver(queueTick);
            content.observe(el);
            observers.push(content);
        },
        spacerRef: (el) => {
            spacerEl = el;
        },
        pillVisible: pill,
        jumpToLatest: () => {
            const el = transcriptEl;
            if (!el) return;
            following = true;
            anchored = false;
            glideUntil = now() + GLIDE_WINDOW_MS;
            el.scrollTo({ top: el.scrollHeight, behavior: "smooth" });
        },
        observeLines: (lines) => {
            const next = gaugeLines(lines);
            const before = prev;
            prev = next;
            if (before === undefined) {
                if (next.count > 0) placeAtBottom();
                return;
            }
            if (isHistoryLoad(before, next)) {
                placeAtBottom();
                return;
            }
            if (isSend(before, next) && !anchorQueued) {
                anchorQueued = true;
                requestAnimationFrame(anchorToLastSend);
            }
        },
        reset: () => {
            prev = undefined;
            following = false;
            anchored = false;
            intentUntil = 0;
            glideUntil = 0;
            setSpacer(0);
            setPill(false);
        },
        dispose: () => {
            for (const observer of observers) observer.disconnect();
            observers.length = 0;
            for (const remove of removeListeners) remove();
            removeListeners.length = 0;
        },
    };
}
