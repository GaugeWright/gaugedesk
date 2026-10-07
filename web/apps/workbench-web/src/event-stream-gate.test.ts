import { describe, expect, it, vi } from "vitest";
import type { RouteEventClose, RouteEventStream } from "@gaugewright/control-plane-client";
import { EVENT_STREAMS_RESUMED, EventStreamGate } from "./event-stream-gate";

interface Opened {
    readonly path: string;
    readonly message: (data: string) => void;
    readonly open?: () => void;
    readonly close?: (reason?: RouteEventClose) => void;
    stopped: boolean;
}

function fakeSource(): { source: RouteEventStream; opened: Opened[] } {
    const opened: Opened[] = [];
    const source: RouteEventStream = (path, message, open, close) => {
        const entry: Opened = { path, message, open, close, stopped: false };
        opened.push(entry);
        return () => { entry.stopped = true; };
    };
    return { source, opened };
}

describe("EventStreamGate (WS-581)", () => {
    it("passes a stream through untouched while open", () => {
        const { source, opened } = fakeSource();
        const gate = new EventStreamGate();
        const onMessage = vi.fn();
        const onOpen = vi.fn();
        const onClose = vi.fn();
        const stop = gate.wrap(source)("/workspace/events", onMessage, onOpen, onClose);
        expect(opened).toHaveLength(1);
        opened[0].open?.();
        opened[0].message("x");
        expect(onOpen).toHaveBeenCalledOnce();
        expect(onMessage).toHaveBeenCalledWith("x");
        opened[0].close?.({ status: 502 });
        expect(onClose).toHaveBeenCalledWith({ status: 502 });
        stop();
        expect(opened[0].stopped).toBe(false);
    });

    it("stops every live stream on suspend without telling its subscriber", () => {
        const { source, opened } = fakeSource();
        const gate = new EventStreamGate();
        const closes = [vi.fn(), vi.fn(), vi.fn()];
        const messages = vi.fn();
        for (const close of closes) gate.wrap(source)("/workspace/events", messages, undefined, close);
        gate.suspend();
        expect(opened.every((entry) => entry.stopped)).toBe(true);
        // A late callback from a stopped connection reaches nobody, so the
        // subscriber's reconnect loop does not reopen it under the change.
        opened[0].message("late");
        opened[0].close?.();
        expect(messages).not.toHaveBeenCalled();
        for (const close of closes) expect(close).not.toHaveBeenCalled();
    });

    it("parks a stream opened while suspended", () => {
        const { source, opened } = fakeSource();
        const gate = new EventStreamGate();
        gate.suspend();
        const onClose = vi.fn();
        gate.wrap(source)("/engagements/e/events", vi.fn(), undefined, onClose);
        expect(opened).toHaveLength(0);
        gate.resume();
        expect(opened).toHaveLength(0);
        expect(onClose).toHaveBeenCalledWith(EVENT_STREAMS_RESUMED);
    });

    it("hands every held stream back as closed on resume, once", () => {
        const { source, opened } = fakeSource();
        const gate = new EventStreamGate();
        const kept = vi.fn();
        const dropped = vi.fn();
        gate.wrap(source)("/a", vi.fn(), undefined, kept);
        const stopDropped = gate.wrap(source)("/b", vi.fn(), undefined, dropped);
        gate.suspend();
        stopDropped();
        gate.resume();
        gate.resume();
        expect(kept).toHaveBeenCalledOnce();
        expect(kept).toHaveBeenCalledWith(EVENT_STREAMS_RESUMED);
        expect(dropped).not.toHaveBeenCalled();
        expect(gate.isSuspended).toBe(false);
        // After resuming, a new stream opens normally.
        gate.wrap(source)("/c", vi.fn());
        expect(opened.at(-1)?.path).toBe("/c");
        expect(opened.at(-1)?.stopped).toBe(false);
    });

    it("forgets a stream its own connection closed", () => {
        const { source, opened } = fakeSource();
        const gate = new EventStreamGate();
        const onClose = vi.fn();
        gate.wrap(source)("/a", vi.fn(), undefined, onClose);
        opened[0].close?.({ status: 401 });
        gate.suspend();
        gate.resume();
        expect(onClose).toHaveBeenCalledOnce();
    });
});
