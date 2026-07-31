import { describe, expect, it, vi } from "vitest";

import {
    observeBrowserLatency,
    relayServerLatency,
    type LatencyObservation,
} from "./latency";

describe("browser latency observations", () => {
    it("contains only the named phase, monotonic time, and correlation fields", () => {
        const observer = vi.fn();
        observeBrowserLatency(observer, "first_text_received", {
            request_id: "request-1",
            sequence: 4,
        });

        expect(observer).toHaveBeenCalledWith({
            phase: "first_text_received",
            monotonic_ms: expect.any(Number),
            request_id: "request-1",
            sequence: 4,
        });
    });

    it("drops a broken diagnostic sink without breaking the serving path", () => {
        expect(() =>
            observeBrowserLatency(
                () => {
                    throw new Error("collector failed");
                },
                "command_sent",
                { request_id: "request-1" },
            ),
        ).not.toThrow();
    });

    it("relays only bounded payload-free Session DO timing frames", () => {
        const observations: LatencyObservation[] = [];
        expect(
            relayServerLatency(
                (observation) => observations.push(observation),
                {
                    type: "latency",
                    source: "session",
                    span: "public_turn",
                    phase: "settlement_complete",
                    request_id: "request-1",
                    elapsed_ms: 42.25,
                    text: "must not be projected",
                },
            ),
        ).toBe(true);
        expect(observations).toEqual([
            {
                source: "session",
                span: "public_turn",
                phase: "settlement_complete",
                request_id: "request-1",
                elapsed_ms: 42.25,
            },
        ]);
        expect(
            relayServerLatency(
                (observation) => observations.push(observation),
                {
                    source: "session",
                    span: "runtime",
                    phase: "unknown_boundary",
                    request_id: "request-1",
                    elapsed_ms: 1,
                },
            ),
        ).toBe(false);
        expect(observations).toHaveLength(1);
    });

    it("relays only bounded payload-free deployment bootstrap observations", () => {
        const observations: LatencyObservation[] = [];
        expect(
            relayServerLatency(
                (observation) => observations.push(observation),
                {
                    source: "deployment",
                    span: "bootstrap",
                    phase: "runtime_bootstrap_complete",
                    trace_id: "boot_request_1",
                    elapsed_ms: 18.5,
                    connection_capability: "must not be projected",
                },
            ),
        ).toBe(true);
        expect(observations).toEqual([
            {
                source: "deployment",
                span: "bootstrap",
                phase: "runtime_bootstrap_complete",
                trace_id: "boot_request_1",
                elapsed_ms: 18.5,
            },
        ]);
        expect(
            relayServerLatency(
                (observation) => observations.push(observation),
                {
                    source: "deployment",
                    span: "bootstrap",
                    phase: "unknown_boundary",
                    trace_id: "boot_request_1",
                    elapsed_ms: 1,
                },
            ),
        ).toBe(false);
        expect(observations).toHaveLength(1);
    });
});
