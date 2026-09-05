import { describe, expect, it } from "vitest";
import {
    KNOWN_ENGINES,
    engineChangePending,
    engineLabel,
    isServedEngine,
} from "./tokenwright-panel";

describe("engine kinds drive the controls", () => {
    it("treats freetoken as embedded and the rest as served", () => {
        expect(isServedEngine("freetoken")).toBe(false);
        expect(isServedEngine("FreeToken")).toBe(false);
        for (const served of ["vllm", "vLLM", "sglang", "SGLang"]) {
            expect(isServedEngine(served), served).toBe(true);
        }
    });

    it("an empty engine name is not 'served'", () => {
        // A box with the engine down reports an empty name; that must not read
        // as a served engine and hide the controls a stopped box still offers.
        expect(isServedEngine("")).toBe(false);
    });

    it("labels every known engine and passes an unknown one through", () => {
        expect(KNOWN_ENGINES.map(engineLabel)).toEqual(["FreeToken", "vLLM", "SGLang"]);
        expect(engineLabel("mystery")).toBe("mystery");
    });

    it("a change is pending when requested and running disagree, spelling aside", () => {
        expect(engineChangePending("vllm", "FreeToken")).toBe(true);
        expect(engineChangePending("freetoken", "FreeToken")).toBe(false);
    });
});

import type { InferenceDocument } from "./tokenwright-panel";

/** The smallest inference doc the control-decision folds read. */
function inference(over: Partial<InferenceDocument> = {}): InferenceDocument {
    return {
        desired: { model: "tinyllama", models: ["tinyllama"], autostart: true, direct_access: false, engine: "freetoken" },
        engine: { name: "FreeToken", version: "0.3.2", status: "running", listen: "", uptime: "1h", restarts: 0, last_error: null },
        model: { id: "tinyllama", quantization: "q4_k_m", context_length: 2048, size_mib: 608, loaded_at: null },
        models: [], hardware: { gpu: "", driver: "", cuda: "", vram_used_mib: 0, vram_total_mib: 0, ram_total_mib: 0 },
        storage: { disk_total_mib: 1, disk_free_mib: 1, orphaned_mib: 0 },
        throughput: { tokens_per_second: 0, active_requests: 0, max_concurrent: 4, rejected_overload_total: 0, requests_total: 0 },
        events: [], ...over,
    } as InferenceDocument;
}

describe("served vs embedded, at the level a control decision needs it", () => {
    it("a served engine's running name reads as served regardless of the requested id", () => {
        const doc = inference({ engine: { ...inference().engine, name: "vLLM" }, desired: { ...inference().desired, engine: "vllm" } });
        expect(isServedEngine(doc.engine.name)).toBe(true);
    });

    it("switching is pending until the running engine matches the requested one", () => {
        // FreeToken running, vLLM requested → pending; after a restart the names
        // agree and it is no longer pending.
        expect(engineChangePending("vllm", "FreeToken")).toBe(true);
        expect(engineChangePending("vllm", "vLLM")).toBe(false);
    });
});

describe("serving metrics are carried, not interpreted", () => {
    it("the type admits null (embedded / engine down) and a populated block", () => {
        // A compile-level guarantee, exercised: both shapes are assignable.
        const down: InferenceDocument["serving"] = null;
        const up: InferenceDocument["serving"] = {
            kv_cache_used_pct: 63, running: 3, queued: 1,
            native: { Preemptions: 4, "Prefix-cache hit rate": 0.55 },
        };
        expect(down).toBeNull();
        expect(up?.native["Preemptions"]).toBe(4);
    });
});
