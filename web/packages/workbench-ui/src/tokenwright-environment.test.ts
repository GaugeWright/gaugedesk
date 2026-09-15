import { describe, expect, it } from "vitest";
import {
    TOKENWRIGHT_COMMANDS,
    TOKENWRIGHT_DOCUMENTS,
    TOKENWRIGHT_SCHEMAS,
} from "./tokenwright-environment";

/** A document with every block the inference schema requires. */
const inferenceDocument = {
    desired: {
        model: null, models: [], autostart: true, direct_access: false,
        engine: "freetoken",
    },
    engine: {
        // What answered, which is not always what `desired.engine` asked for —
        // they differ while a change reconciles, and persistently when the
        // requested engine will not start.
        name: "FreeToken", version: "0.3.2", status: "running",
        listen: "127.0.0.1:8721", uptime: "3d 14h", restarts: 1, last_error: null,
    },
    model: { id: null, quantization: null, context_length: null, size_mib: null, loaded_at: null },
    models: [],
    hardware: {
        gpu: "NVIDIA GeForce RTX 5090", driver: "580.65.06", cuda: "13.0",
        vram_used_mib: 0, vram_total_mib: 32607, ram_total_mib: 196608,
    },
    storage: { disk_total_mib: 1, disk_free_mib: 1, orphaned_mib: 0 },
    throughput: {
        tokens_per_second: 0, active_requests: 0, max_concurrent: 4,
        rejected_overload_total: 0, requests_total: 0,
    },
    // Null: this fixture is an embedded (FreeToken) box; a served engine
    // carries a populated block. Required either way by the schema.
    serving: null,
    events: [],
};

describe("the pinned TokenWright native-control metadata", () => {
    it("names exactly the three supported server documents", () => {
        expect(TOKENWRIGHT_DOCUMENTS.map((document) => document.id)).toEqual([
            "tokenwright.inference", "tokenwright.posture", "tokenwright.access",
        ]);
    });

    it("registers a validator for every supported document", () => {
        for (const document of TOKENWRIGHT_DOCUMENTS) {
            expect(TOKENWRIGHT_SCHEMAS[document.schema], document.schema).toBeTypeOf("function");
        }
    });

    it("carries the box's advertised command labels without granting them", () => {
        const ids = TOKENWRIGHT_COMMANDS.map((command) => command.id);
        expect(ids).toContain("tokenwright.engine.restart");
        expect(ids).toContain("tokenwright.unpair");
        expect(new Set(ids).size).toBe(ids.length);
    });
});

describe("the TokenWright document validators", () => {
    const inference = TOKENWRIGHT_SCHEMAS["gw://schemas/tokenwright/inference/v1"]!;

    it("accepts a document carrying every required block", () => {
        expect(inference(inferenceDocument)).toBe(true);
    });

    it("refuses a document missing a required block", () => {
        const { throughput, ...missing } = inferenceDocument;
        expect(throughput).toBeDefined();
        expect(inference(missing)).toBe(false);
    });

    it("refuses a non-object", () => {
        expect(inference(null)).toBe(false);
        expect(inference([])).toBe(false);
        expect(inference("a box says hello")).toBe(false);
    });
});
