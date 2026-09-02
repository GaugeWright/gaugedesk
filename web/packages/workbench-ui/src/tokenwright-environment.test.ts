import { describe, expect, it } from "vitest";
import { parseEnvironmentView, resolveDocumentPath } from "./environment-view";
import { BUILTIN_COMPONENTS } from "./EnvironmentDocumentView";
import {
    TOKENWRIGHT_COMMANDS,
    TOKENWRIGHT_HELP_SOURCES,
    TOKENWRIGHT_MANIFEST,
    TOKENWRIGHT_SCHEMAS,
    TOKENWRIGHT_VIEW_SOURCES,
    tokenwrightViewRegistry,
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
    events: [],
};

describe("the carried TokenWright Environment bundle", () => {
    it("parses as a manifest naming three documents", () => {
        expect(TOKENWRIGHT_MANIFEST.version).toBe(1);
        expect(TOKENWRIGHT_MANIFEST.documents.map((d) => d.id)).toEqual([
            "tokenwright.inference", "tokenwright.posture", "tokenwright.access",
        ]);
    });

    it("carries a View and a Help document for every manifest entry", () => {
        // A manifest entry whose View is missing renders a blank panel rather
        // than an error anyone sees.
        for (const document of TOKENWRIGHT_MANIFEST.documents) {
            expect(TOKENWRIGHT_VIEW_SOURCES[document.view!], document.id).toBeTypeOf("string");
            expect(TOKENWRIGHT_HELP_SOURCES[document.help!], document.id).toBeTypeOf("string");
        }
    });

    it("registers a validator for every schema the manifest declares", () => {
        // A schema id with no validator falls back to generic JSON, which is
        // readable but is silently not the View that was written.
        for (const document of TOKENWRIGHT_MANIFEST.documents) {
            expect(TOKENWRIGHT_SCHEMAS[document.schema], document.schema).toBeTypeOf("function");
        }
    });

    it("parses every carried View through the real renderer's parser", () => {
        // The parser raising collapses the whole View to a raw-JSON block, so a
        // View this rejects is a broken page rather than a cosmetic problem.
        for (const [path, source] of Object.entries(TOKENWRIGHT_VIEW_SOURCES)) {
            expect(() => parseEnvironmentView(source, BUILTIN_COMPONENTS), path).not.toThrow();
        }
    });

    it("uses only components this renderer builds in", () => {
        // The bundle comes from another repository. A View naming a component
        // this GaugeDesk does not have collapses the whole page to raw JSON.
        for (const [path, source] of Object.entries(TOKENWRIGHT_VIEW_SOURCES)) {
            for (const [, name] of source.matchAll(/<([A-Z][A-Za-z0-9]*)/gu)) {
                expect(BUILTIN_COMPONENTS.has(name!), `${path} uses <${name}>`).toBe(true);
            }
        }
    });

    it("binds only paths that resolve in a document of the declared shape", () => {
        const nodes = parseEnvironmentView(
            TOKENWRIGHT_VIEW_SOURCES["views/inference.mdx"]!, BUILTIN_COMPONENTS);
        const bindings: string[] = [];
        const walk = (list: readonly ReturnType<typeof parseEnvironmentView>[number][]): void => {
            for (const node of list) {
                if (node.kind !== "element") continue;
                if (node.name !== "Notice" && node.name !== "Command" && node.attributes.value) {
                    bindings.push(node.attributes.value);
                }
                walk(node.children);
            }
        };
        walk(nodes);
        expect(bindings.length).toBeGreaterThan(0);
        for (const binding of bindings) {
            expect(resolveDocumentPath(inferenceDocument, binding), binding).not.toBeUndefined();
        }
    });
});

describe("the schema validators", () => {
    const inference = TOKENWRIGHT_SCHEMAS["gw://schemas/tokenwright/inference/v1"]!;

    it("accepts a document carrying every required block", () => {
        expect(inference(inferenceDocument)).toBe(true);
    });

    it("refuses a document missing a block, rather than rendering Unknown over it", () => {
        // The design's fallback for a document this GaugeDesk does not
        // understand is a readable generic JSON rendering. A View drawn
        // confidently over a document it does not describe is what that
        // fallback exists to prevent, and only a validator that looks gets there.
        const { throughput, ...missing } = inferenceDocument;
        expect(inference(missing)).toBe(false);
    });

    it("refuses a non-object", () => {
        expect(inference(null)).toBe(false);
        expect(inference([])).toBe(false);
        expect(inference("a box says hello")).toBe(false);
    });
});

describe("the command declarations", () => {
    it("carries the box's advertised set", () => {
        const ids = TOKENWRIGHT_COMMANDS.map((command) => command.id);
        expect(ids).toContain("tokenwright.engine.restart");
        expect(ids).toContain("tokenwright.unpair");
        expect(new Set(ids).size).toBe(ids.length);
    });

    it("grants nothing — the registry takes its commands from the session", () => {
        // Referencing a command in the bundle must not make it invocable. The
        // grant is authoritative, and a command absent from it renders as an
        // inert "Unavailable in this session" control.
        const registry = tokenwrightViewRegistry({});
        expect(registry.commands).toEqual({});

        const granted = tokenwrightViewRegistry({
            "tokenwright.engine.restart": { run: () => undefined },
        });
        expect(Object.keys(granted.commands ?? {})).toEqual(["tokenwright.engine.restart"]);
    });
});
