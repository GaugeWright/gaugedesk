import { describe, expect, it } from "vitest";
import { initialDraft, isPersonType, parseDraft } from "./whip-run-form";
import type { WorkflowInputType } from "@gaugewright/control-plane-client";

const learner: WorkflowInputType = { kind: "object", name: "Learner", fields: [{ name: "authority", type: { kind: "string" } }] };

describe("whip run form", () => {
    it("offers a person for an authority-only input, starting as the signed-in person", () => {
        expect(isPersonType(learner)).toBe(true);
        expect(initialDraft(learner, "alice")).toEqual({ kind: "person", authority: "alice" });
        expect(parseDraft(learner, initialDraft(learner, "alice"), "learner")).toEqual({ ok: true, value: { authority: "alice" } });
        expect(parseDraft(learner, initialDraft(learner), "learner")).toEqual({ ok: false, error: "choose who learner is" });
        const shape: WorkflowInputType = { kind: "object", fields: [{ name: "authority", type: { kind: "string" } }, { name: "team", type: { kind: "string" } }] };
        expect(isPersonType(shape)).toBe(false);
    });
    it("parses numbers, choices, optionals and JSON, and names what is wrong", () => {
        expect(parseDraft({ kind: "int" }, { kind: "text", text: "42" }, "n")).toEqual({ ok: true, value: 42 });
        expect(parseDraft({ kind: "int" }, { kind: "text", text: "4.2" }, "n")).toEqual({ ok: false, error: "n must be a whole number" });
        expect(parseDraft({ kind: "float" }, { kind: "text", text: "" }, "x")).toEqual({ ok: false, error: "x must be a number" });
        expect(parseDraft({ kind: "enum", variants: ["Calm", "Busy"] }, initialDraft({ kind: "enum", variants: ["Calm", "Busy"] }), "mood")).toEqual({ ok: true, value: "Calm" });
        const optional: WorkflowInputType = { kind: "optional", of: { kind: "string" } };
        expect(parseDraft(optional, initialDraft(optional), "note")).toEqual({ ok: true, value: null });
        expect(parseDraft(optional, { kind: "optional", set: true, inner: { kind: "text", text: "hi" } }, "note")).toEqual({ ok: true, value: "hi" });
        expect(parseDraft({ kind: "json" }, { kind: "text", text: "[1,2]" }, "tags")).toEqual({ ok: true, value: [1, 2] });
        expect(parseDraft({ kind: "json" }, { kind: "text", text: "[1," }, "tags")).toEqual({ ok: false, error: "tags must be JSON" });
        expect(parseDraft({ kind: "literal", value: "v1" }, initialDraft({ kind: "literal", value: "v1" }), "tag")).toEqual({ ok: true, value: "v1" });
    });
    it("reports the first bad field inside an object by its path", () => {
        const shape: WorkflowInputType = { kind: "object", fields: [{ name: "size", type: { kind: "int" } }] };
        expect(parseDraft(shape, { kind: "object", fields: { size: { kind: "text", text: "big" } } }, "box")).toEqual({ ok: false, error: "box.size must be a whole number" });
    });
});
