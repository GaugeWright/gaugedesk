import { describe, expect, it } from "vitest";
import { MODEL_CATALOG, type CatalogModel } from "./model-catalog.generated";
import {
    defaultOption,
    defaultVisibleKeys,
    isDefaultVisible,
    modelAcceptsImages,
    modelKey,
    modelOptions,
    parseEnabledModels,
    pickableModels,
    providerTakesCustomModel,
    serializeEnabledModels,
    thinkingLevelsFor,
} from "./model-picker";

// A small fixture so the tests don't ride on the live (regenerated) catalog.
const CAT: CatalogModel[] = [
    // codex native (primary for openai-codex)
    { provider: "openai-codex", id: "gpt-5.5", name: "GPT-5.5", reasoning: true, thinking: ["off", "low", "high"], input: ["text"] },
    // regular openai (secondary for codex, primary for an openai key)
    { provider: "openai", id: "gpt-5.5", name: "GPT-5.5", reasoning: true, thinking: ["low", "high"], input: ["text"] },
    { provider: "openai", id: "gpt-4o", name: "GPT-4o", reasoning: false, thinking: ["off"], input: ["text"] },
    { provider: "openai", id: "o3", name: "o3", reasoning: true, thinking: ["off", "high"], input: ["text"] },
    // anthropic
    { provider: "anthropic", id: "claude-opus-4-6", name: "Claude Opus 4.6", reasoning: true, thinking: ["off", "high", "xhigh"], input: ["text"] },
    { provider: "anthropic", id: "claude-3-5-haiku-20241022", name: "Claude Haiku 3.5", reasoning: false, thinking: ["off"], input: ["text"] },
    // a reasoning snapshot (default-hidden by the date in its id)
    { provider: "anthropic", id: "claude-opus-4-6-20260101", name: "Claude Opus 4.6 (snap)", reasoning: true, thinking: ["off", "high"], input: ["text"] },
];

describe("model-picker", () => {
    it("nothing linked → no pickable models, picker is just Default", () => {
        expect(pickableModels([], CAT)).toEqual([]);
        expect(modelOptions([], null, undefined, CAT).map((o) => o.label)).toEqual(["Default"]);
    });

    it("the default row is named after the engine's resolved default when known", () => {
        // Known to the catalog → the display name; the value stays empty (no pin).
        const named = defaultOption({ provider: "openai-codex", model: "gpt-5.5" }, CAT);
        expect(named.label).toBe("GPT-5.5 (default)");
        expect(named.id).toBe("");
        expect(named.provider).toBe("");
        // Absent from the catalog → the raw id still beats a blind "Default".
        expect(defaultOption({ provider: "openai-codex", model: "gpt-9" }, CAT).label).toBe("gpt-9 (default)");
        // Unknown / no default model → the blind fallback.
        expect(defaultOption(null, CAT).label).toBe("Default");
        expect(defaultOption({ provider: "openai", model: null }, CAT).label).toBe("Default");
        // modelOptions threads it into the first row.
        const labels = modelOptions([], null, undefined, CAT, { provider: "openai-codex", model: "gpt-5.5" });
        expect(labels[0].label).toBe("GPT-5.5 (default)");
    });

    it("codex linked → its primary set plus the OpenAI set as secondary, all pinned to openai-codex", () => {
        const ms = pickableModels(["openai-codex"], CAT);
        // every entry pins the codex provider (so the engine uses the OAuth endpoint)
        expect(ms.every((m) => m.provider === "openai-codex")).toBe(true);
        // gpt-5.5 is deduped to the primary (codex) entry, not the secondary openai one
        const gpt = ms.filter((m) => m.id === "gpt-5.5");
        expect(gpt).toHaveLength(1);
        expect(gpt[0].primary).toBe(true);
        expect(gpt[0].thinking).toEqual(["off", "low", "high"]); // primary's levels
        // the OpenAI-only models came in as secondary
        expect(ms.find((m) => m.id === "gpt-4o")?.primary).toBe(false);
        expect(ms.find((m) => m.id === "o3")?.primary).toBe(false);
    });

    it("default picker shows primary + reasoning + non-snapshot only", () => {
        const labels = modelOptions(["openai-codex", "anthropic"], null, undefined, CAT).map((o) => o.label);
        expect(labels).toContain("GPT-5.5"); // codex primary, reasoning
        expect(labels).toContain("Claude Opus 4.6"); // anthropic primary, reasoning
        expect(labels).not.toContain("GPT-4o"); // secondary + non-reasoning
        expect(labels).not.toContain("o3"); // secondary (codex's openai set) — settings-only
        expect(labels).not.toContain("Claude Haiku 3.5"); // non-reasoning
        expect(labels.some((l) => l.includes("snap"))).toBe(false); // snapshot hidden
    });

    it("the same model via two linked accounts gets a (provider) suffix", () => {
        const ms = pickableModels(["openai-codex", "openai"], CAT);
        const gpt = ms.filter((m) => m.name === "GPT-5.5");
        // one pinned to codex, one to the openai key
        expect(new Set(gpt.map((m) => m.provider))).toEqual(new Set(["openai-codex", "openai"]));
        expect(gpt.map((m) => m.label).sort()).toEqual(["GPT-5.5 (Codex)", "GPT-5.5 (OpenAI)"]);
    });

    it("an enabled-set overrides the default and is honoured exactly", () => {
        const enabled = new Set([modelKey({ id: "gpt-4o", provider: "openai-codex" })]);
        const labels = modelOptions(["openai-codex"], enabled, undefined, CAT).map((o) => o.label);
        expect(labels).toEqual(["Default", "GPT-4o"]); // only the enabled one (+ Default)
    });

    it("a pinned model stays selectable even when filtered out of the default set", () => {
        // gpt-4o is non-reasoning (default-hidden) but the chat is pinned to it
        const opts = modelOptions(["openai-codex"], null, { id: "gpt-4o", provider: "openai-codex" }, CAT);
        expect(opts.some((o) => o.id === "gpt-4o")).toBe(true);
    });

    it("thinking levels follow the pinned model; Default/unknown → [off]", () => {
        expect(thinkingLevelsFor(["anthropic"], "claude-opus-4-6", "anthropic", CAT)).toEqual(["off", "high", "xhigh"]);
        expect(thinkingLevelsFor(["openai-codex"], "gpt-5.5", "openai-codex", CAT)).toEqual(["off", "low", "high"]);
        expect(thinkingLevelsFor(["anthropic"], "", "", CAT)).toEqual(["off"]);
        expect(thinkingLevelsFor(["anthropic"], "nope", "anthropic", CAT)).toEqual(["off"]);
    });

    it("isDefaultVisible: primary + reasoning + non-snapshot", () => {
        const [codexGpt] = pickableModels(["openai-codex"], CAT).filter((m) => m.id === "gpt-5.5");
        expect(isDefaultVisible(codexGpt)).toBe(true);
    });

    it("an explicit empty enabled set shows only Default (operator disabled everything)", () => {
        const labels = modelOptions(["openai-codex"], new Set(), undefined, CAT).map((o) => o.label);
        expect(labels).toEqual(["Default"]);
    });

    it("parse/serialize the enabled-set preference round-trips; absent/bad → null", () => {
        expect(parseEnabledModels(null)).toBeNull();
        expect(parseEnabledModels("")).toBeNull();
        expect(parseEnabledModels("not json")).toBeNull();
        expect(parseEnabledModels('{"a":1}')).toBeNull(); // not an array
        expect(parseEnabledModels("[]")).toEqual(new Set()); // present-but-empty is honoured
        const set = new Set(["openai-codex:gpt-5.5", "anthropic:claude-opus-4-6"]);
        expect(parseEnabledModels(serializeEnabledModels(set))).toEqual(set);
        expect(serializeEnabledModels(new Set(["b", "a"]))).toBe('["a","b"]'); // sorted
    });

    it("defaultVisibleKeys are exactly the default-visible models' keys", () => {
        const keys = defaultVisibleKeys(["openai-codex", "anthropic"], CAT);
        expect(keys.has(modelKey({ id: "gpt-5.5", provider: "openai-codex" }))).toBe(true);
        expect(keys.has(modelKey({ id: "claude-opus-4-6", provider: "anthropic" }))).toBe(true);
        expect(keys.has(modelKey({ id: "gpt-4o", provider: "openai-codex" }))).toBe(false);
    });
});

describe("openai-generic custom model (ADR 0083)", () => {
    it("marks openai-generic as a free-text-model provider", () => {
        expect(providerTakesCustomModel("openai-generic")).toBe(true);
        expect(providerTakesCustomModel("openai")).toBe(false);
        expect(providerTakesCustomModel("anthropic")).toBe(false);
    });

    it("keeps an openai-generic pin visible though it has no catalog entry", () => {
        const opts = modelOptions(
            ["openai-generic"],
            null,
            { id: "llama-3.3-70b", provider: "openai-generic" },
            CAT,
        );
        // No catalog rows for openai-generic, but the pinned custom model survives so the
        // <select> reflects the chat's real config (label = the raw id).
        expect(opts.map((o) => o.label)).toEqual(["Default", "llama-3.3-70b"]);
        const pinned = opts.find((o) => o.provider === "openai-generic");
        expect(pinned).toMatchObject({ id: "llama-3.3-70b", provider: "openai-generic" });
    });
});

describe("xai fixed-host provider", () => {
    it("contributes its shipped Grok catalog when the account is linked", () => {
        // ACCOUNT_SOURCES membership is what makes a linked account contribute
        // models; a provider missing there fails QUIET (zero models, no error),
        // so this is the drift guard.
        const opts = modelOptions(["xai"], null, undefined, MODEL_CATALOG);
        const grok = opts.filter((o) => o.provider === "xai");
        expect(grok.map((o) => o.id)).toContain("grok-4.6");
        expect(grok.length).toBeGreaterThanOrEqual(2);
    });

    it("is a catalog provider, not a free-text-model one", () => {
        expect(providerTakesCustomModel("xai")).toBe(false);
    });
});

describe("modelAcceptsImages (UX-14 vision pre-check)", () => {
    // A vision-capable model alongside the text-only fixture entries.
    const VISION: CatalogModel[] = [
        ...CAT,
        { provider: "anthropic", id: "claude-vision-x", name: "Claude Vision", reasoning: true, thinking: ["off"], input: ["text", "image"] },
    ];

    it("blocks a KNOWN non-vision model", () => {
        expect(modelAcceptsImages({ id: "gpt-4o", provider: "openai" }, VISION)).toBe(false);
    });

    it("allows a known vision-capable model", () => {
        expect(modelAcceptsImages({ id: "claude-vision-x", provider: "anthropic" }, VISION)).toBe(true);
    });

    it("is permissive for the default model (no pin)", () => {
        expect(modelAcceptsImages({ id: "", provider: "" }, VISION)).toBe(true);
        expect(modelAcceptsImages(null, VISION)).toBe(true);
        expect(modelAcceptsImages(undefined, VISION)).toBe(true);
    });

    it("is permissive for a model absent from the catalog", () => {
        expect(modelAcceptsImages({ id: "made-up", provider: "nobody" }, VISION)).toBe(true);
    });
});
