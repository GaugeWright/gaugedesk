/**
 * The Settings modal's plain form (#5 round-5) reads/writes the config keys the
 * GaugeDesk actually owns. These guard the read↔write round-trip and the
 * "preserve unknown keys / don't fight the Advanced JSON" contract.
 */

import { describe, expect, it } from "vitest";
import {
    AGENT_ABILITY_PRESETS,
    optionalAbilities,
    preferredModelChoices,
    presetAbilities,
    plainConfigError,
    readFormConfig,
    writeFormConfig,
} from "./AgentSettings";

describe("agent ability presets", () => {
    it("exposes the four ordered ceilings without ask_human", () => {
        expect(AGENT_ABILITY_PRESETS.map(({ name, value }) => ({ name, value }))).toEqual([
            { name: "Chat only", value: [] },
            { name: "Read workspace", value: ["workspace.read"] },
            {
                name: "Create artifacts",
                value: ["workspace.read", "workspace.write"],
            },
            {
                name: "Run workspace commands",
                value: ["workspace.read", "workspace.write", "command.run"],
            },
        ]);
        expect(JSON.stringify(AGENT_ABILITY_PRESETS)).not.toContain("ask_human");
    });
});

describe("readFormConfig", () => {
    it("falls back to the host default on an empty config", () => {
        expect(readFormConfig({})).toEqual({ model: "" });
    });

    it("reads the preferred model", () => {
        expect(readFormConfig({ model: "gpt-5.5" })).toEqual({ model: "gpt-5.5" });
    });

    it("treats a missing/garbage parse as defaults", () => {
        expect(readFormConfig(null)).toEqual({ model: "" });
    });
});

describe("writeFormConfig", () => {
    it("omits model when blank", () => {
        const out = writeFormConfig({}, { model: "" });
        expect(out.model).toBeUndefined();
    });

    it("preserves GaugeDesk-owned provider keys and removes retired package policy", () => {
        const prev = { provider: "openai-codex", thinking: "high", policy: { allow_tools: ["read"] } };
        const out = writeFormConfig(prev, { model: "x" });
        expect(out.provider).toBe("openai-codex");
        expect(out.thinking).toBe("high");
        expect(out.policy).toBeUndefined();
    });

    it("round-trips read→write→read", () => {
        const original = { model: "m", provider: "openai-codex" };
        const form = readFormConfig(original);
        const written = writeFormConfig(original, form);
        expect(readFormConfig(written)).toEqual(form);
    });
});

describe("plainConfigError", () => {
    it("collapses a parser error to one plain sentence", () => {
        expect(plainConfigError('Error: invalid config: {"error":"trailing characters at line 1 column 3"}')).toMatch(
            /isn't valid settings text/,
        );
    });

    it("explains a visitor ability the agent itself does not have", () => {
        const message = plainConfigError(
            'Error: PUT /archetypes/agent-1/panel-profile: 422 {"error":"public ability `workspace.read` is not granted to the authored agent"}',
        );
        expect(message).toContain("“Read files”");
        expect(message).toContain("Give the agent that ability under Abilities");
        expect(message).not.toContain("422");
    });

    it("routes package authority to the authored draft", () => {
        expect(plainConfigError("`policy` is package-owned; edit `.whipple/draft/package.json`")).toMatch(
            /package-owned/,
        );
    });
});

describe("ability preset matching", () => {
    it("ignores the optional abilities, so a new Chat only agent selects Chat only", () => {
        expect(presetAbilities(["question.ask"])).toEqual([]);
        expect(presetAbilities(["workspace.write", "tracker.file", "workspace.read", "question.ask"]))
            .toEqual(["workspace.read", "workspace.write"]);
    });

    it("keeps the optional abilities when a preset changes", () => {
        expect(optionalAbilities(["command.run", "tracker.file", "question.ask"]))
            .toEqual(["tracker.file", "question.ask"]);
    });
});

describe("preferred model choices", () => {
    const choice = (id: string, provider: string, label: string) => ({ id, provider, label, thinking: ["off"] });

    it("leads with the default row and lists each reachable model once", () => {
        expect(preferredModelChoices([
            choice("", "", "GPT-6.1 Sol (default)"),
            choice("gpt-6.1", "openai", "GPT-6.1 Sol"),
            choice("gpt-6.1", "openrouter", "GPT-6.1 Sol"),
            choice("claude-opus-5-5", "anthropic", "Claude Opus 5.5"),
        ], "")).toEqual([
            { value: "", label: "GPT-6.1 Sol (default)" },
            { value: "gpt-6.1", label: "GPT-6.1 Sol" },
            { value: "claude-opus-5-5", label: "Claude Opus 5.5" },
        ]);
    });

    it("keeps a saved model that is no longer reachable", () => {
        expect(preferredModelChoices([], "old-model")).toEqual([
            { value: "", label: "Default" },
            { value: "old-model", label: "old-model" },
        ]);
    });
});
