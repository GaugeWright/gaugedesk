/**
 * What the owner reads and what the contract carries (PANEL-12).
 *
 * The Panel-agent surfaces show plain names and dollars, hours, and megabytes;
 * the contract and the publisher carry `gw-chat`, cents, seconds, and bytes.
 * These pin each translation, so a figure the owner enters is the figure that
 * publishes, and so a collecting contract the editor offers is one the Home
 * will accept.
 */

import { describe, expect, it } from "vitest";
import type { PanelPublicProfile } from "@gaugewright/control-plane-client";
import {
    centsFromDollars,
    collectionPathProblem,
    contractFacts,
    DEFAULT_COLLECTED_PATH,
    dollarsFromCents,
    durationParts,
    formatCents,
    formatDuration,
    panelModelChoices,
    PROVIDER_CHOICES,
    secondsFrom,
    withProvider,
} from "./panel-agent-presentation";

const PROFILE: PanelPublicProfile = {
    panels: { components: ["gw-chat", "gw-files"], default_component: "gw-chat", attribution: "gauge_wright" },
    public_abilities: ["workspace.read", "workspace.write"],
    provider: { provider: "openai", model: "gpt-5-mini", base_url: "https://api.openai.com", credential_class: "openai-api-key" },
    audience_inputs: ["text"],
    initial_workspace: [{ path: "welcome.md", media_type: "text/markdown", sha256: "0".repeat(64), bytes: [1, 2, 3] }],
    retention: { idle_ttl_seconds: 86_400, absolute_ttl_seconds: 2_592_000, transcript_retained: true, workspace_retained: false },
    collection: null,
};

describe("money", () => {
    it("publishes the cents the owner typed in dollars", () => {
        expect(centsFromDollars("10")).toBe(1_000);
        expect(centsFromDollars("$12.84")).toBe(1_284);
        expect(centsFromDollars("0.05")).toBe(5);
        expect(centsFromDollars(".5")).toBe(50);
        // 0.29 * 100 is 28.999… in binary; the owner typed 29 cents.
        expect(centsFromDollars("0.29")).toBe(29);
    });

    it("refuses what is not an amount rather than publishing a guess", () => {
        expect(centsFromDollars("")).toBeNull();
        expect(centsFromDollars("ten")).toBeNull();
        expect(centsFromDollars("1.005")).toBeNull();
        expect(centsFromDollars("-1")).toBeNull();
    });

    it("shows a stored limit back as the dollars it was entered as", () => {
        expect(dollarsFromCents(1_000)).toBe("10");
        expect(dollarsFromCents(5)).toBe("0.05");
        expect(centsFromDollars(dollarsFromCents(1_284))).toBe(1_284);
        expect(formatCents(1_284)).toBe("$12.84");
    });
});

describe("durations", () => {
    it("reads whole days as days and anything else as hours", () => {
        expect(durationParts(86_400)).toEqual({ value: 1, unit: "days" });
        expect(durationParts(2_592_000)).toEqual({ value: 30, unit: "days" });
        expect(durationParts(7_200)).toEqual({ value: 2, unit: "hours" });
        expect(durationParts(129_600)).toEqual({ value: 36, unit: "hours" });
    });

    it("round-trips what it shows", () => {
        for (const seconds of [3_600, 7_200, 86_400, 129_600, 604_800]) {
            const { value, unit } = durationParts(seconds);
            expect(secondsFrom(value, unit)).toBe(seconds);
        }
    });

    it("says a duration in words", () => {
        expect(formatDuration(86_400)).toBe("1 day");
        expect(formatDuration(2_592_000)).toBe("30 days");
        expect(formatDuration(3_600)).toBe("1 hour");
        expect(formatDuration(129_600)).toBe("36 hours");
        expect(formatDuration(2_700)).toBe("45 minutes");
    });
});

describe("collection paths", () => {
    it("starts a new collecting contract with a path the Home accepts", () => {
        expect(collectionPathProblem(DEFAULT_COLLECTED_PATH)).toBe("");
    });

    it("accepts a file or a folder's direct files inside artifacts/", () => {
        expect(collectionPathProblem("artifacts/brief.pdf")).toBe("");
        expect(collectionPathProblem("artifacts/reports/*")).toBe("");
    });

    it("refuses what validate_panel_profile refuses, saying why", () => {
        // The old default. The Home has always refused it.
        expect(collectionPathProblem("outputs/**")).toMatch(/inside artifacts\//);
        expect(collectionPathProblem("artifacts/**")).toMatch(/can't use \*\*/);
        expect(collectionPathProblem("artifacts/../secrets")).toMatch(/isn't a file or folder path/);
        expect(collectionPathProblem("artifacts//x")).toMatch(/isn't a file or folder path/);
    });
});

describe("switching provider", () => {
    it("carries the provider's own defaults with it", () => {
        expect(withProvider(PROFILE.provider, "anthropic")).toEqual({
            provider: "anthropic",
            model: "claude-sonnet-4-6",
            base_url: "https://api.anthropic.com",
            credential_class: "anthropic-api-key",
        });
    });

    it("leaves a base URL or credential class the owner set by hand", () => {
        const custom = { ...PROFILE.provider, base_url: "https://gateway.example.com" };
        const switched = withProvider(custom, "anthropic");
        expect(switched.base_url).toBe("https://gateway.example.com");
        expect(switched.credential_class).toBe("openai-api-key");
    });
});

describe("choosing a model", () => {
    const ids = (provider: string, current?: string) =>
        panelModelChoices(provider, current).map((choice) => choice.value);

    it("offers every model the catalog lists for the provider", () => {
        // Containment, not an exact list: the catalog grows, and this follows it.
        expect(ids("openai")).toEqual(expect.arrayContaining([
            "gpt-5.4", "gpt-5.4-mini", "gpt-5.4-nano", "gpt-5.4-pro", "gpt-5.5", "gpt-5.5-pro",
            "gpt-5.6-sol", "gpt-5.6-terra", "gpt-5.6-luna",
        ]));
        expect(ids("anthropic")).toContain("claude-opus-4-7");
        expect(ids("anthropic")).toContain("claude-sonnet-4-6");
        expect(ids("anthropic")).toContain("claude-haiku-4-5");
        // The moving alias stands for its date-pinned snapshot, as in the chat picker.
        expect(ids("anthropic")).not.toContain("claude-haiku-4-5-20251001");
    });

    it("keeps a model the profile already names, even one the catalog lacks", () => {
        const choices = ids("openai", "gpt-5-mini");
        expect(choices).toContain("gpt-5-mini");
        expect(choices).toContain("gpt-5.5");
        expect(ids("openai", "gpt-5.5").filter((id) => id === "gpt-5.5")).toHaveLength(1);
    });

    it("lands a provider switch on a model that provider offers", () => {
        for (const choice of PROVIDER_CHOICES) {
            expect(ids(choice.value)).toContain(choice.defaultModel);
        }
    });
});

describe("the contract, read back", () => {
    it("names what a deployment gives visitors in plain words", () => {
        expect(contractFacts(PROFILE)).toEqual([
            { label: "Visitors see", value: "Chat and Files" },
            { label: "The agent can", value: "read files, create and edit files" },
            { label: "Model", value: "OpenAI · gpt-5-mini" },
            { label: "Starting files", value: "welcome.md" },
            { label: "History", value: "Resumable for 1 day after the last message, deleted after at most 30 days; keeps the transcript" },
            { label: "Results", value: "Not collected" },
        ]);
    });

    it("says a chat-only agent only chats, and what a collecting one sends", () => {
        const facts = contractFacts({
            ...PROFILE,
            public_abilities: [],
            collection: {
                exportable_paths: ["artifacts/*"],
                transcript_eligible: true,
                schema_ref: "gaugewright.panel-output/v1",
                recipient_class: "project",
                max_artifact_bytes: 1_048_576,
            },
        });
        expect(facts.find((fact) => fact.label === "The agent can")?.value).toBe("only chat");
        expect(facts.find((fact) => fact.label === "Results")?.value).toBe("Sent to the project Inbox: artifacts/* and the transcript");
    });
});
