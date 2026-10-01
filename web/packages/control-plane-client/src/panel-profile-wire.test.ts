import { describe, expect, it } from "vitest";
import { panelProfileFromWire, panelProfileToWire } from "./panel-profile-wire";

const base = {
    panels: { components: ["gw-chat"], default_component: "gw-chat", attribution: "gauge_wright" },
    public_abilities: [],
    audience_inputs: ["text"],
    initial_workspace: [],
    retention: { idle_ttl_seconds: 86_400, absolute_ttl_seconds: 2_592_000, transcript_retained: true, workspace_retained: true },
    collection: null,
};

/** The web client is served to Homes of every version at once (DR-0272). */
describe("Panel profile wire shape", () => {
    it("reads a current Home's model and writes it back unchanged", () => {
        const profile = panelProfileFromWire({ ...base, model: { pinned: "gpt-5.5" } });
        expect(profile.model).toEqual({ pinned: "gpt-5.5" });
        expect(profile.legacyProvider).toBeUndefined();
        expect(panelProfileToWire(profile)).toEqual({ ...base, model: { pinned: "gpt-5.5" } });
    });

    it("reads an older Home's untouched default posture as unpinned", () => {
        const profile = panelProfileFromWire({
            ...base,
            provider: { provider: "openai", model: "gpt-5-mini", base_url: "https://api.openai.com", credential_class: "openai-api-key" },
        });
        expect(profile.model).toEqual({});
    });

    it("reads an older Home's chosen posture as a pin and writes back the shape it accepts", () => {
        const provider = {
            provider: "cloudflare-ai-gateway",
            model: "gpt-5.6-terra",
            base_url: "https://gateway.ai.cloudflare.com/v1/a/g/openai",
            credential_class: "managed-openai",
            max_output_tokens: 4096,
        };
        const profile = panelProfileFromWire({ ...base, provider });
        expect(profile.model).toEqual({ pinned: "gpt-5.6-terra", max_output_tokens: 4096 });
        const wire = panelProfileToWire({ ...profile, model: { ...profile.model, pinned: "gpt-5.5" } }) as Record<string, unknown>;
        expect(wire.model).toBeUndefined();
        expect(wire.legacyProvider).toBeUndefined();
        expect(wire.provider).toEqual({ ...provider, model: "gpt-5.5" });
    });
});
