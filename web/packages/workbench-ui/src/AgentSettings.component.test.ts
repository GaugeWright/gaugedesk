import { createComponent } from "solid-js";
import { render } from "solid-js/web";
import { afterEach, expect, it, vi } from "vitest";
import type { AgentAbility, ArchetypeId, PanelPublicProfile } from "@gaugewright/control-plane-client";
import { AgentSettings, type AgentSettingsApi } from "./AgentSettings";
import { BEYOND_AGENT_ABILITIES } from "./agent-controls";

let dispose: (() => void) | undefined;
afterEach(() => { dispose?.(); document.body.replaceChildren(); });

const profile: PanelPublicProfile = {
    panels: { components: ["gw-chat"], default_component: "gw-chat", attribution: "gauge_wright" },
    public_abilities: [], model: {}, audience_inputs: ["text"],
    initial_workspace: [], collection: null,
    retention: { idle_ttl_seconds: 86_400, absolute_ttl_seconds: 2_592_000, transcript_retained: true, workspace_retained: false },
};

function option(host: HTMLElement, group: string, label: string): HTMLInputElement {
    const input = Array.from(host.querySelectorAll<HTMLInputElement>(`input[name="${group}"]`))
        .find((candidate) => candidate.closest("label")?.querySelector("strong")?.textContent === label);
    if (!input) throw new Error(`no ${label} in ${group}`);
    return input;
}

function choose(input: HTMLInputElement) {
    input.checked = true;
    input.dispatchEvent(new Event("change", { bubbles: true }));
}

it("offers a visitor ability only once the agent has it, and saves the agent's first", async () => {
    const calls: string[] = [];
    const api: AgentSettingsApi = {
        getArchetypeConfig: vi.fn(async () => "{}"),
        setArchetypeConfig: vi.fn(async () => { calls.push("config"); }),
        getArchetypeAbilities: vi.fn(async (): Promise<AgentAbility[]> => []),
        setArchetypeAbilities: vi.fn(async () => { calls.push("abilities"); }),
        getPanelProfile: vi.fn(async () => profile),
        setPanelProfile: vi.fn(async (_id, next) => { calls.push("panel"); return next; }),
    };
    const host = document.createElement("div");
    document.body.append(host);
    dispose = render(() => createComponent(AgentSettings, {
        api, id: "agent-1" as ArchetypeId, name: "Panel", kind: "panel", onClose: () => {},
    }), host);
    await vi.waitFor(() => expect(host.querySelector("[data-panel-public-profile]")).not.toBeNull());

    // A Chat only agent cannot offer visitors file reading, and says why.
    const visitorRead = option(host, "panel-public-abilities", "Read workspace");
    expect(visitorRead.disabled).toBe(true);
    expect(visitorRead.closest("label")!.textContent).toContain(BEYOND_AGENT_ABILITIES);
    expect(option(host, "panel-public-abilities", "Chat only").closest("label")!.textContent)
        .not.toContain(BEYOND_AGENT_ABILITIES);

    // Once the agent itself reads the workspace, visitors can be given it too.
    choose(option(host, "agent-abilities", "Read workspace"));
    await vi.waitFor(() => expect(option(host, "panel-public-abilities", "Read workspace").disabled).toBe(false));
    choose(option(host, "panel-public-abilities", "Read workspace"));

    host.querySelector<HTMLButtonElement>("[data-settings-save]")!.click();
    await vi.waitFor(() => expect(calls).toContain("config"));
    // The Home refuses a profile beyond the agent's saved abilities, so the
    // agent's widened abilities are written before the profile that needs them.
    expect(calls).toEqual(["abilities", "panel", "config"]);
    expect(api.setPanelProfile).toHaveBeenCalledWith("agent-1",
        expect.objectContaining({ public_abilities: ["workspace.read"] }));
});
