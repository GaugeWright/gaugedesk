import { createComponent } from "solid-js";
import { render } from "solid-js/web";
import { afterEach, expect, it, vi } from "vitest";
import type { AccountTenant } from "@gaugewright/control-plane-client";
import { DeploymentPanel, type DeploymentPanelApi, type DeploymentSelection } from "./DeploymentPanel";

let dispose: (() => void) | undefined;
afterEach(() => { dispose?.(); document.body.replaceChildren(); });

const selection: DeploymentSelection = {
    projectId: "project", projectName: "Project", placementId: "panel" as DeploymentSelection["placementId"], archetypeName: "Panel",
    version: 1, deployments: [],
    profile: {
        panels: { components: ["gw-chat"], default_component: "gw-chat", attribution: "gauge_wright" },
        public_abilities: [], model: { pinned: "gpt-5-mini" }, audience_inputs: ["text"],
        initial_workspace: [], collection: null,
        retention: { idle_ttl_seconds: 86_400, absolute_ttl_seconds: 2_592_000, transcript_retained: true, workspace_retained: false },
    },
};
const owner: AccountTenant = {
    id: "account", displayName: "My account", role: "owner", personal: true, providerCommercial: false,
};

it("recovers the account list in place without losing the deployment draft or choosing its funding", async () => {
    let resolveRetry!: (tenants: AccountTenant[]) => void;
    const deploymentManagedTenants = vi.fn<NonNullable<DeploymentPanelApi["deploymentManagedTenants"]>>()
        .mockRejectedValueOnce(new TypeError("Failed to fetch"))
        .mockImplementationOnce(() => new Promise((resolve) => { resolveRetry = resolve; }));
    const onClose = vi.fn();
    const publishDeployment = vi.fn<DeploymentPanelApi["publishDeployment"]>();
    const host = document.createElement("div");
    document.body.append(host);
    dispose = render(() => createComponent(DeploymentPanel, {
        api: { deploymentManagedTenants, publishDeployment }, selection,
        defaultEdgeOrigin: "https://edge.example.com", defaultCredentialRef: "provider-key", onClose,
    }), host);
    await vi.waitFor(() => expect(host.textContent).toContain("The account service can't be reached right now."));
    expect(host.textContent).not.toContain("TypeError");
    const funding = host.querySelectorAll<HTMLInputElement>('input[name="pa-funding"]');
    expect(funding[0]!.disabled).toBe(true);
    expect(funding[0]!.title).not.toContain("You don't administer");
    expect(funding[1]!.checked).toBe(true);
    const origin = host.querySelector<HTMLInputElement>('input[aria-label="Website address"]')!;
    origin.value = "https://draft.example.com";
    origin.dispatchEvent(new Event("input", { bubbles: true }));
    const retry = Array.from(host.querySelectorAll("button")).find((button) => button.textContent === "Retry")!;
    retry.click();
    expect(retry.disabled).toBe(true);
    expect(host.textContent).toContain("Loading accounts…");
    expect(host.textContent).not.toContain("Try again in a minute.");
    retry.click();
    expect(deploymentManagedTenants).toHaveBeenCalledTimes(2);
    resolveRetry([owner, { ...owner, id: "member", role: "member" }]);
    await vi.waitFor(() => expect(funding[0]!.disabled).toBe(false));
    expect(host.textContent).not.toContain("The account service can't be reached");
    expect(funding[1]!.checked).toBe(true);
    expect(origin.value).toBe("https://draft.example.com");
    funding[0]!.click();
    const accounts = host.querySelector<HTMLSelectElement>("[data-deployment-funding] select")!;
    expect(Array.from(accounts.options).map((option) => option.value)).toEqual([owner.id]);
    expect(onClose).not.toHaveBeenCalled();
    expect(publishDeployment).not.toHaveBeenCalled();
});

it("lists the provider keys of the publisher deploying the placement signs with (DR-0453)", async () => {
    // A member of a shared project deploys its owner's Panel agent with the
    // owner's keys, which the Home lists only for a named placement.
    const listPublicCredentials = vi.fn<NonNullable<DeploymentPanelApi["listPublicCredentials"]>>(async () => []);
    const host = document.createElement("div");
    document.body.append(host);
    dispose = render(() => createComponent(DeploymentPanel, {
        api: { publishDeployment: vi.fn<DeploymentPanelApi["publishDeployment"]>(), listPublicCredentials },
        selection,
        defaultEdgeOrigin: "https://edge.example.com", defaultCredentialRef: "provider-key", onClose: vi.fn(),
    }), host);
    await vi.waitFor(() => expect(listPublicCredentials).toHaveBeenCalled());
    expect(listPublicCredentials).toHaveBeenCalledWith("https://edge.example.com", selection.placementId);
});
