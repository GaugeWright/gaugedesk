import { createComponent, createSignal } from "solid-js";
import { render } from "solid-js/web";
import { afterEach, expect, it, vi } from "vitest";
import { SettingsMenu, type SettingsMenuApi } from "./OpenSettingsMenu";
let dispose: (() => void) | undefined;
afterEach(() => { dispose?.(); document.body.replaceChildren(); });
it("switches between a signed-in account and the named local account", () => {
    const host = document.createElement("div");
    document.body.append(host);
    const [local, setLocal] = createSignal(false);
    const useLocal = vi.fn(() => setLocal(true));
    dispose = render(() => createComponent(SettingsMenu, {
        api: {} as SettingsMenuApi,
        identity: () => ({ name: local() ? "Local account" : "Alice" }),
        localAccount: local,
        gaugeAppActions: () => [],
        accountChoices: () => [{ person: "alice", label: "Alice", selected: !local(), expired: false }],
        onUseLocal: useLocal,
        onSignIn: vi.fn(), onSignOut: vi.fn(),
    }), host);
    const click = (selector: string) => (host.querySelector(selector) as HTMLButtonElement).click();
    click("[data-account-menu-trigger]");
    expect(host.querySelector('[data-account-menu-item="sign-out"]')).not.toBeNull();
    click('[data-account-menu-item="change-account"]');
    expect(host.querySelector('[data-account-menu-item="use-local"]')?.textContent).toContain("Local account");
    click('[data-account-menu-item="use-local"]');
    expect(useLocal).toHaveBeenCalledOnce();
    expect(host.querySelector('[data-account-menu-item="use-local"]')?.hasAttribute("disabled")).toBe(true);
    click('[data-account-menu-item="account-picker-back"]');
    expect(host.querySelector("[data-account-menu-trigger]")?.textContent).toContain("Local account");
    expect(host.querySelector('[data-account-menu-item="sign-in"]')).not.toBeNull();
    expect(host.querySelector('[data-account-menu-item="sign-out"]')).toBeNull();
});
it("keeps the invite-accepting Devices modal reachable beside GaugeApp pages", () => {
    const host = document.createElement("div");
    document.body.append(host);
    const openAccount = vi.fn();
    dispose = render(() => createComponent(SettingsMenu, {
        api: { desktopFederationAvailable: false } as SettingsMenuApi,
        identity: () => ({ name: "Alice" }),
        gaugeAppActions: () => [{ id: "account", label: "Account Settings", open: openAccount }],
        onSignIn: vi.fn(), onSignOut: vi.fn(),
    }), host);
    const click = (selector: string) => (host.querySelector(selector) as HTMLButtonElement).click();
    click("[data-account-menu-trigger]");
    expect(host.querySelector('[data-account-menu-item="gaugeapp-account"]')).not.toBeNull();
    expect(host.querySelector('[data-account-menu-item="devices"]')?.textContent).toContain("Add a device or party");
    expect(host.querySelector("[data-devices-modal]")).toBeNull();
    click('[data-account-menu-item="devices"]');
    expect(host.querySelector("[data-devices-modal]")).not.toBeNull();
    expect(host.textContent).toContain("Have an invite link?");
});
