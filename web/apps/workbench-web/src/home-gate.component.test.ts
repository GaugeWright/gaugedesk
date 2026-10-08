// Account work does not wait for a Home (DR-0260, DR-0463). These mount the
// real workbench as desk.gaugewright.com runs it — the account/Home split on —
// against an account service that never answers, so "Finding your Home…" stands
// until discovery's own ceiling turns it into the failure card. The GaugeApps
// host is a stand-in: what is under test is whether the workbench lets the
// GaugeApp the person opened through its Home gate, not the GaugeApp itself.
import { createComponent, createSignal } from "solid-js";
import { render } from "solid-js/web";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import type { WorkbenchGaugeApps } from "./App";
import { HOME_DISCOVERY_SLOW_MS, HOME_DISCOVERY_TIMEOUT_MS } from "./home-bootstrap";

let dispose: (() => void) | undefined;

beforeEach(() => {
    vi.stubEnv("VITE_HOME_SPLIT", "true");
    vi.stubGlobal("fetch", vi.fn(() => new Promise<Response>(() => undefined)));
});

afterEach(() => {
    dispose?.();
    dispose = undefined;
    document.body.replaceChildren();
    vi.useRealTimers();
    vi.unstubAllEnvs();
    vi.unstubAllGlobals();
    vi.resetModules();
});

/** The Account Settings GaugeApp, standing in for the enterprise host's. */
function accountSettings(open: boolean) {
    const [active, setActive] = createSignal(open);
    const pages = vi.fn(() => {
        const heading = document.createElement("h1");
        heading.textContent = "Trusted Devices";
        return heading;
    });
    const apps: WorkbenchGaugeApps = {
        active,
        selectedTenant: () => null,
        accountActions: () => [{ id: "account", label: "Account Settings", open: () => setActive(true) }],
        accountIdentity: () => ({ name: "Canary", email: "canary@example.test" }),
        organizationSelector: () => document.createElement("div"),
        chat: () => document.createElement("div"),
        content: pages,
        menu: () => document.createElement("div"),
        titles: () => ({ chat: "Account Settings agent", content: "Account Settings", files: "Account Settings pages" }),
        onNewChat: () => undefined,
        close: () => setActive(false),
    };
    return { apps, pages };
}

async function mount(apps: WorkbenchGaugeApps): Promise<HTMLElement> {
    // The workbench module builds its control plane as it loads, reading the
    // split from the environment, so it is loaded afresh under the stub.
    const { App } = await import("./App");
    vi.useFakeTimers();
    const host = document.createElement("div");
    document.body.append(host);
    dispose = render(() => createComponent(App, { gaugeApps: apps }), host);
    await vi.advanceTimersByTimeAsync(0);
    return host;
}

const surface = (host: HTMLElement) => host.querySelector<HTMLElement>("[data-no-home-account-surface]");
const finding = (host: HTMLElement) => host.querySelector<HTMLElement>("[data-home-loading]");
const failed = (host: HTMLElement) => host.querySelector<HTMLElement>("[data-home-error]");

it("opens Account Settings at Trusted Devices while desk is still finding the Home", { timeout: 60_000 }, async () => {
    const { apps, pages } = accountSettings(true);
    const host = await mount(apps);

    // A Home found at once goes straight to the workbench, so nothing is
    // flashed before discovery has been slow.
    expect(finding(host)?.textContent).toContain("Finding your Home…");
    expect(surface(host)).toBeNull();

    await vi.advanceTimersByTimeAsync(HOME_DISCOVERY_SLOW_MS);
    const opened = surface(host);
    expect(opened).not.toBeNull();
    expect(opened?.querySelector(".account-surface-title")?.textContent).toBe("Account Settings");
    expect(opened?.querySelector(".account-surface-content h1")?.textContent).toBe("Trusted Devices");
    expect(finding(host)).toBeNull();

    // Discovery giving up while the person is on the page does not take it
    // away or rebuild it.
    await vi.advanceTimersByTimeAsync(HOME_DISCOVERY_TIMEOUT_MS);
    expect(failed(host)).toBeNull();
    expect(surface(host)).toBe(opened);
    expect(pages).toHaveBeenCalledOnce();

    // Back returns to whichever card desk is still showing.
    (opened?.querySelector("[data-account-surface-close]") as HTMLButtonElement).click();
    await vi.advanceTimersByTimeAsync(0);
    expect(surface(host)).toBeNull();
    expect(failed(host)).not.toBeNull();
});

it("offers Account settings on a slow finding card and on the failure card, and opens it from both", { timeout: 60_000 }, async () => {
    const { apps } = accountSettings(false);
    const host = await mount(apps);
    const offer = (card: HTMLElement | null) => card?.querySelector<HTMLButtonElement>("[data-home-account-settings]") ?? null;

    expect(offer(finding(host))).toBeNull();
    await vi.advanceTimersByTimeAsync(HOME_DISCOVERY_SLOW_MS);
    offer(finding(host))!.click();
    await vi.advanceTimersByTimeAsync(0);
    expect(surface(host)?.querySelector(".account-surface-content h1")?.textContent).toBe("Trusted Devices");
    expect(finding(host)).toBeNull();

    (surface(host)?.querySelector("[data-account-surface-close]") as HTMLButtonElement).click();
    await vi.advanceTimersByTimeAsync(HOME_DISCOVERY_TIMEOUT_MS);
    expect(surface(host)).toBeNull();
    const card = failed(host);
    expect(card).not.toBeNull();

    // Before DR-0463 this changed the address and showed nothing.
    offer(card)!.click();
    await vi.advanceTimersByTimeAsync(0);
    expect(surface(host)?.querySelector(".account-surface-content h1")?.textContent).toBe("Trusted Devices");
    expect(failed(host)).toBeNull();
});
