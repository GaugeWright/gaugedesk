import { createComponent } from "solid-js";
import { render } from "solid-js/web";
import { afterEach, expect, it, vi } from "vitest";
import { SettingsPanel, type SettingsPanelApi } from "./SettingsPanel";
import { DevicesModal, type DevicesModalApi } from "./DevicesModal";

let dispose: (() => void) | undefined;
afterEach(() => { dispose?.(); document.body.replaceChildren(); });

it.each([false, true])("Settings reads desktop jurisdictions only when available=%s", async (available) => {
    const host = document.createElement("div");
    document.body.append(host);
    const listPeers = vi.fn(async () => []);
    const hubSessionStatus = vi.fn(async () => null);
    const accountDevices = vi.fn(async () => []);
    const api = new Proxy({} as SettingsPanelApi, {
        get: (_target, property) => {
            if (property === "desktopFederationAvailable" || property === "desktopSessionAvailable") return available;
            if (property === "listPeers") return listPeers;
            if (property === "hubSessionStatus") return hubSessionStatus;
            if (property === "accountDevices") return accountDevices;
            if (property === "accountSignInMethod") return async () => null;
            if (property === "accountManagedInference") return async () => null;
            return async () => [];
        },
    });
    dispose = render(() => createComponent(SettingsPanel, {
        api, onEnrollDevice: vi.fn(), onPairParty: vi.fn(), onClose: vi.fn(), initialRoom: "devices",
    }), host);
    await vi.waitFor(() => expect(accountDevices).toHaveBeenCalledOnce());
    expect(listPeers).toHaveBeenCalledTimes(available ? 1 : 0);
    expect(hubSessionStatus).toHaveBeenCalledTimes(available ? 1 : 0);
});

it.each([false, true])("Devices reads desktop peers only when available=%s", async (available) => {
    const host = document.createElement("div");
    document.body.append(host);
    const listPeers = vi.fn(async () => []);
    const handoffIncoming = vi.fn(async () => []);
    const api = new Proxy({} as DevicesModalApi, {
        get: (_target, property) => {
            if (property === "desktopFederationAvailable") return available;
            if (property === "listPeers") return listPeers;
            if (property === "handoffIncoming") return handoffIncoming;
            return async () => [];
        },
    });
    dispose = render(() => createComponent(DevicesModal, { api, onClose: vi.fn() }), host);
    await vi.waitFor(() => expect(handoffIncoming).toHaveBeenCalledOnce());
    expect(listPeers).toHaveBeenCalledTimes(available ? 1 : 0);
});
