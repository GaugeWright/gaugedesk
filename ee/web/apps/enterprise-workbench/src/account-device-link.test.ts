import { describe, expect, it } from "vitest";
import { deviceLinkBrowserUrl, parseDeviceLinkInvitation } from "./account-device-link";

describe("trusted-device QR invitations", () => {
    it("parses the server-owned native payload", () => {
        expect(parseDeviceLinkInvitation(
            "gaugewright://auth/device-link?id=link-1&code=ABCD-EF12",
        )).toEqual({ id: "link-1", code: "ABCD-EF12" });
    });

    it("lands a QR on the receiving Desk and retains the exact invitation", () => {
        const href = deviceLinkBrowserUrl(
            { id: "link-1", code: "ABCD-EF12" },
            "https://desk.gw.localhost:7523/?composition=gaugeapps",
        );
        expect(href).toBe(
            "https://desk.gw.localhost:7523/?gaugeapp=account-settings&page=trusted-devices&device_link_id=link-1&device_link_code=ABCD-EF12",
        );
        expect(parseDeviceLinkInvitation(href)).toEqual({ id: "link-1", code: "ABCD-EF12" });
    });

    it("uses the public Desk for a native sender and rejects unrelated links", () => {
        expect(deviceLinkBrowserUrl(
            { id: "link-2", code: "EFGH-3456" },
            "tauri://localhost/",
        )).toBe(
            "https://desk.gaugewright.com/?gaugeapp=account-settings&page=trusted-devices&device_link_id=link-2&device_link_code=EFGH-3456",
        );
        expect(parseDeviceLinkInvitation("gaugewright://invite?d=unrelated")).toBeNull();
        expect(parseDeviceLinkInvitation("https://example.com/?device_link_id=x&device_link_code=y")).toBeNull();
    });
});
