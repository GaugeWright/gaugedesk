import { HomeTunnelError } from "@gaugewright/control-plane-client";
import { describe, expect, it } from "vitest";
import {
    accountWorkReplacesHomeGate,
    captureHomeDiscovery,
    isHomeAuthenticationFailure,
    isRelayClosedRefusal,
} from "./home-bootstrap";

describe("hosted Home bootstrap failure", () => {
    it("recognizes an expired or absent Hub session", () => {
        expect(
            isHomeAuthenticationFailure(
                new Error("GET /account/homes: 401 authenticate to access your account"),
            ),
        ).toBe(true);
    });

    it("keeps availability failures distinct from authentication", () => {
        expect(isHomeAuthenticationFailure(new Error("GET /account/homes: 503 unavailable"))).toBe(
            false,
        );
        expect(isHomeAuthenticationFailure(null)).toBe(false);
    });

    it("resolves an authentication rejection into renderable UI state", async () => {
        await expect(
            captureHomeDiscovery(async () => {
                throw new Error("GET /account/homes: 401 authenticate to access your account");
            }),
        ).resolves.toEqual({
            kind: "failure",
            authentication: true,
            relayClosed: false,
            homeConnection: false,
            message: "GET /account/homes: 401 authenticate to access your account",
        });
    });

    it("passes a successful Home result through unchanged", async () => {
        const result = { kind: "connected" as const, homeId: "home:cloud:test" };
        await expect(captureHomeDiscovery(async () => result)).resolves.toBe(result);
    });

    it("ends a discovery that never settles as a failure the Retry card can start again", async () => {
        const result = await captureHomeDiscovery(() => new Promise<never>(() => {}), 10);
        expect(result).toMatchObject({ kind: "failure", authentication: false });
    });

    it("tells a Home that cannot act for this person apart from an outage", async () => {
        // What a desktop Home's relay router answers its owner while GaugeDesk
        // there is not signed in as them (DR-0206). It must not read as "the
        // account service could not be reached", and it is not this page's
        // sign-in failing either.
        const words = "this computer is not signed in to GaugeDesk as you; "
            + "sign in on the computer itself";
        // The tunnel reports the raw body; the direct route, which the phone
        // uses to reach the same router, reports only its `error` text.
        const tunnelled = `POST /home/admissions: 403 ${JSON.stringify({ error: words })}`;
        const direct = `POST /home/admissions: 403 ${words}`;
        for (const refusal of [tunnelled, direct]) {
            expect(isRelayClosedRefusal(new Error(refusal))).toBe(true);
            await expect(captureHomeDiscovery(async () => { throw new Error(refusal); }))
                .resolves.toMatchObject({ kind: "failure", authentication: false, relayClosed: true });
        }
    });

    it("does not take another refusal for a closed relay", () => {
        expect(isRelayClosedRefusal(new Error("POST /home/admissions: 403 not an active member")))
            .toBe(false);
        expect(isRelayClosedRefusal(
            new Error("GET /x: 404 this computer is not signed in to GaugeDesk as you"),
        )).toBe(false);
        expect(isRelayClosedRefusal(null)).toBe(false);
    });
    it("keeps relay capacity and connection failures separate from account discovery", async () => {
        for (const message of ["relay connection capacity reached", "the Home tunnel could not open", "the Home tunnel timed out"]) {
            const result = await captureHomeDiscovery(async () => { throw new HomeTunnelError(message); });
            expect(result).toMatchObject({ kind: "failure", homeConnection: true, authentication: false });
        }
        const result = await captureHomeDiscovery(async () => { throw new Error("GET /account/homes: 503 unavailable"); });
        expect(result).toMatchObject({ kind: "failure", homeConnection: false });
    });

});

describe("account work in place of the Home gate", () => {
    const gate = { finding: false, findingSlow: false, failed: false, noHome: false };

    it("shows an open GaugeApp while a slow discovery is still finding the Home", () => {
        expect(accountWorkReplacesHomeGate(true, { ...gate, finding: true, findingSlow: true })).toBe(true);
    });

    it("keeps the finding card while discovery has not yet been slow", () => {
        expect(accountWorkReplacesHomeGate(true, { ...gate, finding: true })).toBe(false);
    });

    it("shows an open GaugeApp in place of the failure card and of no Home", () => {
        expect(accountWorkReplacesHomeGate(true, { ...gate, failed: true })).toBe(true);
        expect(accountWorkReplacesHomeGate(true, { ...gate, noHome: true })).toBe(true);
    });

    it("leaves a found Home to the workbench, and every gate alone when nothing is open", () => {
        expect(accountWorkReplacesHomeGate(true, gate)).toBe(false);
        for (const state of [
            { ...gate, finding: true, findingSlow: true },
            { ...gate, failed: true },
            { ...gate, noHome: true },
        ]) {
            expect(accountWorkReplacesHomeGate(false, state)).toBe(false);
        }
    });
});
