import { describe, expect, it } from "vitest";
import type { Page } from "@playwright/test";
import { hasProductionCredential } from "./authenticated-transport-proof";
import { installTransportFidelityGuards, installStandardFixtureGuards } from "./fidelity-guard";

function guardedPage() {
    const context = {
        route() {},
        routeFromHAR() {},
        routeWebSocket() {},
    };
    const page = {
        context: () => context,
        route() {},
        routeFromHAR() {},
        routeWebSocket() {},
    };
    installTransportFidelityGuards(page as unknown as Page, ["@transport", "@authenticated"]);
    return { page, context };
}

describe("transport fidelity guard", () => {
    it("rejects HTTP and WebSocket interception on both Playwright scopes", () => {
        const { page, context } = guardedPage();
        for (const [label, target] of [["page", page], ["browser context", context]] as const) {
            for (const method of ["route", "routeFromHAR", "routeWebSocket"] as const) {
                expect(() => target[method]()).toThrow(
                    `@transport @authenticated scenarios may not call ${label}.${method}()`,
                );
            }
        }
    });

    it("recognizes only the production session credential shapes", () => {
        expect(hasProductionCredential({ cookie: "theme=dark; gw_session=session-1" }))
            .toBe(true);
        expect(hasProductionCredential([{ name: "Authorization", value: "Bearer token-1" }]))
            .toBe(true);
        expect(hasProductionCredential({ cookie: "gw_session=", "x-actor": "owner" }))
            .toBe(false);
        expect(hasProductionCredential({ "x-actor": "owner" })).toBe(false);
    });
});


describe("standard fixture guard ordering", () => {
    function fixturePage() {
        const registrations: Array<{ matcher: (url: URL) => boolean; handler: (route: { abort(reason: string): Promise<void> }) => Promise<void> }> = [];
        const context = {
            async route(matcher: typeof registrations[number]["matcher"], handler: typeof registrations[number]["handler"]) { registrations.push({ matcher, handler }); },
            routeFromHAR() {}, routeWebSocket() {},
        };
        const page = { context: () => context, route() {}, routeFromHAR() {}, routeWebSocket() {} };
        return { page, context, registrations };
    }
    it("installs only Stripe denial before all six transport interception methods are sealed", async () => {
        const { page, context, registrations } = fixturePage();
        await installStandardFixtureGuards(page as unknown as Page, ["@transport", "@authenticated"]);
        expect(registrations).toHaveLength(1);
        expect(registrations[0].matcher(new URL("https://connect-js.stripe.com/v1.0/connect.js"))).toBe(true);
        expect(registrations[0].matcher(new URL("http://127.0.0.1:53717/projects"))).toBe(false);
        expect(registrations[0].matcher(new URL("https://stripe.com.example.test/"))).toBe(false);
        const aborts: string[] = [];
        await registrations[0].handler({ async abort(reason) { aborts.push(reason); } });
        expect(aborts).toEqual(["blockedbyclient"]);
        for (const [label, target] of [["page", page], ["browser context", context]] as const) {
            for (const method of ["route", "routeFromHAR", "routeWebSocket"] as const) {
                expect(() => (target[method] as () => void)()).toThrow(`@transport @authenticated scenarios may not call ${label}.${method}()`);
            }
        }
    });
    it("installs Stripe denial for untagged defaults without adding a transport seal", async () => {
        const { page, context, registrations } = fixturePage();
        await installStandardFixtureGuards(page as unknown as Page, []);
        expect(registrations).toHaveLength(1);
        for (const target of [context, page]) {
            for (const method of ["routeFromHAR", "routeWebSocket"] as const) {
                expect(() => target[method]()).not.toThrow();
            }
        }
    });
});
