import { describe, expect, it } from "vitest";
import type { Page } from "@playwright/test";
import { hasProductionCredential } from "./authenticated-transport-proof";
import { installTransportFidelityGuards } from "./fidelity-guard";

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
