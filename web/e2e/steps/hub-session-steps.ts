/**
 * Desktop account sign-in journey steps (LOGIN-5, ADR 0123): the native
 * device handoff against the stand-in Hub (`e2e/account-hub.sh`). UI where
 * the journey has a surface (the account panel), the control-plane API where
 * the mechanism has none (expiry extension across refreshes).
 */

import { expect } from "@playwright/test";
import { createBdd } from "playwright-bdd";
import { aliceCP, hubURL } from "../ports.mjs";

const { When, Then } = createBdd();

async function sessionExpires(page: import("@playwright/test").Page): Promise<number> {
    const response = await page.request.get(`${aliceCP}/account/hub-session`);
    expect(response.status()).toBe(200);
    const body = (await response.json()) as { expires?: number };
    return body.expires ?? 0;
}

Then("the GaugeWright account section offers sign-in", async ({ page }) => {
    await expect(page.locator("[data-hub-session-signin]")).toBeVisible();
});

When("I begin GaugeWright sign-in", async ({ page }) => {
    // Starting mints and holds the verifier in the control plane; the button
    // also opens the (stand-in) Hub login URL in a new tab, which this
    // headless journey simply ignores — the return arrives as a deep link.
    await page.locator("[data-hub-session-signin]").click();
});

When("the OS delivers the sign-in return {string}", async ({ page }, url: string) => {
    // The Tauri shell forwards OS deep links as this DOM event (FED-7); the
    // web client posts only the one-time code to the control plane. Delivery
    // races the start request that minted the pending verifier, so the poll
    // re-dispatches: a too-early delivery finds no pending sign-in and is
    // refused without side effects.
    await expect
        .poll(async () => {
            await page.evaluate((detail) => {
                window.dispatchEvent(new CustomEvent("gw-deep-link", { detail }));
            }, url);
            const response = await page.request.get(`${aliceCP}/account/hub-session`);
            const body = (await response.json()) as { linked?: boolean };
            return body.linked === true;
        })
        .toBe(true);
});

Then("the account section shows me signed in as {string}", async ({ page }, person: string) => {
    // Reopen the panel so it reads the fresh server truth.
    await page.getByRole("button", { name: "close", exact: true }).click();
    await page.locator("[data-settings]").click();
    await page.locator("[data-settings-account]").click();
    await expect(page.locator("[data-hub-session-state='linked']")).toBeVisible();
    await expect(page.locator("[data-hub-session]")).toContainText(person);
});

Then("the session refresh extends the session", async ({ page }) => {
    // Every status read inside the expiry window refreshes at the Hub, whose
    // stand-in advances exp monotonically — so a later read reports more life.
    const first = await sessionExpires(page);
    await expect.poll(() => sessionExpires(page)).toBeGreaterThan(first);
});

Then(
    "my account reach lists home {string} and project {string}",
    async ({ page }, homeId: string, project: string) => {
        const response = await page.request.get(`${aliceCP}/account/hub-session/reach`);
        expect(response.status()).toBe(200);
        const body = (await response.json()) as {
            homes?: { homes?: { id?: string }[] };
            routes?: { routes?: { project?: string }[] };
        };
        expect((body.homes?.homes ?? []).map((home) => home.id)).toContain(homeId);
        expect((body.routes?.routes ?? []).map((route) => route.project)).toContain(project);
    },
);

When("the Hub revokes this device", async ({ page }) => {
    const response = await page.request.post(`${hubURL}/test/revoke`);
    expect(response.status()).toBe(204);
});

Then("the session refresh no longer extends the session", async ({ page }) => {
    // The device is revoked at the Hub: refresh is refused, so repeated reads
    // stop extending the session (INV-18 — future use stops, history stays).
    const first = await sessionExpires(page);
    await sessionExpires(page);
    await sessionExpires(page);
    expect(await sessionExpires(page)).toBe(first);
});

When("I sign out of my GaugeWright account", async ({ page }) => {
    await page.locator("[data-hub-session-signout]").click();
});
