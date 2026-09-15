/**
 * Desktop account sign-in journey steps (LOGIN-5, ADR 0123): the native
 * device handoff against the stand-in Hub (`e2e/account-hub.sh`). UI where
 * the journey has a surface (the account panel), the control-plane API where
 * the mechanism has none (server-directed renewal scheduling).
 */

import { expect } from "@playwright/test";
import { createBdd } from "playwright-bdd";
import { aliceCP, hubURL } from "../ports.mjs";
import { openAccountMenu } from "./settings-nav";

const { When, Then } = createBdd();

async function sessionRefreshAfter(page: import("@playwright/test").Page): Promise<number> {
    const response = await page.request.get(`${aliceCP}/account/hub-session`);
    expect(response.status()).toBe(200);
    const body = (await response.json()) as { refresh_after?: number };
    return body.refresh_after ?? 0;
}

Then("the GaugeWright account section offers sign-in", async ({ page }) => {
    const menu = page.locator("[data-account-menu]");
    if (!await menu.isVisible()) await openAccountMenu(page);
    await expect(page.locator('[data-account-menu-item="sign-in"]')).toBeVisible();
});

When("I begin GaugeWright sign-in", async ({ page }) => {
    // Starting mints and holds the verifier in the control plane; the button
    // also opens the (stand-in) Hub login URL in a new tab, which this
    // headless journey simply ignores — the return arrives as a deep link.
    await page.locator('[data-account-menu-item="sign-in"]').click();
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
    // Native custody changed outside the webview. The shared identity menu
    // rereads the local control plane's non-secret projection; the opaque
    // account session itself never enters browser state.
    await openAccountMenu(page);
    await expect(page.locator("[data-account-menu]"))
        .toContainText(person);
    await expect(page.locator('[data-account-menu-item="sign-out"]')).toBeVisible();
});

Then("the native Account Settings page is available", async ({ page }) => {
    await page.locator('[data-account-menu-item="gaugeapp-account"]').click();
    await expect(page).toHaveURL(/gaugeapp=account-settings/);
    await expect(page).toHaveURL(/page=account/);
    await expect(page.locator(".gaugeapp-content h1")).toContainText("Account Settings");
    await expect(page.getByLabel("Display name")).toHaveValue("E2E Person");
});

When("I open native Provider Connections", async ({ page }) => {
    await page.getByRole("button", { name: "Provider Connections", exact: true }).click();
    await expect(page).toHaveURL(/page=provider-connections/);
    await expect(page.getByRole("heading", { name: "Provider Connections", exact: true, level: 1 })).toBeVisible();
});

When("I connect the native OpenAI credential", async ({ page }) => {
    await page.getByRole("button", { name: "Add connection", exact: true }).click();
    const secret = page.getByLabel("API key", { exact: true });
    await secret.fill("native-e2e-provider-secret");
    await page.getByRole("button", { name: "Connect", exact: true }).click();
    await expect(secret).toHaveValue("");
});

Then("the native provider connection is loaded from account authority", async ({ page }) => {
    const row = page.locator(".gaugeapp-provider-row").filter({ hasText: "OpenAI" });
    await expect(row).toBeVisible();
    await expect(row).toContainText("unverified");
    await page.reload();
    await expect(page.locator(".gaugeapp-provider-row").filter({ hasText: "OpenAI" })).toBeVisible();
    await expect(page.locator("body")).not.toContainText("native-e2e-provider-secret");
});

When("I open native Trusted Devices", async ({ page }) => {
    await page.getByRole("button", { name: "Trusted Devices", exact: true }).click();
    await expect(page).toHaveURL(/page=trusted-devices/);
    await expect(page.getByRole("heading", { name: "Trusted Devices", exact: true, level: 1 })).toBeVisible();
});

When("I start native device linking", async ({ page }) => {
    await page.getByRole("button", { name: "New code", exact: true }).click();
});

Then("the native device link is loaded from account authority", async ({ page }) => {
    await expect(page.getByText("DESK-4821", { exact: true })).toBeVisible();
    await expect(page.locator(".gaugeapp-device-qr svg")).toBeVisible();
    await page.reload();
    await expect(page.getByText("DESK-4821", { exact: true })).toBeVisible();
});

When("I send a message to the native Account conversation", async ({ page }) => {
    const composer = page.getByRole("textbox", { name: "Message", exact: true });
    await expect(composer).toBeVisible();
    await composer.fill("native account continuity marker");
    await composer.press("Enter");
    await expect(page.getByText("Account authority remembers this conversation.", { exact: true })).toBeVisible();
});

Then("the native Account conversation returns after reload", async ({ page }) => {
    await page.reload();
    const composer = page.getByRole("textbox", { name: "Message", exact: true });
    await expect(composer).toBeVisible();
    await expect(page.getByText("native account continuity marker", { exact: true })).toBeVisible();
    await expect(page.getByText("Account authority remembers this conversation.", { exact: true })).toBeVisible();
});

Then("the session renewal advances", async ({ page }) => {
    // Every status read inside the renewal window refreshes at the Hub, whose
    // stand-in advances the next-renewal time monotonically.
    const first = await sessionRefreshAfter(page);
    await expect.poll(() => sessionRefreshAfter(page)).toBeGreaterThan(first);
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

When("the account authority revokes this device", async ({ page }) => {
    const response = await page.request.post(`${hubURL}/test/revoke`);
    expect(response.status()).toBe(204);
});

Then("the session renewal no longer advances", async ({ page }) => {
    // The device is revoked at the Hub: refresh is refused, so repeated reads
    // stop advancing the renewal schedule (INV-18 — future use stops).
    const first = await sessionRefreshAfter(page);
    await sessionRefreshAfter(page);
    await sessionRefreshAfter(page);
    expect(await sessionRefreshAfter(page)).toBe(first);
});

When("I sign out of my GaugeWright account", async ({ page }) => {
    await openAccountMenu(page);
    await Promise.all([
        page.waitForEvent("framenavigated"),
        page.locator('[data-account-menu-item="sign-out"]').click(),
    ]);
    await expect(page.locator("[data-account-menu-trigger]")).toContainText("Sign in");
});
