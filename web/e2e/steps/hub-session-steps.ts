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

When("I begin GaugeWright sign-in", async ({ page }) => beginSignIn(page));

When("the OS delivers the sign-in return {string}", async ({ page }, url: string) => deliverSignInReturn(page, url));

/** Start the native handoff from the account menu. The menu opens the
 *  sign-in card, which offers a choice of address, passkey and provider
 *  (account.feature); choosing a provider starts the handoff, which mints and
 *  holds the verifier in the control plane and opens the (stand-in) Hub login
 *  URL externally — this headless journey ignores that page, because the
 *  return arrives as a deep link. */
export async function beginSignIn(page: import("@playwright/test").Page): Promise<void> {
    await page.locator('[data-account-menu-item="sign-in"]').click();
    const card = page.locator("[data-signin-overlay] [data-signin]");
    await expect(card).toBeVisible();
    const started = page.waitForResponse((response) =>
        response.request().method() === "POST"
        && new URL(response.url()).pathname === "/account/hub-session/start");
    await card.locator('[data-signin-provider="google"]').click();
    expect((await started).ok()).toBe(true);
}

/** Deliver the OS deep link that completes the handoff, once.
 *
 *  The Tauri shell forwards an OS deep link as this DOM event (FED-7), and
 *  delivers each link once: the launch link is queued behind a sessionStorage
 *  guard (`src-tauri/src/main.rs`), so a reload does not replay it. The web
 *  client posts only the one-time code to the control plane, and on success
 *  reloads the window at `/` so every surface rereads the new account.
 *
 *  `beginSignIn` has already waited for the start that minted the pending
 *  verifier, so there is nothing to race. Delivering again would be a second
 *  use of a single-use code, which the control plane refuses ("no sign-in was
 *  started on this device") and the reloaded window reports on the sign-in
 *  card — the dead-end notice a real repeated return is owed. */
export async function deliverSignInReturn(page: import("@playwright/test").Page, url: string): Promise<void> {
    const redeemed = page.waitForResponse((response) =>
        response.request().method() === "POST"
        && new URL(response.url()).pathname === "/account/hub-session/callback");
    const reloaded = page.waitForEvent("load");
    await page.evaluate((detail) => {
        window.dispatchEvent(new CustomEvent("gw-deep-link", { detail }));
    }, url);
    expect((await redeemed).status()).toBe(200);
    await reloaded;
    const response = await page.request.get(`${aliceCP}/account/hub-session`);
    expect(((await response.json()) as { linked?: boolean }).linked).toBe(true);
}

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
    // The row reports the link's state, not a verification: a key is checked
    // on the device that uses it, and the page no longer shows one (DR-0360,
    // specs/experience/account.md "Provider Connections"). The stand-in
    // account authority admitted the link only as a copy sealed to this
    // device that opens to the key typed above (DR-0334).
    await expect(row.locator(".gaugeapp-connection-state")).toHaveText("linked");
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

/** The Account Settings conversation's composer. A management page opens
 *  with its conversation folded to a rail, to give the page the reading
 *  width, and the rail opens it in one click (#861, `chatBeforeGaugeApp` in
 *  App.tsx), so a person reaches it through that control. */
async function accountConversation(page: import("@playwright/test").Page) {
    const composer = page.getByRole("textbox", { name: "Message", exact: true });
    const rail = page.getByRole("button", { name: /Account Settings agent/ });
    await expect(composer.or(rail).first()).toBeVisible();
    if (!await composer.isVisible()) await rail.click();
    await expect(composer).toBeVisible();
    return composer;
}

When("I send a message to the native Account conversation", async ({ page }) => {
    const composer = await accountConversation(page);
    await composer.fill("native account continuity marker");
    await composer.press("Enter");
    await expect(page.getByText("Account authority remembers this conversation.", { exact: true })).toBeVisible();
});

Then("the native Account conversation returns after reload", async ({ page }) => {
    await page.reload();
    await accountConversation(page);
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
