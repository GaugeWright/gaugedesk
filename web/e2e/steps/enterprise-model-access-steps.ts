/** DR-0360: the enterprise Account page hands local operations to Model access. */
import { expect, type Page, type Response } from "@playwright/test";
import { createBdd } from "playwright-bdd";
import { aliceCP } from "../ports.mjs";
import { openAccountMenu } from "./settings-nav";

const { When, Then } = createBdd();
const localOrigin = new URL(aliceCP).origin;
const plan = { plan: "ws913-enterprise-managed", status: "active", included_tokens: 250000 };

function localResponse(page: Page, method: string, path: string): Promise<Response> {
    return page.waitForResponse(async (response) => {
        const url = new URL(response.url());
        if (url.origin !== localOrigin || url.pathname !== path
            || response.request().method() !== method) return false;
        // Reload also starts install-scope credential lookups before the desktop
        // session is restored. Select the admitted SettingsPanel request.
        const headers = await response.request().allHeaders();
        return /^Bearer \S+$/.test(headers.authorization ?? "");
    });
}

async function openLocalModelAccess(page: Page): Promise<void> {
    await openAccountMenu(page);
    await page.locator('[data-account-menu-item="gaugeapp-account"]').click();
    await expect(page.locator(".gaugeapp-content h1")).toContainText("Account Settings");
    await page.getByRole("button", { name: "Provider Connections", exact: true }).click();
    await expect(page).toHaveURL(/page=provider-connections/);
    await expect(page.getByRole("heading", { name: "Provider Connections", exact: true, level: 1 }))
        .toBeVisible();
    await page.getByRole("button", { name: "Sign in in GaugeDesk", exact: true }).click();
    await expect(page.locator("[data-settings-surface]")).toBeVisible();
    await expect(page.locator('[data-settings-room-body="models"]')).toBeVisible();
}

When("I open local Model access from enterprise Provider Connections", async ({ page }) => {
    await openLocalModelAccess(page);
});

When("I link a local enterprise OpenAI credential", async ({ page }) => {
    await page.locator("[data-add-credential-open]").click();
    await page.locator("[data-account-provider]").selectOption("openai");
    await page.locator("[data-account-token]").fill("ws913-synthetic-local-provider-key");
    const written = localResponse(page, "POST", "/account/credentials");
    await page.locator("[data-account-link]").click();
    const response = await written;
    expect(response.status()).toBe(200);
    expect((await response.request().allHeaders()).authorization).toMatch(/^Bearer \S+$/);
    expect(await response.json()).toMatchObject({ provider: "openai", linked: true });
    await expect(page.locator('[data-credential="openai"]')).toBeVisible();
});

Then("the local enterprise provider link survives reload through Provider Connections", async ({ page }) => {
    await page.reload();
    // Opening a fresh SettingsPanel reads the real local projection through the
    // same admitted browser client; the old panel's in-memory row cannot pass.
    const read = localResponse(page, "GET", "/account/credentials");
    await openLocalModelAccess(page);
    const response = await read;
    expect(response.status()).toBe(200);
    expect((await response.request().allHeaders()).authorization).toMatch(/^Bearer \S+$/);
    const body = await response.json() as { credentials: { provider: string; linked: boolean }[] };
    expect(body.credentials.find((credential) => credential.provider === "openai"))
        .toEqual({ provider: "openai", linked: true });
    await expect(page.locator('[data-credential="openai"]')).toBeVisible();
    await expect(page.locator("[data-account-token]")).toHaveCount(0);
});

When("I save local enterprise managed inference settings", async ({ page }) => {
    // HOME_SPLIT's hosted account entry is intentionally read-only. This
    // ordinary enterprise desktop path must expose the existing local editor.
    await expect(page.locator("[data-managed-inference-read-only]")).toHaveCount(0);
    const managed = page.locator("[data-managed-inference]");
    await managed.getByRole("textbox", { name: "plan", exact: true }).fill(plan.plan);
    await managed.getByRole("combobox", { name: "status", exact: true }).selectOption(plan.status);
    await managed.getByRole("spinbutton", { name: "included tokens", exact: true })
        .fill(String(plan.included_tokens));
    const written = localResponse(page, "POST", "/account/managed-inference");
    await managed.getByRole("button", { name: "save plan", exact: true }).click();
    const response = await written;
    expect(response.status()).toBe(200);
    expect((await response.request().allHeaders()).authorization).toMatch(/^Bearer \S+$/);
    expect(await response.json()).toMatchObject({ plan });
    await expect(page.locator("[data-account-status]")).toHaveText("managed plan active ✓");
});

Then("the local enterprise managed inference settings survive reload through Provider Connections", async ({ page }) => {
    await page.reload();
    const read = localResponse(page, "GET", "/account/managed-inference");
    await openLocalModelAccess(page);
    const response = await read;
    expect(response.status()).toBe(200);
    expect((await response.request().allHeaders()).authorization).toMatch(/^Bearer \S+$/);
    expect(await response.json()).toMatchObject({ plan });
    const managed = page.locator("[data-managed-inference]");
    await expect(managed.getByRole("textbox", { name: "plan", exact: true })).toHaveValue(plan.plan);
    await expect(managed.getByRole("combobox", { name: "status", exact: true })).toHaveValue(plan.status);
    await expect(managed.getByRole("spinbutton", { name: "included tokens", exact: true }))
        .toHaveValue(String(plan.included_tokens));
    await expect(page.locator("[data-managed-inference-read-only]")).toHaveCount(0);
});
