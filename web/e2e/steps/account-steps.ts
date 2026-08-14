/**
 * Account steps (ACCT-1, ADR 0053): reach the operator's own settings from the account
 * menu and link an LLM provider credential.
 */

import { expect } from "@playwright/test";
import { createBdd } from "playwright-bdd";
import { closeSettings, openSettings } from "./settings-nav";

const { When, Then } = createBdd();

When("I open my account", async ({ page }) => {
    await openSettings(page, "account");
});

When("I open my model access", async ({ page }) => {
    await openSettings(page, "models");
});

When("I link the {string} account with token {string}", async ({ page }, provider: string, token: string) => {
    // Adding a credential is a deliberate act behind its own control, so the room is not
    // a permanently open form over the list of what is already linked.
    await page.locator("[data-add-credential-open]").click();
    await page.locator("[data-account-provider]").selectOption(provider);
    await page.locator("[data-account-token]").fill(token);
    await page.locator("[data-account-link]").click();
});

Then("{string} shows as a linked account", async ({ page }, provider: string) => {
    // The store keys a credential by its provider, so the provider is the row's id.
    await expect(page.locator(`[data-credential="${provider}"]`)).toBeVisible();
});

When(
    "I configure managed inference plan {string} as {string} with {int} included tokens",
    async ({ page }, plan: string, status: string, includedTokens: number) => {
        const managed = page.locator("[data-managed-inference]");
        await managed.getByRole("textbox", { name: "plan", exact: true }).fill(plan);
        await managed.getByRole("combobox", { name: "status", exact: true }).selectOption(status);
        await managed.getByRole("spinbutton", { name: "included tokens", exact: true })
            .fill(String(includedTokens));
        await managed.getByRole("button", { name: "save plan", exact: true }).click();
        await expect(page.locator("[data-account-status]")).toHaveText(`managed plan ${status} ✓`);
    },
);

Then(
    "the managed inference plan {string} is durably {string} with {int} included tokens",
    async ({ page }, plan: string, status: string, includedTokens: number) => {
        await closeSettings(page);
        await openSettings(page, "models");
        const managed = page.locator("[data-managed-inference]");
        await expect(managed.getByRole("textbox", { name: "plan", exact: true }))
            .toHaveValue(plan);
        await expect(managed.getByRole("combobox", { name: "status", exact: true }))
            .toHaveValue(status);
        await expect(managed.getByRole("spinbutton", { name: "included tokens", exact: true }))
            .toHaveValue(String(includedTokens));
    },
);
