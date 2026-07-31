/**
 * "Your account" steps (ACCT-1, ADR 0053): open the account panel from
 * Settings ▸ Your account and link an LLM provider account.
 */

import { expect } from "@playwright/test";
import { createBdd } from "playwright-bdd";

const { When, Then } = createBdd();

When("I open my account", async ({ page }) => {
    await page.locator("[data-settings]").click();
    await page.locator("[data-settings-account]").click();
    await expect(page.locator("[data-account-panel]")).toBeVisible();
});

When("I link the {string} account with token {string}", async ({ page }, provider: string, token: string) => {
    await page.locator("[data-account-provider]").selectOption(provider);
    await page.locator("[data-account-token]").fill(token);
    await page.locator("[data-account-link]").click();
});

Then("{string} shows as a linked account", async ({ page }, provider: string) => {
    await expect(page.locator(`[data-linked="${provider}"]`)).toBeVisible();
});

When(
    "I configure managed inference plan {string} as {string} with {int} included tokens",
    async ({ page }, plan: string, status: string, includedTokens: number) => {
        const managed = page.locator("[data-managed-inference]");
        await managed.getByRole("textbox", { name: "plan", exact: true }).fill(plan);
        await managed.getByRole("combobox", { name: "status", exact: true }).selectOption(status);
        await managed.getByRole("spinbutton", { name: "included tokens", exact: true })
            .fill(String(includedTokens));
        await managed.getByRole("button", { name: "save managed plan", exact: true }).click();
        await expect(page.locator("[data-account-status]")).toHaveText(`managed plan ${status} ✓`);
    },
);

Then(
    "the managed inference plan {string} is durably {string} with {int} included tokens",
    async ({ page }, plan: string, status: string, includedTokens: number) => {
        await page.getByRole("button", { name: "close", exact: true }).click();
        await page.locator("[data-settings]").click();
        await page.locator("[data-settings-account]").click();
        const managed = page.locator("[data-managed-inference]");
        await expect(managed.getByRole("textbox", { name: "plan", exact: true }))
            .toHaveValue(plan);
        await expect(managed.getByRole("combobox", { name: "status", exact: true }))
            .toHaveValue(status);
        await expect(managed.getByRole("spinbutton", { name: "included tokens", exact: true }))
            .toHaveValue(String(includedTokens));
    },
);
