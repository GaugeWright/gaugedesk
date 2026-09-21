/**
 * Account steps (ACCT-1, ADR 0053): reach the operator's own settings from the account
 * menu and link an LLM provider credential.
 */

import { expect } from "@playwright/test";
import { createBdd } from "playwright-bdd";
import { closeSettings, openAccountMenu, openSettings } from "./settings-nav";

const { When, Then } = createBdd();

When("I open my account", async ({ page }) => {
    // Account Settings is now a first-party GaugeApp reached from the existing
    // identity menu. A signed-out desktop has no admitted Account pages yet;
    // the menu itself is the entry surface until native handoff completes.
    await openAccountMenu(page);
});

// The account menu's entrance to identity (LOGIN-3/4/5), on every distro.
// `[data-account-menu-item="sign-in"]` renders whether or not it does anything
// useful, so asserting the row is visible is not a test of this. Pressing it is.
When("I choose sign-in from the account menu", async ({ page }) => {
    await page.locator('[data-account-menu-item="sign-in"]').click();
});

Then("the sign-in card is open over the workbench", async ({ page }) => {
    const overlay = page.locator("[data-signin-overlay]");
    await expect(overlay).toBeVisible();
    await expect(overlay.locator("[data-signin]")).toBeVisible();
    // Over the running shell, not behind a failed Home — that branch is the one
    // a desktop never reaches, and it is where this card used to live.
    await expect(page.locator("[data-home-error]")).toHaveCount(0);
});

Then("it offers an address, a passkey, and the provider marks", async ({ page }) => {
    const card = page.locator("[data-signin-overlay] [data-signin]");
    // The point of the card: a choice. The behaviour this replaces made that
    // choice for the person by opening one provider.
    await expect(card.locator("[data-signin-email]")).toBeVisible();
    await expect(card.locator("[data-signin-create-open]")).toBeVisible();
    for (const provider of ["google", "apple", "microsoft"]) {
        await expect(card.locator(`[data-signin-provider="${provider}"]`)).toBeVisible();
    }
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
