/**
 * Presentation-only refusal of a chat start, and the workbench's per-pane
 * action errors.
 *
 * Isolated in a `*.mocked-steps.ts` module for the same reason as the
 * freshness simulation: the matching feature is `@ui-mocked`, and real-transport
 * scenarios refuse application-route interceptors.
 */

import { expect } from "@playwright/test";
import { createBdd } from "playwright-bdd";

const { When, Then } = createBdd();

// Both ways the empty chat pane starts a chat: a bare chat, and a chat under
// the Personal placement's default target.
const CREATE_CHAT = /\/chats(\?|$)/;

When("starting a chat is refused with {string}", async ({ page }, reason: string) => {
    await page.route(CREATE_CHAT, (route) =>
        route.request().method() === "POST"
            ? route.fulfill({ status: 409, json: { rejected: reason } })
            : route.fallback());
});

When("I task the agent with {string} from the empty chat", async ({ page }, prompt: string) => {
    const composer = page.locator('[data-desktop-composer] textarea[aria-label="Message"]');
    await composer.fill(prompt);
    await composer.press("Enter");
});

Then("the composer says {string}", async ({ page }, reason: string) => {
    await expect(page.locator("[data-desktop-composer] [data-composer-error]")).toContainText(reason);
});

Then("the message {string} is back in the composer", async ({ page }, text: string) => {
    await expect(page.locator('[data-desktop-composer] textarea[aria-label="Message"]')).toHaveValue(text);
});

When("I dismiss the files pane's action error", async ({ page }) => {
    await page.locator('[data-action-error="files"] button').click();
});

Then("the files pane shows the action error {string}", async ({ page }, reason: string) => {
    const notice = page.locator('[data-action-error="files"]');
    await expect(notice).toHaveAttribute("role", "alert");
    await expect(notice).toContainText(reason);
});

Then("the files pane shows no action error", async ({ page }) => {
    await expect(page.locator('[data-action-error="files"]')).toHaveCount(0);
});
