/**
 * Step(s) for the content viewer's empty top row.
 * Kept in its own file so it composes with the shared steps without editing them.
 */
import { expect } from "@playwright/test";
import { createBdd } from "playwright-bdd";

const { Then } = createBdd();

Then("the content header says only CONTENT", async ({ page }) => {
    await expect(page.locator(".panel.content [data-content-title]")).toHaveText("Content");
    await expect(page.locator(".panel.content [data-viewer-tabs] .tab")).toHaveCount(0);
    await expect(page.locator(".panel.content")).not.toContainText("Pick a file");
});
