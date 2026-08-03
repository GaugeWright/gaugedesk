/**
 * RF-E4 presentation-only error simulation.
 *
 * This is intentionally isolated in a `*.mocked-steps.ts` module. The matching
 * feature is `@ui-mocked`; real-transport fidelity scenarios are guarded at
 * runtime from installing application-route interceptors.
 */

import { expect } from "@playwright/test";
import { createBdd } from "playwright-bdd";

const { When, Then } = createBdd();

// Fail every per-chat projection the desktop freshness signal folds. Aborting
// only some lets a successful load race the shared signal back to `fresh`.
const FAILING_PROJECTIONS =
    /\/(chats\/[^/]+\/diff|scopes\/[^/]+\/run|projections\/[^/]+\/merge)(\?|$)/;

When("the projection refresh starts failing", async ({ page }) => {
    await page.route(FAILING_PROJECTIONS, (route) => route.abort());
});

When("the projection refresh recovers", async ({ page }) => {
    await page.unroute(FAILING_PROJECTIONS);
});

When("I trigger a projection refresh", async ({ page }) => {
    await page.reload();
});

When("I retry the projection refresh", async ({ page }) => {
    await page.locator("[data-freshness-retry]").click();
});

Then("the freshness banner is shown", async ({ page }) => {
    await expect(page.locator("[data-freshness-banner]")).toBeVisible();
});

Then("the freshness banner offers a retry", async ({ page }) => {
    await expect(page.locator("[data-freshness-retry]")).toBeVisible();
});

Then("the freshness banner clears", async ({ page }) => {
    await expect(page.locator("[data-freshness-banner]")).toHaveCount(0);
});
