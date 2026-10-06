/**
 * Presentation-only refusal of a navigator create.
 *
 * Isolated in a `*.mocked-steps.ts` module for the same reason as the
 * freshness simulation: the matching feature is `@ui-mocked`, and real-transport
 * scenarios refuse application-route interceptors.
 */

import { expect } from "@playwright/test";
import { createBdd } from "playwright-bdd";

const { When, Then } = createBdd();

const CREATE_PROJECT = /\/projects(\?|$)/;

When("creating a project is refused with {string}", async ({ page }, reason: string) => {
    await page.route(CREATE_PROJECT, (route) =>
        route.request().method() === "POST"
            ? route.fulfill({ status: 403, json: { error: reason } })
            : route.fallback());
});

When("I create a project named {string} from the navigator", async ({ page }, name: string) => {
    await page.locator(".facet", { hasText: "Projects" }).click();
    await page.getByText("+ project", { exact: true }).click();
    await page.locator(".inline-edit").fill(name);
    await page.locator(".inline-edit").press("Enter");
});

When("I dismiss the navigator error", async ({ page }) => {
    await page.locator("[data-action-error='nav'] button").click();
});

Then("the navigator shows the error {string}", async ({ page }, reason: string) => {
    await expect(page.locator("[data-action-error='nav']")).toContainText(reason);
});

Then("the navigator shows no error", async ({ page }) => {
    await expect(page.locator("[data-action-error='nav']")).toHaveCount(0);
});
