/**
 * A slow Home, for the first message of a new chat (WS-892).
 *
 * Isolated in a `*.mocked-steps.ts` module like the other route simulations:
 * the matching feature is `@ui-mocked`. Nothing is answered here; each read is
 * only held for a while before it goes on to the real control plane.
 */

import { expect, type Route } from "@playwright/test";
import { createBdd } from "playwright-bdd";

const { When, Then } = createBdd();

const WORKSPACE_READ = /\/workspace(\?|$)/;
const ACTOR_READ = /\/file-actions\/actor(\?|$)/;

const heldFor = (ms: number) => async (route: Route) => {
    if (route.request().method() !== "GET") return route.fallback();
    await new Promise((resolve) => setTimeout(resolve, ms));
    return route.fallback();
};

// The workspace read is what tells desk a new chat's project; the actor read
// is the first thing a turn asks the Home. Holding the second longer than the
// first is the order production met: the route moved while a turn's first
// request was out.
When("the Home is slow to answer workspace and actor reads", async ({ page }) => {
    await page.route(WORKSPACE_READ, heldFor(1_000));
    await page.route(ACTOR_READ, heldFor(2_000));
});

When("I start a chat in project {string} and send {string} at once", async ({ page }, name: string, prompt: string) => {
    await page.locator(".facet", { hasText: "Projects" }).click();
    const opened = page.url();
    await page.locator("[data-project]", { hasText: name }).locator("[data-create='new-project-chat']").click();
    // Selected: the address names the new chat. Its project is not known yet.
    await page.waitForURL((url) => url.searchParams.has("chat") && url.toString() !== opened);
    const composer = page.locator('[data-desktop-composer] textarea[aria-label="Message"]');
    await composer.fill(prompt);
    await composer.press("Enter");
});

// Says what the composer said when the turn was refused, rather than only
// that it never completed.
Then("the turn completes", async ({ page }) => {
    const refusal = page.locator("[data-composer-error]");
    const phase = page.getByTestId("run-phase");
    await expect.poll(async () => await refusal.count()
        ? `refused: ${(await refusal.first().textContent())?.trim()}`
        : await phase.getAttribute("data-run-phase"), { timeout: 45_000 }).toBe("Completed");
});
