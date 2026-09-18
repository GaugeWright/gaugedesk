/**
 * Provider signup, at the card (LOGIN-3/4/5).
 *
 * One route is simulated — `POST /auth/account/consumer-signup/claim`, the
 * non-secret projection of a ticket — because the ticket itself is minted by a
 * real Google round trip a browser test cannot perform, and the Hub that mints
 * it is not in this composition.
 *
 * Everything the assertion is about is real: the URL fragment, the client's own
 * `consumeAccountSignupTicket`, the resource that claims it, and the card's
 * reaction to a prop that arrives after its first render. That last one is the
 * whole point — simulating the card instead would reproduce the bug this gate
 * exists to catch.
 *
 * `@ui-mocked`, and isolated here, because the fidelity guard refuses route
 * interception from a `@transport` scenario.
 */

import { expect } from "@playwright/test";
import { createBdd } from "playwright-bdd";

const { Given, Then } = createBdd();

const SIGNUP_CLAIM = "**/auth/account/consumer-signup/claim";

Given("a signup ticket from the provider is on the URL", async ({ page }) => {
    await page.route(SIGNUP_CLAIM, (route) =>
        route.fulfill({
            status: 200,
            contentType: "application/json",
            body: JSON.stringify({
                email: "attested@example.com",
                display_name: "Attested Person",
                provider: "google",
            }),
        }),
    );
    // The fragment the Hub redirects to for a verified first-time subject.
    await page.goto("/#account_signup=e2e-ticket");
});

Then("the card opens on the provider account step", async ({ page }) => {
    await expect(page.locator("[data-signin]")).toBeVisible();
    // The step, not merely "a card". Asserting the card alone is exactly what
    // the broken version passed: it rendered the identify step quite happily.
    await expect(page.locator("[data-signin-provider-create]")).toBeVisible();
    await expect(page.locator("[data-signin-email]")).toHaveCount(0);
});

Then("it shows the address the provider attested", async ({ page }) => {
    await expect(page.locator("[data-signin-provider-create]")).toContainText(
        "attested@example.com",
    );
});
