/**
 * Moving signed-out projects to the signed-in account (DR-0328 §7).
 *
 * The window's control plane lists and moves the local account's projects
 * only for its own window holding an account session; this browser lane signs
 * in with a test identity instead, so the real plane answers it with a
 * refusal. The two routes are simulated, and everything the assertions are
 * about is real: the shipped client, the account menu, and the dialog.
 *
 * `@ui-mocked`, and isolated here, because the fidelity guard refuses route
 * interception from a `@transport` scenario.
 */

import { expect, type Page } from "@playwright/test";
import { createBdd } from "playwright-bdd";
import { openAccountMenu } from "./settings-nav";

const { Given, When, Then } = createBdd();

const LIST = /\/local-projects(\?|$)/;
const TRANSFER = /\/local-projects\/transfer(\?|$)/;
const HUB_SESSION = /\/account\/hub-session(\?|$)/;

/** What the simulated window plane holds and was asked to move. */
const transfers = new WeakMap<Page, { posted: string[][] }>();

Given(
    "this computer has signed-out projects {string} and {string} for {string}",
    async ({ page }, first: string, second: string, label: string) => {
        const state = { posted: [] as string[][] };
        transfers.set(page, state);
        // The window's selected account, as the native sign-in projects it:
        // an account id, and the label the person knows it by.
        const account = "acct-dana";
        await page.route(HUB_SESSION, (route) => route.request().method() === "GET"
            ? route.fulfill({
                status: 200,
                json: {
                    available: true,
                    linked: true,
                    person: account,
                    label,
                    expires: Date.now() + 3_600_000,
                    expired: false,
                },
            })
            : route.fallback());
        let projects = [
            { id: "proj-garden", name: first },
            { id: "proj-tax", name: second },
        ];
        await page.route(LIST, (route) => route.request().method() === "GET"
            ? route.fulfill({ status: 200, json: { account, projects } })
            : route.fallback());
        await page.route(TRANSFER, async (route) => {
            if (route.request().method() !== "POST") return route.fallback();
            const body = route.request().postDataJSON() as { projects: string[] };
            state.posted.push(body.projects);
            projects = projects.filter((project) => !body.projects.includes(project.id));
            await route.fulfill({ status: 200, json: { account, moved: body.projects } });
        });
    },
);

When("I open the account menu", async ({ page }) => {
    await openAccountMenu(page);
});

When("I choose {string} in the account menu", async ({ page }, label: string) => {
    const item = page.locator("[data-account-menu-item]").filter({ hasText: label });
    await expect(item).toHaveCount(1);
    await item.click();
});

const dialog = (page: Page) => page.locator("[data-local-project-transfer] [role=dialog]");

Then(
    "the transfer names {string} and the projects {string} and {string}",
    async ({ page }, account: string, first: string, second: string) => {
        await expect(dialog(page)).toBeVisible();
        await expect(dialog(page).locator("h3")).toHaveText(`Move signed-out projects to ${account}`);
        await expect(dialog(page).locator("[data-local-project-transfer-account]")).toHaveText(account);
        const rows = dialog(page).locator("[data-local-project]");
        await expect(rows).toHaveText([first, second]);
        for (const row of await rows.all()) await expect(row.locator("input")).toBeChecked();
    },
);

Then("the transfer offers {string}", async ({ page }, label: string) => {
    await expect(dialog(page).locator("[data-local-project-transfer-confirm]")).toHaveText(label);
});

When("I untick {string}", async ({ page }, name: string) => {
    await dialog(page).locator("[data-local-project]", { hasText: name }).locator("input").uncheck();
});

When("I confirm the transfer", async ({ page }) => {
    await dialog(page).locator("[data-local-project-transfer-confirm]").click();
});

Then("the transfer posted only {string}", async ({ page }, name: string) => {
    await expect(page.locator("[data-local-project-transfer]")).toHaveCount(0);
    const ids: Record<string, string> = { "Garden plans": "proj-garden", "Tax notes": "proj-tax" };
    expect(transfers.get(page)?.posted).toEqual([[ids[name]]]);
});

Then("the account menu offers to move only {string}", async ({ page }, name: string) => {
    // The offer is read again after the move, so it names only what is left.
    await openAccountMenu(page);
    await page.locator('[data-account-menu-item="move-local-projects"]').click();
    await expect(dialog(page).locator("[data-local-project]")).toHaveText([name]);
});
