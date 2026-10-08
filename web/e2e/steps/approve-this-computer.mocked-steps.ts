/**
 * Approving this computer from one that holds the account's keys, or from
 * the account's recovery code (DR-0359, DR-0361). The window's control plane
 * answers these only for its own window holding an account session; the
 * routes are simulated, and the shipped client, the account bar, the account
 * menu and both dialogs are real.
 *
 * `@ui-mocked`, and isolated here, because the fidelity guard refuses route
 * interception from a `@transport` scenario.
 */

import { expect, type Page } from "@playwright/test";
import { createBdd } from "playwright-bdd";
import { openAccountMenu } from "./settings-nav";

const { Given, When, Then } = createBdd();

const HUB_SESSION = /\/account\/hub-session(\?|$)/;
const JOIN = /\/account\/devices\/enroll\/join(\?|$)/;
const JOIN_STATUS = /\/account\/devices\/enroll\/join\/[^/?]+(\?|$)/;
const RECOVERY_CODE = /\/account\/recovery-code(\?|$)/;
const RESTORE = /\/account\/recovery-code\/restore(\?|$)/;

/** What the simulated plane was asked. */
const asked = new WeakMap<Page, { restored: string[] }>();

function session(label: string, reach: string | null) {
    return {
        available: true,
        linked: true,
        person: "acct-dana",
        label,
        expires: Date.now() + 3_600_000,
        expired: false,
        ...(reach ? { reach } : {}),
    };
}

Given("another computer holds the keys of {string}", async ({ page }, label: string) => {
    const state = { restored: [] as string[] };
    asked.set(page, state);
    let reach = "needs_approval";
    await page.route(HUB_SESSION, (route) => route.request().method() === "GET"
        ? route.fulfill({ status: 200, json: session(label, reach) })
        : route.fallback());
    await page.route(JOIN, (route) => route.request().method() === "POST"
        ? route.fulfill({ status: 200, json: { session: "sess-1" } })
        : route.fallback());
    let polls = 0;
    await page.route(JOIN_STATUS, (route) => {
        polls += 1;
        const done = polls > 2;
        if (done) reach = "published";
        return route.fulfill({
            status: 200,
            json: { phase: done ? "completed" : "sas_ready", sas: "482913", error: null },
        });
    });
    await page.route(RESTORE, async (route) => {
        if (route.request().method() !== "POST") return route.fallback();
        state.restored.push((route.request().postDataJSON() as { code: string }).code);
        reach = "published";
        await route.fulfill({ status: 200, json: { account: "acct-dana", restored: true } });
    });
});

Given(
    "this computer holds the keys of {string} with the recovery code {string}",
    async ({ page }, label: string, code: string) => {
        await page.route(HUB_SESSION, (route) => route.request().method() === "GET"
            ? route.fulfill({ status: 200, json: session(label, "published") })
            : route.fallback());
        await page.route(RECOVERY_CODE, (route) => route.request().method() === "GET"
            ? route.fulfill({ status: 200, json: { account: "acct-dana", code } })
            : route.fallback());
    },
);

async function shot(page: Page, name: string) {
    if (process.env.GW_E2E_SCREENSHOTS) {
        await page.screenshot({ path: `${process.env.GW_E2E_SCREENSHOTS}/${name}.png` });
    }
}

Then("the account bar offers {string}", async ({ page }, label: string) => {
    const button = page.locator("[data-open-device-approval]");
    await expect(button).toBeVisible();
    await expect(button).toHaveText(label);
    await shot(page, "approve-this-computer-bar");
});

When("I choose to approve this computer", async ({ page }) => {
    await page.locator("[data-open-device-approval]").click();
});

const dialog = (page: Page) => page.locator("[data-approve-this-computer] [role=dialog]");

Then("the approval names {string}", async ({ page }, account: string) => {
    await expect(dialog(page)).toBeVisible();
    await expect(dialog(page).locator("h3")).toContainText(account);
    await shot(page, "approve-this-computer-dialog");
});

When("I paste the other computer's ticket and join", async ({ page }) => {
    const ticket = { session: "sess-1", account_root: "04ab", broker: "wss://broker.example", account: "acct-dana" };
    await dialog(page).locator("[data-approve-ticket]").fill(JSON.stringify(ticket));
    await dialog(page).locator("[data-approve-join-start]").click();
});

Then("this computer shows the matching code {string}", async ({ page }, sas: string) => {
    await expect(dialog(page).locator("[data-approve-sas]")).toContainText(sas);
    await shot(page, "approve-this-computer-sas");
});

Then("the approval finishes", async ({ page }) => {
    await expect(page.locator("[data-approve-this-computer]")).toHaveCount(0);
    await expect(page.locator("[data-open-device-approval]")).toHaveCount(0);
});

When("I restore with the recovery code {string}", async ({ page }, code: string) => {
    await dialog(page).locator("[data-approve-recovery-code]").fill(code);
    await dialog(page).locator("[data-approve-recover-start]").click();
});

Then("the recovery code {string} was sent", async ({ page }, code: string) => {
    await expect.poll(() => asked.get(page)?.restored ?? []).toEqual([code]);
});

Then("the recovery code {string} is shown", async ({ page }, code: string) => {
    const value = page.locator("[data-recovery-code] [data-recovery-code-value]");
    await expect(value).toHaveText(code);
    await shot(page, "recovery-code-dialog");
});
