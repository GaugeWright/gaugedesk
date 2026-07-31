/**
 * Merge conflict-repair steps (UX-7, INV-24): arm the test-only conflict injection so a
 * completing turn's merge is forced to conflict, then drive the isolate → repair → retry
 * recovery through the real merge UI (ContentViewer's merge-review bar).
 */

import { expect } from "@playwright/test";
import { createBdd } from "playwright-bdd";
import { aliceCP } from "../ports.mjs";
import { mutationHeaders } from "./idempotency";

const { When, Then } = createBdd();

When("merge conflict injection is on", async ({ request }) => {
    const res = await request.post(`${aliceCP}/test/force-conflict`, {
        headers: mutationHeaders(),
        data: { on: true },
    });
    expect(res.ok()).toBeTruthy();
});

Then("the work is isolated with a repair option", async ({ page }) => {
    // A forced conflict drives the merge to Rejected/Isolated with a preserved candidate +
    // repair context (INV-24); the diff-tab merge-review bar surfaces the repair affordance.
    await expect(page.locator("[data-merge-repair]")).toBeVisible();
    // UX-7 framing: a conflict says "conflicted", never "you discarded" (which would be a lie).
    const conflict = page.locator("[data-merge-conflict]");
    await expect(conflict).toBeVisible();
    await expect(conflict).toContainText("conflicted");
    await expect(conflict).not.toContainText("discarded");
});

When("I start the repair", async ({ page }) => {
    await page.locator("[data-merge-repair]").click();
});

Then("I can retry the merge", async ({ page }) => {
    await expect(page.locator("[data-merge-retry]")).toBeVisible();
});

When("I retry the merge", async ({ page }) => {
    await page.locator("[data-merge-retry]").click();
});

Then("the merge conflict is resolved", async ({ page }) => {
    // After the repair retry the engagement advances (thread Current) — the repair/retry
    // affordances are gone, so there is no longer an isolated conflict to resolve.
    await expect(page.locator("[data-merge-retry]")).toHaveCount(0);
    await expect(page.locator("[data-merge-repair]")).toHaveCount(0);
});
