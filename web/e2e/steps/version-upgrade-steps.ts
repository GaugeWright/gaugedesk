/**
 * Placement version-upgrade steps (UX-9, ADR 0063): publish a new archetype version from the
 * Workshop, then take the resulting "upgrade available" notice on a placement (manual default).
 * The facet that holds Agents is named Workshop (DR-0211; navigation.md: Recent | Projects |
 * Workshop).
 */

import { expect, type APIRequestContext, type Page } from "@playwright/test";
import { createBdd } from "playwright-bdd";
import { aliceCP } from "../ports.mjs";

const { When, Then } = createBdd();

When("I publish a new version of the archetype {string}", async ({ page }, name: string) => {
    await page.locator(".facet", { hasText: "Workshop" }).click();
    await page
        .locator("[data-archetype]", { hasText: name })
        .locator(".tree-node.archetype")
        .click({ button: "right" });
    await page.locator(".menu-item", { hasText: "publish a new version" }).click();
});

// Agent view shows every placement, the project's built-in general placement
// included (navigation.md: "Agent view shows each chat under its Agent placement,
// including the built-in Default placement"), and each one that pins the
// published Agent is offered the upgrade. The id only addresses a row; what is
// asserted is what the row renders.
async function placementOn(
    request: APIRequestContext,
    project: string,
    deliberate: boolean,
): Promise<string> {
    const response = await request.get(`${aliceCP}/workspace`);
    if (!response.ok()) throw new Error(`workspace read failed: ${response.status()}`);
    const workspace = await response.json() as {
        projects: { name: string; placements: { placement_id: string; is_default?: boolean }[] }[];
    };
    const placements = workspace.projects
        .find((candidate) => candidate.name === project)?.placements
        .filter((placement) => Boolean(placement.is_default) !== deliberate) ?? [];
    if (placements.length !== 1) {
        throw new Error(`expected one ${deliberate ? "placed" : "built-in"} placement on ${project}, found ${placements.length}`);
    }
    return placements[0].placement_id;
}

const upgradeBadge = (page: Page, project: string, placement: string) =>
    page.locator("[data-project]", { hasText: project }).locator(`[data-upgrade-available="${placement}"]`);

Then("the placement on {string} shows an upgrade is available", async ({ page, request }, project: string) => {
    await page.locator(".facet", { hasText: "Projects" }).click();
    await expect(upgradeBadge(page, project, await placementOn(request, project, true))).toBeVisible();
});

When("I upgrade the placement on {string}", async ({ page, request }, project: string) => {
    await page.locator(".facet", { hasText: "Projects" }).click();
    await upgradeBadge(page, project, await placementOn(request, project, true)).click();
});

Then("the placement on {string} is up to date", async ({ page, request }, project: string) => {
    await page.locator(".facet", { hasText: "Projects" }).click();
    await expect(upgradeBadge(page, project, await placementOn(request, project, true))).toHaveCount(0);
});

// Upgrading is per placement and deliberate (ADR 0063; archetype.md: placements
// are notified "which they take deliberately"): taking it on one placement
// leaves the built-in placement on its version, still offered the upgrade.
Then("the built-in placement on {string} still offers its upgrade", async ({ page, request }, project: string) => {
    await expect(upgradeBadge(page, project, await placementOn(request, project, false))).toBeVisible();
});
