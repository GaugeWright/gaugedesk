/**
 * Steps for the `.whip` program views (Structure / Instances).
 *
 * In its own file so it composes with the shared steps without editing them,
 * matching `content-default.steps.ts`.
 *
 * Every selector below was read off the running app before it was written here.
 * The previous version targeted `.whip-rule-name`, `.whip-fact` and
 * `.whip-effect`, none of which these views have ever rendered — it was written
 * against a sketch and never ran, because the suite fails earlier on `Given a
 * new engagement` in this environment. A step file that cannot pass is worse
 * than no step file: it reads as coverage.
 */
import { expect } from "@playwright/test";
import { createBdd } from "playwright-bdd";

const { Then } = createBdd();

Then("the content viewer offers the {string} tab", async ({ page }, tab: string) => {
    await expect(page.locator(`[data-viewer-tabs] .tab[data-tab="${tab}"]`)).toBeVisible();
});

Then("the content viewer does not offer the {string} tab", async ({ page }, tab: string) => {
    // An ordinary file keeps the three tabs it always had; the extra two are not
    // merely disabled, they are absent, because they mean nothing for it.
    await expect(page.locator(`[data-viewer-tabs] .tab[data-tab="${tab}"]`)).toHaveCount(0);
});

Then("the structure view names the rule {string}", async ({ page }, rule: string) => {
    await expect(
        page.locator(`[data-whip-structure] .whip-rule-node[data-rule="${rule}"] .whip-rule-name`),
    ).toBeVisible();
});

Then(
    "the rule graph couples {string} to {string} by {string}",
    async ({ page }, producer: string, consumer: string, fact: string) => {
        // Drawn, not listed. The edge carries the fact because the fact is what
        // does the coupling — one rule writes it, another's `when` picks it up.
        await expect(
            page.locator(
                `[data-whip-structure] .whip-rule-edge[data-from="${producer}"][data-to="${consumer}"] text`,
                { hasText: fact },
            ),
        ).toBeVisible();
    },
);

Then("the rule graph shows {string} feeding itself", async ({ page }, rule: string) => {
    // A rule that writes a fact it also matches. Drawn as nothing, the reader
    // concludes it runs once; the loop is the engine of the whole workflow.
    await expect(
        page.locator(
            `[data-whip-structure] .whip-rule-edge[data-kind="self"][data-from="${rule}"]`,
        ),
    ).toBeVisible();
});

Then(
    "the instance {string} shows the effect {string} as {string}",
    async ({ page }, instance: string, node: string, label: string) => {
        await expect(
            page.locator(
                `[data-whip-instances] [data-instance="${instance}"] .whip-dag-node[data-node="${node}"] .whip-dag-status`,
            ),
        ).toHaveText(label);
    },
);

Then(
    "the instance {string} marks the effect {string} never requested",
    async ({ page }, instance: string, node: string) => {
        // The distinction the view exists for: absence is carried in the markup,
        // not inferred from the word, so a renderer that started drawing it as
        // one more status would fail here.
        await expect(
            page.locator(
                `[data-whip-instances] [data-instance="${instance}"] .whip-dag-node[data-node="${node}"]`,
            ),
        ).toHaveAttribute("data-tone", "absent");
    },
);

Then(
    "the instance {string} lanes {int} firings",
    async ({ page }, instance: string, count: number) => {
        // Many firings of one rule collapse to rows on a shared axis. One firing
        // does not: a single row proves no pattern, and the graph says more.
        await expect(
            page.locator(`[data-whip-instances] [data-instance="${instance}"] .whip-lane`),
        ).toHaveCount(count);
    },
);

Then(
    "the instance {string} has {int} firings blocked at {string}",
    async ({ page }, instance: string, count: number, node: string) => {
        // The column IS the finding: a run of like marks down one column says
        // "these are all stuck on the same thing" without anyone reading a row.
        await expect(
            page.locator(
                `[data-whip-instances] [data-instance="${instance}"] .whip-lane .whip-lane-cell[data-node="${node}"][data-tone="blocked"]`,
            ),
        ).toHaveCount(count);
    },
);

Then("the instance {string} disowns its absence marks", async ({ page }, instance: string) => {
    // The projection's self-check. A restored instance is keyed differently than
    // its own run, so its absences are artefacts — and saying so is the
    // difference between an incomplete picture and a confident lie.
    await expect(
        page.locator(`[data-whip-instances] [data-instance="${instance}"] [data-whip-untrusted]`),
    ).toBeVisible();
});

Then("the instances view says nothing is running", async ({ page }) => {
    await expect(page.locator("[data-whip-instances] .status")).toContainText("No instance");
});
