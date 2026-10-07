/**
 * The Panel agent's whole custody journey past "Deploy" (PANEL-7): a preview
 * chat, publication to the loopback edge fixture (`e2e/panel-edge.mjs`), a
 * visitor's collected result drained into the project's Inbox, review at the
 * project's gate, and the explicit import a deployment from before project
 * bindings needs before it can be updated.
 *
 * The browser drives the real workbench against the real control plane; the
 * edge is the only stand-in. A step that plays the visitor calls the fixture's
 * test route directly, because a visitor is a website, not the owner's
 * workbench.
 */
import { expect, type Page } from "@playwright/test";
import { createBdd } from "playwright-bdd";
import { edgeURL } from "../ports.mjs";

const { Given, When, Then } = createBdd();

/** How many edge requests had been served when this scenario's legacy deployment was seeded. */
let legacySeededAt = 0;

const deployDialog = (page: Page) => page.getByRole("dialog", { name: "Deploy Panel agent" });

/** The deployment address the dialog proposes for an agent's name. */
function slug(name: string): string {
    return name.toLowerCase().replace(/[^a-z0-9_-]+/g, "-").replace(/^-+|-+$/g, "");
}

async function edgeRequests(): Promise<{ method: string; path: string }[]> {
    const response = await fetch(`${edgeURL}/__test/requests`);
    expect(response.ok).toBe(true);
    return ((await response.json()) as { requests: { method: string; path: string }[] }).requests;
}

// What a deployment needs from the version it runs: a model, since this
// workbench has no work-chat default to fall back on, and — for the journey —
// a result to collect into the project's Inbox.
async function setContract(page: Page, options: { model: string; collect: boolean }) {
    const model = page.locator("[data-panel-contract-model]");
    await model.locator("summary", { hasText: "Advanced" }).click();
    await model.getByLabel("Model ID").fill(options.model);
    if (options.collect) {
        const collection = page.locator("[data-panel-contract-collection]");
        await collection.getByText("Collect results", { exact: true }).click();
        await expect(collection.getByText("Files to collect", { exact: true })).toBeVisible();
    }
    await page.locator("[data-config-editor] [data-settings-save]").click();
    await expect(page.locator("[data-config-editor]").getByText("saved", { exact: true })).toBeVisible();
}

When("I set its Panel contract to collect results on the model {string}", async ({ page }, model: string) => {
    await setContract(page, { model, collect: true });
});

When("I set its Panel contract to the model {string}", async ({ page }, model: string) => {
    await setContract(page, { model, collect: false });
});

When("I publish a new version of the Panel agent {string}", async ({ page }, name: string) => {
    await page.locator(".facet", { hasText: "Workshop" }).click();
    await page.locator("[data-archetype]", { hasText: name }).locator(".tree-node.archetype").click({ button: "right" });
    await page.locator(".menu-item-label", { hasText: /^publish a new version$/ }).click();
});

// Trying a Panel agent is a disposable work chat on the author's own model and
// funding, listed under the agent in the Workshop (DR-0272).
When("I try the Panel agent {string} in a preview chat", async ({ page }, name: string) => {
    await page.locator(".facet", { hasText: "Workshop" }).click();
    await page.locator("[data-archetype]", { hasText: name }).locator(".tree-node.archetype").click({ button: "right" });
    await page.locator(".menu-item-label", { hasText: /^try in a preview chat$/ }).click();
});

Then("a Panel preview chat is open that says what it does not exercise", async ({ page }) => {
    await expect(page.locator('[data-panel-previews] [data-chat].active')).toBeVisible({ timeout: 15_000 });
    // A narrow composer folds its model row, the note with it, behind "More".
    const more = page.locator("[data-composer-more]");
    if (await more.isVisible()) await more.click();
    const note = page.locator("[data-panel-preview-note]");
    await expect(note).toBeVisible();
    await expect(note).toContainText("doesn't exercise the website panels or visitor sign-in");
    if (await more.isVisible()) await page.keyboard.press("Escape");
});

When(
    "I deploy it for the website {string} paying with a new provider key",
    async ({ page }, website: string) => {
        const dialog = deployDialog(page);
        await expect(dialog).toBeVisible();
        await dialog.getByLabel("Website address").fill(website);
        await dialog.getByRole("button", { name: "Add website" }).click();
        await expect(dialog.locator("[data-deployment-websites] .pa-list")).toContainText(new URL(website).host);
        await dialog.locator("[data-deployment-funding]").getByText("Your own provider key", { exact: true }).click();
        await dialog.getByRole("button", { name: "Add a provider key…" }).click();
        await dialog.getByLabel(/API key$/).fill("sk-e2e-fixture-not-a-real-key");
        await dialog.getByRole("button", { name: "Save key" }).click();
        await expect(dialog.getByRole("radiogroup", { name: "Provider key" })).toBeVisible();
        await dialog.getByRole("button", { name: "Deploy", exact: true }).click();
    },
);

Then("the deployment {string} is live at the local edge", async ({ page }, name: string) => {
    const dialog = deployDialog(page);
    await expect(dialog.getByText(`${name} is live`)).toBeVisible({ timeout: 20_000 });
    await expect(dialog.locator("[data-deployment-status]")).toBeVisible();
    await expect(dialog.locator(".pa-pill")).toHaveText("Live");
    // What the Home sent the edge: a release, then the deployment that serves it.
    const requests = await edgeRequests();
    const deployment = `/v1/deployments/${slug(name)}`;
    expect(requests.some((request) => request.method === "PUT" && request.path.startsWith("/v1/releases/"))).toBe(true);
    expect(requests.some((request) => request.method === "PUT" && request.path === deployment)).toBe(true);
});

When(
    "a visitor to {string} leaves the result {string}",
    async ({}, name: string, text: string) => {
        const response = await fetch(`${edgeURL}/__test/visitor-result`, {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({ deployment_id: slug(name), text }),
        });
        expect(response.status, await response.text()).toBe(200);
    },
);

When("I bring the deployment's results into the Inbox", async ({ page }) => {
    await deployDialog(page).getByRole("button", { name: "Bring results into the Inbox" }).click();
});

Then("the deployment says 1 result arrived in the {string} Inbox", async ({ page }, project: string) => {
    await expect(deployDialog(page).getByText(`1 result arrived in the ${project} Inbox`)).toBeVisible({ timeout: 20_000 });
});

Then(
    "the {string} Inbox holds the visitor's result {string}",
    async ({ page }, project: string, text: string) => {
        const inbox = page.getByRole("dialog", { name: `${project} Inbox` });
        await expect(inbox).toBeVisible();
        const row = inbox.locator(".quarantine-item").first();
        await expect(row.locator(".quarantine-schema")).toHaveText("gaugewright.panel-output/v1");
        await row.locator(".quarantine-row").click();
        await expect(row.locator(".quarantine-payload")).toHaveText(text);
    },
);

When("I keep the visitor's result", async ({ page }) => {
    const inbox = page.getByTestId("project-inbox");
    const row = inbox.locator(".quarantine-item").first();
    // A drain asks the project's gate first. A project with no screening
    // program parks the item on a person, so it is still awaiting review here.
    await expect(row.locator(".quarantine-status")).toHaveText("awaiting review");
    if (!(await row.locator(".quarantine-actions").count())) await row.locator(".quarantine-row").click();
    await row.locator(".quarantine-actions").getByRole("button", { name: "keep", exact: true }).click();
});

Then("the project gate has kept the visitor's result", async ({ page }) => {
    const inbox = page.getByTestId("project-inbox");
    await expect(inbox.getByText(/The project gate kept this at /)).toBeVisible({ timeout: 20_000 });
    await expect(inbox.locator(".quarantine-item").first().locator(".quarantine-status")).toHaveText("approved");
    // The hosted copy was released only once it was held here.
    const requests = await edgeRequests();
    expect(requests.some((request) => request.method === "POST" && request.path.endsWith("/collections"))).toBe(true);
});

Given(
    "the edge already serves {string} from before project bindings",
    async ({}, name: string) => {
        const response = await fetch(`${edgeURL}/__test/legacy-deployment`, {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({ deployment_id: slug(name), panel_ceiling: ["gw-chat"], credential_class: "openai-api-key" }),
        });
        expect(response.status, await response.text()).toBe(200);
        legacySeededAt = (await edgeRequests()).length;
    },
);

When("I try to deploy it for the website {string} with the existing key", async ({ page }, website: string) => {
    const dialog = deployDialog(page);
    await expect(dialog).toBeVisible();
    await dialog.getByLabel("Website address").fill(website);
    await dialog.getByRole("button", { name: "Add website" }).click();
    await dialog.locator("[data-deployment-funding]").getByText("Your own provider key", { exact: true }).click();
    await dialog.getByRole("radiogroup", { name: "Provider key" }).getByText("Key from before projects").click();
    await dialog.getByRole("button", { name: "Deploy", exact: true }).click();
});

Then("the deployment is refused until it is imported", async ({ page }) => {
    const dialog = deployDialog(page);
    await expect(dialog.getByRole("alert")).toContainText("legacy hosted deployment requires import");
    await expect(dialog.getByText("This deployment was made before project bindings")).toBeVisible();
    await expect(dialog.getByRole("button", { name: "Import existing deployment" })).toBeDisabled();
});

When("I confirm this Panel agent and project own it and import it", async ({ page }) => {
    const dialog = deployDialog(page);
    await dialog.getByText("This is the source Panel agent and the project that should receive it.").click();
    await dialog.getByRole("button", { name: "Import existing deployment" }).click();
});

Then(
    "{string} is imported without anything changing at the edge",
    async ({ page }, name: string) => {
        await expect(deployDialog(page).getByText(/Imported without changing hosted release sha256:/)).toBeVisible({ timeout: 20_000 });
        const deployment = `/v1/deployments/${slug(name)}`;
        // Everything the Home sent the edge since the deployment was seeded —
        // the refused deploy and the import — touching it or any release.
        const touched = (await edgeRequests()).slice(legacySeededAt).filter((request) =>
            request.path === deployment
            || request.path.startsWith(`${deployment}/`)
            || request.path.startsWith("/v1/releases/"));
        expect(touched.length).toBeGreaterThan(0);
        for (const request of touched) {
            expect(`${request.method} ${request.path}`).toMatch(/^GET /);
        }
    },
);
