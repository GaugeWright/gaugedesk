import { test, expect } from "@playwright/test";
// Native component QA: add/rename/models/default; member/project grants and caps;
// key entry/cancel/activate/rotation; suspend/resume/revoke/erase; usage disclosure;
// read-only, stale basis and aborted scope switch; wide/narrow initial + editor.
// This is component evidence, not a substitute for authenticated service proof.
// Verification evidence QA: sealed Check key -> passed catalog check + limitation;
// activation is still a proposal; legacy missing-check observations cannot
// offer activation; switch between current/legacy/read-only and wide/narrow
// candidate states. Capture viewport screenshots for the changed status row.
test.beforeEach(async ({ page }) => { await page.goto("/"); await expect(page.getByRole("heading", { name: "Model Providers", exact: true })).toBeVisible(); });
const editor = (page) => page.locator(".gaugeapp-org-provider-editor");
const calls = async (page) => JSON.parse(await page.getByTestId("calls").textContent());
const view = async (page) => page.getByRole("button", { name: "View", exact: true }).click();
test("the access prompt names both supported grant subjects", async ({ page }) => {
    await expect(page.getByText("Select a connection to grant member access.", { exact: true })).toHaveCount(0);
    await page.getByRole("button", { name: "Empty fixture" }).click();
    await expect(page.getByText("No access grants. Select a connection to grant access to a member or project.", { exact: true })).toBeVisible();
});
test("add, rename, approved models and default are proposals, not optimistic mutations", async ({ page }) => {
    await page.getByRole("button", { name: "Add connection" }).click();
    await editor(page).getByLabel("Name", { exact: true }).fill("Shared analysis");
    await editor(page).getByRole("button", { name: "Save", exact: true }).click();
    await expect(page.locator(".gaugeapp-proposals")).toContainText("Shared analysis");
    await expect(page.locator(".gaugeapp-org-provider-row")).toHaveCount(1);
    await view(page); await page.getByRole("button", { name: "Rename", exact: true }).click();
    await editor(page).getByLabel("Name", { exact: true }).fill("Renamed research");
    await editor(page).getByRole("button", { name: "Save", exact: true }).click();
    await expect(page.locator(".gaugeapp-proposals")).toContainText("Research team → Renamed research");
    await page.getByRole("button", { name: "Models", exact: true }).click();
    await expect(editor(page).getByRole("checkbox", { name: "model-a", exact: true })).toBeChecked();
    await editor(page).getByRole("checkbox", { name: "model-a", exact: true }).uncheck();
    await expect(editor(page).getByRole("button", { name: "Save", exact: true })).toBeDisabled();
    await editor(page).getByRole("checkbox", { name: "model-a", exact: true }).check();
    await editor(page).getByRole("button", { name: "Save", exact: true }).click();
    await page.getByLabel("Organization default model").selectOption({ label: "Research team · model-a" });
    await expect(page.locator(".gaugeapp-proposals")).toContainText("Change organization default model");
    expect((await calls(page)).at(-1).payload.action.arguments.selection).toEqual({ connection: "connection-a", model: "model-a" });
});
test("member and governed-project grants carry exact subjects and caps", async ({ page }) => {
    for (const id of ["grant-a", "project-grant"]) {
        const row = page.locator(`[data-grant-id="${id}"]`);
        await row.getByRole("button", { name: "Edit caps" }).click();
        await editor(page).getByLabel("Token cap / month").fill("0");
        await editor(page).getByLabel("Spend cap / month").fill("12.000001");
        await editor(page).getByRole("button", { name: "Save", exact: true }).click();
        const command = (await calls(page)).at(-1);
        expect(command.payload.action.arguments).toEqual({ grant: id, caps: { tokens: "0", money: { currency: "USD", micros: "12000001" } } });
        await expect(page.locator(".gaugeapp-proposals")).toContainText("Existing usage and reservations remain counted");
    }
    await view(page); await page.getByRole("button", { name: "Grant access" }).click();
    await editor(page).getByLabel("Member", { exact: true }).selectOption("person-a");
    await editor(page).getByRole("button", { name: "Save", exact: true }).click();
    expect((await calls(page)).at(-1).payload.action.arguments.subject).toEqual({ kind: "member", id: "person-a" });
    await page.getByRole("button", { name: "Grant access" }).click();
    await editor(page).getByLabel("Grant to", { exact: true }).selectOption("project");
    await editor(page).getByLabel("Project", { exact: true }).selectOption("project-a");
    await editor(page).getByRole("button", { name: "Save", exact: true }).click();
    expect((await calls(page)).at(-1).payload.action.arguments.subject).toEqual({ kind: "project", authority: "project-authority", id: "project-a" });
});
test("stale revision closes drafts; changing organization clears and aborts key input", async ({ page }) => {
    await view(page); await page.getByRole("button", { name: "Rename", exact: true }).click();
    await editor(page).getByLabel("Name", { exact: true }).fill("Stale draft");
    await page.getByRole("button", { name: "Change server revision" }).click();
    await expect(editor(page)).toHaveCount(0); expect(await calls(page)).toEqual([]);
    await page.getByRole("button", { name: "Enter key" }).click();
    await editor(page).getByLabel("API key", { exact: true }).fill("synthetic-sensitive-key");
    await page.getByRole("button", { name: "Hold upload" }).click();
    await editor(page).getByRole("button", { name: "Store key" }).click();
    await expect(editor(page).getByLabel("API key", { exact: true })).toHaveValue("");
    await page.getByRole("button", { name: "Switch organization" }).click();
    await expect(editor(page)).toHaveCount(0); await expect(page.getByLabel("Upload status")).toContainText("aborted");
    expect(JSON.stringify(await calls(page))).not.toContain("synthetic-sensitive-key");
});
test("lifecycle and grant actions produce concrete summaries", async ({ page }) => {
    await view(page);
    for (const name of ["Suspend", "Revoke", "Erase credentials", "Cancel setup"]) {
        await page.locator(".gaugeapp-org-provider-detail").getByRole("button", { name, exact: true }).click();
        await expect(page.locator(".gaugeapp-proposals dl")).toBeVisible();
    }
    await page.getByRole("button", { name: "Verify candidate" }).click();
    await page.locator(".gaugeapp-org-provider-detail").getByRole("button", { name: "Activate", exact: true }).click();
    await expect(page.locator(".gaugeapp-proposals")).toContainText("Make this verified version current");
    await page.getByRole("button", { name: "Remove candidate" }).click();
    await page.getByRole("button", { name: "Replace key", exact: true }).click();
    await expect(page.locator(".gaugeapp-proposals")).toContainText("Start replacement key setup");
    const grant = page.locator('[data-grant-id="grant-a"]');
    await grant.getByText("Usage & access", { exact: true }).click();
    for (const name of ["Suspend", "Revoke"]) { await grant.getByRole("button", { name, exact: true }).click(); await expect(page.locator(".gaugeapp-proposals dl")).toBeVisible(); }
    await page.getByRole("button", { name: "Suspend fixture" }).click();
    await page.locator(".gaugeapp-org-provider-detail").getByRole("button", { name: "Resume", exact: true }).click();
    await grant.getByRole("button", { name: "Resume", exact: true }).click();
    await expect(page.locator(".gaugeapp-proposals")).toContainText("Other grants may still authorize use");
});
test("read-only removes management actions", async ({ page }) => {
    await view(page); await page.getByRole("button", { name: "Enter key", exact: true }).click();
    await editor(page).getByLabel("API key", { exact: true }).fill("synthetic-sensitive-key");
    await page.getByRole("button", { name: "Remove management role" }).click(); await view(page);
    await expect(editor(page)).toHaveCount(0);
    for (const name of ["Add connection", "Rename", "Edit caps", "Enter key", "Check key", "Revoke"]) await expect(page.getByRole("button", { name, exact: true })).toHaveCount(0);
    await expect(page.getByLabel("Organization default model")).toBeDisabled();
    await page.getByRole("button", { name: "Refresh", exact: true }).click();
    await expect(page.getByRole("heading", { name: "Model Providers", exact: true })).toBeVisible();
});
test("storing a key clears its field and waits for verified authority state", async ({ page }) => {
    await view(page); await page.getByRole("button", { name: "Enter key", exact: true }).click();
    await editor(page).getByLabel("API key", { exact: true }).fill("synthetic-key");
    await editor(page).getByRole("button", { name: "Cancel", exact: true }).click();
    await page.getByRole("button", { name: "Enter key", exact: true }).click();
    await expect(editor(page).getByLabel("API key", { exact: true })).toHaveValue("");
    await editor(page).getByLabel("API key", { exact: true }).fill("synthetic-key");
    await editor(page).getByRole("button", { name: "Store key", exact: true }).click();
    await expect(editor(page)).toHaveCount(0);
    await expect(page.locator(".gaugeapp-org-provider-detail")).toContainText("Stored · verification pending");
    await expect(page.getByRole("button", { name: "Check key", exact: true })).toBeVisible();
    await expect(page.getByRole("button", { name: "Activate", exact: true })).toHaveCount(0);
    expect(JSON.stringify(await calls(page))).not.toContain("synthetic-key");
    await page.getByRole("button", { name: "Check key", exact: true }).click();
    await expect(page.locator(".gaugeapp-org-provider-candidate")).toContainText("Model catalog check passed");
    await expect(page.getByRole("button", { name: "Activate", exact: true })).toBeVisible();
    await expect(page.locator("p[role=status]")).toContainText("Review and activate");
    expect((await calls(page)).at(-1).verification).toEqual({ binding: { authority: "credential-authority", organization: "example-organization", environment: "test" }, connection: "connection-a", version: "candidate-a" });
});
for (const width of [1100, 390]) test(`verification names its limited check and fences historical unknowns at ${width}px`, async ({ page }, info) => {
    await page.setViewportSize({ width, height: 900 });
    await view(page);
    await page.getByRole("button", { name: "Verify candidate", exact: true }).click();
    const candidate = page.locator(".gaugeapp-org-provider-candidate");
    await expect(candidate).toContainText("Model catalog check passed");
    await expect(candidate).toContainText("Inference access and billing have not been tested.");
    await candidate.scrollIntoViewIfNeeded();
    await expect(candidate.getByRole("button", { name: "Activate", exact: true })).toBeInViewport();
    await page.screenshot({ path: info.outputPath("catalog-verified.png") });
    await candidate.getByRole("button", { name: "Activate", exact: true }).click();
    await expect(page.locator(".gaugeapp-proposals")).toContainText("Check performed");
    expect((await calls(page)).at(-1).payload.action.arguments).toEqual({ connection: "connection-a", version: "candidate-a" });
    await page.getByRole("button", { name: "Legacy candidate", exact: true }).click();
    await expect(candidate).toContainText("Check details unavailable");
    await expect(candidate.getByRole("button", { name: "Activate", exact: true })).toHaveCount(0);
    await expect(candidate.getByRole("button", { name: "Cancel setup", exact: true })).toBeVisible();
    await candidate.scrollIntoViewIfNeeded();
    await page.screenshot({ path: info.outputPath("legacy-unknown.png") });
    await page.getByRole("button", { name: "Verify candidate", exact: true }).click();
    await expect(candidate.getByRole("button", { name: "Activate", exact: true })).toBeVisible();
});
test("a delayed directory never lends the previous organization's member choices", async ({ page }) => {
    await expect(page.locator('[data-grant-id="grant-a"]')).toContainText("researcher@example.invalid");
    await page.getByRole("button", { name: "Hold directory", exact: true }).click();
    await page.getByRole("button", { name: "Switch organization", exact: true }).click();
    await view(page);
    await expect(page.getByRole("button", { name: "Grant access", exact: true })).toBeDisabled();
    await expect(page.locator(".gaugeapp-org-providers")).not.toContainText("researcher@example.invalid");
});
for (const width of [1100, 390]) test(`aligned initial page and cap editor at ${width}px`, async ({ page }, info) => {
    await page.setViewportSize({ width, height: 900 });
    await expect(page.getByRole("button", { name: "Add connection" })).toBeInViewport();
    await page.screenshot({ path: info.outputPath(`providers-${width}.png`), scale: "css" });
    await page.locator('[data-grant-id="project-grant"]').getByRole("button", { name: "Edit caps" }).click();
    await editor(page).scrollIntoViewIfNeeded();
    await page.screenshot({ path: info.outputPath(`caps-${width}.png`), scale: "css" });
    const bounds = await page.locator(".gaugeapp-page").evaluate((element) => ({ width: element.clientWidth, scroll: element.scrollWidth }));
    expect(bounds.scroll).toBeLessThanOrEqual(bounds.width + 1);
    for (const button of await editor(page).getByRole("button").all()) {
        const box = await button.boundingBox(); expect(box!.width).toBeLessThan(120); expect(box!.height).toBeLessThan(40); expect(box!.x + box!.width).toBeLessThanOrEqual(width);
    }
});
