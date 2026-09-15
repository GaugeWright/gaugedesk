import { expect, type Page } from "@playwright/test";
import { createBdd } from "playwright-bdd";

const { Given, When, Then } = createBdd();
type Request = { path: string; key: string | undefined; body: unknown };
type Fixture = { readable: boolean; signedOut: boolean; canComplete: boolean; closed: boolean; outcome: "ok" | "lost" | "failed" | "held"; release?: () => void; requests: Request[] };
const fixtures = new WeakMap<Page, Fixture>();
const panel = (page: Page) => page.getByRole("dialog", { name: "Personal tasks", exact: true });

Given("a simulated project tracker backlog", async ({ page }) => {
    const fixture: Fixture = { readable: true, signedOut: false, canComplete: true, closed: false, outcome: "ok", requests: [] };
    fixtures.set(page, fixture);
    await page.route(/\/projects\/[^/]+\/trackers(?:\/|$)/, async route => {
        const request = route.request();
        const path = new URL(request.url()).pathname;
        const project = decodeURIComponent(path.split("/")[2]);
        if (fixture.signedOut) {
            await route.fulfill({ status: 401, json: { error: "Sign in to read project tasks" } });
            return;
        }
        const tracker = { project_id: project, workspace_id: "workspace-personal", queue: "tutorials", resource_id: "tracker", can_complete: fixture.canComplete };
        if (path.endsWith("/complete")) {
            fixture.requests.push({ path, key: request.headers()["idempotency-key"], body: request.postDataJSON() });
            if (fixture.outcome === "held") await new Promise<void>(resolve => { fixture.release = resolve; });
            if (fixture.outcome === "lost" && fixture.requests.length === 1) {
                fixture.closed = true;
                await route.abort();
                return;
            }
            if (fixture.outcome !== "failed") fixture.closed = true;
            await route.fulfill({ json: {
                snapshot: { admission: { instance_ref: "human-completion" }, instance_status: fixture.outcome === "failed" ? "failed" : "completed" },
                executed_effect: null, recovered_effect: fixture.outcome === "lost" ? "closing-effect" : null,
            } });
            return;
        }
        if (path.endsWith("/trackers")) {
            await route.fulfill({ json: { trackers: [tracker] } });
            return;
        }
        if (!fixture.readable) {
            await route.fulfill({ status: 403, json: { error: "Tracker is not readable" } });
            return;
        }
        const base = { body: "", labels: [], created_at: "2026-09-11T00:00:00Z", updated_at: "2026-09-11T00:00:00Z", filed_by: "learner", claimed_by: null };
        await route.fulfill({ json: { tracker, issues: [
            { ...base, id: "WS-1", subject_id: "assistant-subject", title: "Make a personal assistant", body: "Open Library, create an Agent, and describe how it should help you.", status: fixture.closed ? "closed" : "open", assigned_to: "learner" },
            { ...base, id: "WS-2", subject_id: "unassigned-subject", title: "Organize the shared folder", status: "open", assigned_to: null },
            { ...base, id: "WS-3", subject_id: "colleague-subject", title: "Review the project outline", status: "in_progress", assigned_to: "colleague", claimed_by: "colleague" },
            { ...base, id: "WS-4", subject_id: "earlier-subject", title: "Earlier task", status: "closed", assigned_to: "learner" },
        ] } });
    });
});

When("I open the Personal project task backlog", async ({ page }) => {
    await page.locator(".facet", { hasText: "Projects" }).click();
    await page.locator("[data-project]", { hasText: "Personal" }).locator(".tree-node.project").click({ button: "right" });
    await page.locator(".menu-item").filter({ hasText: /^tasks…$/ }).click();
    await expect(panel(page).getByRole("button", { name: "Refresh tasks" })).toBeEnabled();
});
Then("the backlog shows unassigned and colleague tasks", async ({ page }) => {
    await expect(panel(page).getByRole("button", { name: /Organize the shared folder/ })).toContainText("Unassigned");
    await expect(panel(page).getByRole("button", { name: /Review the project outline/ })).toContainText("Assigned to colleague");
    await expect(panel(page).getByRole("button", { name: /Earlier task/ })).toHaveCount(0);
    await expect(page.getByTestId("taskbar")).toBeVisible();
});
When("I open the backlog task {string}", async ({ page }, title: string) => {
    await panel(page).getByRole("button", { name: new RegExp(title) }).click();
});
Then("the backlog shows its instructions and separate claim", async ({ page }) => {
    await expect(panel(page).locator(".project-task-instructions")).toHaveText("Open Library, create an Agent, and describe how it should help you.");
    await expect(panel(page).locator(".project-task-facts")).toContainText("Assigned tolearnerClaimed byNo current claim");
    await expect(panel(page).getByRole("button", { name: "Mark complete" })).toBeDisabled();
    await page.screenshot({ path: "/var/tmp/desk-whip-backlog-ui.png", fullPage: true });
});
When("I include completed backlog tasks", async ({ page }) => {
    await panel(page).getByLabel("Show all tasks").check();
});
Then("the backlog shows {string}", async ({ page }, title: string) => {
    await expect(panel(page).getByRole("button", { name: new RegExp(title) })).toBeVisible();
});
When("the simulated tracker becomes read-only", async ({ page }) => { fixtures.get(page)!.canComplete = false; });
When("I refresh project tasks", async ({ page }) => {
    await panel(page).getByRole("button", { name: "Refresh tasks" }).click();
    await expect(panel(page).getByRole("button", { name: "Refresh tasks" })).toBeEnabled();
});
Then("the task completion form is unavailable", async ({ page }) => {
    await expect(panel(page).getByLabel("Completion note")).toHaveCount(0);
    await expect(panel(page).getByText("Completion isn’t available with your current access.")).toBeVisible();
});
When("the simulated backlog becomes unavailable", async ({ page }) => { fixtures.get(page)!.readable = false; });
Then("the backlog shows an error instead of old or empty tasks", async ({ page }) => {
    await expect(panel(page).getByRole("alert")).toContainText("You don’t currently have access to this tracker.");
    await expect(panel(page).getByText("No active tasks in this tracker.")).toHaveCount(0);
    await expect(panel(page).locator(".project-task-instructions")).toHaveCount(0);
    await expect(panel(page).getByRole("button", { name: /Make a personal assistant/ })).toHaveCount(0);
});
When("the simulated tracker requires sign-in", async ({ page }) => { fixtures.get(page)!.signedOut = true; });
Then("the backlog asks me to sign in", async ({ page }) => {
    await expect(panel(page).getByRole("alert")).toHaveText("Sign in to read project tasks.");
    await expect(panel(page).locator(".project-task-instructions")).toHaveCount(0);
});
async function submit(page: Page) {
    await panel(page).getByLabel("Completion note").fill("I made an assistant in Library.");
    await panel(page).getByLabel("Complete regardless of the current claim").check();
    await panel(page).getByRole("button", { name: "Mark complete" }).click();
}
When("I submit a completion whose response is lost", async ({ page }) => { fixtures.get(page)!.outcome = "lost"; await submit(page); });
When("I submit a completion that is still in flight", async ({ page }) => {
    fixtures.get(page)!.outcome = "held";
    await submit(page);
    await expect.poll(() => Boolean(fixtures.get(page)!.release)).toBe(true);
});
When("the original task completion returns", async ({ page }) => {
    const response = page.waitForResponse(response => response.url().endsWith("/complete"));
    fixtures.get(page)!.release!();
    await response;
});
Then("completion feedback does not appear on the other task", async ({ page }) => {
    // Removal from the active list proves that the completed command's UI
    // handler and subsequent read finished before checking the other detail.
    await expect(panel(page).getByRole("button", { name: /Make a personal assistant/ })).toHaveCount(0);
    await expect(panel(page).getByRole("heading", { name: "Review the project outline" })).toBeVisible();
    await expect(panel(page).getByText("Your completion was recorded.")).toHaveCount(0);
});
Then("the backlog offers the original completion retry", async ({ page }) => {
    await expect(panel(page).getByText("Couldn’t confirm completion. Retry will confirm the same request.")).toBeVisible();
    await expect(panel(page).getByLabel("Completion note")).toHaveCount(0);
});
Then("the original completion retry is disabled", async ({ page }) => {
    await expect(panel(page).getByRole("button", { name: "Retry completion" })).toBeDisabled();
    expect(fixtures.get(page)!.requests).toHaveLength(1);
});
When("I close and reopen the Personal task backlog", async ({ page }) => {
    await panel(page).getByRole("button", { name: "Close tasks" }).click();
    await page.locator("[data-project]", { hasText: "Personal" }).locator(".tree-node.project").click({ button: "right" });
    await page.locator(".menu-item").filter({ hasText: /^tasks…$/ }).click();
});
When("I retry the pending task completion", async ({ page }) => { await panel(page).getByRole("button", { name: "Retry completion" }).click(); });
Then("the same completion request is confirmed", async ({ page }) => {
    await expect(panel(page).getByText("Your completion was recorded.")).toBeVisible();
    const requests = fixtures.get(page)!.requests;
    expect(requests).toHaveLength(2);
    expect(requests[0].key).toBeTruthy();
    expect(requests[1]).toEqual(requests[0]);
    expect(requests[0].body).toEqual({ subject_id: "assistant-subject", summary: "I made an assistant in Library.", claim: { kind: "override" } });
});
When("I submit a completion that fails natively", async ({ page }) => { fixtures.get(page)!.outcome = "failed"; await submit(page); });
Then("the backlog reports failed completion", async ({ page }) => {
    await expect(panel(page).getByText("Completion did not succeed. Refresh the task before trying again.")).toBeVisible();
    await expect(panel(page).getByText("Your completion was recorded.")).toHaveCount(0);
});
