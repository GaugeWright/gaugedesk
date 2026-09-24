import { expect, type Page } from "@playwright/test";
import { createBdd } from "playwright-bdd";

const { Given, When, Then } = createBdd();
type Request = { path: string; key: string | undefined; body: unknown };
type Fixture = {
    readable: boolean; signedOut: boolean; canComplete: boolean; closed: boolean; outcome: "ok" | "lost" | "failed" | "held"; release?: () => void; requests: Request[];
    /** WHIP-4 controls: the simulated claim and assignment of each task, what
     *  every control request asked, and whether the next one is contested. */
    claims: Record<string, string | null>; assigned: Record<string, string | null>; controls: Request[]; contested: boolean;
};
const fixtures = new WeakMap<Page, Fixture>();
const panel = (page: Page) => page.getByRole("dialog", { name: "Personal tasks", exact: true });

Given("a simulated project tracker backlog", async ({ page }) => {
    const fixture: Fixture = {
        readable: true, signedOut: false, canComplete: true, closed: false, outcome: "ok", requests: [],
        claims: { "WS-3": "colleague" }, assigned: { "WS-1": "learner", "WS-2": null, "WS-3": "colleague", "WS-4": "learner" }, controls: [], contested: false,
    };
    fixtures.set(page, fixture);
    // The people a task can be directed at, as the Home's roster names them.
    await page.route(/\/roster$/, route => route.fulfill({ json: { people: [
        { authority: "learner", display: "Learner", role: "owner" },
        { authority: "colleague", display: "Colleague", role: "member" },
    ] } }));
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
        if (path.endsWith("/control")) {
            const body = request.postDataJSON() as { control: { kind: string; expected_holder?: string | null; expected_assignee?: string | null; assigned_to?: string | null } };
            fixture.controls.push({ path, key: request.headers()["idempotency-key"], body });
            const item = decodeURIComponent(path.split("/")[6]);
            if (fixture.contested) {
                fixture.contested = false;
                fixture.claims[item] = "colleague";
                await route.fulfill({ status: 409, json: { error: "The task change could not be confirmed" } });
                return;
            }
            const control = body.control;
            if (control.kind === "claim" || control.kind === "renew") fixture.claims[item] = "learner";
            if (control.kind === "release") fixture.claims[item] = null;
            if (control.kind === "assign") fixture.assigned[item] = control.assigned_to ?? null;
            await route.fulfill({ json: {
                snapshot: { admission: { instance_ref: "human-control" }, instance_status: "completed" },
                executed_effect: "control-effect", recovered_effect: null,
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
        const base = { body: "", labels: [], created_at: "2026-09-11T00:00:00Z", updated_at: "2026-09-11T00:00:00Z", filed_by: "learner" };
        const facts = (id: string) => ({
            assigned_to: fixture.assigned[id] ?? null,
            claimed_by: fixture.claims[id] ?? null,
            claim_expires_at: fixture.claims[id] ? "2026-09-11 16:00:00" : null,
        });
        const issues = [
            { ...base, ...facts("WS-1"), id: "WS-1", subject_id: "assistant-subject", title: "Make a personal assistant", body: "Open Library, create an Agent, and describe how it should help you.", status: fixture.closed ? "closed" : "open",
                closed_by: fixture.closed ? "learner" : null, closing_summary: fixture.closed ? "I made an assistant in Library." : null },
            { ...base, ...facts("WS-2"), id: "WS-2", subject_id: "unassigned-subject", title: "Organize the shared folder", status: "open" },
            { ...base, ...facts("WS-3"), id: "WS-3", subject_id: "colleague-subject", title: "Review the project outline", status: "in_progress" },
            { ...base, ...facts("WS-4"), id: "WS-4", subject_id: "earlier-subject", title: "Earlier task", status: "closed" },
        ];
        if (path.endsWith("/tasks")) {
            // The person's own queue carries the actor the Home authenticated.
            await route.fulfill({ json: { actor: "learner", tracker, issues: issues.filter(issue => issue.assigned_to === "learner" && ["open", "in_progress"].includes(issue.status)) } });
            return;
        }
        await route.fulfill({ json: { tracker, issues } });
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
    await expect(panel(page).getByLabel("Assigned to")).toHaveValue("learner");
    await expect(panel(page).locator("[data-task-claim]")).toHaveText("No current claim");
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

const controlKinds = (page: Page) => fixtures.get(page)!.controls.map(request => (request.body as { control: { kind: string } }).control.kind);
When("I take the task", async ({ page }) => {
    await panel(page).getByRole("button", { name: "Take this task" }).click();
});
Then("the task is mine until its lease runs out", async ({ page }) => {
    await expect(panel(page).getByText("You’ve taken this task.")).toBeVisible();
    await expect(panel(page).locator("[data-task-claim]")).toContainText("you until");
    await expect(panel(page).getByRole("button", { name: "Keep it longer" })).toBeVisible();
    const [claim] = fixtures.get(page)!.controls;
    expect(claim.body).toEqual({ subject_id: "unassigned-subject", control: { kind: "claim", lease_seconds: 14400 } });
    expect(claim.key).toBeTruthy();
});
When("I let the task go", async ({ page }) => {
    await panel(page).getByRole("button", { name: "Let it go" }).click();
});
Then("the task is released as its expected holder", async ({ page }) => {
    await expect(panel(page).getByText("You’ve let it go.")).toBeVisible();
    await expect(panel(page).locator("[data-task-claim]")).toHaveText("No current claim");
    const release = fixtures.get(page)!.controls.at(-1)!;
    expect(release.body).toEqual({ subject_id: "unassigned-subject", control: { kind: "release", expected_holder: "learner" } });
});
When("I assign the task to myself", async ({ page }) => {
    await panel(page).getByLabel("Assigned to").selectOption("learner");
});
Then("the task is reassigned only if it was still unassigned", async ({ page }) => {
    await expect(panel(page).getByText(/^Assigned to /)).toBeVisible();
    await expect(panel(page).getByLabel("Assigned to")).toHaveValue("learner");
    const assign = fixtures.get(page)!.controls.at(-1)!;
    expect(assign.body).toEqual({ subject_id: "unassigned-subject", control: { kind: "assign", expected_assignee: null, assigned_to: "learner" } });
    expect(controlKinds(page)).toEqual(["claim", "release", "assign"]);
});
When("someone else claims the task first", async ({ page }) => { fixtures.get(page)!.contested = true; });
Then("the backlog says the task changed and shows its holder", async ({ page }) => {
    await expect(panel(page).getByText("The task changed since you read it.", { exact: false })).toBeVisible();
    await expect(panel(page).locator("[data-task-claim]")).toContainText("Colleague");
    await expect(panel(page).getByText("It frees itself when Colleague’s claim runs out.")).toBeVisible();
});
Then("the closed task says who closed it and what they reported", async ({ page }) => {
    await expect(panel(page).locator("[data-task-closed-by]")).toHaveText("you");
    await expect(panel(page).locator("[data-task-closing-summary]")).toHaveText("I made an assistant in Library.");
});
