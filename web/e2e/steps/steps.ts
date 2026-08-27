/**
 * Step definitions for the GaugeDesk user stories. The client is a thin
 * renderer over the control plane, so the steps drive the real UI (clicks +
 * reads) and assert on rendered projections — never on internal state.
 *
 * The model (ADR 0035/0036): the nav is **project-first**, facets
 * **Recent | Projects | Library** (default Projects). An **archetype** is the
 * reusable method (Library); a **placement** is an archetype installed on a
 * **project** (Projects) — what you chat with to do work. A chat's **kind** is
 * its ROOT, fixed at creation: rooted on an archetype ⇒ an *edit* chat; rooted on
 * a placement ⇒ a *work* chat. There is no mode toggle. The default "Personal"
 * project is explicit and carries the zero-setup default placement.
 */

import { expect, type APIRequestContext, type Locator, type Page } from "@playwright/test";
import { createBdd } from "playwright-bdd";
import { mkdtemp, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { aliceCP } from "../ports.mjs";
import { mutationHeaders } from "./idempotency";

const { Given, When, Then, Before } = createBdd();

// Per-scenario clean slate. The whole suite shares ONE control plane, run serially,
// so without this the append-only store accumulates every prior scenario's projects,
// archetypes and chats — and later scenarios collide with the pile (a global
// `.first()` grabs a stale chat; a context menu opens off-screen on a tall tree).
// The test-only POST /test/reset route (gated by GAUGEDESK_TEST_RESET, set in
// fed-control-plane.sh) stops live agents, wipes the state, and re-seeds — so every
// scenario starts from the same fresh workbench, pollution-proof by construction.
Before(async ({ request }) => {
    const res = await request.post(`${aliceCP}/test/reset`, { headers: mutationHeaders() });
    if (!res.ok()) throw new Error(`control-plane reset failed: ${res.status()} ${await res.text()}`);
    await linkLiveModelCredential(request);
});

/** Link the live lane's model credential, through the production link route.
 *
 *  The lane has to do this per scenario, not once per run: the control plane
 *  wipes its state root at startup and the reset above wipes it again, and a
 *  linked credential lives in that state. So nothing linked interactively
 *  survives to the first turn, which is why every `@live-provider` scenario met
 *  the fresh-state scrim (modal, intercepting pointer events) and then, past it,
 *  a turn that failed closed with "No GaugeDesk-owned Codex OAuth credential is
 *  linked". Re-linking here is what makes the lane reach the provider at all,
 *  and so what makes the cancellation scenario cover the path it claims to.
 *
 *  The material is the operator's and stays theirs: `run.mjs` requires
 *  `GW_E2E_LIVE_TOKEN` before it will launch the lane, nothing is committed, and
 *  nothing is logged. For `openai-codex` the token is the GaugeDesk-owned OAuth
 *  bundle (`{"access","refresh","expires","accountId"}`, and an expired `access`
 *  is fine because the turn refreshes it); for a BYOK provider it is the API key. */
async function linkLiveModelCredential(request: APIRequestContext): Promise<void> {
    if (!process.env.GW_E2E_LIVE) return;
    const token = process.env.GW_E2E_LIVE_TOKEN;
    if (!token) {
        throw new Error(
            "the live lane needs GW_E2E_LIVE_TOKEN (see web/e2e/README.md); without it every turn fails closed on a missing credential",
        );
    }
    const provider = process.env.GW_E2E_LIVE_PROVIDER ?? "openai-codex";
    const res = await request.post(`${aliceCP}/account/credentials`, {
        headers: mutationHeaders(),
        data: { provider, token },
    });
    // The status and the provider name are safe to report; the token is not.
    if (!res.ok()) {
        throw new Error(`linking the live ${provider} credential failed: ${res.status()}`);
    }
}

// A fresh, uniquely-named project per call: the control plane is shared across
// scenarios (serial, single worker), so unique names keep them isolated.
let seq = 0;
function freshProjectName(): string {
    return `e2e-proj-${Date.now()}-${seq++}`;
}

// The project whose placement the multi-agent scenario opens several chats under
// (round-13): shared across that scenario's steps so "another chat under that
// placement" targets the same placement.
let concProject = "";
let exportDestination = "";

/** Create a project, place the (default) archetype on it, and return the project
 *  group locator — the placement under it is what work chats are rooted on. */
async function placeArchetypeOnFreshProject(page: Page): Promise<string> {
    const name = freshProjectName();
    await page.locator(".facet", { hasText: "Projects" }).click();
    await page.getByText("+ project", { exact: true }).click();
    await page.locator(".inline-edit").fill(name);
    await page.locator(".inline-edit").press("Enter");
    const group = page.locator(`.tree-group[data-project]`, { hasText: name });
    await expect(group.locator(".tree-node.project")).toBeVisible();
    // "add a method" opens the picker (#1); choose the first available method.
    await group.locator(".tree-node.project").click({ button: "right" });
    await page.locator(".menu-item", { hasText: "add an archetype" }).click();
    await pickFirstMethod(page);
    await ensureArchetypeLens(page, name);
    await expect(group.locator(".tree-subgroup[data-placement]").first()).toBeVisible();
    return name;
}

// The place picker (#1): pick the first listed method (an `[data-picker-archetype]`
// row, not the "+ create a new method" row).
async function pickFirstMethod(page: import("@playwright/test").Page) {
    await expect(page.locator("[data-place-picker]")).toBeVisible();
    await page.locator("[data-picker-archetype]").first().click();
}

// ADR 0112: projects open in the flat `chats` lens. Steps that address placement
// STRUCTURE (placement nodes, workstream groups, drag targets) pivot the project
// to its `by archetype` lens first. Idempotent; the lens persists for the
// scenario, so one pivot covers every later structural step on that project.
async function ensureArchetypeLens(page: import("@playwright/test").Page, name: string) {
    const toggle = page.locator("[data-project]", { hasText: name }).locator("[data-lens-toggle]");
    if ((await toggle.getAttribute("data-lens")) === "chats") await toggle.click();
}

// ---- navigation / setup ----

Given("the workbench is open", async ({ page }) => {
    await page.goto("/");
    await expect(page.locator(".facet.active", { hasText: "Projects" })).toBeVisible();
});

Then("the empty chat composer is ready", async ({ page }) => {
    await expect(page.locator("[data-empty-chat-composer] textarea[aria-label='Message']")).toBeVisible();
});

// A new engagement is a usable WORK chat: a chat rooted on a placement (an
// archetype installed on a project), opened and ready to task.
//
// Neither lane meets the fresh-state scrim, and neither dismisses one: the
// mock-LLM control plane answers `credentialRequired` false, and the live lane
// arrives with a credential linked (`linkLiveModelCredential`), so the overlay's
// condition (a run that needs a credential and has none) is false in both.
Given("a new engagement", async ({ page }) => {
    await page.goto("/");
    const project = await placeArchetypeOnFreshProject(page);
    const group = page.locator(`.tree-group[data-project]`, { hasText: project });
    await group.locator(".tree-subgroup[data-placement] [data-create='new-placement-chat']").first().click();
    // selected → the chat-status badge carries the raw run phase as data-run-phase
    // (its visible text is the plain-language label).
    await expect(page.getByTestId("run-phase")).toHaveAttribute("data-run-phase", "Init");
    // wait for the live SSE stream to connect before any task — the fake agent is
    // faster than the connection, so an early task would stream into the void.
    await expect(page.getByTestId("stream-ready")).toBeAttached();
});

// ---- tasking the agent ----

When("I task the agent with {string}", async ({ page }, prompt: string) => {
    // Target the composer input structurally, not by placeholder: a work chat reads
    // "task the agent…" but an edit chat reads "Describe what to change about …", so
    // a placeholder match silently fails in edit chats (round10:6).
    const composer = page.locator('[data-desktop-composer] textarea[aria-label="Message"]');
    await composer.fill(prompt);
    await sendDraft(composer);
    // Fake agent returns instantly; a real-model (@live) turn can take ~20s. The turn's
    // completion shows on the chat-status badge reaching the terminal run phase.
    await expect(page.getByTestId("run-phase")).toHaveAttribute("data-run-phase", "Completed", { timeout: 45_000 });
});

// ---- run lifecycle ----

Then("the run phase is {string}", async ({ page }, phase: string) => {
    await expect(page.getByTestId("run-phase")).toHaveAttribute("data-run-phase", phase);
});

// ---- human task queue (top bar) ----

Given("an assignable onboarding task", async ({ page, request }) => {
    const response = await request.post(`${aliceCP}/test/reset?assignable_task=true`, {
        headers: mutationHeaders(),
    });
    if (!response.ok()) throw new Error(`task seed failed: ${response.status()} ${await response.text()}`);
    const roster = page.waitForResponse((candidate) => {
        const url = new URL(candidate.url());
        return candidate.request().method() === "GET" && url.pathname === "/roster";
    });
    const tasks = page.waitForResponse((candidate) => {
        const url = new URL(candidate.url());
        return candidate.request().method() === "GET" && url.pathname === "/tasks";
    });
    await page.goto("/");
    expect((await roster).status()).toBe(200);
    const taskResponse = await tasks;
    expect(taskResponse.status()).toBe(200);
    expect((await taskResponse.json()).tasks).toEqual(expect.arrayContaining([
        expect.objectContaining({ kind: "issue", boundary: "account::global" }),
    ]));
    await expect(page.getByRole("combobox", {
        name: "assign Assign this onboarding step",
        exact: true,
    })).toBeVisible();
});

When("I assign the onboarding task to the active owner", async ({ page }) => {
    const assigned = page.waitForResponse((candidate) => {
        const url = new URL(candidate.url());
        return candidate.request().method() === "POST"
            && /^\/work-items\/[^/]+\/assign$/.test(url.pathname);
    });
    await page.getByRole("combobox", {
        name: "assign Assign this onboarding step",
        exact: true,
    }).selectOption("local-user");
    expect((await assigned).status()).toBe(200);
});

Then("the onboarding task shows the active owner", async ({ page }) => {
    await expect(page.getByRole("combobox", {
        name: "assign Assign this onboarding step",
        exact: true,
    })).toHaveValue("local-user");
});

// Only tool lines with additive detail (a command's full text / output, a file's
// contents) are expandable now; a file write is a tight non-expandable one-liner.
// So target the first *expandable* tool line, not merely the first tool line.
When("I expand the first tool line", async ({ page }) => {
    await page.locator('[data-testid="tool-line"] .tool-head.expandable').first().click();
});

Then("the first tool line is expanded", async ({ page }) => {
    await expect(
        page.locator('[data-testid="tool-line"] .tool-head.expandable .tool-caret').first(),
    ).toHaveText("▾");
});

// Round-8 #4: the expanded detail must be a plain sentence, never the raw
// `{"path":…}` JSON arg blob. The raw args are preserved on data-tool-args (for
// automation) but the visible text must not start with a "{".
Then("the expanded tool detail reads in plain language", async ({ page }) => {
    const detail = page.locator('[data-testid="tool-line"] .tool-detail-line').first();
    await expect(detail).toBeVisible();
    const text = (await detail.innerText()).trim();
    expect(text.startsWith("{")).toBe(false);
    expect(text).not.toMatch(/"path"|"command"/);
});

// ---- transcript ----

Then("the transcript shows {string}", async ({ page }, text: string) => {
    // A phrase may legitimately appear in more than one line — assert ≥1. Lifecycle
    // lines are shown in plain language but keep their raw phase on `data-line-text`,
    // so match either the visible text or the underlying raw line text.
    const byText = page.locator(".run .line", { hasText: text });
    const byRaw = page.locator(`.run .line[data-line-text="${text}"]`);
    await expect(byText.or(byRaw).first()).toBeVisible();
});

Then("a mediated tool line is shown", async ({ page }) => {
    // A boundary-mediated effect renders as a B4 tool line `▸ {tool} …` (run-chat.md);
    // blocked effects render separately. Its presence is the mediation made visible.
    await expect(page.locator('.run [data-testid="tool-line"]').first()).toBeVisible();
});

// ---- chat-log grouping + filter (view state over the transcript) ----

When("I collapse the first turn", async ({ page }) => {
    await page.locator('.run [data-testid="turn"] .turn-head').first().click();
});

Then("the first turn is collapsed", async ({ page }) => {
    const turn = page.locator('.run [data-testid="turn"]').first();
    await expect(turn).toHaveClass(/collapsed/);
    // The fold leaves a one-line gist in place of the turn body.
    await expect(turn.locator(".turn-summary")).toBeVisible();
});

Then("no tool line is shown", async ({ page }) => {
    await expect(page.locator('.run [data-testid="tool-line"]')).toHaveCount(0);
});

Then("no {string} tool line is shown", async ({ page }, category: string) => {
    await expect(page.locator(`.run [data-tool-category="${category}"]`)).toHaveCount(0);
});

When("I hide {string} tool calls from the chat log", async ({ page }, category: string) => {
    await page.locator("[data-transcript-filter]").click();
    await page.locator(`[data-filter-visible="${category}"]`).uncheck();
    // Dismiss the popover so the log is unobstructed for the following assertions.
    await page.locator(".popover-catcher").click();
});

Then("the chat log does not show {string}", async ({ page }, text: string) => {
    await expect(page.locator(".run .transcript")).not.toContainText(text);
});

When("I save the filter as default", async ({ page }) => {
    await page.locator("[data-transcript-filter]").click();
    await page.locator("[data-filter-save]").click();
    // The button acknowledges the persist before we dismiss the menu.
    await expect(page.locator("[data-filter-save]")).toHaveText(/Saved/);
    await page.locator(".popover-catcher").click();
});

When("I click the tool target {string}", async ({ page }, target: string) => {
    await page.locator(".run .tool-target", { hasText: target }).first().click();
});

Then("the content viewer shows {string}", async ({ page }, file: string) => {
    // Selecting a file only auto-switches to View when there's no pending review;
    // after a turn the viewer defaults to Changes (round-7 #3), so open View
    // explicitly rather than racing on whether the merge phase has loaded.
    await page.locator('[data-viewer-tabs] .tab[data-tab="view"]').click();
    await expect(page.locator("[data-file-view]")).toBeVisible();
    await expect(page.locator(".panel.content", { hasText: file })).toBeVisible();
});

// ---- shell / facets ----

Then("the facet {string} is active", async ({ page }, label: string) => {
    await expect(page.locator(".facet.active", { hasText: label })).toBeVisible();
});

Then("the facet {string} is present", async ({ page }, label: string) => {
    await expect(page.locator(".facet", { hasText: label })).toBeVisible();
});

When("I switch to the {string} facet", async ({ page }, label: string) => {
    await page.locator(".facet", { hasText: label }).click();
    await expect(page.locator(".facet.active", { hasText: label })).toBeVisible();
});

Then(
    "Recent shows a chat in project {string} with archetype {string} and workstream {string}",
    async ({ page }, project: string, archetype: string, workstream: string) => {
        const lineage = `${project} · ${archetype} · ${workstream}`;
        const row = page.locator("[data-recent-chat]", {
            has: page.locator("[data-recent-lineage]", { hasText: new RegExp(`^${lineage}$`) }),
        });
        await expect(row).toBeVisible();
        await expect(row.locator("[data-recent-lineage]")).toHaveText(lineage);
        await expect(row).not.toHaveAttribute("draggable", "true");
    },
);

Then("Recent shows no workstream groups", async ({ page }) => {
    await expect(page.locator("[data-recent-list] .ws-group")).toHaveCount(0);
    await expect(page.locator("[data-recent-list] [data-workstream]")).toHaveCount(0);
    await expect(page.locator("[data-recent-list] [data-main-workstream]")).toHaveCount(0);
});

Then("Recent uses the same menu as the chat's rooted row", async ({ page }) => {
    const rooted = page.locator('.chat-item.active[data-chat]:not([data-recent-chat])');
    await expect(rooted).toBeVisible();
    const chatId = await rooted.getAttribute("data-chat");
    await rooted.click({ button: "right" });
    const rootedItems = await page.locator(".context-menu .menu-item-label").allTextContents();
    await page.keyboard.press("Escape");

    await page.locator(".facet", { hasText: "Recent" }).click();
    const recent = page.locator(`[data-recent-chat="${chatId}"]`);
    await expect(recent).toBeVisible();
    await recent.click({ button: "right" });
    await expect(page.locator(".context-menu")).toBeVisible();
    const recentItems = await page.locator(".context-menu .menu-item-label").allTextContents();
    expect(recentItems).toEqual(rootedItems);
    expect(recentItems).toContain("rename");
    expect(recentItems).toContain("delete");
    expect(recentItems).toContain("fork");
});

When("I search the facets for {string}", async ({ page }, q: string) => {
    await page.locator('[data-testid="facet-search"]').fill(q);
});

When("I clear the facet search", async ({ page }) => {
    await page.locator('[data-testid="facet-search"]').fill("");
});

// Content search (SEARCH-1): a chat whose transcript matches surfaces in the tree
// carrying a snippet of the hit, even when its title does not match the query.
Then("a chat surfaces with a content snippet", async ({ page }) => {
    const snippet = page.locator("[data-snippet]").first();
    await expect(snippet).toBeVisible();
    // The snippet sits inside a real chat row (it is why the row stayed).
    await expect(snippet.locator("xpath=ancestor::*[contains(@class,'chat-item')]")).toBeVisible();
});

Then("the archetype {string} is hidden", async ({ page }, name: string) => {
    await expect(
        page.locator("[data-archetype] .node-label", { hasText: new RegExp(`^${name}$`) }),
    ).toHaveCount(0);
});

// ---- the archetype / project library (facet browser CRUD) ----

// Archetypes live in the Library facet.
Then("I see the archetype {string}", async ({ page }, name: string) => {
    await expect(
        page.locator("[data-archetype] .node-label", { hasText: new RegExp(`^${name}$`) }),
    ).toBeVisible();
});

Then("I see the project {string}", async ({ page }, name: string) => {
    await expect(page.locator("[data-project] .node-label", { hasText: new RegExp(`^${name}$`) })).toBeVisible();
});

When("I create an archetype named {string}", async ({ page }, name: string) => {
    await page.locator(".facet", { hasText: "Library" }).click();
    await page.getByText("+ agent", { exact: true }).click();
    await page.locator(".inline-edit").fill(name);
    await page.locator(".inline-edit").press("Enter");
    await expect(
        page.locator("[data-archetype] .node-label", { hasText: new RegExp(`^${name}$`) }),
    ).toBeVisible();
});

When("I create a Panel agent named {string}", async ({ page }, name: string) => {
    await page.locator(".facet", { hasText: "Library" }).click();
    await page.getByText("+ agent", { exact: true }).click();
    await page.getByRole("button", { name: "Panel agent", exact: true }).click();
    await page.locator(".inline-edit").fill(name);
    await page.locator(".inline-edit").press("Enter");
});

Then("the Panel agent {string} is in the Library", async ({ page }, name: string) => {
    const row = page.locator("[data-archetype]", { hasText: name });
    await expect(row.locator(".node-label", { hasText: new RegExp(`^${name}$`) })).toBeVisible();
    await expect(row.locator(".cfg-badge", { hasText: "Panel agent" })).toBeVisible();
});

When("I preview the Panel agent {string}", async ({ page }, name: string) => {
    await page.locator(".facet", { hasText: "Library" }).click();
    await page.locator("[data-archetype]", { hasText: name }).locator(".tree-node.archetype").click({ button: "right" });
    await page.locator(".menu-item-label", { hasText: /^preview$/ }).click();
});

Then("its disposable public preview is open", async ({ page }) => {
    await expect(page.getByRole("dialog", { name: /Preview/ })).toBeVisible();
    await expect(page.getByText(/Disposable public session/)).toBeVisible();
});

Then("the preview says it writes no production Inbox data", async ({ page }) => {
    await expect(page.getByText(/never enter Personal or a project Inbox/)).toBeVisible();
});

Then("the preview offers a real disposable Session", async ({ page }) => {
    const dialog = page.getByRole("dialog", { name: /Preview/ });
    await expect(dialog.getByRole("button", { name: "Start real Preview" })).toBeVisible();
    await expect(dialog.getByText("GaugeWright managed inference", { exact: true })).toBeVisible();
    await expect(dialog.getByText("Bring your own provider key", { exact: true })).toBeVisible();
});

When("I close the Panel agent preview", async ({ page }) => {
    await page
        .getByRole("dialog", { name: /Preview/ })
        .locator('button[aria-label="Close"]')
        .click();
});

When("I open settings for the Panel agent {string}", async ({ page }, name: string) => {
    await page.locator("[data-archetype]", { hasText: name }).locator(".tree-node.archetype").click({ button: "right" });
    await page.locator(".menu-item-label", { hasText: /^settings$/ }).click();
});

Then("its Panel contract editor is open", async ({ page }) => {
    await expect(page.locator("[data-panel-public-profile]")).toBeVisible();
    await expect(page.getByText("Published panels", { exact: true })).toBeVisible();
    await expect(page.getByText("Project Inbox collection", { exact: true })).toBeVisible();
});

When("I close the Agent settings", async ({ page }) => {
    await page.locator("[data-config-editor]").getByRole("button", { name: "close" }).click();
});

When("I place the Panel agent {string} on project {string}", async ({ page }, agent: string, project: string) => {
    await page.locator(".facet", { hasText: "Projects" }).click();
    await page.locator("[data-project]", { hasText: project }).locator(".tree-node.project").click({ button: "right" });
    await page.locator(".menu-item-label", { hasText: /^add an agent$/ }).click();
    await page.locator("[data-picker-archetype]", { hasText: agent }).click();
});

Then("project {string} has a Panel-agent placement without a new-chat action", async ({ page }, project: string) => {
    const placement = page.locator("[data-project]", { hasText: project }).locator(".tree-subgroup[data-placement]", { hasText: "Panel agent" });
    await expect(placement).toBeVisible();
    await expect(placement.locator("[data-create='new-placement-chat']")).toHaveCount(0);
    await expect(placement.locator("[data-create='preview-panel-agent']")).toBeVisible();
});

When("I open deployment for the Panel agent in project {string}", async ({ page }, project: string) => {
    await page.locator("[data-project]", { hasText: project }).locator(".tree-subgroup[data-placement]", { hasText: "Panel agent" }).locator(".tree-node.placement").click({ button: "right" });
    await page.locator(".menu-item-label", { hasText: /^deploy…$/ }).click();
});

Then("deployment shows the frozen public contract", async ({ page }) => {
    await expect(page.getByRole("dialog", { name: "Deploy Panel agent" })).toBeVisible();
    await expect(page.getByText("Frozen public contract", { exact: true })).toBeVisible();
    await expect(page.getByText(/Deployment operates it; it does not redefine it/)).toBeVisible();
});

Then("deployment exposes publication and Inbox controls", async ({ page }) => {
    const dialog = page.getByRole("dialog", { name: "Deploy Panel agent" });
    await expect(dialog.getByRole("button", { name: "Publish deployment" })).toBeVisible();
    await expect(dialog.getByRole("button", { name: "Open Inbox" })).toBeVisible();
});

When("I open the deployment Inbox", async ({ page }) => {
    await page.getByRole("dialog", { name: "Deploy Panel agent" }).getByRole("button", { name: "Open Inbox" }).click();
});

Then("the project Inbox for {string} is open", async ({ page }, project: string) => {
    await expect(page.getByRole("dialog", { name: `${project} Inbox` })).toBeVisible();
    await expect(page.getByText(/stays isolated until this project’s gate admits it/)).toBeVisible();
});

When("I create a project named {string}", async ({ page }, name: string) => {
    await page.locator(".facet", { hasText: "Projects" }).click();
    await page.getByText("+ project", { exact: true }).click();
    await page.locator(".inline-edit").fill(name);
    await page.locator(".inline-edit").press("Enter");
});

// An EDIT chat is rooted on an archetype — opened from its right-click menu ("edit").
When("I add an edit chat under the archetype {string}", async ({ page }, name: string) => {
    await page.locator(".facet", { hasText: "Library" }).click();
    await page
        .locator("[data-archetype]", { hasText: name })
        .locator(".tree-node.archetype")
        .click({ button: "right" });
    await page.locator(".menu-item", { hasText: "edit" }).click();
    // Creating the chat and opening its event stream are separate operations.
    // The scripted agent can finish before a late subscriber sees completion,
    // so never send until the same production SSE path used by work chats is up.
    await expect(page.getByTestId("stream-ready")).toBeAttached();
});

// Place an archetype onto a project → a placement (the old "bind").
When("I place an archetype on the project {string}", async ({ page }, name: string) => {
    await page.locator(".facet", { hasText: "Projects" }).click();
    await page
        .locator("[data-project]", { hasText: name })
        .locator(".tree-node.project")
        .click({ button: "right" });
    await page.locator(".menu-item", { hasText: "add an agent" }).click();
    await pickFirstMethod(page);
    await ensureArchetypeLens(page, name);
    await expect(
        page.locator("[data-project]", { hasText: name }).locator(".tree-subgroup[data-placement]").first(),
    ).toBeVisible();
});

// A WORK chat is rooted on a placement (do the job).
When("I add a chat under the placement", async ({ page }) => {
    await page.locator("[data-placement]").first().locator("[data-create='new-placement-chat']").click();
});

// Personal is the explicit zero-setup project (ADR 0097). Its chat action roots
// the new work chat on Personal's default placement.
When("I start a new chat in Personal", async ({ page }) => {
    const chats = page.locator(".chat-item");
    const before = await chats.count();
    await page.locator("[data-create='new-project-chat']").first().click();
    // `stream-ready` may already belong to the previously selected chat. Wait for
    // the standing workspace projection to contain the newly-created row before a
    // following step addresses "latest"; otherwise it can right-click the old row
    // while the refresh is still in flight (the intermittent WS-H timeout).
    await expect(chats).toHaveCount(before + 1);
    await expect(page.getByTestId("stream-ready")).toBeAttached();
});

// The just-created chat (active), rooted on a placement ⇒ a work chat (ADR 0035).
Then("the active chat is a work chat", async ({ page }) => {
    await expect(page.locator('[data-chat].active[data-kind="work"]')).toBeVisible();
});

Then("I see a chat in Personal", async ({ page }) => {
    await expect(page.locator(".facet.active", { hasText: "Projects" })).toBeVisible();
    await expect(page.locator("[data-project]", { hasText: "Personal" }).locator(".chat-item").first()).toBeVisible();
});

// WS-H: start a workstream from a chat row. Right-click the chat → "new workstream" →
// name it. The control plane creates the line on the chat's own placement and joins it.
When("I create a workstream named {string} from that chat", async ({ page }, name: string) => {
    await page.locator(".facet", { hasText: "Projects" }).click();
    await page.locator(".chat-item").first().click({ button: "right" });
    await page.locator(".menu-item", { hasText: "new workstream" }).click();
    await page.locator(".inline-edit").fill(name);
    await page.locator(".inline-edit").press("Enter");
    await ensureArchetypeLens(page, "Personal");
    // Creating the line and joining the chat are one asynchronous command chain.
    // Do not let a following facet switch outrun the resulting workspace refresh.
    const group = page.locator(".ws-group", {
        has: page.locator(".ws-label-name", { hasText: new RegExp(`^${name}$`) }),
    });
    await expect(group.locator(".ws-members .chat-item").first()).toBeVisible();
});

// The chat is now a member of the named line: it renders inside that workstream's
// group (a non-empty, visible group — the bug this guards against was the create
// landing silently with nothing shown).
Then("the chat is on the workstream {string}", async ({ page }, name: string) => {
    const group = page.locator(".ws-group", {
        has: page.locator(".ws-label-name", { hasText: new RegExp(`^${name}$`) }),
    });
    await expect(group).toBeVisible();
    await expect(group.locator(".ws-members .chat-item").first()).toBeVisible();
});

// Start a chat directly in a project (WS-H): the project's built-in general placement
// is hidden, so a project-level "+ new chat" opens a work chat with no archetype choice.
When("I start a chat in project {string}", async ({ page }, name: string) => {
    await page.locator(".facet", { hasText: "Projects" }).click();
    await page.locator("[data-project]", { hasText: name }).locator("[data-create='new-project-chat']").click();
});

// The chat appears directly under the project (in its general home), not under any
// placement node — proving the default placement is invisible plumbing.
Then("project {string} shows a chat", async ({ page }, name: string) => {
    await page.locator(".facet", { hasText: "Projects" }).click();
    await expect(
        page.locator("[data-project]", { hasText: name }).locator("[data-project-home] .chat-item").first(),
    ).toBeVisible();
});

// Leave the line via the chat's own context menu (WS-F): the chat returns to the
// placement mainline; the now-empty line stays for others to join.
When("I remove that chat from its workstream", async ({ page }) => {
    await page.locator(".ws-group .ws-members .chat-item").first().click({ button: "right" });
    await page.locator(".menu-item", { hasText: "leave workstream" }).click();
});

// An empty line is still shown — proving the create/leave landed and the line is
// joinable, not broken — but its member list is empty (no hint message; WS-H).
Then("the workstream {string} shows it has no chats yet", async ({ page }, name: string) => {
    const group = page.locator(".ws-group", {
        has: page.locator(".ws-label-name", { hasText: new RegExp(`^${name}$`) }),
    });
    await expect(group).toBeVisible();
    await expect(group.locator(".ws-members .chat-item")).toHaveCount(0);
});

// Archive the line via its label's context menu (WS-F): it re-homes members and is
// gone from the nav (only active lines render as groups). Archive is destructive, so
// the menu arms on the first click and runs on the confirming second (like delete).
When("I archive the workstream {string}", async ({ page }, name: string) => {
    await page.locator(".ws-label", { hasText: new RegExp(name) }).first().click({ button: "right" });
    await page.locator(".menu-item", { hasText: /^archive$/ }).click(); // arm
    await page.locator(".menu-item.confirming").click(); // confirm
});

Then("there is no workstream {string}", async ({ page }, name: string) => {
    await expect(
        page.locator(".ws-group", { has: page.locator(".ws-label-name", { hasText: new RegExp(`^${name}$`) }) }),
    ).toHaveCount(0);
});

// Promote the line into the placement mainline from its right-aligned nav control.
// The first click only arms the operation; the second is the explicit confirmation.
When("I promote the workstream {string}", async ({ page }, name: string) => {
    const group = page.locator(".ws-group", {
        has: page.locator(".ws-label-name", { hasText: new RegExp(`^${name}$`) }),
    });
    const merge = group.locator(".ws-merge");
    await merge.click();
    await expect(merge).toHaveText("Confirm merge");
    await merge.click();
});

When("I arm merge for workstream {string}", async ({ page }, name: string) => {
    const merge = page.locator(".ws-group", {
        has: page.locator(".ws-label-name", { hasText: new RegExp(`^${name}$`) }),
    }).locator(".ws-merge");
    await merge.click();
    await expect(merge).toHaveText("Confirm merge");
});

When("I click away from the workstream merge", async ({ page }) => {
    await page.locator("[data-main-workstream].ws-label").click();
});

Then("workstream {string} merge is not armed", async ({ page }, name: string) => {
    const merge = page.locator(".ws-group", {
        has: page.locator(".ws-label-name", { hasText: new RegExp(`^${name}$`) }),
    }).locator(".ws-merge");
    await expect(merge).toHaveText("Merge");
});

// Join the most-recently-created chat from Main to an existing line via its context
// menu (WS-H join from the rooted Projects facet). Main renders before named groups, so document
// order cannot identify this row once a named workstream exists.
When("I add the latest chat to the workstream {string}", async ({ page }, name: string) => {
    await page.locator("[data-main-workstream].ws-group .chat-item").last().click({ button: "right" });
    await page.locator(".menu-item", { hasText: `join "${name}"` }).click();
});

Then("the workstream {string} has {int} chats", async ({ page }, name: string, n: number) => {
    const group = page.locator(".ws-group", {
        has: page.locator(".ws-label-name", { hasText: new RegExp(`^${name}$`) }),
    });
    await expect(group.locator(".ws-members .chat-item")).toHaveCount(n);
});

When("I drag a chat from workstream {string} onto workstream {string}", async ({ page }, source, destination) => {
    const group = (name: string) => page.locator(".ws-group", {
        has: page.locator(".ws-label-name", { hasText: new RegExp(`^${name}$`) }),
    });
    const sourceRow = group(source).locator(".ws-members .chat-item").first();
    const destinationLabel = group(destination).locator(".ws-label");
    const destinationElement = await destinationLabel.elementHandle();
    if (!destinationElement) throw new Error(`missing workstream drop target ${destination}`);
    // Playwright's convenience `dragTo` cannot consistently retain DataTransfer across
    // delegated Solid handlers. Drive the browser's native drag event sequence directly.
    await sourceRow.evaluate((sourceElement, targetElement) => {
        const target = targetElement as HTMLElement;
        const dataTransfer = new DataTransfer();
        sourceElement.dispatchEvent(new DragEvent("dragstart", { bubbles: true, cancelable: true, dataTransfer }));
        target.dispatchEvent(new DragEvent("dragenter", { bubbles: true, cancelable: true, dataTransfer }));
        target.dispatchEvent(new DragEvent("dragover", { bubbles: true, cancelable: true, dataTransfer }));
        target.dispatchEvent(new DragEvent("drop", { bubbles: true, cancelable: true, dataTransfer }));
        sourceElement.dispatchEvent(new DragEvent("dragend", { bubbles: true, cancelable: true, dataTransfer }));
    }, destinationElement);
});

When("I drag a chat from workstream {string} onto Main", async ({ page }, source) => {
    const sourceRow = page.locator(".ws-group", {
        has: page.locator(".ws-label-name", { hasText: new RegExp(`^${source}$`) }),
    }).locator(".ws-members .chat-item").first();
    const mainLabel = page.locator("[data-main-workstream].ws-label").first();
    const mainElement = await mainLabel.elementHandle();
    if (!mainElement) throw new Error("missing Main workstream drop target");
    await sourceRow.evaluate((sourceElement, targetElement) => {
        const target = targetElement as HTMLElement;
        const dataTransfer = new DataTransfer();
        sourceElement.dispatchEvent(new DragEvent("dragstart", { bubbles: true, cancelable: true, dataTransfer }));
        target.dispatchEvent(new DragEvent("dragenter", { bubbles: true, cancelable: true, dataTransfer }));
        target.dispatchEvent(new DragEvent("dragover", { bubbles: true, cancelable: true, dataTransfer }));
        target.dispatchEvent(new DragEvent("drop", { bubbles: true, cancelable: true, dataTransfer }));
        sourceElement.dispatchEvent(new DragEvent("dragend", { bubbles: true, cancelable: true, dataTransfer }));
    }, mainElement);
});

Then("the archetype {string} is gone", async ({ page }, name: string) => {
    await expect(
        page.locator("[data-archetype] .node-label", { hasText: new RegExp(`^${name}$`) }),
    ).toHaveCount(0);
});

When("I delete the archetype {string}", async ({ page }, name: string) => {
    await page.locator(".facet", { hasText: "Library" }).click();
    await page
        .locator("[data-archetype]", { hasText: name })
        .locator(".tree-node.archetype")
        .click({ button: "right" });
    await page.locator(".menu-item", { hasText: /^delete$/ }).click(); // arm inline confirm
    await page.locator(".menu-item.confirming").click(); // confirm
});

// Tree collapse/expand (the node ▾/▸ icon).
When("I collapse the project {string}", async ({ page }, name: string) => {
    await page.locator(".facet", { hasText: "Projects" }).click();
    await page.locator("[data-project]", { hasText: name }).locator(".tree-node.project .node-icon").first().click();
});

When("I add a work chat in project {string}", async ({ page }, name: string) => {
    await page.locator(".facet", { hasText: "Projects" }).click();
    await ensureArchetypeLens(page, name);
    await page.locator("[data-project]", { hasText: name }).locator(".tree-subgroup[data-placement] [data-create='new-placement-chat']").first().click();
    await expect(page.getByTestId("run-phase")).toHaveAttribute("data-run-phase", "Init");
});

Then("the placement in project {string} shows a chat", async ({ page }, name: string) => {
    await page.locator(".facet", { hasText: "Projects" }).click();
    await ensureArchetypeLens(page, name);
    await expect(page.locator("[data-project]", { hasText: name }).locator(".tree-subgroup[data-placement] .chat-item").first()).toBeVisible();
});

// Per-placement config-only customization (placement.md): right-click the placement →
// customize → set notes → save. Tweaks this client's placement without forking.
When("I customize the placement in project {string} with notes {string}", async ({ page }, project: string, notes: string) => {
    await page.locator(".facet", { hasText: "Projects" }).click();
    await ensureArchetypeLens(page, project);
    await page
        .locator("[data-project]", { hasText: project })
        .locator(".tree-subgroup[data-placement] .tree-node.placement")
        .first()
        .click({ button: "right" });
    await page.locator(".menu-item", { hasText: "customize" }).click();
    await page.locator("[data-cfg-notes]").fill(notes);
    await page.locator("[data-cfg-save]").click();
});

Then("the placement in project {string} shows it is customized", async ({ page }, project: string) => {
    await expect(
        page.locator("[data-project]", { hasText: project }).locator("[data-placement-customized]").first(),
    ).toBeVisible();
});

// Fork lineage (ADR 0038): the fork carries a "forked from <source>" line.
Then("an archetype is forked from {string}", async ({ page }, source: string) => {
    await page.locator(".facet", { hasText: "Library" }).click();
    await expect(page.locator(".fork-lineage", { hasText: `forked from ${source}` })).toBeVisible();
});

// Pull the source's improvements into the fork (the archetype carrying that lineage).
When("I pull updates into the fork of {string}", async ({ page }, source: string) => {
    await page.locator(".facet", { hasText: "Library" }).click();
    await page
        .locator("[data-archetype]", { has: page.locator(".fork-lineage", { hasText: `forked from ${source}` }) })
        .locator(".tree-node.archetype")
        .first()
        .click({ button: "right" });
    await page.locator(".menu-item", { hasText: "pull updates from source" }).click();
});

When("I collapse the placement in project {string}", async ({ page }, name: string) => {
    await ensureArchetypeLens(page, name);
    await page.locator("[data-project]", { hasText: name }).locator(".tree-subgroup[data-placement] .tree-node.placement .node-icon").first().click();
});

Then("the placement in project {string} hides its chats", async ({ page }, name: string) => {
    await expect(page.locator("[data-project]", { hasText: name }).locator(".tree-subgroup[data-placement] .chat-item")).toHaveCount(0);
});

Then("the project {string} hides its placements", async ({ page }, name: string) => {
    await expect(page.locator("[data-project]", { hasText: name }).locator(".tree-subgroup")).toHaveCount(0);
});

// C1 many-to-many: placing one archetype on N projects must REUSE it, not clone it —
// so the Library still lists a single archetype after two placements.
Then("the Library lists {int} archetype", async ({ page }, n: number) => {
    await page.locator(".facet", { hasText: "Library" }).click();
    await expect(page.locator("[data-archetype]")).toHaveCount(n);
});

Then("the project {string} shows its placements", async ({ page }, name: string) => {
    // The placement may have been made from the *Library* side (the reverse "place
    // on a project…" flow leaves you on Library); the project tree lives under the
    // Projects facet, so pivot there before reading it.
    await page.locator(".facet", { hasText: "Projects" }).click();
    await ensureArchetypeLens(page, name);
    await expect(page.locator("[data-project]", { hasText: name }).locator(".tree-subgroup").first()).toBeVisible();
});

// Fork (ADR 0035/0038).
When("I fork the archetype {string}", async ({ page }, name: string) => {
    await page.locator(".facet", { hasText: "Library" }).click();
    await page
        .locator("[data-archetype]", { hasText: name })
        .locator(".tree-node.archetype")
        .first()
        .click({ button: "right" });
    await page.locator(".menu-item", { hasText: /^fork$/ }).click();
});

Then("I see a forked copy of the archetype {string}", async ({ page }, name: string) => {
    await page.locator(".facet", { hasText: "Library" }).click();
    await expect(page.locator("[data-archetype] .node-label", { hasText: `${name} (fork)` }).first()).toBeVisible();
});

When("I fork the first chat", async ({ page }) => {
    await page.locator("[data-chat].active").click({ button: "right" });
    await page.locator(".menu-item", { hasText: /^fork$/ }).click();
});

Then("I see a forked chat", async ({ page }) => {
    await expect(page.locator(".chat-item", { hasText: "(fork)" }).first()).toBeVisible();
});

// Round-8 #3: the forked row carries a quiet "copy of {source}" sublabel so its
// lineage is legible (it's not just a coincidental name-twin of its source).
Then("the forked chat shows it is a copy of its source", async ({ page }) => {
    const sub = page.locator(".chat-item", { hasText: "(fork)" }).first().locator(".leaf-sub");
    await expect(sub).toBeVisible();
    await expect(sub).toContainText("copy of");
});

// Round-8 #3, revised by ADR 0141: a fork inherits its parent's transcript, so
// the first-view note appears only when there was no history to inherit (the
// parent had run no turns) — and says what did carry over: the files.
Then(
    "the chat shows it started as a copy with its files",
    async ({ page }) => {
        await page.locator(".chat-item", { hasText: "(fork)" }).first().click();
        const note = page.locator("[data-fork-note]");
        await expect(note).toBeVisible();
        await expect(note).toContainText("files came along");
    },
);

// ADR 0141: the seam in a fork's transcript where inherited lineage history
// ends and the chat's own lines begin.
Then("the fork point marker is visible", async ({ page }) => {
    await expect(page.locator("[data-fork-boundary]").first()).toBeVisible();
});

// ---- edit vs work chats (chat rooting, ADR 0035) ----

// An edit chat is created under an archetype, via its context menu.
When("I create an edit chat under the archetype {string}", async ({ page }, name: string) => {
    await page.locator(".facet", { hasText: "Library" }).click();
    await page
        .locator("[data-archetype]", { hasText: name })
        .locator(".tree-node.archetype")
        .click({ button: "right" });
    await page.locator(".menu-item", { hasText: "edit" }).click();
    // Creation navigates asynchronously. Do not let the next step operate on the
    // quick-start composer that was visible before the new edit chat was selected.
    await expect(page.locator('[data-chat].active[data-kind="edit"]')).toBeVisible();
    await expect(page.getByTestId("stream-ready")).toBeAttached();
});

// The chat's kind (its root) is shown read-only, with no toggle and no composer
// caption. It is anchored on the header's status gem rather than the context slot:
// the gem's glyph *is* the kind and it is present for every selected chat, while
// the context slot names the project and is deliberately empty in the Personal
// project, which names nothing a reader does not already know.
Then("the chat pane kind is {string}", async ({ page }, kind: string) => {
    await expect(page.locator(`.chat-heading .status-gem[data-kind="${kind}"]`)).toBeVisible();
});

Then("an edit chat is marked in the nav", async ({ page }) => {
    // The just-created chat (active), not the first edit chat in an accumulated tree.
    await expect(page.locator('[data-chat].active[data-kind="edit"]')).toBeVisible();
});

When("I reopen the chat", async ({ page }) => {
    await page.locator("[data-chat].active").click();
    await expect(page.getByTestId("stream-ready")).toBeAttached();
});

When("I reload the workbench", async ({ page }) => {
    await page.reload();
    await expect(page.locator(".facet.active", { hasText: "Projects" })).toBeVisible();
});

// ---- content viewer (view / edit / diff) ----

When("I select the file {string} in the workspace", async ({ page }, file: string) => {
    await page.locator("[data-worktree] .file", { hasText: file }).click();
});

Then("the target workspace does not contain {string}", async ({ page }, file: string) => {
    await expect(page.locator("[data-worktree] .file", { hasText: file })).toHaveCount(0);
});

When("I replace the editor content with {string}", async ({ page }, text: string) => {
    await page.locator("[data-file-edit]").fill(text);
});

When("I save the file", async ({ page }) => {
    await page.locator("[data-file-save]").click();
    await expect(page.locator("[data-edit-status]")).toHaveText("saved");
});

Then("the file view shows {string}", async ({ page }, text: string) => {
    await expect(page.locator("[data-file-view]")).toContainText(text);
});

When("I open the {string} tab", async ({ page }, tab: string) => {
    // The visible label may be plain language ("changes" for the diff), so match
    // the stable data-tab mode value the feature passes (view/edit/diff).
    await page.locator(`[data-viewer-tabs] .tab[data-tab="${tab}"]`).click();
});

Then("the diff shows {string}", async ({ page }, text: string) => {
    await expect(page.locator(".diff", { hasText: text })).toBeVisible();
});

// ---- the review/audit shelf (an overlay surface) ----

When("I open the audit shelf", async ({ page }) => {
    await page.getByRole("button", { name: "History", exact: true }).click();
    // In the user-facing build the Activity list is the only thing in the drawer
    // (no tabs); the tab only exists under dev mode. Click it only if present.
    const auditTab = page.locator('.shelf-drawer .tab[data-tab="audit"]');
    if (await auditTab.count()) await auditTab.click();
});

// ---- audit ----

Then("the audit timeline shows {string}", async ({ page }, text: string) => {
    // Raw engine event names (RunRequested, …) live behind the developer "raw
    // event log" toggle now (round-6 #1); the default view is plain-language
    // activity. The toggle only renders once the audit events have loaded, so wait
    // for it rather than a one-shot count() that can read 0 mid-fetch and skip the
    // reveal (the same race that bit config:13). Reveal only if not already shown.
    const toggle = page.locator("[data-raw-log-toggle]");
    await toggle.waitFor();
    if (!(await page.locator("[data-raw-log]").count())) await toggle.click();
    await expect(page.locator("[data-raw-log] .event", { hasText: text })).toBeVisible();
});

// ---- archetype settings (config) ----

When("I open the config editor", async ({ page }) => {
    // Settings live on the archetype now (ADR 0035): Library → right-click the
    // default archetype → settings.
    await page.locator(".facet", { hasText: "Library" }).click();
    await page.locator("[data-archetype] .tree-node.archetype").first().click({ button: "right" });
    await page.locator(".menu-item", { hasText: /^settings$/ }).click();
    await expect(page.locator("[data-config-editor]")).toBeVisible();
});

When("I set the config to {string}", async ({ page }, json: string) => {
    // The raw settings text is now a collapsed "Advanced" surface (round 5 #5):
    // the plain form leads. Reveal Advanced, then edit the JSON. Click the toggle
    // directly (it auto-waits) rather than a one-shot isVisible() check, which can
    // read false before the modal paints and skip the reveal (config:13 race).
    await page.locator("[data-settings-advanced-toggle]").click();
    await page.locator("[data-config-text]").fill(json);
    await page.locator("[data-settings-save]").click();
});

Then("the config status shows {string}", async ({ page }, text: string) => {
    await expect(page.locator("[data-config-status]").last()).toContainText(text);
});

When("I close the config editor", async ({ page }) => {
    await page.getByRole("button", { name: "close", exact: true }).click();
    await expect(page.locator("[data-config-editor]")).toBeHidden();
});

// ---- context ingestion ----

When("I attach the context folder {string}", async ({ page }, path: string) => {
    // The browser build ingests context by uploading the picked folder's file
    // *contents* (ENTSEC-5), not by a server-local path — browsers hide real paths.
    // Playwright drives the hidden `webkitdirectory` input by handing it a real
    // directory path, which it walks and uploads; `path` is that folder (its files,
    // e.g. gaugewright-plugin.ts, are what downstream diff/context assertions look
    // for). No `Add files` click is needed — the input is set programmatically.
    await page.locator("[data-add-folder-input]").setInputFiles(path);
});

When("I reload as the desktop app and add the repository plugin folder", async ({ page }) => {
    const pluginPath = resolve(process.cwd(), "../plugin");
    await page.addInitScript(({ selectedPath }) => {
        Object.defineProperty(window, "__TAURI_INTERNALS__", {
            configurable: true,
            value: {
                invoke: async (command: string) =>
                    command === "plugin:dialog|open" ? selectedPath : null,
            },
        });
    }, { selectedPath: pluginPath });
    await page.reload();
    const addFiles = page.getByRole("button", { name: "Add files" });
    await expect(addFiles).toBeVisible();
    const responsePromise = page.waitForResponse((response) => {
        const url = new URL(response.url());
        return response.request().method() === "POST"
            && /^\/chats\/[^/]+\/context$/.test(url.pathname);
    });
    await addFiles.click();
    const response = await responsePromise;
    expect(response.status()).toBe(200);
    expect(await response.json()).toMatchObject({
        ingested: expect.any(Number),
    });
});

// ---- message attachments (composer paperclip, UX-14) ----

// Clip a file to the message being composed. The paperclip opens a plain file
// input ([data-attach-input]); its text is read client-side and rides the next
// prompt — no backend ingest. setInputFiles hands an in-memory file to that input.
When(
    "I attach the file {string} containing {string}",
    async ({ page }, name: string, content: string) => {
        await page.locator("[data-attach-input]").setInputFiles({
            name,
            mimeType: "text/plain",
            buffer: Buffer.from(content),
        });
        await expect(page.locator("[data-attachment]", { hasText: name })).toBeVisible();
    },
);

// A 1x1 transparent PNG — enough for the client to classify + base64 + chip it.
const TINY_PNG = Buffer.from(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+M8AAAMBAQDJ/pLvAAAAAElFTkSuQmCC",
    "base64",
);

When("I attach a PNG image {string}", async ({ page }, name: string) => {
    await page.locator("[data-attach-input]").setInputFiles({
        name,
        mimeType: "image/png",
        buffer: TINY_PNG,
    });
});

When("I paste a PNG image {string}", async ({ page }, name: string) => {
    await page.locator("[data-desktop-composer] textarea").evaluate(
        (composer, image) => {
            const bytes = Uint8Array.from(atob(image.base64), (character) =>
                character.charCodeAt(0),
            );
            const transfer = new DataTransfer();
            transfer.items.add(new File([bytes], image.name, { type: "image/png" }));
            composer.dispatchEvent(new ClipboardEvent("paste", {
                bubbles: true,
                cancelable: true,
                clipboardData: transfer,
            }));
        },
        { name, base64: TINY_PNG.toString("base64") },
    );
});

Then("the composer shows an image attachment {string}", async ({ page }, name: string) => {
    await expect(page.locator(`[data-attachment][data-kind="image"]`, { hasText: name })).toBeVisible();
});

// A minimal, valid DOCX package containing one paragraph. Its bytes stay in the
// browser; the composer only receives the locally extracted text.
const TINY_DOCX = Buffer.from(
    "UEsDBBQAAAAIAN0A7lzMVIwQ4AAAAJwBAAATAAAAW0NvbnRlbnRfVHlwZXNdLnhtbH2Qy07DMBBFf8XyFsUOLBBCSbrgsQQW5QNG9iSx8Eset5S/Z9KWLlDbpX0fZ3S71S54scVCLsVe3qpWCowmWRenXn6uX5sHuRq69U9GEmyN1Mu51vyoNZkZA5BKGSMrYyoBKj/LpDOYL5hQ37XtvTYpVoy1qUuHHLpnHGHjq3jZ8fcBW9CTFE8H48LqJeTsnYHKut5G+4/SHAmKk3sPzS7TDRukPktYlMuAY+6ddyjOoviAUt8gsEt/p2K1TWYTOKmu15y5M42jM3jKL225JINEPHDw6qQEcPHvfr2fe/gFUEsDBBQAAAAIAN0A7lw2V97cogAAABgBAAALAAAAX3JlbHMvLnJlbHONzzsOwjAMBuCrRN6pCwNCqGkXhNQVlQNEiZtGNA8l4XV7MjBQxMBo+/dnuekedmY3isl4x2Fd1cDISa+M0xzOw3G1g65tTjSLXBJpMiGxsuIShynnsEdMciIrUuUDuTIZfbQilzJqDEJehCbc1PUW46cBS5P1ikPs1RrY8Az0j+3H0Ug6eHm15PKPE1+JIouoKXO4+6hQvdtVYQHbBhcvti9QSwMEFAAAAAgA3QDuXLF/RYedAAAA0gAAABEAAAB3b3JkL2RvY3VtZW50LnhtbDWOuw7CMAxFfyXKTlMYEKr62JgZQMwlcR9SEkdOIPD3OEUsx497feV2eDsrXkBxRd/JfVVLAV6jWf3cydv1vDvJoW9zY1A/Hfgk2O9jkzu5pBQapaJewI2xwgCetQnJjYlHmlVGMoFQQ4wc56w61PVRuXH1skQ+0HxKDQVUkPoFrEUxETpx5+tWlWUh68zNGkGnC6lt8cvg5v9f/wVQSwECFAAUAAAACADdAO5czFSMEOAAAACcAQAAEwAAAAAAAAAAAAAAAAAAAAAAW0NvbnRlbnRfVHlwZXNdLnhtbFBLAQIUABQAAAAIAN0A7lw2V97cogAAABgBAAALAAAAAAAAAAAAAAAAABEBAABfcmVscy8ucmVsc1BLAQIUABQAAAAIAN0A7lyxf0WHnQAAANIAAAARAAAAAAAAAAAAAAAAANwBAAB3b3JkL2RvY3VtZW50LnhtbFBLBQYAAAAAAwADALkAAACoAgAAAAA=",
    "base64",
);

When("I attach a DOCX document {string}", async ({ page }, name: string) => {
    await page.locator("[data-attach-input]").setInputFiles({
        name,
        mimeType: "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        buffer: TINY_DOCX,
    });
    await expect(page.locator(`[data-attachment][data-kind="text"]`, { hasText: name })).toBeVisible();
});

/** Build a small valid PDF with exact xref offsets so PDF.js exercises its real
 *  browser worker rather than a mocked parser. */
function tinyPdf(text: string): Buffer {
    const escaped = text.replaceAll("\\", "\\\\").replaceAll("(", "\\(").replaceAll(")", "\\)");
    const stream = `BT /F1 12 Tf 72 720 Td (${escaped}) Tj ET`;
    const objects = [
        "<< /Type /Catalog /Pages 2 0 R >>",
        "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>",
        "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        `<< /Length ${Buffer.byteLength(stream)} >>\nstream\n${stream}\nendstream`,
    ];
    let body = "%PDF-1.4\n";
    const offsets = [0];
    for (const [index, object] of objects.entries()) {
        offsets.push(Buffer.byteLength(body));
        body += `${index + 1} 0 obj\n${object}\nendobj\n`;
    }
    const xref = Buffer.byteLength(body);
    body += `xref\n0 ${objects.length + 1}\n0000000000 65535 f \n`;
    body += offsets
        .slice(1)
        .map((offset) => `${offset.toString().padStart(10, "0")} 00000 n \n`)
        .join("");
    body += `trailer\n<< /Size ${objects.length + 1} /Root 1 0 R >>\nstartxref\n${xref}\n%%EOF\n`;
    return Buffer.from(body);
}

When(
    "I attach the PDF document {string} containing {string}",
    async ({ page }, name: string, content: string) => {
        await page.locator("[data-attach-input]").setInputFiles({
            name,
            mimeType: "application/pdf",
            buffer: tinyPdf(content),
        });
        await expect(page.locator(`[data-attachment][data-kind="text"]`, { hasText: name })).toBeVisible();
    },
);

Then("the composer has no pending attachments", async ({ page }) => {
    await expect(page.locator("[data-attachment]")).toHaveCount(0);
});

// ---- send queue & steering (composer dock) ----

// How the turn route answered each turn this scenario started, in order. It is
// the one value carrying the *reason* a turn ended: the engine classifies the
// outcome and the status carries that classification out (499 for a stop, 502 for
// a fault, 403 for a refusal, 200 for a turn that ran to a phase). Recorded from
// the moment the turn starts, so an answer cannot arrive while nothing is
// listening.
let turnOutcomes: number[] = [];
const recordingTurnOutcomes = new WeakSet<Page>();
function recordTurnOutcomes(page: Page): void {
    turnOutcomes = [];
    if (recordingTurnOutcomes.has(page)) return;
    recordingTurnOutcomes.add(page);
    page.on("response", (response) => {
        if (response.request().method() !== "POST") return;
        if (!/^\/chats\/[^/]+\/task$/.test(new URL(response.url()).pathname)) return;
        turnOutcomes.push(response.status());
    });
}

// Start a turn without waiting for it to settle, so the queue can be exercised
// while the agent is busy. Pair with a `[slow]` prompt to widen that window.
When("I start tasking the agent with {string}", async ({ page }, prompt: string) => {
    recordTurnOutcomes(page);
    const composer = page.getByPlaceholder("task the agent…");
    await composer.fill(prompt);
    await sendDraft(composer);
});

Then("the agent is working", async ({ page }) => {
    await expect(page.getByTestId("agent-working")).toBeVisible();
});

/** What a pointer aiming at the send button actually reaches.
 *
 *  The destination menu opens on hover and deliberately lays its **active row
 *  over the button** (round 10), so that moving toward the menu never crosses an
 *  un-hovered gap and a click without moving still hits the destination the
 *  button was offering. Both dispatch the same thing, so for a person the two
 *  are one control.
 *
 *  Playwright is stricter than a person: it hovers, the menu opens, the row is
 *  now the hit target, and it refuses to click an element something else
 *  intercepts — reporting the row's own glyph as the interceptor and retrying
 *  until the test times out. Clicking the row is not a workaround for that; the
 *  row is the honest target, because it is what the pointer lands on. */
/** Send the draft the way the composer is built to be driven: ⏎ follows the mode,
 *  and these steps all run in the default one.
 *
 *  Clicking the primary is deliberately awkward to automate, and the awkwardness
 *  is the design rather than a defect. The destination menu lays its active row
 *  over the button (round 10) so the pointer never crosses an un-hovered gap —
 *  which means at rest the row's own centre is over the *textarea*, and hovered
 *  it is over the button. Either way Playwright's hit-test finds something other
 *  than the element it was asked to click and retries until the test times out.
 *  The pointer path is real and is covered once, in `composer.feature`; every
 *  other step here just needs the message sent. */
const sendDraft = (composer: Locator) => composer.press("Enter");

/** The delivery cluster: the primary button plus the destination menu that opens
 *  over it. Hovering the *stack* is what arms the menu, so the pointer path has
 *  to be driven in that order — hover the cluster, then act on what it shows. */
const deliveryStack = (page: Page) =>
    page.locator('[data-desktop-composer] .deliver-stack').last();

When("I type {string} into the composer", async ({ page }, text: string) => {
    await page.locator('[data-desktop-composer] textarea[aria-label="Message"]').fill(text);
});

When("I click the primary destination", async ({ page }) => {
    const stack = deliveryStack(page);
    // Hover first: at rest the menu is `pointer-events: none`, so the row that
    // will receive this click is not yet the hit target.
    await stack.hover();
    await stack.locator(".deliver-option.primary").click();
});

When("I hover the primary destination", async ({ page }) => {
    await deliveryStack(page).hover();
});

Then("the destination menu offers {string}", async ({ page }, destination: string) => {
    // Assert against the whole offered set rather than one locator: a missing
    // destination then fails with the list that *was* offered, which is the
    // difference between "something is wrong" and knowing which capability the
    // Environment declined. Scoped to the desktop composer — an unselected shell
    // also mounts a quick-start composer.
    const offered = page.locator("[data-desktop-composer] [data-deliver-option]");
    await expect(offered.first()).toBeAttached();
    const ids = await offered.evaluateAll((els) =>
        els.map((el) => el.getAttribute("data-deliver-option")));
    expect(ids, "destinations offered by the composer").toContain(destination);
});

// Enter follows the composer's mode, so a step that means "queue this" says so
// with the chord that always reaches the queue whatever mode is set. Queueing
// needs something to queue behind: use this only while a turn is running.
When("I queue the message {string}", async ({ page }, text: string) => {
    await page.getByPlaceholder("task the agent…").fill(text);
    await page.getByPlaceholder("task the agent…").press("Control+Enter");
    await expect(page.getByTestId("queue-item").filter({ hasText: text })).toBeVisible();
});

// The same, for the destination that holds: joins the queue but nothing runs it.
When("I stash the message {string}", async ({ page }, text: string) => {
    await page.getByPlaceholder("task the agent…").fill(text);
    await page.getByPlaceholder("task the agent…").press("Alt+Enter");
    await expect(
        page.getByTestId("queue-item").filter({ hasText: text }),
    ).toHaveAttribute("data-held", "");
});

// Plain Enter, deliberately: this is the step for asserting what the *mode* does
// with a message, so it must not name a destination.
When("I send the message {string}", async ({ page }, text: string) => {
    await page.getByPlaceholder("task the agent…").fill(text);
    await page.getByPlaceholder("task the agent…").press("Enter");
});

// Stop a running turn (run-chat.md): abort, the composer re-enables.
When("I stop the turn", async ({ page }) => {
    await page.getByTestId("stop-turn").click();
});

// Paired with a `[hold]` prompt, which nothing outlasts: a turn that ends here
// ended because it was interrupted, not because its window expired.
Then("the turn ends promptly", async ({ page }) => {
    await expect(page.getByTestId("agent-working")).toBeHidden({ timeout: 8_000 });
});

// A real cancellation crosses a store and a provider delegate, so it is slower
// than the fake's condvar — but it is still an interrupt, not a wait: the turn
// it stops would run for minutes.
Then("the real turn ends within twenty seconds", async ({ page }) => {
    await expect(page.getByTestId("agent-working")).toBeHidden({ timeout: 20_000 });
});

// The counterfactual, which is what makes the assertion above mean anything: a
// turn that ran to the end would have said its closing word.
//
// Scoped to what the agent said, not to the transcript: the prompt asking for
// that closing word is itself in the transcript, so the whole-pane form could
// never pass — it read its own instruction back as the agent's answer.
Then("the agent never says {string}", async ({ page }, marker: string) => {
    await expect(page.locator(".run .transcript .line.assistant")).not.toContainText(marker);
});

// The receipt that says *cancelled*, instead of leaving cancellation inferred
// from timing plus the absence of model-controlled text. A real provider has
// other ways to go quiet inside the assertion window (a rate limit, a dropped
// transport, a refusal, a turn that simply finished early), and every one of them
// would also hide `agent-working` and omit the closing marker.
//
// None of them answers this. `499` (`TURN_STOPPED_STATUS`, minted by
// `task_failure_status`) is reached for exactly one leg,
// `EngineError::Interrupted`, and the engine reaches that leg only by asking the
// claim that recorded the interrupt landing: the harness stream died AND this
// turn was stopped on purpose. A fault answers `502`, a policy refusal `403`, and
// a turn that reached a phase answers `200`, so a provider that ignored the
// interrupt cannot pass this step.
const TURN_STOPPED_STATUS = 499;
Then("the stop is receipted as a cancellation", async () => {
    await expect
        .poll(() => turnOutcomes, {
            message: "what the turn route answered for this scenario's turns",
            timeout: 25_000,
        })
        .toEqual([TURN_STOPPED_STATUS]);
});

Then("the composer shows no error", async ({ page }) => {
    await expect(page.locator("[data-composer-error]")).toHaveCount(0);
});

// The pointer path a person takes to Stop crosses the delivery cluster, which
// opens the destination menu over it. Hover the cluster first, so the hit test
// below asks the question that actually bit: not "is the button there" but "is
// the button reachable once the menu it sits beside is open".
When("I aim at the stop button with the delivery menu open", async ({ page }) => {
    await page.locator(".deliver-stack").hover();
    await expect(page.locator("[data-deliver-menu]")).toHaveCSS("opacity", "1");
});

Then("every part of the stop button reaches stop", async ({ page }) => {
    const covered = await page.evaluate(() => {
        const stop = document.querySelector('[data-testid="stop-turn"]')!;
        const box = stop.getBoundingClientRect();
        return [0.05, 0.25, 0.5, 0.75, 0.95]
            .filter((across) => {
                const at = document.elementFromPoint(
                    box.left + box.width * across,
                    box.top + box.height / 2,
                );
                return !stop.contains(at);
            })
            .map((across) => `${Math.round(across * 100)}%`);
    });
    expect(covered, "these points across the stop button hit something else").toEqual([]);
});

// Escape wherever the previous step left focus, which is the point: sending the
// turn leaves it in the field, opening a menu leaves it on that menu's button,
// and Escape has to mean the right thing from both. Forcing focus somewhere
// first would test a state no one can actually be in.
When("I press Escape in the composer", async ({ page }) => {
    await page.keyboard.press("Escape");
});

When("I open the composer mode menu", async ({ page }) => {
    await page.locator("[data-mode-picker]").click();
    await expect(page.locator("[data-mode-menu]")).toBeVisible();
});

Then("the composer mode menu is closed", async ({ page }) => {
    await expect(page.locator("[data-mode-menu]")).toHaveCount(0);
});
Then("the composer is ready to send again", async ({ page }) => {
    await expect(page.getByTestId("send-msg")).toBeVisible();
});
// Panel captions are empty-state placeholders: with no chat open the chat and
// content panes carry their captions; opening a chat replaces them with the
// working rows (the chat's own header, the viewer's tab strip). The nav never
// captions — the facet tabs are always its top row. Files always captions.
Then("the browse pane opens with the facet tabs and no caption", async ({ page }) => {
    await expect(page.locator(".panel.nav .panel-heading")).toHaveCount(0);
    await expect(page.locator(".panel.nav .facets")).toBeVisible();
});
Then("the run pane is labelled {string}", async ({ page }, label) => {
    await expect(page.locator(".panel.run > .panel-heading")).toContainText(label);
});
Then("the content pane is labelled {string}", async ({ page }, label) => {
    await expect(page.locator(".panel.content .panel-body > h2")).toContainText(label);
});
Then("the run pane has no caption row", async ({ page }) => {
    await expect(page.locator(".panel.run > .panel-heading")).toHaveCount(0);
});
Then("the content pane shows the viewer tabs in place of its caption", async ({ page }) => {
    await expect(page.locator(".panel.content .panel-body > h2")).toHaveCount(0);
    await expect(page.locator(".panel.content .tabs .tab").first()).toBeVisible();
});
Then("the workspace pane is labelled {string}", async ({ page }, label) => {
    await expect(page.locator(".panel.workspace .panel-body > h2")).toContainText(label);
});

// Panel collapse (legacy 13-chrome-ui.md §6). Steps refer to a panel by its
// visible title; the grid class is the stable hook the UI exposes.
const PANEL_CLASS: Record<string, string> = { Browse: "nav", Chat: "run", Content: "content", Files: "workspace" };
function panelClass(title: string): string {
    const cls = PANEL_CLASS[title];
    if (!cls) throw new Error(`unknown panel "${title}"`);
    return cls;
}
When("I collapse the {string} panel", async ({ page }, title: string) => {
    await page.locator(`[data-collapse="${panelClass(title)}"]`).click();
});
When("I expand the {string} panel", async ({ page }, title: string) => {
    await page.locator(`[data-rail="${panelClass(title)}"]`).click();
});
Then("the {string} panel is folded", async ({ page }, title: string) => {
    const cls = panelClass(title);
    await expect(page.locator(`[data-rail="${cls}"]`)).toBeVisible();
    await expect(page.locator(`[data-collapse="${cls}"]`)).toHaveCount(0);
});
Then("the {string} panel is open", async ({ page }, title: string) => {
    const cls = panelClass(title);
    await expect(page.locator(`[data-collapse="${cls}"]`)).toBeVisible();
    await expect(page.locator(`[data-rail="${cls}"]`)).toHaveCount(0);
});
Then("the {string} panel collapse control is on the left edge", async ({ page }, title: string) => {
    const cls = panelClass(title);
    const control = page.locator(`[data-collapse="${cls}"]`);
    const panel = page.locator(`.panel.${cls}.collapsible`);
    await expect(control).toBeVisible();
    await expect(panel).toBeVisible();
    const [controlBox, panelBox] = await Promise.all([control.boundingBox(), panel.boundingBox()]);
    if (!controlBox || !panelBox) throw new Error(`${title} panel geometry is unavailable`);
    expect(controlBox.x).toBeLessThanOrEqual(panelBox.x + 12);
});
Then("the {string} panel collapse control is on the right edge", async ({ page }, title: string) => {
    const cls = panelClass(title);
    const control = page.locator(`[data-collapse="${cls}"]`);
    const panel = page.locator(`.panel.${cls}`);
    await expect(control).toBeVisible();
    await expect(panel).toBeVisible();
    const [controlBox, panelBox] = await Promise.all([control.boundingBox(), panel.boundingBox()]);
    if (!controlBox || !panelBox) throw new Error(`${title} panel geometry is unavailable`);
    expect(controlBox.x + controlBox.width).toBeGreaterThanOrEqual(panelBox.x + panelBox.width - 12);
});
Then("the {string} panel collapse control faces {string}", async ({ page }, title: string, direction: string) => {
    const icon = page.locator(`[data-collapse="${panelClass(title)}"] .panel-collapse-icon`);
    await expect(icon).toHaveAttribute("data-direction", direction);
});

// The delivery mode (#24, superseding the stage-gate): what the primary button
// and Enter do with the draft. The picker sits on the settings rail and never
// folds into the compact expander, so there is nothing to reveal first.
When("I set the composer mode to {string}", async ({ page }, mode: string) => {
    await page.locator("[data-mode-picker]").click();
    await page.locator(`[data-mode-menu] [data-mode-option="${mode}"]`).click();
    await expect(page.locator("[data-mode-picker]")).toContainText(mode);
});

// Put one held row back in the running order. Releasing the row at the head of
// the line starts it, so the row may leave the queue as this returns.
When("I release the held message {string}", async ({ page }, text: string) => {
    await page.getByTestId("queue-item").filter({ hasText: text }).getByTestId("queue-hold").click();
});

// The whole point of holding: the runner takes the ready messages and steps over
// the held ones, so the queue comes to rest holding exactly those. Counting with
// a retry rather than waiting for idle — the gap between one turn settling and
// the next draining is real, and `agent-working` is briefly hidden inside it.
Then("the queue settles to {int} held message(s)", async ({ page }, n: number) => {
    const rows = page.getByTestId("queue-item");
    await expect(rows).toHaveCount(n, { timeout: 45_000 });
    const held = await rows.evaluateAll((nodes) =>
        nodes.every((node) => node.hasAttribute("data-held")));
    expect(held).toBe(true);
});

// Steer: send now, interrupting the running turn (front of the queue). Driven by
// its fixed chord rather than the primary button — while a turn runs the primary
// wears the steer glyph and the destination menu covers it, so a click cannot
// land (see `sendDraft`). The chord reaches steer from any mode by design.
When("I steer with {string}", async ({ page }, text: string) => {
    const composer = page.getByPlaceholder("task the agent…");
    await composer.fill(text);
    await composer.press("Control+Shift+Enter");
    // Steering interrupts one run and starts another asynchronously. Do not let
    // the following "agent finishes" observe the old run's brief idle edge
    // before the redirected turn has been admitted.
    await expect(composer).toHaveValue("");
    // CMP-19: the steering message is a user line like any other, and survives a
    // transcript re-read. Assert the durable record, not the optimistic echo.
    await expect(page.locator(".run .transcript .line.user", { hasText: text })).toBeVisible();
});

Then(/^the queue shows (\d+) messages?$/, async ({ page }, n: string) => {
    await expect(page.getByTestId("queue-item")).toHaveCount(Number(n));
});

Then("queued message {int} is {string}", async ({ page }, pos: number, text: string) => {
    await expect(page.getByTestId("queue-item").nth(pos - 1)).toContainText(text);
});

When("I cancel the queued message {string}", async ({ page }, text: string) => {
    await page.getByTestId("queue-item").filter({ hasText: text }).locator(".queue-remove").click();
    await expect(page.getByTestId("queue-item").filter({ hasText: text })).toHaveCount(0);
});

When("I send now the queued message {string}", async ({ page }, text: string) => {
    await page.getByTestId("queue-item").filter({ hasText: text }).getByTestId("queue-send-now").click();
});

When("I edit the queued message {string} to {string}", async ({ page }, from: string, to: string) => {
    await page.getByTestId("queue-item").filter({ hasText: from }).locator(".queue-text").click();
    const edit = page.locator(".queue-edit");
    await edit.fill(to);
    await edit.press("Enter");
    await expect(page.getByTestId("queue-item").filter({ hasText: to })).toBeVisible();
});

When("I drag queued message {string} above {string}", async ({ page }, from: string, to: string) => {
    const src = page.getByTestId("queue-item").filter({ hasText: from }).locator(".queue-grip");
    const dst = page.getByTestId("queue-item").filter({ hasText: to });
    await src.dragTo(dst, { targetPosition: { x: 8, y: 2 } });
});

// The queue has drained and the agent is idle again.
Then("the agent finishes", async ({ page }) => {
    await expect(page.getByTestId("queue-stack")).toHaveCount(0, { timeout: 45_000 });
    await expect(page.getByTestId("agent-working")).toBeHidden({ timeout: 45_000 });
});

// The current turn has settled, without requiring the queue to be empty (a held
// queue can still hold messages after one is sent now).
Then("the agent is idle", async ({ page }) => {
    await expect(page.getByTestId("agent-working")).toBeHidden({ timeout: 45_000 });
});

// ---- round-1: on-ramps & plain language ----

// The chat-status badge (#4): a real coloured pill whose visible text is plain.
Then("the chat status badge reads {string}", async ({ page }, label: string) => {
    await expect(page.getByTestId("run-phase")).toContainText(label);
});

// ---- the place picker (#1, round 2) ----

// Open the picker from the project's context menu. (A project is never empty now —
// it gets a default placement at creation — so "add an archetype" lives on the menu,
// not an empty-state CTA: it adds a *further* archetype alongside the default.)
When("I open the add-method picker for project {string}", async ({ page }, name: string) => {
    await page.locator(".facet", { hasText: "Projects" }).click();
    await page
        .locator("[data-project]", { hasText: name })
        .locator(".tree-node.project")
        .click({ button: "right" });
    await page.locator(".menu-item", { hasText: "add an agent" }).click();
});

Then("the place picker is open", async ({ page }) => {
    await expect(page.locator("[data-place-picker]")).toBeVisible();
});

When("I choose the first method in the picker", async ({ page }) => {
    await pickFirstMethod(page);
});

// Use an archetype with no placement (ADR 0045): from the Library, its menu opens a
// work chat in the hidden Personal project directly — no place picker.
When("I use the archetype {string} from its menu", async ({ page }, name: string) => {
    await page.locator(".facet", { hasText: "Library" }).click();
    await page
        .locator("[data-archetype]", { hasText: name })
        .locator(".tree-node.archetype")
        .click({ button: "right" });
    // The label lives in `.menu-item-label`; the `.menu-item` text also carries the
    // hint, so anchor on the label span (the click bubbles to the item).
    // The Library menu label is "test" (run the method to try it out) — same action
    // as the old "use": opens a work chat in the hidden Personal project.
    await page.locator(".menu-item-label", { hasText: /^test$/ }).click();
});

Then("a work chat opens", async ({ page }) => {
    await expect(page.getByTestId("run-phase")).toHaveAttribute("data-run-phase", "Init");
    // This opens into the hidden Personal project, whose context slot is empty by
    // design, so the kind is read from the gem — the element that carries it.
    await expect(page.locator('.chat-heading .status-gem[data-kind="work"]')).toBeVisible();
});

// ---- auto-titling a new chat (#4, round 2) ----

Then("a chat titled {string} appears in the nav", async ({ page }, title: string) => {
    // The auto-titled chat is the one we just tasked (active); scope to it so an
    // identically-titled chat from another scenario can't mask a real failure.
    await expect(page.locator("[data-chat].active .leaf-label", { hasText: title })).toBeVisible();
});

// ---- holding messages before running (#24): a mode, not a chip ----

Then("I can stash messages before running", async ({ page }) => {
    await page.locator("[data-mode-picker]").click();
    await expect(page.locator('[data-mode-menu] [data-mode-option="stash"]')).toBeVisible();
});

// ---- round 3: honest discard, settings link, grouped all-chats ----

// An archetype's settings open from its right-click menu (the empty-state hint
// link was removed — settings/edit now live in the context menu).
When("I click the settings link on the method {string}", async ({ page }, name: string) => {
    await page.locator(".facet", { hasText: "Library" }).click();
    await page
        .locator("[data-archetype]", { hasText: name })
        .locator(".tree-node.archetype")
        .click({ button: "right" });
    await page.locator(".menu-item", { hasText: /^settings$/ }).click();
});

Then("the method settings modal is open", async ({ page }) => {
    await expect(page.locator("[data-config-editor]")).toBeVisible();
});

// All chats groups by archetype rather than repeating the label per row (#5).
Then("all chats are grouped under the archetype {string}", async ({ page }, name: string) => {
    await page.locator(".facet", { hasText: "Chats" }).click();
    await expect(page.locator(`.chat-group[data-chat-group="${name}"]`).first()).toBeVisible();
});

// Un-started chats render as distinct "Untitled · N" rows, never two identical ones (#5).
Then("no two un-started chats read identically", async ({ page }) => {
    await page.locator(".facet", { hasText: "Chats" }).click();
    const untitled = page.locator("[data-chat] .leaf-label", { hasText: /^Untitled/ });
    const n = await untitled.count();
    const seen = new Set<string>();
    for (let i = 0; i < n; i++) {
        const t = (await untitled.nth(i).textContent())?.trim() ?? "";
        expect(seen.has(t)).toBe(false);
        seen.add(t);
    }
});

// The decorative "v0" version badge is gone (#6).
Then("placements carry no version badge", async ({ page }) => {
    await page.locator(".facet", { hasText: "Projects" }).click();
    await expect(page.locator(".pinned-version")).toHaveCount(0);
});

// ---- round 4: config-edit safety, legible diffs, one canonical title ----

// The Files panel hides internal/config dotfiles behind a quiet toggle (#6 round-2);
// revealing them lets the test reach .agent-config.json directly.
When("I reveal the internal files", async ({ page }) => {
    await page.locator("[data-show-internal]").click();
});

// Host runtime settings and frozen package versions are never editable through
// the worktree surface. Settings owns the former; only an edit chat's package
// draft owns authored behavior.
Then("the selected file is read-only in the editor", async ({ page }) => {
    await expect(page.locator("[data-file-readonly]")).toBeVisible();
    await expect(page.locator("[data-file-save]")).toHaveCount(0);
});

// Split is illegible at the Content panel's default width, so it isn't offered (#2).
Then("the split diff toggle is not offered at the default panel width", async ({ page }) => {
    await expect(page.locator(".diff-toolbar")).toBeVisible();
    await expect(page.locator(".diff-mode")).toHaveCount(0);
});

// ---- round 5 ----

// The tree rows are real treeitems a keyboard/SR user can reach and activate (#4).
// Target the chat we just opened (the active row), not the first chat anywhere —
// the shared serial control plane accumulates older chats ahead of it, and opening
// one of those would land on a *completed* run rather than the fresh "Init" chat.
Then("the chat rows are keyboard-reachable", async ({ page }) => {
    const row = page.locator('[data-chat].active[role="treeitem"]');
    await expect(row).toHaveAttribute("tabindex", "0");
});

When("I open a chat by keyboard", async ({ page }) => {
    const row = page.locator('[data-chat].active[role="treeitem"]');
    await row.focus();
    await row.press("Enter");
});

// The settings modal leads with a plain-language form, with the raw JSON demoted (#5).
Then("the settings modal shows a plain-language form", async ({ page }) => {
    await expect(page.locator("[data-settings-form]")).toBeVisible();
    await expect(page.locator("[data-settings-model]")).toBeVisible();
    // The raw JSON is hidden until Advanced is expanded.
    await expect(page.locator("[data-config-text]")).toHaveCount(0);
});

When("I expand the advanced settings", async ({ page }) => {
    await page.locator("[data-settings-advanced-toggle]").click();
});

Then("the raw settings text is shown", async ({ page }) => {
    await expect(page.locator("[data-config-text]")).toBeVisible();
});

// Escape closes the settings modal (#6).
When("I press Escape", async ({ page }) => {
    await page.keyboard.press("Escape");
});

Then("the settings modal is closed", async ({ page }) => {
    await expect(page.locator("[data-config-editor]")).toBeHidden();
});

// Search has a clear control that resets the filter (#6).
When("I type {string} in the search box", async ({ page }, q: string) => {
    await page.getByTestId("facet-search").fill(q);
});

When("I clear the search", async ({ page }) => {
    await page.getByTestId("facet-search-clear").click();
});

Then("the search box is empty", async ({ page }) => {
    await expect(page.getByTestId("facet-search")).toHaveValue("");
});

// ---- round 6: plain-language history, keep guard, "method" wording ----

// The history "Activity" tab folds the raw event log into plain language (#1).
Then(
    "the history shows the plain activity for my request {string}",
    async ({ page }, prompt: string) => {
        await expect(page.locator("[data-audit] .activity-item", { hasText: prompt })).toBeVisible();
    },
);

// No raw engine type names leak into the user-facing activity list (#1).
Then("the history shows no raw engine event names", async ({ page }) => {
    // `data-audit` sits ON the `.activity` container (AuditTimeline), so match the
    // element itself — `[data-audit] .activity` would look for a non-existent child.
    const activity = page.locator("[data-audit]");
    await expect(activity).toBeVisible();
    // The raw log (with .event rows) must not be rendered until the dev toggle
    // is used — by default there are no raw event rows on screen.
    await expect(page.locator("[data-raw-log]")).toHaveCount(0);
    await expect(activity).not.toContainText("RunRequested");
    await expect(activity).not.toContainText("ObservationRecorded");
});

// The review/export state machine is gated behind dev mode, absent by default (#1).
Then("the history shows no review state-machine controls", async ({ page }) => {
    await expect(page.getByTestId("review-propose")).toHaveCount(0);
    await expect(page.getByTestId("export-target-admit")).toHaveCount(0);
});

When("I reveal the raw event log", async ({ page }) => {
    await page.locator("[data-raw-log-toggle]").click();
});

// The internal config file is folded out of the review by default (#4): the
// changed-files count reads "1 file changed" and only the deliverable shows.
Then("the changed-files review hides the internal settings file", async ({ page }) => {
    await expect(page.locator(".diff .diff-file-head", { hasText: ".agent-config.json" })).toHaveCount(0);
    await expect(page.locator(".diff-toolbar")).toContainText("1 file changed");
});

When("I reveal the internal settings file in the review", async ({ page }) => {
    await page.locator("[data-diff-internal-toggle]").click();
});

Then("the review offers no internal-file toggle", async ({ page }) => {
    await expect(page.locator("[data-diff-internal-toggle]")).toHaveCount(0);
});

// The chat header leads with the chat's own name (#6) so two chats under one
// method are distinguishable.
Then("the chat header shows the title {string}", async ({ page }, title: string) => {
    await expect(page.locator("[data-chat-title]")).toContainText(title);
});

// Rename the currently-open chat from its nav row. The header reads a library
// projection, so it must reflect this live off the workspace event stream.
When("I rename the open chat to {string}", async ({ page }, name: string) => {
    await page.locator("[data-chat].active").click({ button: "right" });
    await page.locator(".menu-item-label", { hasText: /^rename$/ }).click();
    await page.locator(".inline-edit").fill(name);
    await page.locator(".inline-edit").press("Enter");
});

// ---- round 7: responsive layout, pinned composer, immediate feedback ----

// A narrow laptop width (round-7 #1): below the old assumption of a very wide
// window. The shell must not clip the primary `send` control — the chat lane has
// a hard min-width and the composer input shrinks instead of pushing send off.
When("the window is a narrow laptop size", async ({ page }) => {
    await page.setViewportSize({ width: 1040, height: 760 });
});

// A short frame (round-7 #2): the composer is pinned to the bottom of the chat
// panel, so it stays on screen regardless of transcript length or window height.
When("the window is a short frame", async ({ page }) => {
    await page.setViewportSize({ width: 1040, height: 520 });
});

// The single most important control must be fully within the viewport — not
// clipped off-panel and not scrolled below the fold.
Then("the send button is fully on screen", async ({ page }) => {
    const send = page.getByTestId("send-msg");
    await expect(send).toBeVisible();
    const box = await send.boundingBox();
    const vp = page.viewportSize();
    expect(box).not.toBeNull();
    expect(box!.x).toBeGreaterThanOrEqual(0);
    expect(box!.y).toBeGreaterThanOrEqual(0);
    expect(box!.x + box!.width).toBeLessThanOrEqual(vp!.width + 1);
    expect(box!.y + box!.height).toBeLessThanOrEqual(vp!.height + 1);
});

Then("the message field wraps, grows, and stops at half the Chat panel", async ({ page }) => {
    const composer = page.locator('[data-desktop-composer] textarea[aria-label="Message"]');
    const panel = page.locator(".panel.run");
    const initial = await composer.boundingBox();
    await composer.fill("This is wrapped text ".repeat(240));
    await expect.poll(async () => (await composer.boundingBox())?.height).toBeGreaterThan(initial!.height);
    const [grown, panelBox, metrics] = await Promise.all([
        composer.boundingBox(),
        panel.boundingBox(),
        composer.evaluate((element) => ({
            clientHeight: element.clientHeight,
            scrollHeight: element.scrollHeight,
            scrollWidth: element.scrollWidth,
            clientWidth: element.clientWidth,
            whiteSpace: getComputedStyle(element).whiteSpace,
        })),
    ]);
    expect(grown).not.toBeNull();
    expect(panelBox).not.toBeNull();
    expect(grown!.height).toBeLessThanOrEqual(panelBox!.height / 2 + 1);
    expect(metrics.scrollHeight).toBeGreaterThan(metrics.clientHeight);
    expect(metrics.scrollWidth).toBeLessThanOrEqual(metrics.clientWidth);
    expect(metrics.whiteSpace).toBe("pre-wrap");
});

// (View auto-opening the single changed file (round-7 #3) reuses the existing
// "the file view shows {string}" step defined above — no new step needed.)

// Pressing send echoes the user's message into the transcript immediately
// (round-7 #6), so there's a visible reaction before the agent responds.
Then("the transcript echoes my message {string}", async ({ page }, text: string) => {
    await expect(page.locator(".run .transcript .line.user", { hasText: text })).toBeVisible();
});

// ---- round 9: honest banners, legible search, one honest improve entry ----

// Search highlight (#6 round-9): a surviving row marks the literal matched
// substring so a filtered list shows why each row stayed.
Then("the matched text {string} is highlighted in the results", async ({ page }, text: string) => {
    await expect(page.locator("mark.search-hit", { hasText: text }).first()).toBeVisible();
});

// The create affordance is hidden while a search is active so it can't read as a
// stray hit (#6 round-9).
Then("I can create a new method", async ({ page }) => {
    await page.locator(".facet", { hasText: "Library" }).click();
    await expect(page.getByText("+ archetype", { exact: true })).toBeVisible();
});
Then("I cannot create a new method", async ({ page }) => {
    await expect(page.getByText("+ archetype", { exact: true })).toHaveCount(0);
});

// Open the context menu on a named archetype (Library facet).
When("I open the context menu on the archetype {string}", async ({ page }, name: string) => {
    await page.locator(".facet", { hasText: "Library" }).click();
    await page
        .locator("[data-archetype]", { hasText: name })
        .locator(".tree-node.archetype")
        .click({ button: "right" });
    await expect(page.locator(".context-menu")).toBeVisible();
});

// One honest edit entry, not two identically-behaving modes (#5 round-9). The
// action is now called "edit" (was "improve this method").
Then("the menu offers exactly one improve entry", async ({ page }) => {
    await expect(page.locator(".menu-item-label", { hasText: /^edit$/i })).toHaveCount(1);
});
Then("the menu does not promise working alongside it live", async ({ page }) => {
    await expect(page.locator(".context-menu", { hasText: "alongside it live" })).toHaveCount(0);
});

// The improve composer names the method and drops "archetype" / "the editor" (#4).
Then("the composer placeholder does not mention {string}", async ({ page }, word: string) => {
    const ph = await page
        .locator('[data-desktop-composer] textarea[aria-label="Message"]')
        .getAttribute("placeholder");
    expect(ph ?? "").not.toContain(word);
});

// Rename selects the existing name so it can be typed straight over (#smaller r9).
When("I start renaming the archetype {string}", async ({ page }, name: string) => {
    await page.locator(".facet", { hasText: "Library" }).click();
    await page
        .locator("[data-archetype]", { hasText: name })
        .locator(".tree-node.archetype")
        .click({ button: "right" });
    await page.locator(".menu-item", { hasText: "rename" }).click();
    await expect(page.locator(".inline-edit")).toBeVisible();
});
Then("the rename field has the existing name selected", async ({ page }) => {
    const sel = await page.locator(".inline-edit").evaluate((el: HTMLInputElement) => ({
        start: el.selectionStart,
        end: el.selectionEnd,
        len: el.value.length,
    }));
    expect(sel.start).toBe(0);
    expect(sel.end).toBe(sel.len);
    expect(sel.len).toBeGreaterThan(0);
});

// ---- round 10: honest improve vocabulary, legible status, clearer review chrome ----

// #4 — the per-chat status was a 10px grey whisper; it must read at a legible size.
Then("the status badge text is at least {int}px", async ({ page }, px: number) => {
    const size = await page
        .getByTestId("run-phase")
        .evaluate((el) => parseFloat(getComputedStyle(el as HTMLElement).fontSize));
    expect(size).toBeGreaterThanOrEqual(px);
});

// #6 — the hidden-config disclosure must not read like the changed-file count that
// sits directly above it (no second "N file(s)" phrase to be misread as a count).
Then("the internal-file toggle does not read like a changed-file count", async ({ page }) => {
    const toggle = page.locator("[data-diff-internal-toggle]");
    await expect(toggle).toBeVisible();
    await expect(toggle).not.toContainText("file changed");
    await expect(toggle).not.toContainText("internal file");
});

Then("the internal-file toggle reveals the hidden config files", async ({ page }) => {
    await page.locator("[data-diff-internal-toggle]").click();
    await expect(page.locator(".diff .diff-file-head", { hasText: ".agent-config.json" })).toBeVisible();
});


// ---- RF-E1 / O-1: context-sources panel -----------------------------------

When("I open the context sources panel", async ({ page }) => {
    await page.locator("[data-open-sources]").click();
    await expect(page.locator("[data-context-overlay]")).toBeVisible();
});

Then("the context sources panel lists a {string} source", async ({ page }, kind: string) => {
    await expect(page.locator(`[data-context-source][data-kind="${kind}"]`).first()).toBeVisible();
});

Then("the context source is marked {string}", async ({ page }, availability: string) => {
    await expect(
        page.locator(`[data-context-source][data-availability="${availability}"]`).first(),
    ).toBeVisible();
});

Then("the context sources panel shows no context sources", async ({ page }) => {
    // The empty-state copy renders in place of the list; assert no source rows.
    await expect(page.locator("[data-context-source]")).toHaveCount(0);
    await expect(page.locator(".context-drawer .status", { hasText: "No context" })).toBeVisible();
});

Given("a withheld context source", async ({ page, request }) => {
    const response = await request.post(`${aliceCP}/test/reset?withheld_resource=true`, {
        headers: mutationHeaders(),
    });
    if (!response.ok()) {
        throw new Error(`access resource seed failed: ${response.status()} ${await response.text()}`);
    }
    await page.goto("/?chat=access-contract");
    await page.locator("[data-open-sources]").click();
    await expect(page.locator('[data-context-source="withheld-context"]')).toHaveAttribute(
        "data-availability",
        "pending",
    );
});

When("I request access to the withheld context source", async ({ page }) => {
    const posted = page.waitForResponse((response) => {
        const url = new URL(response.url());
        return response.request().method() === "POST"
            && url.pathname === "/chats/access-contract/resources/withheld-context/access/request";
    });
    await page.locator('[data-resource-access-request="withheld-context"]').click();
    expect((await posted).status()).toBe(200);
    await expect(page.locator('[data-resource-access-approve="withheld-context"]')).toBeVisible();
});

When("I approve access to the withheld context source", async ({ page }) => {
    const posted = page.waitForResponse((response) => {
        const url = new URL(response.url());
        return response.request().method() === "POST"
            && url.pathname === "/chats/access-contract/resources/withheld-context/access/approve";
    });
    await page.locator('[data-resource-access-approve="withheld-context"]').click();
    expect((await posted).status()).toBe(200);
});

Then("the withheld context source is available", async ({ page }) => {
    await expect(page.locator('[data-context-source="withheld-context"]')).toHaveAttribute(
        "data-availability",
        "available",
    );
});

// ---- RF-E1 / O-4: output catalog -------------------------------------------

// A turn under a chat that holds context produces the engagement's output
// resource; we run one turn and let it settle so the catalog has an output.
When("I task the agent and let the turn settle", async ({ page }) => {
    const composer = page.locator('[data-desktop-composer] textarea[aria-label="Message"]');
    await composer.fill("produce something");
    await sendDraft(composer);
    await expect(page.getByTestId("run-phase")).toHaveAttribute("data-run-phase", "Completed", { timeout: 45_000 });
});

When("I open the outputs catalog", async ({ page }) => {
    await page.getByRole("button", { name: "History", exact: true }).click();
    await page.locator('.shelf-drawer .tab[data-tab="outputs"]').click();
    await expect(page.locator("[data-output-catalog]")).toBeVisible();
});

Then("the outputs catalog lists an output", async ({ page }) => {
    await expect(page.locator("[data-output]").first()).toBeVisible();
});

Then("the output shows its review state", async ({ page }) => {
    await expect(page.locator("[data-output] [data-output-review]").first()).toBeVisible();
});

Then("the outputs catalog shows no outputs", async ({ page }) => {
    await expect(page.locator("[data-output]")).toHaveCount(0);
    await expect(page.locator(".output-catalog .status", { hasText: "No outputs" })).toBeVisible();
});

Given("a desktop chat with a source-approved output", async ({ page, request }) => {
    const response = await request.post(`${aliceCP}/test/reset?exportable_output=true`, {
        headers: mutationHeaders(),
    });
    if (!response.ok()) {
        throw new Error(`export output seed failed: ${response.status()} ${await response.text()}`);
    }
    exportDestination = await mkdtemp(join(tmpdir(), "gaugedesk-export-bdd-"));
    await page.addInitScript(({ selectedPath }) => {
        Object.defineProperty(window, "__TAURI_INTERNALS__", {
            configurable: true,
            value: {
                invoke: async (command: string) =>
                    command === "plugin:dialog|open" ? selectedPath : null,
            },
        });
    }, { selectedPath: exportDestination });
    await page.goto("/?chat=export-contract");
    await page.getByRole("button", { name: "History", exact: true }).click();
    await page.locator('.shelf-drawer .tab[data-tab="outputs"]').click();
    await expect(page.locator('[data-output="out-export-contract"]')).toBeVisible();
    await expect(page.locator('[data-save-output="out-export-contract"]')).toBeVisible();
});

When("I save the source-approved output to a folder", async ({ page }) => {
    const posted = page.waitForResponse((response) => {
        const url = new URL(response.url());
        return response.request().method() === "POST"
            && url.pathname === "/chats/export-contract/resources/out-export-contract/export-to-disk";
    });
    await page.locator('[data-save-output="out-export-contract"]').click();
    expect((await posted).status()).toBe(200);
    await expect(page.locator("[data-save-output-status]")).toContainText(/saved [1-9]\d* file/);
});

Then("the production export-to-disk route writes the deliverable", async () => {
    await expect(readFile(join(exportDestination, "deliverable.txt"), "utf8"))
        .resolves.toBe("desktop export proof\n");
});

// ---- multi-agent concurrency (round-13): per-chat run state + Browse dots ----

Given("a placement I can open more chats under", async ({ page }) => {
    await page.goto("/");
    concProject = await placeArchetypeOnFreshProject(page);
    const group = page.locator(`.tree-group[data-project]`, { hasText: concProject });
    await group.locator(".tree-subgroup[data-placement] [data-create='new-placement-chat']").first().click();
    await expect(page.getByTestId("run-phase")).toHaveAttribute("data-run-phase", "Init");
    await expect(page.getByTestId("stream-ready")).toBeAttached();
});

When("I open another chat under that placement", async ({ page }) => {
    const group = page.locator(`.tree-group[data-project]`, { hasText: concProject });
    await group.locator(".tree-subgroup[data-placement] [data-create='new-placement-chat']").first().click();
    await expect(page.getByTestId("stream-ready")).toBeAttached();
});

Then("the open chat shows a working dot", async ({ page }) => {
    await expect(page.locator('[data-chat].active .status-gem[data-state="working"]')).toBeVisible();
});

Then("{int} chats show a working dot", async ({ page }, n: number) => {
    await expect(page.locator('.status-gem[data-state="working"]')).toHaveCount(n);
});

// The chat on screen must show its OWN turn, not a concurrently-running chat's —
// scope to the run pane (the nav rows legitimately carry both chats' titles).
Then("the chat pane shows {string} but not {string}", async ({ page }, mine: string, other: string) => {
    await expect(page.locator(".run .transcript")).toContainText(mine);
    await expect(page.locator(".run .transcript")).not.toContainText(other);
});

When("the running turns finish", async ({ page }) => {
    // The [slow] turns hold ~3.5s each; wait until no chat is working any more.
    await expect(page.locator('.status-gem[data-state="working"]')).toHaveCount(0, { timeout: 15_000 });
});

Then("no chat shows a working dot", async ({ page }) => {
    await expect(page.locator('.status-gem[data-state="working"]')).toHaveCount(0);
});

// ---- per-project model access (LLM-2) ----

// Open a project's model-access panel from its right-click context menu (the id comes
// from the node, never typed) — mirrors the "add an archetype" project-menu flow.
When("I open model access for project {string}", async ({ page }, name: string) => {
    await page.locator(".facet", { hasText: "Projects" }).click();
    await page
        .locator("[data-project]", { hasText: name })
        .locator(".tree-node.project")
        .click({ button: "right" });
    await page.locator(".menu-item", { hasText: "model access" }).click();
});

Then("the model-access panel is open", async ({ page }) => {
    await expect(page.locator("[data-project-model-access]")).toBeVisible();
});

// Pin a provider: select it, paste a throwaway token, and submit. The token is sealed
// server-side (SEC-4) and never read back — we only assert the pin appears.
When("I pin the provider {string} for this project", async ({ page }, provider: string) => {
    const panel = page.locator("[data-project-model-access]");
    await panel.locator("select").selectOption(provider);
    await panel.locator("[data-project-credential-token]").fill("sk-e2e-throwaway");
    await panel.locator("button", { hasText: /^pin$/ }).click();
});

Then("the project pins the provider {string}", async ({ page }, provider: string) => {
    await expect(
        page.locator("[data-project-model-access]").locator(`[data-pinned="${provider}"]`),
    ).toBeVisible();
});

When("I unpin the provider {string} for this project", async ({ page }, provider: string) => {
    await page
        .locator("[data-project-model-access]")
        .locator(`[data-pinned="${provider}"]`)
        .locator("button", { hasText: "unpin" })
        .click();
});

Then("the project has no provider pins", async ({ page }) => {
    await expect(
        page.locator("[data-project-model-access]").locator("[data-pinned]"),
    ).toHaveCount(0);
});

// ---- project home rollup (UX-2) ----

// Open a project's home panel from its right-click context menu (id from the node).
When("I open project home for project {string}", async ({ page }, name: string) => {
    await page.locator(".facet", { hasText: "Projects" }).click();
    await page
        .locator("[data-project]", { hasText: name })
        .locator(".tree-node.project")
        .click({ button: "right" });
    await page.locator(".menu-item", { hasText: "project home" }).click();
});

Then("the project-home panel is open", async ({ page }) => {
    await expect(page.locator("[data-project-home-panel]")).toBeVisible();
});

// A project created here gets a default placement, so the audit rollup counts >= 1.
Then("the project-home panel shows at least {int} placement", async ({ page }, n: number) => {
    const badge = page.locator("[data-project-home-panel] [data-audit-placements]");
    await expect(badge).toBeVisible();
    // The dialog mounts before its projection resource resolves. Assert the
    // eventual rollup instead of sampling the transient zero placeholder.
    await expect
        .poll(async () => Number.parseInt((await badge.textContent()) ?? "0", 10))
        .toBeGreaterThanOrEqual(n);
});

// ---- fork tree (UX-8) ----

When("I open the fork tree for the first chat", async ({ page }) => {
    await page.locator(".chat-item").first().click({ button: "right" });
    await page.locator(".menu-item", { hasText: "fork tree" }).click();
});

Then("the fork tree shows at least {int} chats", async ({ page }, n: number) => {
    await expect(page.locator("[data-fork-tree]")).toBeVisible();
    const nodes = page.locator("[data-fork-tree] [data-fork-node]");
    // The dialog shell mounts before its fork-forest resource resolves. Poll the
    // rendered projection instead of sampling the transient empty shell once.
    await expect.poll(() => nodes.count()).toBeGreaterThanOrEqual(n);
});

// ---- UX-11: cross-party output review (held output + provenance + consent) ----

When("I request review of the held output", async ({ page }) => {
    const chat = new URL(page.url()).searchParams.get("chat");
    if (!chat) throw new Error("no chat selected in the URL (UX-4 ?chat=)");
    const posted = page.waitForResponse((response) => {
        const url = new URL(response.url());
        return response.request().method() === "POST"
            && url.pathname === `/chats/${chat}/resources/out-${chat}/review`;
    });
    await page.locator("[data-propose-review]").first().click();
    expect((await posted).status()).toBe(200);
});

Then("the held output shows stakeholder {string}", async ({ page }, party: string) => {
    await expect(page.locator("[data-output-review-hold]").first()).toBeVisible();
    await expect(page.locator(`[data-review-party="${party}"]`).first()).toBeVisible();
});

When("I consent to release the held output for {string}", async ({ page }, party: string) => {
    await expect(page.locator(`[data-review-party="${party}"]`).first()).toBeVisible();
    const posted = page.waitForResponse((response) =>
        response.request().method() === "POST"
        && new URL(response.url()).pathname.endsWith("/review/command"),
    );
    await page.locator("[data-consent-self]").first().click();
    const response = await posted;
    expect(response.status()).toBe(200);
    expect(response.request().postDataJSON()).toEqual({ action: "consent" });
});

Then("the held output is released", async ({ page }) => {
    await expect(page.locator("[data-output-released]").first()).toBeVisible();
});

Then("I release the held output", async ({ page }) => {
    const posted = page.waitForResponse((response) =>
        response.request().method() === "POST"
        && new URL(response.url()).pathname.endsWith("/review/command"),
    );
    await page.locator("[data-release]").first().click();
    const response = await posted;
    expect(response.status()).toBe(200);
    expect(response.request().postDataJSON()).toEqual({ action: "release" });
});

When("I prepare the released output for export", async ({ page }) => {
    const posted = page.waitForResponse((response) =>
        response.request().method() === "POST"
        && /\/resources\/[^/]+\/export$/.test(new URL(response.url()).pathname),
    );
    await page.locator("[data-propose-export]").first().click();
    expect((await posted).status()).toBe(200);
});

When("I consent to export as the source stakeholder", async ({ page }) => {
    const posted = page.waitForResponse((response) =>
        response.request().method() === "POST"
        && new URL(response.url()).pathname.endsWith("/export/command"),
    );
    await page.locator("[data-export-consent-self]").first().click();
    const response = await posted;
    expect(response.status()).toBe(200);
    expect(response.request().postDataJSON()).toEqual({ action: "consent" });
});

Then("the output is waiting for target admission", async ({ page }) => {
    await expect(page.locator("[data-export-source-ready]").first()).toBeVisible();
});
