/** WS-71: production components/client, real socket and controlled issuance.
 * Enterprise cookie authorization and Home admission issuance are distinct:
 * the direct composition does not prove admission-header transport continuity.
 * No application route intercepts, model turn, Hub-login or visitor-runtime claim.
 */
import { expect, type APIRequestContext, type Page } from "@playwright/test";
import { createBdd } from "playwright-bdd";
import { enterpriseAppURL, enterpriseCP } from "../ports.mjs";
import { mutationHeaders } from "./idempotency";

const { Given, When, Then } = createBdd();
const owner = "gw-e2e-owner-token";
const other = "gw-e2e-member-token";
let source: string;
let panel: string;
let project: string;
let placement: string;
let pinned: string;
let firstDraft: string;
let frozenVersion: number;
let sourceBefore: unknown;
let workspaceBefore: { projects: unknown; recent: unknown };

async function json(request: APIRequestContext, method: string, path: string, data?: unknown, bearer: string | null = owner) {
    const response = await request.fetch(`${enterpriseCP}${path}`, {
        method, data,
        headers: { ...mutationHeaders(), ...(bearer ? { authorization: `Bearer ${bearer}` } : {}) },
    });
    expect(response.ok(), `${method} ${path}: ${response.status()} ${await response.text()}`).toBe(true);
    return response.json();
}
async function workshopMenu(page: Page, id: string, label: string) {
    await page.locator(".facet", { hasText: "Workshop" }).click();
    await page.locator(`[data-archetype="${id}"] .tree-node.archetype [data-row-menu]`).click();
    await page.locator(".menu-item-label", { hasText: new RegExp(`^${label}$`) }).click();
}
async function expandPanelPreviews(page: Page) {
    await page.locator(".facet", { hasText: "Workshop" }).click();
    const row = page.locator(`[data-archetype="${panel}"] .tree-node.archetype`);
    // The real Workshop starts collapsed. Wait for its preview-bearing tree
    // projection, then operate its disclosure rather than bypassing rendering.
    await expect(row).toHaveAttribute("aria-expanded", /^(true|false)$/);
    if (await row.getAttribute("aria-expanded") === "false") {
        await row.locator(":scope > .node-icon").click();
    }
    await expect(row).toHaveAttribute("aria-expanded", "true");
}
async function previews(request: APIRequestContext) {
    const workspace = await json(request, "GET", "/workspace");
    return workspace.archetypes.find((agent: { id: string }) => agent.id === panel).previews as {
        chat_id: string; version?: number;
    }[];
}

Given("a controlled authenticated Panel author is using the real Home", async ({ page, request }) => {
    await page.context().clearCookies();
    await json(request, "POST", "/test/reset", undefined, null);
    // Give the second synthetic account authoring standing through the normal
    // owner-reviewed Administration protocol; admission alone is insufficient.
    // Admin authoring still observes each account's own/granted project scope.
    const { session } = await json(request, "POST", "/gaugeapps/administration/sessions", {
        scope: { kind: "tenant", id: "org" },
    }, owner);
    expect(session.actor).toBe("local-user");
    const peopleGrant = session.pages.find((grant: { id: string }) => grant.id === "people");
    expect(peopleGrant.commands).toContain("people.role.change");
    const peoplePath = `/gaugeapps/administration/pages/people?${new URLSearchParams({
        session: session.id, generation: session.generation, scope: session.scope.id,
    })}`;
    const { page: people } = await json(request, "GET", peoplePath, undefined, owner);
    const otherMember = people.model.members.find((member: { authority: string }) => member.authority === "e2e-member");
    expect(otherMember).toMatchObject({ role: "member", status: "active", managed_by_scim: false });
    expect(otherMember.authority).not.toBe(session.actor);
    const commandHeaders = mutationHeaders({ authorization: `Bearer ${owner}` });
    const proposalResponse = await request.post(`${enterpriseCP}/gaugeapps/administration/commands`, {
        headers: commandHeaders,
        data: {
            session_id: session.id, generation: session.generation,
            app: session.app, scope: session.scope, page_id: "people",
            command_id: "people.role.change", expected_basis: people.resource_basis,
            idempotency_key: commandHeaders["idempotency-key"],
            payload: { id: otherMember.id, role: "admin" }, client: "web",
        },
    });
    expect(proposalResponse.status(), await proposalResponse.text()).toBe(200);
    const proposed = await proposalResponse.json();
    expect(proposed.receipt.status).toBe("proposed");
    expect(proposed.proposal.id).toEqual(expect.any(String));
    const applied = await json(request, "POST",
        `/gaugeapps/administration/proposals/${encodeURIComponent(proposed.proposal.id)}/review`, {
            session_id: session.id, generation: session.generation,
            app: session.app, scope: session.scope, decision: "accept", client: "web",
        }, owner);
    expect(applied.receipt.status).toBe("applied");
    const { page: updatedPeople } = await json(request, "GET", peoplePath, undefined, owner);
    expect(updatedPeople.model.members.find((member: { id: string }) => member.id === otherMember.id))
        .toMatchObject({ authority: "e2e-member", role: "admin", status: "active" });
    // Issuance is the existing launcher's debug-only verifier enrollment. Both
    // identities must receive a real Home admission before authoring assertions.
    const admittedOther = await json(request, "POST", "/home/admissions", undefined, other);
    expect(admittedOther.home).toEqual(expect.any(String));
    expect(admittedOther.admission).toEqual(expect.any(String));
    const otherAgent = await json(request, "POST", "/archetypes", { name: "Other author's Panel", kind: "panel" }, other);
    expect(otherAgent.id).toEqual(expect.any(String));
    await page.context().addCookies([{ name: "gw_session", value: owner, url: enterpriseCP, httpOnly: true, sameSite: "Lax" }]);
    const admittedOwner = await json(request, "POST", "/home/admissions");
    expect(admittedOwner.home).toBe(admittedOther.home);
    expect(admittedOwner.admission).not.toBe(admittedOther.admission);
    source = (await json(request, "POST", "/archetypes", { name: "Panel contract source", kind: "work" })).id;
    sourceBefore = await json(request, "GET", `/archetypes/${source}`);
    await page.goto(`${enterpriseAppURL}?cp=${encodeURIComponent(enterpriseCP)}`);
    await expect(page.locator(".facet", { hasText: "Workshop" })).toBeVisible();
});

// panel-authoring-browser-journey
When("the author copies a work Agent as a Panel through the Workshop", async ({ page, request }) => {
    const copied = page.waitForResponse((response) => response.url() === `${enterpriseCP}/archetypes/${source}/copy-as-panel` && response.request().method() === "POST");
    await workshopMenu(page, source, "copy as Panel agent");
    const response = await copied;
    expect(response.status()).toBe(201);
    panel = (await response.json()).id;
    expect(panel).not.toBe(source);
    expect(await json(request, "GET", `/archetypes/${source}`)).toEqual(sourceBefore);
    await expect(page.locator(`[data-archetype="${panel}"] [data-agent-kind="panel"]`)).toBeVisible();
});

When("the author saves and reloads the Panel contract", async ({ page, request }) => {
    const read = page.waitForResponse((response) => response.url() === `${enterpriseCP}/archetypes/${panel}/panel-profile` && response.request().method() === "GET");
    await workshopMenu(page, panel, "open");
    expect((await read).status()).toBe(200);
    const surface = page.locator("[data-panel-agent-surface]");
    await surface.getByRole("checkbox", { name: "Files", exact: true }).check();
    const write = page.waitForResponse((response) => response.url() === `${enterpriseCP}/archetypes/${panel}/panel-profile` && response.request().method() === "PUT");
    await surface.locator("[data-panel-contract-save]").click();
    const response = await write;
    expect(response.status()).toBe(200);
    const saved = await response.json();
    expect(saved.panels.components).toContain("gw-files");
    expect(await json(request, "GET", `/archetypes/${panel}/panel-profile`)).toEqual(saved);
    await page.reload();
    await workshopMenu(page, panel, "open");
    await expect(page.locator("[data-panel-agent-surface]").getByRole("checkbox", { name: "Files", exact: true })).toBeChecked();
});

When("the author previews both the frozen placement and its newer draft", async ({ page, request }) => {
    const published = page.waitForResponse((response) => response.url() === `${enterpriseCP}/archetypes/${panel}/publish` && response.request().method() === "POST");
    await page.locator("[data-panel-agent-surface]").getByRole("button", { name: "Publish new version", exact: true }).click();
    frozenVersion = (await (await published).json()).version;
    project = (await json(request, "POST", "/projects", { name: "Panel proof project" })).id;
    placement = (await json(request, "POST", `/projects/${project}/placements`, { agent_id: panel })).instance_id;
    workspaceBefore = await json(request, "GET", "/workspace");
    // Change only the Workshop draft through the actual editor after freezing.
    const surface = page.locator("[data-panel-agent-surface]");
    await surface.getByRole("checkbox", { name: "Viewer", exact: true }).check();
    const write = page.waitForResponse((response) => response.url() === `${enterpriseCP}/archetypes/${panel}/panel-profile` && response.request().method() === "PUT");
    await surface.locator("[data-panel-contract-save]").click();
    expect((await write).status()).toBe(200);
    await page.reload();
    await page.locator(".facet", { hasText: "Projects" }).click();
    const projectRow = page.locator(`[data-project="${project}"]`);
    const expand = projectRow.getByRole("button", { name: "Expand Panel proof project", exact: true });
    if (await expand.count()) await expand.click();
    await projectRow.locator(`[data-placement="${placement}"] [data-row-menu]`).click();
    const pinnedResponse = page.waitForResponse((response) => response.url() === `${enterpriseCP}/archetypes/${panel}/preview` && response.request().method() === "POST");
    await page.locator(".menu-item-label", { hasText: /^preview this version$/ }).click();
    pinned = (await (await pinnedResponse).json()).id;
    const draftResponse = page.waitForResponse((response) => response.url() === `${enterpriseCP}/archetypes/${panel}/preview` && response.request().method() === "POST");
    await workshopMenu(page, panel, "try in a preview chat");
    firstDraft = (await (await draftResponse).json()).id;
    const livePreviews = await previews(request);
    expect(livePreviews).toContainEqual(expect.objectContaining({ chat_id: pinned, version: frozenVersion }));
    const draftPreview = livePreviews.find((preview) => preview.chat_id === firstDraft);
    expect(draftPreview).toBeDefined();
    // The raw projection omits an unpinned version; the production client
    // normalizes that absence separately when constructing its domain model.
    expect(draftPreview).not.toHaveProperty("version");
    await expandPanelPreviews(page);
    await expect(page.locator(`[data-panel-previews="${panel}"] [data-chat="${firstDraft}"]`)).toBeVisible();
    await expect(page.locator("gw-session")).toHaveCount(0);
});

Then("replacing and deleting previews preserves the project and authoring source", async ({ page, request }) => {
    const replace = page.waitForResponse((response) => response.url() === `${enterpriseCP}/archetypes/${panel}/preview` && response.request().method() === "POST");
    await workshopMenu(page, panel, "try in a preview chat");
    const replacement = (await (await replace).json()).id;
    expect(replacement).not.toBe(firstDraft);
    expect((await previews(request)).map((preview) => preview.chat_id)).not.toContain(firstDraft);
    await expandPanelPreviews(page);
    for (const chat of [pinned, replacement]) {
        const row = page.locator(`[data-panel-previews="${panel}"] [data-chat="${chat}"]`);
        await expect(row).toBeVisible();
        // Existing Workshop menus offer Archive, which hides these rows, not a
        // direct Delete action. Cleanup uses the ordinary owned DELETE route;
        // this is not credited as a rendered delete-button journey.
        await json(request, "DELETE", `/chats/${chat}`);
    }
    await page.reload();
    await page.locator(".facet", { hasText: "Workshop" }).click();
    await expect(page.locator(`[data-panel-previews="${panel}"]`)).toHaveCount(0);
    expect(await previews(request)).toEqual([]);
    const after = await json(request, "GET", "/workspace");
    expect(after.projects).toEqual(workspaceBefore.projects);
    expect(after.recent).toEqual(workspaceBefore.recent);
    expect(await json(request, "GET", `/archetypes/${source}`)).toEqual(sourceBefore);
});

Then("another admitted author and an unsigned caller cannot author that Panel", async ({ page, request }) => {
    const before = await json(request, "GET", `/archetypes/${panel}/panel-profile`);
    // The standalone request fixture uses explicit bearer authorization and
    // does not share page cookies. Direct fetch keeps the unsigned case bare.
    for (const bearer of [other, null]) {
        if (!bearer) await page.context().clearCookies();
        for (const [method, path, data] of [
            ["POST", `/archetypes/${panel}/copy-as-panel`, {}],
            ["GET", `/archetypes/${panel}/panel-profile`, undefined],
            ["PUT", `/archetypes/${panel}/panel-profile`, before],
            ["POST", `/archetypes/${panel}/preview`, {}],
        ] as const) {
            const response = await request.fetch(`${enterpriseCP}${path}`, { method, data,
                headers: { ...mutationHeaders(), ...(bearer ? { authorization: `Bearer ${bearer}` } : {}) } });
            expect([401, 403]).toContain(response.status());
        }
    }
    expect(await json(request, "GET", `/archetypes/${panel}/panel-profile`, undefined, owner)).toEqual(before);
    expect(await previewsWithOwner(request)).toEqual([]);
});
async function previewsWithOwner(request: APIRequestContext) {
    const workspace = await json(request, "GET", "/workspace", undefined, owner);
    return workspace.archetypes.find((agent: { id: string }) => agent.id === panel).previews;
}
