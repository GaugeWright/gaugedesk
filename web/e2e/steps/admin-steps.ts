/**
 * Admin Environment steps (ADR 0092): drive the enterprise composition of the
 * shared workbench shell inside one capability-gated enterprise composition.
 */

import { expect, type APIRequestContext } from "@playwright/test";
import { createBdd } from "playwright-bdd";
import { enterpriseAppURL, enterpriseCP } from "../ports.mjs";
import { mutationHeaders } from "./idempotency";
import { openAccountMenu } from "./settings-nav";

const { Given, When, Then } = createBdd();
const ownerToken = "gw-e2e-owner-token";
const memberToken = "gw-e2e-member-token";
let issuedScimToken: string | null = null;
let advertisedIntegration: {
    saml: { sp_entity_id: string; acs_url: string; metadata_url: string };
} | null = null;
let downloadedAuditExport = "";
let desktopSoftwarePolicy: unknown = null;
let enrolledPlacementPolicy: unknown = null;
const generatedWrongIdentities = [
    "wrong",
    "wrong:delimiter:tenant",
    "wrong/encoded-segment",
    "wrong-\u03bc-unicode",
    `wrong-${"x".repeat(192)}`,
] as const;

async function resetAuthenticatedEnterprise(request: APIRequestContext): Promise<void> {
    issuedScimToken = null;
    advertisedIntegration = null;
    downloadedAuditExport = "";
    desktopSoftwarePolicy = null;
    enrolledPlacementPolicy = null;
    const res = await request.post(`${enterpriseCP}/test/reset`, { headers: mutationHeaders() });
    if (!res.ok()) {
        throw new Error(`enterprise control-plane reset failed: ${res.status()} ${await res.text()}`);
    }
}

Given("the enterprise workbench is open for an administered tenant", async ({ page, request }) => {
    // ADMIN-ENV-2: provision the local enterprise operator as an active owner. A
    // configured `?cp=` is intentionally insufficient; the Home's capability route
    // must admit this actor before the deep link can open Administration.
    await resetAuthenticatedEnterprise(request);
    await page.context().addCookies([{
        name: "gw_session",
        value: ownerToken,
        url: enterpriseCP,
        httpOnly: true,
        sameSite: "Lax",
    }]);
    const capabilityResponse = page.waitForResponse((response) =>
        new URL(response.url()).pathname === "/admin/capabilities"
        && response.request().method() === "GET"
    );
    await page.goto(`${enterpriseAppURL}?cp=${encodeURIComponent(enterpriseCP)}&environment=admin`);
    const capability = await capabilityResponse;
    expect(capability.status()).toBe(200);
    const capabilityBody = await capability.json();
    expect(Array.isArray(capabilityBody.capabilities)).toBe(true);
    expect(capabilityBody.capabilities.length).toBeGreaterThan(0);
    await expect(page.locator("[data-environment-document]")).toBeVisible();
});

Given("the authenticated enterprise tenant is reset", async ({ page, request }) => {
    await resetAuthenticatedEnterprise(request);
    await page.context().clearCookies();
});

Given("the authenticated enterprise workbench has an assignable onboarding task", async ({ page, request }) => {
    const reset = await request.post(`${enterpriseCP}/test/reset?assignable_task=true`, {
        headers: mutationHeaders(),
    });
    if (!reset.ok()) {
        throw new Error(`enterprise task seed failed: ${reset.status()} ${await reset.text()}`);
    }
    await page.context().addCookies([{
        name: "gw_session",
        value: ownerToken,
        url: enterpriseCP,
        httpOnly: true,
        sameSite: "Lax",
    }]);
    const roster = page.waitForResponse((response) =>
        response.request().method() === "GET"
        && new URL(response.url()).pathname === "/roster"
    );
    const tasks = page.waitForResponse((response) =>
        response.request().method() === "GET"
        && new URL(response.url()).pathname === "/tasks"
    );
    await page.goto(`${enterpriseAppURL}?cp=${encodeURIComponent(enterpriseCP)}`);
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

Given("the authenticated enterprise workbench has a withheld context source", async ({ page, request }) => {
    const reset = await request.post(`${enterpriseCP}/test/reset?withheld_resource=true`, {
        headers: mutationHeaders(),
    });
    if (!reset.ok()) {
        throw new Error(`enterprise access seed failed: ${reset.status()} ${await reset.text()}`);
    }
    await page.context().addCookies([{
        name: "gw_session",
        value: ownerToken,
        url: enterpriseCP,
        httpOnly: true,
        sameSite: "Lax",
    }]);
    await page.goto(
        `${enterpriseAppURL}?cp=${encodeURIComponent(enterpriseCP)}&chat=access-contract`,
    );
    await page.locator("[data-open-sources]").click();
    await expect(page.locator('[data-context-source="withheld-context"]')).toHaveAttribute(
        "data-availability",
        "pending",
    );
});

Given("the enterprise workbench has an attested-only placement policy", async ({ page, request }) => {
    const reset = await request.post(
        `${enterpriseCP}/test/reset?attested_placement_policy=true`,
        { headers: mutationHeaders() },
    );
    expect(reset.status()).toBe(200);
    enrolledPlacementPolicy = null;
    await page.context().addCookies([{
        name: "gw_session",
        value: ownerToken,
        url: enterpriseCP,
        httpOnly: true,
        sameSite: "Lax",
    }]);
    const policyResponse = page.waitForResponse((response) =>
        response.request().method() === "GET"
        && new URL(response.url()).pathname === "/admin/placement-policy"
    );
    await page.goto(`${enterpriseAppURL}?cp=${encodeURIComponent(enterpriseCP)}`);
    const response = await policyResponse;
    expect(response.status()).toBe(200);
    enrolledPlacementPolicy = await response.json();
});

// authority-matrix
// admin-bootstrap-authority-matrix
// generated-identity-encoding-state
Then("the Administration route family enforces identity and capability", async ({ request }) => {
    type Operation = {
        id: string;
        method: "GET" | "POST";
        path: string;
        data?: Record<string, unknown>;
    };
    const operations = (identity: string): ReadonlyArray<Operation> => {
        const scope = { kind: "organization", id: `organization:${identity}` };
        const session = `environment-session:${identity}`;
        const query = new URLSearchParams({ session, scope: scope.id });
        return [
            { id: "administration.session.open", method: "POST", path: "/environments/administration/sessions", data: { scope } },
            { id: "administration.document.read", method: "GET", path: `/environments/administration/documents/administration.access?${query}` },
            { id: "administration.agent.read", method: "GET", path: `/environments/administration/agent/messages?${query}` },
            { id: "administration.agent.send", method: "POST", path: "/environments/administration/agent/messages", data: { session_id: session, scope, message: identity } },
            { id: "administration.domain-verification.read", method: "GET", path: `/environments/administration/domain-verification?${query}&domain=${encodeURIComponent(`${identity}.example.test`)}` },
            { id: "administration.command.submit", method: "POST", path: "/environments/administration/commands", data: { session_id: session, environment: "administration", scope, document_id: "administration.access", command_id: "member.invite", base_revision: `revision:${identity}`, payload: { authority: identity }, client: "browser" } },
            { id: "administration.change.list", method: "GET", path: `/environments/administration/changes?${query}` },
            { id: "administration.change.propose", method: "POST", path: "/environments/administration/changes", data: { session_id: session, environment: "administration", scope, document_id: "administration.access", command_id: "member.invite", base_revision: `revision:${identity}`, payload: { authority: identity }, client: "browser" } },
            { id: "administration.change.review", method: "POST", path: `/environments/administration/changes/${encodeURIComponent(`change:${identity}`)}/review`, data: { session_id: session, environment: "administration", scope, decision: "accept", client: "browser" } },
        ];
    };

    const ownerHeaders = { authorization: `Bearer ${ownerToken}` };
    const baselineSessionResponse = await request.post(
        `${enterpriseCP}/environments/administration/sessions`,
        { headers: ownerHeaders, data: {} },
    );
    expect(baselineSessionResponse.status()).toBe(200);
    const baselineSession = (await baselineSessionResponse.json()).session;
    const snapshotPath =
        `/environments/administration/documents/administration.access?`
        + new URLSearchParams({
            session: baselineSession.id,
            scope: baselineSession.scope.id,
        }).toString();
    const snapshot = async () => {
        const response = await request.get(`${enterpriseCP}${snapshotPath}`, {
            headers: ownerHeaders,
        });
        expect(response.status()).toBe(200);
        return response.text();
    };
    const before = await snapshot();
    let generatedCases = 0;
    for (const identity of generatedWrongIdentities) {
        for (const operation of operations(identity)) {
            for (const [variant, headers, expected] of [
                ["anonymous", undefined, 401],
                ["invalid-identity", { authorization: "Bearer not-a-valid-test-identity" }, 401],
                ["wrong-scope", ownerHeaders, undefined],
            ] as const) {
                const response = await request.fetch(
                    `${enterpriseCP}${operation.path}`,
                    {
                        method: operation.method,
                        data: operation.data,
                        ...(headers ? { headers } : {}),
                    },
                );
                if (expected === undefined) {
                    expect(
                        response.status(),
                        `${operation.id} ${identity} ${variant}`,
                    ).toBeGreaterThanOrEqual(400);
                } else {
                    expect(
                        response.status(),
                        `${operation.id} ${identity} ${variant}`,
                    ).toBe(expected);
                }
                generatedCases += 1;
            }
        }
    }
    const bootstrapOperations = [
        {
            id: "administration.capabilities.read",
            method: "GET",
            path: "/admin/capabilities",
            memberStatus: 200,
        },
        {
            id: "administration.integration.read",
            method: "GET",
            path: "/admin/integration",
            memberStatus: 403,
        },
        {
            id: "administration.audit.export",
            method: "GET",
            path: "/admin/audit?format=json&action=generated-authority-check",
            memberStatus: 403,
        },
        {
            id: "administration.software-policy.recovery",
            method: "GET",
            path: "/admin/software-policy",
            memberStatus: 200,
        },
        {
            id: "administration.placement-policy.enrollment",
            method: "GET",
            path: "/admin/placement-policy",
            memberStatus: 200,
        },
        {
            id: "administration.sso.test",
            method: "POST",
            path: "/admin/sso/test",
            data: {
                protocol: "oidc",
                issuer: "",
                audiences: [],
                metadata: "",
                enforce_sso: false,
            },
            memberStatus: 403,
        },
    ] as const;
    for (const operation of bootstrapOperations) {
        const mutation = operation.method === "POST" ? mutationHeaders() : {};
        const anonymous = await request.fetch(`${enterpriseCP}${operation.path}`, {
            method: operation.method,
            headers: mutation,
            ...("data" in operation ? { data: operation.data } : {}),
        });
        expect(anonymous.status(), `${operation.id} anonymous`).toBe(401);
        generatedCases += 1;
        for (const identity of generatedWrongIdentities) {
            const invalid = await request.fetch(`${enterpriseCP}${operation.path}`, {
                method: operation.method,
                headers: {
                    ...mutation,
                    authorization:
                        `Bearer invalid-${Buffer.from(identity).toString("base64url")}`,
                },
                ...("data" in operation ? { data: operation.data } : {}),
            });
            expect(invalid.status(), `${operation.id} invalid ${identity}`).toBe(401);
            generatedCases += 1;
        }
        const member = await request.fetch(`${enterpriseCP}${operation.path}`, {
            method: operation.method,
            headers: { ...mutation, authorization: `Bearer ${memberToken}` },
            ...("data" in operation ? { data: operation.data } : {}),
        });
        expect(member.status(), `${operation.id} incapable member`).toBe(operation.memberStatus);
        if (operation.id === "administration.capabilities.read") {
            expect(await member.json()).toMatchObject({ capabilities: [] });
        }
        generatedCases += 1;
    }
    expect(await snapshot(), `${generatedCases} authority cases changed Administration state`)
        .toBe(before);
    const incapable = await request.post(`${enterpriseCP}/environments/administration/sessions`, {
        headers: { authorization: `Bearer ${memberToken}` },
        data: {},
    });
    expect(incapable.status()).toBe(403);
});

When("I open the settings menu", async ({ page }) => {
    await openAccountMenu(page);
});

Then("the organization admin entry is not offered", async ({ page }) => {
    await expect(page.locator('[data-account-menu-item="environment"]')).toHaveCount(0);
});

When("I return to work", async ({ page }) => {
    await page.locator("[data-admin-return]").click();
});

Then("the ordinary Work Environment is shown", async ({ page }) => {
    await expect(page.locator("[data-work-environment]")).toBeVisible();
    await expect(page.locator("[data-admin-environment]")).toBeHidden();
});

Then("the Administration entry is offered", async ({ page }) => {
    await expect(page.locator('[data-account-menu-item="environment"]')).toHaveText("Administration");
});

When("I choose Administration", async ({ page }) => {
    await page.locator('[data-account-menu-item="environment"]').click();
});

Then("the Admin Environment is shown", async ({ page }) => {
    await expect(page.locator("[data-admin-environment]")).toBeVisible();
    await expect(page.locator("[data-admin-navigator]")).toBeVisible();
});

When("I invite member {string} as {string}", async ({ page }, authority: string, role: string) => {
    await page.getByRole("button", { name: "People & access", exact: true }).click();
    await page.locator("[data-admin-invite-authority]").fill(authority);
    await page.locator("[data-admin-invite] select").selectOption(role);
    await page.locator("[data-admin-invite] button").click();
});

Then("the member {string} is pending review and not yet admitted", async ({ page }, authority: string) => {
    const review = page.locator(".environment-change-review");
    await expect(review).toContainText("member.invite");
    await expect(page.locator(`[data-member="${authority}"]`)).toHaveCount(0);
});

When("I apply the pending Administration change", async ({ page }) => {
    await page.locator(".environment-change-review").getByRole("button", { name: "apply change" }).click();
    await expect(page.locator(".environment-change-review")).toHaveCount(0);
});

When("I reject the pending Administration change", async ({ page }) => {
    await page.locator(".environment-change-review").getByRole("button", { name: "reject" }).click();
    await expect(page.locator(".environment-change-review")).toHaveCount(0);
});

Then("the member {string} remains absent", async ({ page }, authority: string) => {
    await expect(page.locator(`[data-member="${authority}"]`)).toHaveCount(0);
});

Then("the member {string} appears in the directory", async ({ page }, authority: string) => {
    await expect(page.locator(`[data-member="${authority}"]`)).toBeVisible();
});

Then("the audit log shows the {string} action", async ({ page }, action: string) => {
    await page.getByRole("button", { name: "Audit", exact: true }).click();
    await expect(page.locator("[data-audit-list]")).toContainText(action);
});

When("I filter the audit timeline to action {string}", async ({ page }, action: string) => {
    await page.getByRole("button", { name: "Audit", exact: true }).click();
    await page.locator("[data-audit-action]").fill(action);
});

Then("every visible audit row has action {string}", async ({ page }, action: string) => {
    const rows = page.locator("[data-audit-list] .resource-row");
    expect(await rows.count()).toBeGreaterThan(0);
    for (let index = 0; index < await rows.count(); index += 1) {
        await expect(rows.nth(index).locator(".resource-title")).toHaveText(action);
    }
});

When("I export the filtered audit timeline as {string}", async ({ page }, format: string) => {
    const normalized = format.toLowerCase();
    expect(["csv", "json"]).toContain(normalized);
    const responsePromise = page.waitForResponse((response) => {
        const url = new URL(response.url());
        return url.pathname === "/admin/audit"
            && url.searchParams.get("format") === normalized
            && url.searchParams.get("action") === "member.invite";
    });
    const downloadPromise = page.waitForEvent("download");
    await page.locator(`[data-audit-export="${normalized}"]`).click();
    const [response, download] = await Promise.all([responsePromise, downloadPromise]);
    expect(response.status()).toBe(200);
    expect(download.suggestedFilename()).toBe(`gaugewright-audit.${normalized}`);
    const stream = await download.createReadStream();
    const chunks: Buffer[] = [];
    for await (const chunk of stream) chunks.push(Buffer.from(chunk));
    downloadedAuditExport = Buffer.concat(chunks).toString("utf8");
    expect(downloadedAuditExport).toBe((await response.body()).toString("utf8"));
});

Then("the downloaded audit export contains {string}", async ({}, value: string) => {
    expect(downloadedAuditExport).toContain(value);
});

Then("the Admin Environment shows its resource navigator, agent, dashboard, and configuration workspace", async ({ page }) => {
    await expect(page.locator("[data-admin-environment] .workbench:not(.mobile)")).toBeVisible();
    await expect(page.locator("[data-admin-navigator]")).toBeVisible();
    await expect(page.getByPlaceholder("task the admin agent…")).toBeVisible();
    await expect(page.locator("[data-admin-dashboard=overview]")).toBeVisible();
    await expect(page.locator("[data-worktree]")).toBeVisible();
    await expect(page.locator("[data-embed-composer]")).toHaveCount(0);
});

Then("the Admin Environment exposes canonical configuration documents", async ({ page }) => {
    const workspace = page.locator("[data-worktree]");
    await expect(workspace).toContainText("organization.json");
    await expect(workspace).toContainText("access.json");
    await expect(workspace).toContainText("identity.json");
    await expect(workspace).toContainText("software-policy.json");
    await expect(workspace).toContainText("clients.json");
    await expect(workspace).toContainText("machines.json");
    await expect(workspace).not.toContainText("token_sha256");
    await expect(workspace).not.toContainText("metadata\"");
});

When("I open the {string} configuration file", async ({ page }, path: string) => {
    await page.locator("[data-worktree]").getByText(path, { exact: true }).click();
});

Then("its derived policy view is shown", async ({ page }) => {
    await expect(page.locator('[data-environment-document="administration.policy"]')).toBeVisible();
    await expect(page.locator("[data-admin-dashboard=policy]")).toContainText("Require MFA");
});

Then("its derived software admission view is shown", async ({ page }) => {
    await expect(page.locator('[data-environment-document="administration.software-policy"]')).toBeVisible();
    await expect(page.locator("[data-admin-dashboard=software-policy]")).toContainText("Minimum GaugeDesk version");
});

Then("its reported clients view is shown", async ({ page }) => {
    await expect(page.locator('[data-environment-document="administration.clients"]')).toBeVisible();
    await expect(page.locator("[data-admin-dashboard=clients]")).toContainText("Client sessions");
    await expect(page.locator("[data-admin-dashboard=clients]")).toContainText("not device attestation");
});

When("I open the raw configuration editor", async ({ page }) => {
    await page.locator('[data-tab="edit"]').click();
});

Then("the editor shows the canonical policy JSON", async ({ page }) => {
    const editor = page.locator("[data-file-edit]");
    await expect(editor).toBeVisible();
    await expect(editor).toHaveValue(/"security"/);
});

When("I open help for the selected Admin file", async ({ page }) => {
    await page.locator(".environment-help").click();
});

Then("its linked Markdown guide is shown", async ({ page }) => {
    const view = page.locator("[data-file-view]");
    await expect(view).toBeVisible();
    await expect(view).toContainText("Overview");
    await expect(view).toContainText("overview.json");
});

Then("the Admin supporting files are hidden from the ordinary Files list", async ({ page }) => {
    const workspace = page.locator("[data-worktree]");
    await expect(workspace).not.toContainText(".environment/help/");
    await expect(workspace).not.toContainText(".environment/agent/");
    await expect(page.locator("[data-show-internal]")).toBeVisible();
});

When("I reveal internal Admin files", async ({ page }) => {
    await page.locator("[data-show-internal]").click();
});

Then("the Admin agent definition files are visible", async ({ page }) => {
    const workspace = page.locator("[data-worktree]");
    await expect(workspace).toContainText(".environment/manifest.json");
    await expect(workspace).toContainText(".environment/agent/SYSTEM.md");
    await expect(workspace).toContainText(".environment/agent/skills/administration/SKILL.md");
    await expect(workspace).toContainText(".environment/agent/TOOLS.json");
});

When("I open the Admin agent tool manifest", async ({ page }) => {
    await page.locator("[data-worktree]").getByText(".environment/agent/TOOLS.json", { exact: true }).click();
});

Then("it contains only governance tools and no shell or web tools", async ({ page }) => {
    const manifest = page.locator("[data-file-view]");
    await expect(manifest).toContainText("environment.files.list");
    await expect(manifest).toContainText("environment.files.read");
    await expect(manifest).toContainText("environment.projections.query");
    await expect(manifest).toContainText("environment.changes.propose");
    // ADR 0113 replaces ambient suspension with an addressed, turn-settling
    // question capability.
    await expect(manifest).not.toContainText("human.ask");
    await expect(manifest).toContainText("question.ask");
    await expect(manifest).not.toContainText("bash");
    await expect(manifest).not.toContainText("shell");
    await expect(manifest).not.toContainText("web");
    await expect(manifest).not.toContainText("http");
    await expect(manifest).not.toContainText("upload");
    await expect(manifest).not.toContainText("attach");
    await expect(manifest).not.toContainText("ingest");
});

Then("the Admin composer offers no attachment control", async ({ page }) => {
    const admin = page.locator("[data-admin-environment]");
    await expect(admin.getByRole("button", { name: "Attach files" })).toHaveCount(0);
    await expect(admin.locator("[data-attach-input]")).toHaveCount(0);
});

Then("the Admin agent upload API is unavailable", async ({ request }) => {
    const discovery = await request.get(`${enterpriseCP}/admin/capabilities`, {
        headers: { authorization: `Bearer ${ownerToken}` },
    });
    expect(discovery.ok()).toBeTruthy();
    const capabilities = await discovery.json();
    expect(capabilities.agent).toMatchObject({
        message_attachments: false,
        additional_tools: false,
    });
    expect(capabilities.agent.tools).not.toEqual(
        expect.arrayContaining([expect.stringMatching(/upload|attach|ingest/i)]),
    );
    const response = await request.post(`${enterpriseCP}/admin/agent/upload`, {
        headers: {
            ...mutationHeaders(),
            authorization: `Bearer ${ownerToken}`,
        },
        multipart: { file: { name: "policy.txt", mimeType: "text/plain", buffer: Buffer.from("policy") } },
    });
    expect(response.status()).toBe(404);
});

When("I launch the SSO setup wizard", async ({ page }) => {
    await page.getByRole("button", { name: "Identity", exact: true }).click();
    const integrationResponse = page.waitForResponse((response) =>
        new URL(response.url()).pathname === "/admin/integration"
        && response.request().method() === "GET"
    );
    await page.locator("[data-admin-sso-wizard]").click();
    const integration = await integrationResponse;
    expect(integration.status()).toBe(200);
    const integrationBody = await integration.json();
    expect(integrationBody).toMatchObject({
        oidc: { redirect_uri: expect.stringContaining("/auth/callback") },
        saml: { metadata_url: expect.stringContaining("/saml/metadata") },
        scim: { base_url: expect.stringContaining("/scim/v2") },
    });
    advertisedIntegration = integrationBody;
    await expect(page.locator("[data-sso-wizard]")).toBeVisible();
});

// saml-metadata-public-authority
Then("an identity provider can register from the advertised SAML metadata", async ({ request }) => {
    expect(advertisedIntegration, "the authenticated Administration client advertised integration details")
        .not.toBeNull();
    const saml = advertisedIntegration!.saml;

    // An IdP registration client deliberately fetches SP metadata without the
    // administrator's cookie or bearer. Metadata is public configuration; the
    // authenticated boundary is the Administration UI that advertises its URL.
    const metadata = await request.get(saml.metadata_url);
    expect(metadata.status()).toBe(200);
    expect(metadata.headers()["content-type"]).toContain("application/samlmetadata+xml");
    const xml = await metadata.text();
    expect(xml).toContain(`entityID="${saml.sp_entity_id}"`);
    expect(xml).toContain(`Location="${saml.acs_url}"`);
    expect(xml).toContain('WantAssertionsSigned="true"');
    expect(xml).toContain("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST");
});

When("I issue a SCIM credential through Administration review", async ({ page }) => {
    await page.getByRole("button", { name: "Identity", exact: true }).click();
    const proposalResponse = page.waitForResponse((response) =>
        new URL(response.url()).pathname === "/environments/administration/commands"
        && response.request().method() === "POST"
    );
    await page.getByRole("button", { name: "propose SCIM token rotation", exact: true }).click();
    expect((await proposalResponse).status()).toBe(200);
    const review = page.locator(".environment-change-review");
    await expect(review).toContainText("scim-token.rotate");

    const reviewResponse = page.waitForResponse((response) =>
        new URL(response.url()).pathname.startsWith("/environments/administration/changes/")
        && new URL(response.url()).pathname.endsWith("/review")
        && response.request().method() === "POST"
    );
    await review.getByRole("button", { name: "apply change" }).click();
    expect((await reviewResponse).status()).toBe(200);
    const oneTimeSecret = page.locator(".environment-one-time-secret code");
    await expect(oneTimeSecret).toBeVisible();
    issuedScimToken = (await oneTimeSecret.textContent())?.trim() ?? null;
    expect(issuedScimToken).toBeTruthy();
});

// scim-bearer-authority-matrix
// scim-provider-state-properties
Then(
    "the external SCIM provider provisions, suspends, restores, and deletes a member",
    async ({ page, request }) => {
        expect(issuedScimToken, "Administration displayed the reviewed SCIM token once").toBeTruthy();
        const user = "provider-user@acme.test";
        const usersPath = "/scim/v2/Users";
        const userPath = `${usersPath}/${encodeURIComponent(user)}`;
        const patchBody = (active: boolean) => ({
            schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            Operations: [{ op: "replace", path: "active", value: active }],
        });
        const send = (
            method: "POST" | "PATCH" | "DELETE",
            path: string,
            token: string | null,
            data?: Record<string, unknown>,
        ) => request.fetch(`${enterpriseCP}${path}`, {
            method,
            headers: mutationHeaders(token ? { authorization: `Bearer ${token}` } : {}),
            ...(data === undefined ? {} : { data }),
        });

        // Authentication is evaluated before resource lookup or mutation for every
        // exported provider operation. Six failures stay below the production
        // brute-force throttle and must leave the Administration projection unchanged.
        for (const operation of [
            { method: "POST" as const, path: usersPath, data: { userName: user } },
            { method: "PATCH" as const, path: userPath, data: patchBody(false) },
            { method: "DELETE" as const, path: userPath },
        ]) {
            for (const token of [null, "not-the-issued-scim-token"]) {
                const denied = await send(operation.method, operation.path, token, operation.data);
                expect(denied.status(), `${operation.method} ${operation.path} rejects ${token ?? "missing token"}`)
                    .toBe(401);
            }
        }
        await page.getByRole("button", { name: "People & access", exact: true }).click();
        await expect(page.locator(`[data-member="${user}"]`)).toHaveCount(0);

        const created = await send("POST", usersPath, issuedScimToken, { userName: user });
        expect(created.status()).toBe(201);
        expect(await created.json()).toMatchObject({
            schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"],
            id: user,
            userName: user,
            active: true,
        });

        const refreshAccess = async () => {
            await page.reload();
            await expect(page.locator("[data-environment-document]")).toBeVisible();
            await page.getByRole("button", { name: "People & access", exact: true }).click();
            return page.locator(`[data-member="${user}"]`);
        };
        let member = await refreshAccess();
        await expect(member).toBeVisible();
        await expect(member.locator("select")).toBeDisabled();
        await expect(member.locator(".resource-availability")).toHaveText("active");

        const suspended = await send("PATCH", userPath, issuedScimToken, patchBody(false));
        expect(suspended.status()).toBe(200);
        expect(await suspended.json()).toMatchObject({ id: user, active: false });
        member = await refreshAccess();
        await expect(member.locator(".resource-availability")).toHaveText("deprovisioned");

        const restored = await send("PATCH", userPath, issuedScimToken, patchBody(true));
        expect(restored.status()).toBe(200);
        expect(await restored.json()).toMatchObject({ id: user, active: true });

        const deleted = await send("DELETE", userPath, issuedScimToken);
        expect(deleted.status()).toBe(200);
        expect(await deleted.json()).toMatchObject({ id: user, active: false });
        member = await refreshAccess();
        await expect(member.locator(".resource-availability")).toHaveText("deprovisioned");
    },
);

Then("the SSO wizard shows the connect step", async ({ page }) => {
    await expect(page.locator("[data-wizard-connect]")).toBeVisible();
    await expect(page.locator("[data-wizard-connect]")).toContainText("/auth/callback");
});

When("I advance the SSO wizard", async ({ page }) => {
    await page.locator("[data-wizard-next]").click();
});

Then("the SSO wizard shows the test step", async ({ page }) => {
    await expect(page.locator("[data-wizard-test]")).toBeVisible();
    await expect(page.locator("[data-wizard-test-btn]")).toBeVisible();
});

When("I test the incomplete SSO connection", async ({ page }) => {
    const testResponse = page.waitForResponse((response) =>
        new URL(response.url()).pathname === "/admin/sso/test"
        && response.request().method() === "POST"
    );
    await page.locator("[data-wizard-test-btn]").click();
    const response = await testResponse;
    expect(response.status()).toBe(200);
    expect(await response.json()).toMatchObject({
        ok: false,
        detail: expect.stringContaining("incomplete OIDC connection"),
    });
});

Then("the SSO test reports the incomplete configuration", async ({ page }) => {
    await expect(page.locator("[data-wizard-test-result]")).toContainText(
        "incomplete OIDC connection",
    );
});

// ITGOV-2: the IT session roster is surfaced in the admin console.
Then("the admin console shows the active sessions roster", async ({ page }) => {
    await page.getByRole("button", { name: "People & access", exact: true }).click();
    const panel = page.locator("[data-sessions]");
    await expect(panel).toBeVisible();
    await expect(panel).toContainText("Active sessions");
});

When("I reload the administered workbench as a desktop client", async ({ page }) => {
    await page.addInitScript(() => {
        Object.defineProperty(window, "__TAURI_INTERNALS__", {
            configurable: true,
            value: { invoke: async () => null },
        });
    });
    const responsePromise = page.waitForResponse((response) =>
        new URL(response.url()).pathname === "/admin/software-policy"
        && response.request().method() === "GET"
    );
    await page.reload();
    const response = await responsePromise;
    expect(response.status()).toBe(200);
    desktopSoftwarePolicy = await response.json();
});

Then("the shipped desktop updater reads the tenant software policy", async () => {
    expect(desktopSoftwarePolicy).toMatchObject({
        software_policy: {
            allowed_channels: expect.any(Array),
        },
    });
});

When("I preview an unattested engagement in the shipped Devices UI", async ({ page }) => {
    await openAccountMenu(page);
    await page.locator('[data-account-menu-item="devices"]').click();
    const payload = JSON.stringify({
        invite_id: "policy-client-journey",
        ticket: { authority: "counterparty" },
        project: "policy-client-project",
        project_name: "Policy client project",
        manifest: [],
        confirm_code: "1-2-3",
        deployment_mode: { operator: "local", attested: false },
    });
    const hex = Array.from(new TextEncoder().encode(payload), (byte) =>
        byte.toString(16).padStart(2, "0")).join("");
    await page.locator("[data-pd-invite-link]").fill(`gaugewright://invite?d=${hex}`);
});

Then(
    "the enrolled client reads the placement floor and refuses the engagement locally",
    async ({ page }) => {
        expect(enrolledPlacementPolicy).toMatchObject({
            placement_policy: {
                require_attested: true,
                allowed_operators: [],
            },
        });
        await expect(page.locator("[data-placement-policy]")).toContainText(
            "attestation required",
        );
        await expect(page.locator("[data-pd-invite-deployment]")).toContainText(
            "local-operated · unattested",
        );
        await expect(page.locator("[data-pd-policy-refusal]")).toBeVisible();
        await expect(page.locator("[data-pd-invite-accept]")).toBeDisabled();
    },
);

Then("the Admin Environment shows the serving machine as live", async ({ page }) => {
    await page.getByRole("button", { name: "Machines", exact: true }).first().click();
    const dashboard = page.locator("[data-admin-dashboard=machines]");
    await expect(dashboard).toContainText("home:local-user");
    await expect(dashboard).toContainText("live");
});

When("I ask the admin agent about Machines", async ({ page }) => {
    const composer = page.getByPlaceholder("task the admin agent…");
    await composer.fill("Which Machines, Homes, projects, and placements are under control?");
    // ⏎ follows the composer's mode; see `sendDraft` in steps.ts for why the
    // primary button is not clicked here.
    await composer.press("Enter");
});

Then("the admin agent answers from admitted Home projections", async ({ page }) => {
    await expect(page.locator("[data-admin-environment] .transcript")).toContainText(
        "registered Homes have live target-admitted projections",
    );
});

When("I ask the Administration agent to propose inviting {string}", async ({ page }, authority: string) => {
    const composer = page.getByPlaceholder("task the admin agent…");
    await composer.fill(`/propose member.invite ${JSON.stringify({ authority, email: authority, role: "member" })}`);
    // ⏎ follows the composer's mode; see `sendDraft` in steps.ts for why the
    // primary button is not clicked here.
    await composer.press("Enter");
});

Then("the Administration agent opens a reviewable member proposal for {string}", async ({ page }, authority: string) => {
    await expect(page.locator("[data-admin-environment] .transcript")).toContainText(
        "I opened a reviewable member.invite proposal",
    );
    await expect(page.locator(".environment-change-review")).toContainText("member.invite");
    await expect(page.locator(`[data-member="${authority}"]`)).toHaveCount(0);
});
