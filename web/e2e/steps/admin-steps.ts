/**
 * Administration GaugeApp steps: drive its tenant-scoped pages and management
 * conversation inside the ordinary capability-gated GaugeDesk composition.
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
let desktopSoftwarePolicy: unknown = null;
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
    desktopSoftwarePolicy = null;
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
    await page.goto(`${enterpriseAppURL}?cp=${encodeURIComponent(enterpriseCP)}&gaugeapp=administration&page=people&tenant=org`);
    await expect(page.locator('[data-gaugeapp-page="people"]')).toBeVisible();
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
        const scope = { kind: "tenant", id: `organization:${identity}` };
        const session = `gaugeapp-session:${identity}`;
        const generation = `generation:${identity}`;
        const query = new URLSearchParams({ session, generation, scope: scope.id });
        const envelope = {
            session_id: session,
            generation,
            app: "administration",
            scope,
            page_id: "people",
            command_id: "people.invitation.create",
            expected_basis: `basis:${identity}`,
            idempotency_key: `e2e-${identity}`,
            payload: { authority: identity, role: "member" },
            client: "web",
        };
        return [
            { id: "administration.session.open", method: "POST", path: "/gaugeapps/administration/sessions", data: { scope } },
            { id: "administration.page.read", method: "GET", path: `/gaugeapps/administration/pages/people?${query}` },
            { id: "administration.updates.read", method: "GET", path: `/gaugeapps/administration/updates?${query}&after=older` },
            { id: "administration.agent.read", method: "GET", path: `/gaugeapps/administration/agent/messages?${query}` },
            { id: "administration.agent.send", method: "POST", path: "/gaugeapps/administration/agent/messages", data: { session_id: session, generation, scope, idempotency_key: `message-${identity}`, message: identity } },
            { id: "administration.domain-verification.read", method: "GET", path: `/gaugeapps/administration/organization/domain-verification?${query}&domain=${encodeURIComponent(`${identity}.example.test`)}` },
            { id: "administration.command.submit", method: "POST", path: "/gaugeapps/administration/commands", data: envelope },
            { id: "administration.proposal.list", method: "GET", path: `/gaugeapps/administration/proposals?${query}` },
            { id: "administration.proposal.prepare", method: "POST", path: "/gaugeapps/administration/proposals", data: { ...envelope, client: "agent" } },
            { id: "administration.proposal.review", method: "POST", path: `/gaugeapps/administration/proposals/${encodeURIComponent(`change:${identity}`)}/review`, data: { session_id: session, generation, app: "administration", scope, decision: "accept", client: "web" } },
        ];
    };

    const ownerHeaders = { authorization: `Bearer ${ownerToken}` };
    const baselineSessionResponse = await request.post(
        `${enterpriseCP}/gaugeapps/administration/sessions`,
        { headers: ownerHeaders, data: { scope: { kind: "tenant", id: "org" } } },
    );
    expect(baselineSessionResponse.status()).toBe(200);
    const baselineSession = (await baselineSessionResponse.json()).session;
    const snapshotPath =
        `/gaugeapps/administration/pages/people?`
        + new URLSearchParams({
            session: baselineSession.id,
            generation: baselineSession.generation,
            scope: baselineSession.scope.id,
        }).toString();
    const snapshot = async () => {
        const response = await request.get(`${enterpriseCP}${snapshotPath}`, {
            headers: ownerHeaders,
        });
        expect(response.status()).toBe(200);
        return response.text();
    };
    const stableSnapshot = async () => {
        const value = JSON.parse(await snapshot());
        // Session presence and freshness are operational observations. Denied
        // requests may authenticate a bearer without gaining Administration;
        // compare the governed People state and its stable resource basis.
        delete value.page.model.sessions;
        return value;
    };
    const before = await stableSnapshot();
    let generatedCases = 0;
    for (const identity of generatedWrongIdentities) {
        for (const operation of operations(identity)) {
            const mutation = operation.method === "POST"
                ? mutationHeaders({
                    "idempotency-key": typeof operation.data?.idempotency_key === "string"
                        ? operation.data.idempotency_key
                        : `e2e-${operation.id}-${identity}`,
                })
                : {};
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
                        headers: { ...mutation, ...(headers ?? {}) },
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
    expect(await stableSnapshot(), `${generatedCases} authority cases changed Administration state`)
        .toEqual(before);
    const incapable = await request.post(`${enterpriseCP}/gaugeapps/administration/sessions`, {
        headers: { authorization: `Bearer ${memberToken}` },
        data: { scope: { kind: "tenant", id: "org" } },
    });
    expect(incapable.status()).toBe(403);
});

Then(
    "the supporting enterprise routes expose capability, integration, audit, policy, and SSO diagnostics",
    async ({ request }) => {
        const headers = { authorization: `Bearer ${ownerToken}` };
        const capabilities = await request.get(`${enterpriseCP}/admin/capabilities`, { headers });
        expect(capabilities.status()).toBe(200);
        expect(await capabilities.json()).toMatchObject({ capabilities: expect.any(Array) });

        const integration = await request.get(`${enterpriseCP}/admin/integration`, { headers });
        expect(integration.status()).toBe(200);
        expect(await integration.json()).toMatchObject({
            oidc: { redirect_uri: expect.stringContaining("/auth/callback") },
            saml: { metadata_url: expect.stringContaining("/saml/metadata") },
            scim: { base_url: expect.stringContaining("/scim/v2") },
        });

        const audit = await request.get(`${enterpriseCP}/admin/audit?format=json`, { headers });
        expect(audit.status()).toBe(200);
        expect(audit.headers()["content-type"]).toContain("application/json");

        const placement = await request.get(`${enterpriseCP}/admin/placement-policy`, { headers });
        expect(placement.status()).toBe(200);
        expect(await placement.json()).toHaveProperty("placement_policy");

        const diagnostic = await request.post(`${enterpriseCP}/admin/sso/test`, {
            headers: { ...headers, ...mutationHeaders() },
            data: {},
        });
        expect(diagnostic.status()).toBe(200);
        expect(await diagnostic.json()).toMatchObject({
            ok: false,
            detail: expect.stringContaining("incomplete OIDC connection"),
        });
    },
);

When("I open the settings menu", async ({ page }) => {
    await openAccountMenu(page);
});

Then("the organization admin entry is not offered", async ({ page }) => {
    await expect(page.locator("[data-gaugeapp-page]")).toHaveCount(0);
    await expect(page.locator(".organization-menu-branch").filter({ hasText: "Administration" })).toHaveCount(0);
});

When("I open the enterprise workbench without identity", async ({ page }) => {
    await page.goto(`${enterpriseAppURL}?cp=${encodeURIComponent(enterpriseCP)}&gaugeapp=administration&page=people&tenant=org`);
});

When("I return to work", async ({ page }) => {
    await page.locator(".organization-trigger").click();
    await page.locator(".organization-popover").getByRole("button", { name: "Work", exact: true }).click();
});

Then("ordinary project work is shown", async ({ page }) => {
    await expect(page.locator("[data-work-chat-slot]")).toBeVisible();
    await expect(page.locator("[data-gaugeapp-page]")).toHaveCount(0);
});

When("I open the organization menu", async ({ page }) => {
    await page.locator(".organization-trigger").click();
});

Then("the Administration entry is offered", async ({ page }) => {
    const branch = page.locator(".organization-menu-branch").filter({ hasText: "Administration" });
    await expect(branch).toBeVisible();
    await expect(branch.getByRole("button", { name: "People", exact: true })).toBeVisible();
});

When("I choose Administration", async ({ page }) => {
    await page.locator(".organization-menu-branch")
        .filter({ hasText: "Administration" })
        .getByRole("button", { name: "People", exact: true })
        .click();
});

Then("the Administration GaugeApp is shown", async ({ page }) => {
    await expect(page.locator('[data-gaugeapp-page="people"]')).toBeVisible();
    await expect(page.getByRole("navigation", { name: "Administration pages" })).toBeVisible();
});

When("I invite member {string} as {string}", async ({ page }, authority: string, role: string) => {
    await page.getByRole("button", { name: "Invite", exact: true }).click();
    await page.getByRole("textbox", { name: "Email addresses" }).fill(authority);
    await page.getByRole("combobox", { name: "Role" }).selectOption(role);
    await page.getByRole("button", { name: "Create invitations", exact: true }).click();
});

Then("the invitation for {string} is pending review and not yet created", async ({ page }, authority: string) => {
    const review = page.getByRole("region", { name: "Pending changes" });
    await expect(review).toContainText(authority);
    await expect(page.locator(".gaugeapp-people-list").getByText(authority, { exact: true })).toHaveCount(0);
});

When("I apply the pending Administration change", async ({ page }) => {
    await page.getByRole("region", { name: "Pending changes" }).getByRole("button", { name: "Accept", exact: true }).click();
    await expect(page.getByRole("region", { name: "Pending changes" })).toHaveCount(0);
});

When("I reject the pending Administration change", async ({ page }) => {
    await page.getByRole("region", { name: "Pending changes" }).getByRole("button", { name: "Discard", exact: true }).click();
    await expect(page.getByRole("region", { name: "Pending changes" })).toHaveCount(0);
});

Then("the invitation for {string} remains absent", async ({ page }, authority: string) => {
    await expect(page.locator(".gaugeapp-people-list").getByText(authority, { exact: true })).toHaveCount(0);
});

Then("the invitation for {string} appears with its one-time link", async ({ page }, authority: string) => {
    await expect(page.locator(".gaugeapp-people-list").getByText(authority, { exact: true })).toBeVisible();
    await expect(page.getByRole("region", { name: "Organization invitation links" })).toContainText(authority);
});

Then("Administration shows its menu, agent, and People workspace", async ({ page }) => {
    await expect(page.locator(".workbench:not(.mobile)")).toBeVisible();
    await expect(page.getByRole("navigation", { name: "Administration pages" })).toBeVisible();
    await expect(page.getByPlaceholder("ask administration…")).toBeVisible();
    await expect(page.locator('[data-gaugeapp-page="people"]')).toBeVisible();
    await expect(page.locator("[data-embed-composer]")).toHaveCount(0);
    for (const retired of ["Overview", "Audit", "Deployments", "Automations"]) {
        await expect(page.getByRole("navigation", { name: "Administration pages" }).getByRole("button", { name: retired, exact: true })).toHaveCount(0);
    }
});

Then("the Admin composer offers no attachment control", async ({ page }) => {
    await expect(page.getByRole("button", { name: "Attach files" })).toHaveCount(0);
    await expect(page.locator("[data-attach-input]:visible")).toHaveCount(0);
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

When("I open Enterprise Identity setup", async ({ page }) => {
    await page.getByRole("navigation", { name: "Administration pages" })
        .getByRole("button", { name: "Enterprise Identity", exact: true })
        .click();
    await expect(page.locator('[data-gaugeapp-page="enterprise-identity"]')).toBeVisible();
    const integration = await page.request.get(`${enterpriseCP}/admin/integration`, {
        headers: { authorization: `Bearer ${ownerToken}` },
    });
    expect(integration.status()).toBe(200);
    const integrationBody = await integration.json();
    expect(integrationBody).toMatchObject({
        oidc: { redirect_uri: expect.stringContaining("/auth/callback") },
        saml: { metadata_url: expect.stringContaining("/saml/metadata") },
        scim: { base_url: expect.stringContaining("/scim/v2") },
    });
    advertisedIntegration = integrationBody;
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
    await page.getByRole("navigation", { name: "Administration pages" })
        .getByRole("button", { name: "Enterprise Identity", exact: true })
        .click();
    const proposalResponse = page.waitForResponse((response) =>
        new URL(response.url()).pathname === "/gaugeapps/administration/commands"
        && response.request().method() === "POST"
    );
    await page.getByRole("button", { name: "Issue credential", exact: true }).click();
    expect((await proposalResponse).status()).toBe(200);
    const review = page.getByRole("region", { name: "Pending changes" });
    await expect(review).toContainText("SCIM");

    const reviewResponse = page.waitForResponse((response) =>
        new URL(response.url()).pathname.startsWith("/gaugeapps/administration/proposals/")
        && new URL(response.url()).pathname.endsWith("/review")
        && response.request().method() === "POST"
    );
    await review.getByRole("button", { name: "Accept", exact: true }).click();
    expect((await reviewResponse).status()).toBe(200);
    const oneTimeSecret = page.getByRole("region", { name: "New SCIM credential" }).locator("code");
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
        await page.getByRole("navigation", { name: "Administration pages" })
            .getByRole("button", { name: "People", exact: true }).click();
        await expect(page.locator(".gaugeapp-person-row").filter({ hasText: user })).toHaveCount(0);

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
            await expect(page.locator("[data-gaugeapp-page]")).toBeVisible();
            await page.getByRole("navigation", { name: "Administration pages" })
                .getByRole("button", { name: "People", exact: true }).click();
            return page.locator(".gaugeapp-person-row").filter({ hasText: user });
        };
        let member = await refreshAccess();
        await expect(member).toBeVisible();
        await expect(member.locator("select")).toHaveCount(0);
        await expect(member).toContainText("Identity provider");

        const suspended = await send("PATCH", userPath, issuedScimToken, patchBody(false));
        expect(suspended.status()).toBe(200);
        expect(await suspended.json()).toMatchObject({ id: user, active: false });
        member = await refreshAccess();
        await expect(page.getByText("Deprovisioned", { exact: true })).toBeVisible();
        await expect(member).toBeVisible();

        const restored = await send("PATCH", userPath, issuedScimToken, patchBody(true));
        expect(restored.status()).toBe(200);
        expect(await restored.json()).toMatchObject({ id: user, active: true });

        const deleted = await send("DELETE", userPath, issuedScimToken);
        expect(deleted.status()).toBe(200);
        expect(await deleted.json()).toMatchObject({ id: user, active: false });
        member = await refreshAccess();
        await expect(page.getByText("Deprovisioned", { exact: true })).toBeVisible();
        await expect(member).toBeVisible();
    },
);

// ITGOV-2: the IT session roster is surfaced in the admin console.
Then("the admin console shows the active sessions roster", async ({ page }) => {
    await page.getByRole("navigation", { name: "Administration pages" })
        .getByRole("button", { name: "Sessions", exact: true }).click();
    await expect(page.locator('[data-gaugeapp-page="sessions"]')).toBeVisible();
    await expect(page.getByRole("heading", { name: "Organization sessions", exact: true })).toBeVisible();
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

When("I ask the Administration agent to propose inviting {string}", async ({ page }, authority: string) => {
    const composer = page.getByPlaceholder("ask administration…");
    await composer.fill(`/propose people.invitation.create ${JSON.stringify({ emails: [authority], role: "member" })}`);
    // ⏎ follows the composer's mode; see `sendDraft` in steps.ts for why the
    // primary button is not clicked here.
    await composer.press("Enter");
});

Then("the Administration agent opens a reviewable member proposal for {string}", async ({ page }, authority: string) => {
    await expect(page.getByText(
        "I opened a reviewable people.invitation.create proposal. It is not applied until you review it.",
        { exact: true },
    )).toBeVisible();
    await expect(page.getByRole("region", { name: "Pending changes" })).toContainText(authority);
    await expect(page.locator(".gaugeapp-people-list").getByText(authority, { exact: true })).toHaveCount(0);
});
