import { spawn } from "node:child_process";
import { createServer } from "node:http";
import { mkdtemp, readFile, rm, stat } from "node:fs/promises";
import { createServer as createTcpServer } from "node:net";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { chromium } from "playwright";
import {
    attachVirtualAuthenticator,
    beginEmailProof,
    completePasskeyAccount,
} from "./passkey-account-door.mjs";

const repositoryRoot = resolve(import.meta.dirname, "../..");
const serverBinary = resolve(repositoryRoot, "target/debug/gaugedesk-enterprise-server");
const apiOrigin = "http://localhost:1421";
const issuer = process.env.OIDC_ISSUER;
const clientId = process.env.OIDC_CLIENT_ID ?? "gaugedesk-app";
const password = process.env.OIDC_PASSWORD ?? "Passw0rd!";
const oidcUsername = process.env.ENTERPRISE_OIDC_USERNAME ?? "oidcuser";
const oidcEmail = process.env.ENTERPRISE_OIDC_EMAIL ?? "oidcuser@gaugewright.test";
const samlUsername = process.env.ENTERPRISE_SAML_USERNAME ?? "samluser";
const samlEmail = process.env.ENTERPRISE_SAML_EMAIL ?? "samluser@gaugewright.test";
if (!issuer) throw new Error("OIDC_ISSUER is required");
await stat(serverBinary);

async function freePort() {
    const server = createTcpServer();
    await new Promise((resolveReady, reject) => {
        server.once("error", reject);
        server.listen(0, "127.0.0.1", resolveReady);
    });
    const address = server.address();
    if (!address || typeof address === "string") {
        throw new Error("ephemeral port did not resolve");
    }
    await new Promise((resolveClosed) => server.close(resolveClosed));
    return address.port;
}

async function waitForHealth(child) {
    const deadline = Date.now() + 30_000;
    while (Date.now() < deadline) {
        if (child.exitCode !== null) {
            throw new Error(`enterprise server exited before readiness (${child.exitCode})`);
        }
        try {
            const response = await fetch(`${apiOrigin}/health`);
            if (response.ok) return;
        } catch {
            // Startup is still in progress.
        }
        await new Promise((resolveWait) => setTimeout(resolveWait, 100));
    }
    throw new Error("enterprise server did not become ready");
}

async function apiJson(page, method, path, body, tenant, idempotencyKey) {
    const result = await page.evaluate(async ({ url, verb, payload, tenantId, key }) => {
        const headers = {};
        if (payload !== undefined) headers["content-type"] = "application/json";
        if (tenantId) headers["x-gaugewright-tenant"] = tenantId;
        if (key) headers["idempotency-key"] = key;
        const response = await fetch(url, {
            method: verb,
            headers,
            credentials: "include",
            ...(payload !== undefined ? { body: JSON.stringify(payload) } : {}),
        });
        const text = await response.text();
        let value = null;
        if (text) {
            try {
                value = JSON.parse(text);
            } catch {
                value = text;
            }
        }
        return { status: response.status, value };
    }, {
        url: `${apiOrigin}${path}`,
        verb: method,
        payload: body,
        tenantId: tenant,
        key: idempotencyKey,
    });
    if (result.status < 200 || result.status >= 300) {
        throw new Error(`${method} ${path} returned ${result.status}: ${JSON.stringify(result.value)}`);
    }
    return result.value;
}

async function openAdministration(page, tenant) {
    const opened = await apiJson(
        page,
        "POST",
        "/gaugeapps/administration/sessions",
        { scope: { kind: "tenant", id: tenant } },
        tenant,
    );
    return opened.session;
}

function commandEnvelope(session, pageId, commandId, payload, key) {
    const page = session.pages.find((candidate) => candidate.id === pageId);
    if (!page) throw new Error(`Administration session did not grant ${pageId}`);
    return {
        session_id: session.id,
        generation: session.generation,
        app: "administration",
        scope: session.scope,
        page_id: pageId,
        command_id: commandId,
        expected_basis: page.resource_basis,
        idempotency_key: key,
        payload,
        client: "web",
    };
}

async function reviewedCommand(page, tenant, pageId, commandId, payload, key) {
    const session = await openAdministration(page, tenant);
    const proposalKey = `${key}:proposal`;
    const proposed = await apiJson(
        page,
        "POST",
        "/gaugeapps/administration/commands",
        commandEnvelope(session, pageId, commandId, payload, proposalKey),
        tenant,
        proposalKey,
    );
    if (proposed.receipt?.status !== "proposed" || !proposed.proposal?.id) {
        throw new Error(`${commandId} did not create a reviewable proposal`);
    }
    const reviewed = await apiJson(
        page,
        "POST",
        `/gaugeapps/administration/proposals/${encodeURIComponent(proposed.proposal.id)}/review`,
        {
            session_id: session.id,
            generation: session.generation,
            app: "administration",
            scope: session.scope,
            decision: "accept",
            client: "web",
        },
        tenant,
        `${key}:review`,
    );
    if (reviewed.receipt?.status !== "applied") {
        throw new Error(`${commandId} was not applied after review`);
    }
    return reviewed;
}

async function immediateCommand(page, tenant, pageId, commandId, payload, key) {
    const session = await openAdministration(page, tenant);
    const result = await apiJson(
        page,
        "POST",
        "/gaugeapps/administration/commands",
        commandEnvelope(session, pageId, commandId, payload, key),
        tenant,
        key,
    );
    if (result.receipt?.status !== "applied") {
        throw new Error(`${commandId} was not applied immediately`);
    }
    return result;
}

async function readAdministrationPage(page, tenant, pageId) {
    const session = await openAdministration(page, tenant);
    const query = new URLSearchParams({
        session: session.id,
        generation: session.generation,
        scope: session.scope.id,
    });
    const response = await apiJson(
        page,
        "GET",
        `/gaugeapps/administration/pages/${pageId}?${query}`,
        undefined,
        tenant,
    );
    return response.page;
}

async function submitIdentityProviderLogin(page, username, expected) {
    await page.locator("#username").fill(username);
    await page.locator("#password").fill(password);
    await Promise.all([
        page.waitForURL(expected, { timeout: 30_000 }),
        page.locator("#kc-login").click(),
    ]);
}

async function runConnectionTest(browser, authorizeUrl, username, protocol) {
    const context = await browser.newContext();
    const page = await context.newPage();
    try {
        await page.goto(authorizeUrl, { waitUntil: "domcontentloaded" });
        await submitIdentityProviderLogin(
            page,
            username,
            (url) => url.origin === apiOrigin && (
                protocol === "oidc"
                    ? url.pathname === "/auth/callback"
                    : url.pathname === "/auth/saml/acs"
            ),
        );
        await page.waitForLoadState("domcontentloaded");
        const heading = await page.locator("h1").textContent({ timeout: 2_000 }).catch(() => null);
        if (heading !== "Sign-in test complete") {
            const body = await page.locator("body").textContent().catch(() => "");
            throw new Error(
                `${protocol} test sign-in did not reach its isolated completion `
                + `at ${page.url()}: ${body?.trim()}`,
            );
        }
    } finally {
        await context.close();
    }
}

async function runCorporateLogin(browser, staticOrigin, tenant, username, expectedMethod) {
    const context = await browser.newContext({
        extraHTTPHeaders: { "x-gaugewright-tenant": tenant },
    });
    const page = await context.newPage();
    try {
        await page.goto(`${apiOrigin}/auth/login`, { waitUntil: "domcontentloaded" });
        await submitIdentityProviderLogin(
            page,
            username,
            (url) => url.origin === staticOrigin,
        );
        const session = await apiJson(page, "GET", "/auth/session", undefined, tenant);
        if (session.method !== expectedMethod || session.label !== `Corporate sign-in (${expectedMethod.toUpperCase()})`) {
            throw new Error(`corporate ${expectedMethod} session was malformed: ${JSON.stringify(session)}`);
        }
        const tenancy = await apiJson(page, "GET", "/account/tenants", undefined, tenant);
        if (!tenancy.tenants?.some((entry) => entry.id === tenant && entry.personal === false)) {
            throw new Error(`corporate ${expectedMethod} account did not index the organization`);
        }
    } finally {
        await context.close();
    }
}

const stateRoot = await mkdtemp(resolve(tmpdir(), "gw-enterprise-login-canary-"));
const emailOutbox = resolve(stateRoot, "auth-email-outbox.json");
const ownerEmail = "enterprise-login-canary@gaugewright.invalid";
const staticPort = await freePort();
const staticOrigin = `http://localhost:${staticPort}`;
const staticServer = createServer((_request, response) => {
    response.writeHead(200, {
        "cache-control": "no-store",
        "content-type": "text/html; charset=utf-8",
    });
    response.end("<!doctype html><title>Enterprise login canary</title>");
});
await new Promise((resolveReady, reject) => {
    staticServer.once("error", reject);
    staticServer.listen(staticPort, "127.0.0.1", resolveReady);
});

let serverOutput = "";
let progress = "server startup";
const enterprise = spawn(serverBinary, [], {
    // Development SAML sidecar resolution is repository-relative. Durable
    // state still lives only in the temporary GAUGEDESK_ROOT below.
    cwd: repositoryRoot,
    env: {
        ...process.env,
        GAUGEDESK_ADDR: "127.0.0.1:1421",
        GAUGEDESK_ROOT: stateRoot,
        GAUGEDESK_WEB_ACCOUNT: "1",
        GAUGEDESK_GOOGLE_CLIENT_ID: clientId,
        GAUGEDESK_OIDC_ISSUER: issuer,
        GAUGEDESK_OIDC_REDIRECT_URI: `${apiOrigin}/auth/callback`,
        GAUGEDESK_OIDC_POST_LOGIN_URL: `${staticOrigin}/`,
        GAUGEDESK_PUBLIC_URL: apiOrigin,
        GAUGEDESK_SP_ENTITY_ID: "gaugewright-saml-sp",
        GAUGEDESK_SESSION_COOKIE_INSECURE: "1",
        GAUGEDESK_ALLOWED_ORIGINS: staticOrigin,
        // The owner arrives by passkey, so this composition needs its WebAuthn
        // relying party and a readable stand-in for the mail provider.
        GAUGEDESK_TEST_RESET: "1",
        GAUGEDESK_ACCOUNT_RP_ID: "localhost",
        GAUGEDESK_ACCOUNT_ORIGIN: staticOrigin,
        GAUGEDESK_TEST_AUTH_EMAIL_OUTBOX: emailOutbox,
    },
    stdio: ["ignore", "pipe", "pipe"],
});
enterprise.stdout.on("data", (chunk) => { serverOutput += chunk.toString(); });
enterprise.stderr.on("data", (chunk) => { serverOutput += chunk.toString(); });

let browser;
try {
    await waitForHealth(enterprise);
    browser = await chromium.launch({ channel: "chrome", headless: true });

    // The owner needs a session to create the organization, not a provider.
    // Consumer sign-in used to supply one; it now resolves an existing subject
    // link and mints nothing (ADR 0146), so on a fresh state root it refuses.
    // The passkey door is how a first person arrives, and this test is about
    // the corporate connections that owner then configures.
    progress = "owner passkey account";
    const ownerContext = await browser.newContext();
    const ownerPage = await ownerContext.newPage();
    await ownerPage.goto(`${staticOrigin}/`, { waitUntil: "domcontentloaded" });
    const detachOwnerAuthenticator = await attachVirtualAuthenticator(ownerContext, ownerPage);
    const ownerChallenge = await beginEmailProof(ownerPage, apiOrigin, ownerEmail);
    const ownerMail = JSON.parse(await readFile(emailOutbox, "utf8"));
    if (ownerMail?.purpose !== "verification" || ownerMail?.email !== ownerEmail) {
        throw new Error(`unexpected verification mail: ${JSON.stringify(ownerMail)}`);
    }
    await completePasskeyAccount(ownerPage, apiOrigin, {
        challengeId: ownerChallenge,
        code: ownerMail.code,
        displayName: "Enterprise login canary owner",
    });
    await detachOwnerAuthenticator();

    progress = "organization creation";
    const created = await apiJson(
        ownerPage,
        "POST",
        "/account/tenants",
        { display_name: "Configured provider canary" },
        undefined,
        "configured-provider-canary:organization",
    );
    const tenant = created.tenant?.id;
    if (typeof tenant !== "string" || !tenant.startsWith("organization:")) {
        throw new Error(`organization creation was malformed: ${JSON.stringify(created)}`);
    }

    progress = "OIDC organization configuration";
    await reviewedCommand(
        ownerPage,
        tenant,
        "enterprise-identity",
        "enterprise-identity.connection.set",
        {
            protocol: "oidc",
            issuer,
            audiences: [clientId],
            metadata: "",
            enforce_sso: false,
            claim_mapping: {
                subject_claim: "sub",
                email_claim: null,
                roles_claim: "roles",
                region_claim: null,
                tenant_claim: null,
            },
        },
        "configured-provider-canary:oidc-connection",
    );
    await reviewedCommand(
        ownerPage,
        tenant,
        "enterprise-identity",
        "enterprise-identity.admission-mode.set",
        { mode: "invited-only" },
        "configured-provider-canary:admission",
    );

    progress = "OIDC isolated test sign-in";
    const oidcTest = await immediateCommand(
        ownerPage,
        tenant,
        "enterprise-identity",
        "enterprise-identity.test.begin",
        {},
        "configured-provider-canary:oidc-test",
    );
    await runConnectionTest(browser, oidcTest.result?.authorize_url, oidcUsername, "oidc");
    const oidcEvidence = await readAdministrationPage(ownerPage, tenant, "enterprise-identity");
    if (oidcEvidence.model?.browser_test?.protocol !== "oidc") {
        throw new Error("OIDC browser-test evidence was not projected for the current revision");
    }

    progress = "OIDC invitation and ordinary login";
    await reviewedCommand(
        ownerPage,
        tenant,
        "people",
        "people.invitation.create",
        { emails: [oidcEmail], role: "member" },
        "configured-provider-canary:oidc-invitation",
    );
    await runCorporateLogin(browser, staticOrigin, tenant, oidcUsername, "oidc");

    progress = "SAML organization configuration";
    const metadata = await fetch(`${issuer}/protocol/saml/descriptor`).then(async (response) => {
        if (!response.ok) throw new Error(`SAML metadata returned ${response.status}`);
        return response.text();
    });
    await reviewedCommand(
        ownerPage,
        tenant,
        "enterprise-identity",
        "enterprise-identity.connection.set",
        {
            protocol: "saml",
            issuer: "",
            audiences: [],
            metadata,
            enforce_sso: false,
            claim_mapping: {
                subject_claim: null,
                email_claim: null,
                roles_claim: "roles",
                region_claim: null,
                tenant_claim: null,
            },
        },
        "configured-provider-canary:saml-connection",
    );

    progress = "SAML isolated test sign-in";
    const samlTest = await immediateCommand(
        ownerPage,
        tenant,
        "enterprise-identity",
        "enterprise-identity.test.begin",
        {},
        "configured-provider-canary:saml-test",
    );
    await runConnectionTest(browser, samlTest.result?.authorize_url, samlUsername, "saml");
    const samlEvidence = await readAdministrationPage(ownerPage, tenant, "enterprise-identity");
    if (samlEvidence.model?.browser_test?.protocol !== "saml") {
        throw new Error("SAML browser-test evidence was not projected for the current revision");
    }

    progress = "SAML invitation and ordinary login";
    await reviewedCommand(
        ownerPage,
        tenant,
        "people",
        "people.invitation.create",
        { emails: [samlEmail], role: "member" },
        "configured-provider-canary:saml-invitation",
    );
    await runCorporateLogin(browser, staticOrigin, tenant, samlUsername, "saml");

    const people = await readAdministrationPage(ownerPage, tenant, "people");
    const admitted = new Map(people.model.members.map((member) => [member.email, member]));
    for (const email of [oidcEmail, samlEmail]) {
        if (admitted.get(email)?.status !== "active") {
            throw new Error(`${email} was not admitted as an active organization member`);
        }
    }
    await ownerContext.close();
    console.log("PASS configured organization OIDC + SAML browser login canary");
} catch (error) {
    throw new Error(`${progress} failed: ${error instanceof Error ? error.message : error}\n${serverOutput}`);
} finally {
    if (browser) await browser.close();
    enterprise.kill("SIGTERM");
    await new Promise((resolveExit) => {
        if (enterprise.exitCode !== null) resolveExit();
        else {
            enterprise.once("exit", resolveExit);
            setTimeout(resolveExit, 2_000);
        }
    });
    await new Promise((resolveClosed) => staticServer.close(resolveClosed));
    await rm(stateRoot, { recursive: true, force: true });
}
