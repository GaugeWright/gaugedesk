import assert from "node:assert/strict";
import { pathToFileURL } from "node:url";

import {
    defaultBrowserType,
    exactOrigin,
} from "./production-account-session-canary.mjs";

function required(environment, name) {
    const value = environment[name]?.trim();
    assert(value, `${name} is required`);
    return value;
}

export function passkeyCanarySettings(environment = process.env) {
    const inbox = new URL(required(environment, "GW_SYNTHETIC_PASSKEY_INBOX_URL"));
    assert.equal(inbox.protocol, "https:", "the synthetic passkey inbox must use HTTPS");
    assert(!inbox.username && !inbox.password,
        "the synthetic passkey inbox URL must not contain credentials");
    assert(!inbox.search, "the synthetic passkey inbox URL must not contain a query");
    assert(!inbox.hash, "the synthetic passkey inbox URL must not contain a fragment");
    const email = required(environment, "GW_SYNTHETIC_PASSKEY_EMAIL").toLowerCase();
    assert(/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email), "the synthetic passkey email is invalid");
    return {
        apiOrigin: exactOrigin(environment, "GW_SYNTHETIC_API_ORIGIN"),
        deskOrigin: exactOrigin(environment, "GW_SYNTHETIC_GAUGEDESK_ORIGIN"),
        email,
        inbox,
        inboxToken: required(environment, "GW_SYNTHETIC_PASSKEY_INBOX_TOKEN"),
    };
}

function delay(milliseconds) {
    return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

export async function pollInboxCode({
    inbox,
    inboxToken,
    purpose,
    after,
    fetchImpl = fetch,
    wait = delay,
    attempts = 30,
}) {
    assert(["verification", "recovery"].includes(purpose), "unknown account email purpose");
    assert.match(after, /^\d{4}-\d{2}-\d{2}T/, "inbox lower bound must be an ISO timestamp");
    const endpoint = new URL(inbox);
    endpoint.searchParams.set("purpose", purpose);
    endpoint.searchParams.set("after", after);
    for (let attempt = 0; attempt < attempts; attempt += 1) {
        const response = await fetchImpl(endpoint, {
            headers: {
                accept: "application/json",
                authorization: `Bearer ${inboxToken}`,
            },
            redirect: "error",
        });
        if (response.status === 404 || response.status === 204) {
            if (attempt + 1 < attempts) await wait(2_000);
            continue;
        }
        assert.equal(response.status, 200, `synthetic inbox returned ${response.status}`);
        const text = await response.text();
        assert(text.length <= 4_096, "synthetic inbox returned an oversized response");
        let body;
        try {
            body = JSON.parse(text);
        } catch {
            assert.fail("synthetic inbox returned invalid JSON");
        }
        assert(body !== null && typeof body === "object" && !Array.isArray(body),
            "synthetic inbox returned an invalid document");
        assert.deepEqual(
            Object.keys(body).sort(),
            ["code", "purpose", "received_at"],
            "synthetic inbox returned an unexpected shape",
        );
        assert.equal(body.purpose, purpose, "synthetic inbox returned the wrong purpose");
        assert(/^\d{8}$/.test(body.code), "synthetic inbox returned an invalid code");
        const receivedAt = Date.parse(body.received_at);
        assert(Number.isFinite(receivedAt), "synthetic inbox returned an invalid delivery time");
        assert(receivedAt >= Date.parse(after), "synthetic inbox returned a stale code");
        return body.code;
    }
    assert.fail(`no fresh ${purpose} email arrived before the bounded deadline`);
}

async function waitForPost(page, apiOrigin, pathname, action) {
    const response = page.waitForResponse((candidate) => {
        const url = new URL(candidate.url());
        return candidate.request().method() === "POST"
            && url.origin === apiOrigin
            && url.pathname === pathname;
    }, { timeout: 60_000 });
    await action();
    const settled = await response;
    assert.equal(settled.status(), pathname.endsWith("/start") ? 202 : 200,
        `${pathname} returned ${settled.status()}`);
}

async function openAccountPage(page, deskOrigin) {
    await page.goto(`${deskOrigin}/?app=account-settings`, { waitUntil: "domcontentloaded" });
    await page.getByRole("heading", { name: "Account Settings", exact: true, level: 1 })
        .waitFor({ state: "visible", timeout: 60_000 });
}

async function signInWithPasskey(page, deskOrigin, email, apiOrigin) {
    await page.goto(`${deskOrigin}/`, { waitUntil: "domcontentloaded" });
    const entry = page.locator("[data-account-entry]");
    await entry.waitFor({ state: "visible", timeout: 60_000 });
    await page.getByRole("button", { name: "Sign in with a passkey", exact: true }).click();
    await page.getByLabel("Account email", { exact: true }).fill(email);
    await waitForPost(page, apiOrigin, "/auth/account/passkey/login/finish", async () => {
        await page.getByRole("button", { name: "Continue with passkey", exact: true }).click();
    });
    await entry.waitFor({ state: "detached", timeout: 60_000 });
}

async function logout(context, apiOrigin, idempotencyKey) {
    const response = await context.request.fetch(`${apiOrigin}/auth/logout`, {
        method: "POST",
        headers: { "idempotency-key": idempotencyKey },
        timeout: 30_000,
    });
    assert.equal(response.status(), 204, `account logout returned ${response.status()}`);
}

async function issueRecoveryCode(page) {
    await page.getByRole("button", { name: "Issue new codes", exact: true }).click();
    const pending = page.getByRole("region", { name: "Pending changes", exact: true });
    if (await pending.count()) {
        await pending.getByRole("button", { name: "Accept", exact: true }).click();
    }
    const region = page.getByRole("region", { name: "New recovery codes", exact: true });
    await region.waitFor({ state: "visible", timeout: 60_000 });
    const lines = (await region.locator("code").innerText())
        .split(/\s+/)
        .map((value) => value.trim())
        .filter(Boolean);
    assert(lines.length > 0, "Account Settings returned no recovery codes");
    assert(lines.every((value) => value.length >= 16 && value.length <= 256),
        "Account Settings returned a malformed recovery code");
    return lines[0];
}

async function eraseAccount(page, deskOrigin) {
    await openAccountPage(page, deskOrigin);
    await page.getByRole("button", { name: "Delete", exact: true }).click();
    await page.getByLabel("Enter ERASE MY ACCOUNT to continue", { exact: true })
        .fill("ERASE MY ACCOUNT");
    await page.getByRole("button", { name: "Continue", exact: true }).click();
    const pending = page.getByRole("region", { name: "Pending changes", exact: true });
    await pending.waitFor({ state: "visible", timeout: 60_000 });
    await pending.getByRole("button", { name: "Accept", exact: true }).click();
    await page.getByLabel("Account erasure result", { exact: true })
        .waitFor({ state: "visible", timeout: 120_000 });
    assert.equal(
        (await page.getByLabel("Account erasure result", { exact: true }).innerText()).trim(),
        "erased",
        "account erasure did not reach its terminal receipt",
    );
}

export async function runPasskeyAccountJourney(
    environment = process.env,
    browserType,
    { fetchImpl = fetch, wait = delay } = {},
) {
    const settings = passkeyCanarySettings(environment);
    const chromium = browserType ?? await defaultBrowserType();
    const browser = await chromium.launch({ headless: true });
    let context;
    let page;
    let cdp;
    let authenticatorId = "";
    let accountCreated = false;
    let accountErased = false;
    let authenticated = false;
    let primaryError = null;
    const cleanupErrors = [];
    const executionId = crypto.randomUUID();
    const key = (operation) => `production-wiring-canary:passkey-account:${operation}:${executionId}`;
    const readCode = (purpose, after) => pollInboxCode({
        inbox: settings.inbox,
        inboxToken: settings.inboxToken,
        purpose,
        after,
        fetchImpl,
        wait,
    });

    try {
        context = await browser.newContext({ locale: "en-US", viewport: { width: 1440, height: 1000 } });
        page = await context.newPage();
        cdp = await context.newCDPSession(page);
        await cdp.send("WebAuthn.enable");
        ({ authenticatorId } = await cdp.send("WebAuthn.addVirtualAuthenticator", {
            options: {
                protocol: "ctap2",
                transport: "internal",
                hasResidentKey: true,
                hasUserVerification: true,
                isUserVerified: true,
                automaticPresenceSimulation: true,
            },
        }));

        await page.goto(`${settings.deskOrigin}/`, { waitUntil: "domcontentloaded" });
        await page.locator("[data-account-entry]").waitFor({ state: "visible", timeout: 60_000 });
        await page.getByRole("button", { name: "Create an account", exact: true }).click();
        await page.getByLabel("Your name", { exact: true }).fill("GaugeDesk passkey canary");
        await page.getByLabel("Email", { exact: true }).fill(settings.email);
        const verificationAfter = new Date().toISOString();
        await waitForPost(page, settings.apiOrigin, "/auth/account/email/start", async () => {
            await page.getByRole("button", { name: "Send verification code", exact: true }).click();
        });
        const verificationCode = await readCode("verification", verificationAfter);
        await page.getByLabel("Email code", { exact: true }).fill(verificationCode);
        await waitForPost(page, settings.apiOrigin, "/auth/account/passkey/register/finish", async () => {
            await page.getByRole("button", { name: "Create passkey account", exact: true }).click();
        });
        accountCreated = true;
        authenticated = true;
        await page.locator("[data-account-entry]").waitFor({ state: "detached", timeout: 60_000 });

        await openAccountPage(page, settings.deskOrigin);
        const recoveryCode = await issueRecoveryCode(page);

        await logout(context, settings.apiOrigin, key("logout-before-login"));
        authenticated = false;
        await signInWithPasskey(page, settings.deskOrigin, settings.email, settings.apiOrigin);
        authenticated = true;

        await logout(context, settings.apiOrigin, key("logout-before-recovery"));
        authenticated = false;
        await page.goto(`${settings.deskOrigin}/`, { waitUntil: "domcontentloaded" });
        await page.locator("[data-account-entry]").waitFor({ state: "visible", timeout: 60_000 });
        await page.getByRole("button", { name: "Use a recovery code", exact: true }).click();
        await page.getByLabel("Verified email", { exact: true }).fill(settings.email);
        const recoveryAfter = new Date().toISOString();
        await waitForPost(page, settings.apiOrigin, "/auth/account/recovery/start", async () => {
            await page.getByRole("button", { name: "Send code", exact: true }).click();
        });
        const recoveryEmailCode = await readCode("recovery", recoveryAfter);
        await page.getByLabel("Email code", { exact: true }).fill(recoveryEmailCode);
        await page.getByLabel("Recovery code", { exact: true }).fill(recoveryCode);
        await waitForPost(page, settings.apiOrigin, "/auth/account/recovery/finish", async () => {
            await page.getByRole("button", { name: "Recover account", exact: true }).click();
        });
        authenticated = true;

        await eraseAccount(page, settings.deskOrigin);
        accountErased = true;
        authenticated = false;
        const session = await context.request.fetch(`${settings.apiOrigin}/auth/session`, {
            timeout: 30_000,
        });
        assert.equal(session.status(), 401, "erased account retained an authenticated session");
        const login = await context.request.fetch(`${settings.apiOrigin}/auth/account/passkey/login/start`, {
            method: "POST",
            data: { email: settings.email },
            timeout: 30_000,
        });
        assert.equal(login.status(), 401, "erased account retained a reusable passkey identity");
        return {
            accountErased: true,
            passkeyReauthenticated: true,
            recoveryReauthenticated: true,
            freshAuthorizationCompleted: true,
        };
    } catch (error) {
        primaryError = error;
    } finally {
        if (page && accountCreated && !accountErased) {
            try {
                if (!authenticated) {
                    await signInWithPasskey(page, settings.deskOrigin, settings.email, settings.apiOrigin);
                    authenticated = true;
                }
                await eraseAccount(page, settings.deskOrigin);
                accountErased = true;
            } catch (error) {
                cleanupErrors.push(error);
            }
        }
        if (context && authenticated && !accountErased) {
            try {
                await logout(context, settings.apiOrigin, key("cleanup-logout"));
            } catch (error) {
                cleanupErrors.push(error);
            }
        }
        if (cdp && authenticatorId) {
            await cdp.send("WebAuthn.removeVirtualAuthenticator", { authenticatorId })
                .catch((error) => cleanupErrors.push(error));
        }
        if (cdp) {
            await cdp.send("WebAuthn.disable").catch((error) => cleanupErrors.push(error));
            await cdp.detach().catch((error) => cleanupErrors.push(error));
        }
        if (context) await context.close().catch((error) => cleanupErrors.push(error));
        await browser.close().catch((error) => cleanupErrors.push(error));
    }
    throw new AggregateError(
        [...(primaryError ? [primaryError] : []), ...cleanupErrors],
        "passkey account journey or terminal cleanup failed",
    );
}

async function main() {
    assert.equal(process.argv[2], "passkey-account-browser-journey", "unknown production canary suite");
    const result = await runPasskeyAccountJourney();
    console.log(`Passkey account browser journey passed; terminal erasure: ${result.accountErased}`);
}

const invoked = process.argv[1]
    && import.meta.url === pathToFileURL(process.argv[1]).href;
if (invoked) await main();
