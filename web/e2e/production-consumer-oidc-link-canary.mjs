import assert from "node:assert/strict";

import {
    advanceProviderStates,
    defaultBrowserType,
    exactOrigin,
    providerOriginFor,
    providerStorageState,
    totpSecretFor,
} from "./production-account-session-canary.mjs";

function required(environment, name) {
    const value = environment[name]?.trim();
    assert(value, `${name} is required`);
    return value;
}

export function independentAccountStorageState(environment) {
    let state;
    const text = required(environment, "GW_SYNTHETIC_LINK_ACCOUNT_STORAGE_STATE");
    assert(text.length <= 1_000_000, "independent account browser storage state is oversized");
    try {
        state = JSON.parse(text);
    } catch {
        assert.fail("GW_SYNTHETIC_LINK_ACCOUNT_STORAGE_STATE is not JSON");
    }
    assert(Array.isArray(state?.cookies), "independent account browser storage state has no cookies");
    const cookies = state.cookies.filter((cookie) => {
        const domain = String(cookie?.domain ?? "").replace(/^\./, "").toLowerCase();
        return domain === "gaugewright.com" || domain.endsWith(".gaugewright.com");
    });
    const sessions = cookies.filter((cookie) => cookie?.name === "gw_session");
    assert.equal(sessions.length, 1, "independent account state must hold exactly one gw_session cookie");
    assert.equal(sessions[0].httpOnly, true, "independent account session is not HttpOnly");
    assert.equal(sessions[0].secure, true, "independent account session is not Secure");
    return { cookies: sessions, origins: [] };
}

function linkProviderStorageState(environment) {
    return providerStorageState({
        ...environment,
        GW_SYNTHETIC_OIDC_STORAGE_STATE: required(
            environment,
            "GW_SYNTHETIC_LINK_OIDC_STORAGE_STATE",
        ),
    });
}

async function requestJson(requestContext, origin, path, {
    method = "GET",
    data,
    idempotencyKey,
    expectedStatus = 200,
} = {}) {
    const response = await requestContext.fetch(`${origin}${path}`, {
        method,
        data,
        headers: {
            accept: "application/json",
            ...(idempotencyKey ? { "idempotency-key": idempotencyKey } : {}),
        },
        timeout: 30_000,
    });
    const status = response.status();
    const text = await response.text();
    assert(text.length <= 1_000_000, `${method} ${path} returned an oversized response`);
    let body = null;
    try {
        body = text ? JSON.parse(text) : null;
    } catch {
        // Status is reported below without echoing an untrusted response body.
    }
    assert.equal(status, expectedStatus, `${method} ${path} returned ${status}`);
    return body;
}

function sessionQuery(session) {
    return new URLSearchParams({
        session: session.id,
        generation: session.generation,
        scope: session.scope.id,
    }).toString();
}

async function readAccount(requestContext, origin) {
    const opened = await requestJson(
        requestContext,
        origin,
        "/gaugeapps/account-settings/sessions",
        { method: "POST", data: {} },
    );
    const session = opened?.session;
    assert.equal(session?.app, "account-settings", "Account Settings returned no GaugeApp session");
    assert.equal(session?.scope?.kind, "person", "Account Settings returned a non-person scope");
    const descriptor = session.pages?.find((page) => page.id === "account");
    assert(descriptor, "Account Settings session returned no Account page");
    const read = await requestJson(
        requestContext,
        origin,
        `/gaugeapps/account-settings/pages/account?${sessionQuery(session)}`,
    );
    assert(Array.isArray(read?.page?.model?.authenticators), "Account page returned no authenticators");
    return { session, descriptor, page: read.page };
}

async function removeAuthenticator(requestContext, origin, account, authenticator, idempotency) {
    assert(
        account.descriptor.commands?.includes("account.authenticator.remove"),
        "Account page does not admit authenticator removal",
    );
    const removeKey = idempotency("remove");
    const proposed = await requestJson(
        requestContext,
        origin,
        "/gaugeapps/account-settings/commands",
        {
            method: "POST",
            idempotencyKey: removeKey,
            data: {
                session_id: account.session.id,
                generation: account.session.generation,
                app: "account-settings",
                scope: account.session.scope,
                page_id: "account",
                command_id: "account.authenticator.remove",
                expected_basis: account.page.resource_basis,
                idempotency_key: removeKey,
                payload: { id: authenticator.id, kind: "consumer-oidc" },
                client: "web",
            },
        },
    );
    assert.equal(proposed?.receipt?.status, "proposed", "consumer sign-in removal skipped review");
    assert.equal(typeof proposed?.proposal?.id, "string", "consumer sign-in removal returned no proposal");
    const reviewed = await requestJson(
        requestContext,
        origin,
        `/gaugeapps/account-settings/proposals/${encodeURIComponent(proposed.proposal.id)}/review`,
        {
            method: "POST",
            idempotencyKey: idempotency("review"),
            data: {
                session_id: account.session.id,
                generation: account.session.generation,
                app: "account-settings",
                scope: account.session.scope,
                decision: "accept",
                client: "web",
            },
        },
    );
    assert.equal(reviewed?.receipt?.status, "applied", "consumer sign-in removal was not applied");
}

export async function runConsumerOidcLinkJourney(
    environment = process.env,
    browserType,
    { advanceProvider = advanceProviderStates } = {},
) {
    const apiOrigin = exactOrigin(environment, "GW_SYNTHETIC_API_ORIGIN");
    const frontendOrigin = exactOrigin(environment, "GW_SYNTHETIC_GAUGEDESK_ORIGIN");
    const providerOrigin = providerOriginFor(environment);
    const accountState = independentAccountStorageState(environment);
    const providerState = linkProviderStorageState(environment);
    const chromium = browserType ?? await defaultBrowserType();
    const browser = await chromium.launch({ headless: true });
    let context;
    let linkedId = null;
    let callbackLinked = false;
    let beforeIds = new Set();
    let removed = false;
    let loggedOut = false;
    let primaryError = null;
    const cleanupErrors = [];
    const executionId = crypto.randomUUID();
    const idempotency = (operation) =>
        `production-wiring-canary:consumer-oidc-link:${operation}:${executionId}`;

    try {
        context = await browser.newContext({
            storageState: {
                cookies: [...accountState.cookies, ...providerState.cookies],
                origins: providerState.origins,
            },
            locale: "en-US",
        });
        const before = await readAccount(context.request, apiOrigin);
        beforeIds = new Set(before.page.model.authenticators.map((item) => item.id));
        const started = await requestJson(
            context.request,
            apiOrigin,
            "/auth/account/consumer-oidc/link/start",
            { method: "POST" },
        );
        assert.match(started?.authorization_url ?? "", /^https:\/\//, "link start returned no HTTPS authorization URL");

        const page = await context.newPage();
        const callback = page.waitForResponse((response) => {
            const url = new URL(response.url());
            return url.origin === apiOrigin && url.pathname === "/auth/callback";
        }, { timeout: 60_000 });
        let callbackSettled = false;
        callback.then(() => { callbackSettled = true; }, () => {});
        await page.goto(started.authorization_url, { waitUntil: "domcontentloaded" });
        await advanceProvider(
            page,
            { provider: providerOrigin, api: apiOrigin, frontend: frontendOrigin },
            () => callbackSettled,
            {
                totpSecret: totpSecretFor({
                    ...environment,
                    GW_SYNTHETIC_OIDC_TOTP_SECRET:
                        environment.GW_SYNTHETIC_LINK_OIDC_TOTP_SECRET,
                }),
            },
        );
        const callbackResponse = await callback;
        assert.equal(callbackResponse.status(), 200, `consumer OIDC callback returned ${callbackResponse.status()}`);
        callbackLinked = true;

        const after = await readAccount(context.request, apiOrigin);
        const linked = after.page.model.authenticators.filter((item) =>
            item.kind === "consumer-oidc" && !beforeIds.has(item.id));
        assert.equal(linked.length, 1, "callback did not add exactly one consumer sign-in method");
        linkedId = linked[0].id;
        await removeAuthenticator(context.request, apiOrigin, after, linked[0], idempotency);
        removed = true;
        const reread = await readAccount(context.request, apiOrigin);
        assert(
            !reread.page.model.authenticators.some((item) => item.id === linkedId),
            "removed consumer sign-in method survived authoritative reread",
        );

        await requestJson(context.request, apiOrigin, "/auth/logout", {
            method: "POST",
            idempotencyKey: idempotency("logout"),
            expectedStatus: 204,
        });
        loggedOut = true;
        const refused = await context.request.fetch(
            `${apiOrigin}/gaugeapps/account-settings/sessions`,
            { method: "POST", data: {}, timeout: 30_000 },
        );
        assert.equal(refused.status(), 401, "independent account session survived logout");
        return { callbackStatus: 200, linkRemoved: true, sessionRevoked: true };
    } catch (error) {
        primaryError = error;
    } finally {
        if (context && callbackLinked && !removed) {
            try {
                const current = await readAccount(context.request, apiOrigin);
                const candidates = current.page.model.authenticators.filter((item) =>
                    item.kind === "consumer-oidc" && !beforeIds.has(item.id));
                assert.equal(candidates.length, 1, "cleanup could not identify the callback-created sign-in method");
                await removeAuthenticator(context.request, apiOrigin, current, candidates[0], idempotency);
            } catch (error) {
                cleanupErrors.push(error);
            }
        }
        if (context && !loggedOut) {
            try {
                await requestJson(context.request, apiOrigin, "/auth/logout", {
                    method: "POST",
                    idempotencyKey: idempotency("cleanup-logout"),
                    expectedStatus: 204,
                });
            } catch (error) {
                cleanupErrors.push(error);
            }
        }
        if (context) await context.close().catch((error) => cleanupErrors.push(error));
        await browser.close().catch((error) => cleanupErrors.push(error));
    }
    throw new AggregateError(
        [...(primaryError ? [primaryError] : []), ...cleanupErrors],
        "consumer OIDC link journey or cleanup failed",
    );
}
