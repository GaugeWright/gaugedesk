import assert from "node:assert/strict";
import { createHash, randomBytes, randomUUID } from "node:crypto";

import {
    defaultBrowserType,
    exactOrigin,
    providerStorageState,
} from "./production-account-session-canary.mjs";

function handoffChallenge(verifier) {
    return createHash("sha256").update(verifier).digest("base64url");
}

async function mobileRoute(fetchImpl, origin, path, { token, body } = {}) {
    const response = await fetchImpl(`${origin}${path}`, {
        method: "POST",
        headers: {
            accept: "application/json",
            "idempotency-key": randomUUID(),
            ...(token ? { authorization: `Bearer ${token}` } : {}),
            ...(body === undefined ? {} : { "content-type": "application/json" }),
        },
        body: body === undefined ? undefined : JSON.stringify(body),
        signal: AbortSignal.timeout(30_000),
    });
    const text = await response.text();
    let parsed = null;
    try {
        parsed = text ? JSON.parse(text) : null;
    } catch {
        // The caller reports only the route and status, never a token body.
    }
    return { status: response.status, body: parsed };
}

export async function runNativeAccountSession(
    environment = process.env,
    browserType,
    fetchImpl = fetch,
) {
    const apiOrigin = exactOrigin(environment, "GW_SYNTHETIC_API_ORIGIN");
    const storageState = providerStorageState(environment);
    const chromium = browserType ?? await defaultBrowserType();
    const browser = await chromium.launch({ headless: true });

    const issueHandoff = async (challenge) => {
        const context = await browser.newContext({ storageState });
        try {
            const page = await context.newPage();
            const login = new URL(`${apiOrigin}/auth/login`);
            login.searchParams.set("return_to", "gaugewright://auth/callback");
            login.searchParams.set("handoff_challenge", challenge);
            const callbackPromise = page.waitForResponse(
                (response) => response.url().startsWith(`${apiOrigin}/auth/callback?`),
                { timeout: 60_000 },
            );
            await page.goto(login.toString(), { waitUntil: "commit" }).catch(() => {});
            const callback = await callbackPromise;
            const location = callback.headers().location;
            assert(
                [302, 303].includes(callback.status()) && location,
                `native callback returned ${callback.status()} without a redirect`,
            );
            const returned = new URL(location);
            assert(
                returned.protocol === "gaugewright:"
                    && returned.hostname === "auth"
                    && returned.pathname === "/callback",
                "native callback target was not allowlisted",
            );
            const code = new URLSearchParams(returned.hash.slice(1)).get("code");
            assert(code, "native callback did not carry an opaque code");
            assert.match(code, /^[A-Za-z0-9_-]{43}$/, "native handoff code is malformed");
            return code;
        } finally {
            await context.close().catch(() => {});
        }
    };

    try {
        const burnedVerifier = randomBytes(32).toString("hex");
        const burnedCode = await issueHandoff(handoffChallenge(burnedVerifier));
        const wrongVerifier = await mobileRoute(fetchImpl, apiOrigin, "/auth/mobile/exchange", {
            body: { code: burnedCode, verifier: randomBytes(32).toString("hex") },
        });
        assert.equal(wrongVerifier.status, 401, "a mismatched PKCE verifier was admitted");
        const burnedRedeem = await mobileRoute(fetchImpl, apiOrigin, "/auth/mobile/exchange", {
            body: { code: burnedCode, verifier: burnedVerifier },
        });
        assert.equal(burnedRedeem.status, 401, "a burned handoff code was redeemed again");

        const verifier = randomBytes(32).toString("hex");
        const code = await issueHandoff(handoffChallenge(verifier));
        const exchanged = await mobileRoute(fetchImpl, apiOrigin, "/auth/mobile/exchange", {
            body: { code, verifier },
        });
        assert.equal(exchanged.status, 200, `native exchange returned ${exchanged.status}`);
        assert.equal(typeof exchanged.body?.id_token, "string", "native exchange returned no token");
        assert(exchanged.body.id_token.length > 100, "native session token is malformed");
        assert.equal(exchanged.body?.token_type, "Bearer", "native exchange token type drifted");

        const replay = await mobileRoute(fetchImpl, apiOrigin, "/auth/mobile/exchange", {
            body: { code, verifier },
        });
        assert.equal(replay.status, 401, "a redeemed handoff code was replayed");

        const refreshed = await mobileRoute(fetchImpl, apiOrigin, "/auth/mobile/refresh", {
            token: exchanged.body.id_token,
        });
        assert.equal(refreshed.status, 200, `native refresh returned ${refreshed.status}`);
        assert.equal(typeof refreshed.body?.id_token, "string", "native refresh returned no token");
        assert.equal(typeof refreshed.body?.person, "string", "native refresh named no person");

        const anonymousRefresh = await mobileRoute(fetchImpl, apiOrigin, "/auth/mobile/refresh", {
            token: "invalid-native-bearer",
        });
        assert.equal(anonymousRefresh.status, 401, "an invalid native bearer was refreshed");

        return {
            exchangeStatus: exchanged.status,
            refreshStatus: refreshed.status,
            person: refreshed.body.person,
        };
    } finally {
        await browser.close().catch(() => {});
    }
}
