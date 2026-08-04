import assert from "node:assert/strict";

function required(environment, name) {
    const value = environment[name]?.trim();
    assert(value, `${name} is required`);
    return value;
}

export function exactOrigin(environment, name) {
    const url = new URL(required(environment, name));
    assert.equal(url.protocol, "https:", `${name} must use HTTPS`);
    assert.equal(url.pathname, "/", `${name} must not contain a path`);
    url.search = "";
    url.hash = "";
    return url.href.replace(/\/$/, "");
}

export function providerStorageState(environment) {
    let state;
    const text = required(environment, "GW_SYNTHETIC_OIDC_STORAGE_STATE");
    assert(text.length <= 1_000_000, "OIDC browser storage state is oversized");
    try {
        state = JSON.parse(text);
    } catch {
        assert.fail("GW_SYNTHETIC_OIDC_STORAGE_STATE is not JSON");
    }
    assert(Array.isArray(state?.cookies), "OIDC browser storage state has no cookies");
    assert(Array.isArray(state?.origins), "OIDC browser storage state has no origins");
    return {
        cookies: state.cookies.filter((cookie) => {
            const domain = String(cookie?.domain ?? "").replace(/^\./, "").toLowerCase();
            return domain !== "gaugewright.com" && !domain.endsWith(".gaugewright.com");
        }),
        origins: state.origins.filter((origin) => {
            try {
                const host = new URL(origin.origin).hostname.toLowerCase();
                return host !== "gaugewright.com" && !host.endsWith(".gaugewright.com");
            } catch {
                return false;
            }
        }),
    };
}

// A provider session that is valid but not yet "selected" interposes an account
// chooser, and a first authorization interposes a consent screen. Both are
// advanced explicitly. Every screen the canary does not recognise, a chooser
// that does not offer exactly one account, and any navigation off the admitted
// origins fail the run: silently tolerating them would let a changed provider
// flow, a second signed-in account, or a redirect to an unexpected host read as
// a healthy production sign-in.
const PROVIDER_STEP_TIMEOUT_MS = 30_000;
const PROVIDER_SCREEN_TIMEOUT_MS = 15_000;
const MAX_PROVIDER_STEPS = 6;
// The provider marks an account tile differently across its chooser variants.
// These are tried in order and only the first that matches is counted: taking
// their union would count one account twice when a variant carries both, and a
// miscount here is the difference between admitting a sole account and refusing
// a profile that holds several.
const ACCOUNT_MARKERS = ["[data-identifier]", "[data-email]"];
const CONSENT_CONTROLS = [
    "#submit_approve_access",
    "[data-consent-continue]",
    "button:has-text('Continue')",
    "button:has-text('Allow')",
].join(", ");

// The control plane labels a session by the provider that backs it: a Google
// issuer reports "google" and any other OIDC issuer reports "oidc". Deriving the
// expectation from the declared provider keeps the assertion exact, so a session
// that silently degrades to "local" — an SSO connection lost — still fails.
function expectedSessionMethod(providerOrigin) {
    const host = new URL(providerOrigin).hostname;
    return host.includes("accounts.google.com") || host.includes("googleusercontent.com")
        ? "google"
        : "oidc";
}

export function providerOriginFor(environment) {
    const raw = environment.GW_SYNTHETIC_OIDC_PROVIDER_ORIGIN?.trim()
        || "https://accounts.google.com";
    const url = new URL(raw);
    assert.equal(url.protocol, "https:", "the provider origin must use HTTPS");
    assert.equal(url.pathname, "/", "the provider origin must not contain a path");
    return url.origin;
}

// Diagnostics name the origin and path of a provider screen and never its
// content, so a failure cannot deposit an account address or page text into a
// job log.
function providerLocation(page) {
    let current;
    try {
        current = new URL(page.url());
    } catch {
        assert.fail("sign-in left the browser on an unparseable URL");
    }
    return { origin: current.origin, path: current.pathname };
}

async function settleAfter(page, clicked) {
    await Promise.any([
        page.waitForLoadState("domcontentloaded", { timeout: PROVIDER_STEP_TIMEOUT_MS }),
        clicked.waitFor({ state: "detached", timeout: PROVIDER_STEP_TIMEOUT_MS }),
    ]).catch(() => {});
}

// A screen is judged only once one of its controls has attached. Counting the
// instant a navigation commits would read an empty document and call every
// provider screen unrecognised, which is exactly how a rendering delay would
// masquerade as a changed provider flow.
async function accountTiles(page) {
    for (const marker of ACCOUNT_MARKERS) {
        const marked = page.locator(marker);
        const markedCount = await marked.count();
        if (markedCount === 0) continue;
        // Prefer the enclosing list item when the provider wraps each tile in
        // one, so the click lands on the control that carries the handler.
        const enclosing = page.locator(`li:has(${marker})`);
        return (await enclosing.count()) === markedCount ? enclosing : marked;
    }
    return null;
}

async function awaitRecognisableScreen(page) {
    await page
        .waitForLoadState("domcontentloaded", { timeout: PROVIDER_STEP_TIMEOUT_MS })
        .catch(() => {});
    const anyAccount = page.locator(ACCOUNT_MARKERS.join(", "));
    const consent = page.locator(CONSENT_CONTROLS);
    await Promise.any([
        anyAccount.first().waitFor({ state: "attached", timeout: PROVIDER_SCREEN_TIMEOUT_MS }),
        consent.first().waitFor({ state: "attached", timeout: PROVIDER_SCREEN_TIMEOUT_MS }),
    ]).catch(() => {});
    return { accounts: await accountTiles(page), consent };
}

export async function advanceProviderStates(page, admitted, isSettled) {
    for (let step = 0; step < MAX_PROVIDER_STEPS; step += 1) {
        if (isSettled()) return;
        const here = providerLocation(page);
        if (here.origin !== admitted.provider) {
            assert(
                [admitted.api, admitted.frontend, admitted.postLogin]
                    .filter(Boolean)
                    .includes(here.origin),
                `sign-in reached the unadmitted origin ${here.origin}`,
            );
            return;
        }

        const { accounts, consent } = await awaitRecognisableScreen(page);
        if (isSettled()) return;
        const offered = accounts ? await accounts.count() : 0;
        if (offered > 0) {
            assert.equal(
                offered,
                1,
                `the provider offered ${offered} accounts at ${here.path}; the synthetic `
                    + "profile must hold exactly one",
            );
            const account = accounts.first();
            await account.click();
            await settleAfter(page, account);
            continue;
        }

        if (await consent.count() > 0) {
            const control = consent.first();
            await control.click();
            await settleAfter(page, control);
            continue;
        }

        assert.fail(`the provider presented an unrecognised screen at ${here.path}`);
    }
    assert(
        isSettled(),
        `sign-in did not return through the callback within ${MAX_PROVIDER_STEPS} provider steps`,
    );
}

export async function defaultBrowserType() {
    const { chromium } = await import("playwright");
    return chromium;
}

async function browserRequest(page, origin, path, method = "GET") {
    return page.evaluate(async ({ target, requestMethod }) => {
        const response = await fetch(target, {
            method: requestMethod,
            credentials: "include",
            headers: requestMethod === "POST"
                ? { "idempotency-key": "production-wiring-canary:hosted-session:v1" }
                : undefined,
        });
        const text = await response.text();
        let body = null;
        try {
            body = text ? JSON.parse(text) : null;
        } catch {
            // The caller reports only the route and status, never an IdP body.
        }
        return { status: response.status, body };
    }, { target: `${origin}${path}`, requestMethod: method });
}

export async function runHostedAccountSession(
    environment = process.env,
    browserType,
) {
    const apiOrigin = exactOrigin(environment, "GW_SYNTHETIC_API_ORIGIN");
    const frontendOrigin = exactOrigin(
        environment,
        "GW_SYNTHETIC_GAUGEDESK_ORIGIN",
    );
    const providerOrigin = providerOriginFor(environment);
    // The deployment, not the client, chooses where a completed sign-in lands
    // (GAUGEWRIGHT_OIDC_POST_LOGIN_URL). Declaring it keeps the journey exact:
    // a changed landing page must fail here rather than pass unnoticed.
    const postLoginOrigin = environment.GW_SYNTHETIC_POST_LOGIN_ORIGIN?.trim()
        ? exactOrigin(environment, "GW_SYNTHETIC_POST_LOGIN_ORIGIN")
        : frontendOrigin;
    const storageState = providerStorageState(environment);
    const chromium = browserType ?? await defaultBrowserType();
    const browser = await chromium.launch({ headless: true });
    let context;
    try {
        context = await browser.newContext({ storageState });
        const page = await context.newPage();
        const observed = new Map();
        page.on("response", (response) => {
            const url = new URL(response.url());
            if (url.origin !== apiOrigin) return;
            if (["/auth/login", "/auth/callback", "/auth/refresh", "/auth/logout"]
                .includes(url.pathname)) {
                observed.set(url.pathname, response.status());
            }
        });

        await page.goto(`${frontendOrigin}/`, { waitUntil: "domcontentloaded" });
        const signIn = page.locator("[data-home-sign-in]");
        await signIn.waitFor({ state: "visible", timeout: 30_000 });
        const callback = page.waitForResponse((response) => {
            const url = new URL(response.url());
            return url.origin === apiOrigin && url.pathname === "/auth/callback";
        }, { timeout: 60_000 });
        let callbackSettled = false;
        // The rejection handler keeps a stalled callback from surfacing as an
        // unhandled rejection; `await callback` below still rethrows it.
        callback.then(() => { callbackSettled = true; }, () => {});
        await signIn.click();
        // Either the provider interposes a screen or the callback is already on
        // its way; both are admitted, anything else is surfaced by the walk.
        await Promise.race([
            page.waitForURL(
                (url) => url.origin === providerOrigin,
                { timeout: PROVIDER_STEP_TIMEOUT_MS },
            ),
            callback,
        ]).catch(() => {});
        await advanceProviderStates(
            page,
            {
                provider: providerOrigin,
                api: apiOrigin,
                frontend: frontendOrigin,
                postLogin: postLoginOrigin,
            },
            () => callbackSettled,
        );
        const callbackResponse = await callback;
        assert(
            [302, 303].includes(callbackResponse.status()),
            `OIDC callback returned ${callbackResponse.status()}`,
        );
        await page.waitForURL((url) => url.origin === postLoginOrigin, {
            timeout: 30_000,
            waitUntil: "domcontentloaded",
        });
        // The session cookie is issued for the whole domain, so the shipped
        // client is exercised where it actually runs rather than wherever the
        // deployment parks the browser after sign-in.
        if (postLoginOrigin !== frontendOrigin) {
            await page.goto(`${frontendOrigin}/`, { waitUntil: "domcontentloaded" });
        }
        assert(observed.has("/auth/login"), "shipped sign-in did not reach /auth/login");
        assert(observed.has("/auth/callback"), "provider did not return through /auth/callback");

        const cookies = await context.cookies(apiOrigin);
        const sessionCookie = cookies.find((cookie) => cookie.name === "gw_session");
        assert(sessionCookie, "OIDC callback set no gw_session cookie");
        assert.equal(sessionCookie.httpOnly, true, "gw_session is readable to JavaScript");
        assert.equal(sessionCookie.secure, true, "gw_session is not production-secure");
        assert.equal(sessionCookie.sameSite, "Lax", "gw_session SameSite drifted");

        const beforeRefresh = await browserRequest(page, apiOrigin, "/auth/session");
        assert.equal(beforeRefresh.status, 200, "new browser session is not authenticated");
        const sessionMethod = expectedSessionMethod(providerOrigin);
        assert.equal(
            beforeRefresh.body?.method,
            sessionMethod,
            `browser session reports ${beforeRefresh.body?.method} rather than the `
                + `${sessionMethod} authority it just signed in through`,
        );
        const refresh = await browserRequest(page, apiOrigin, "/auth/refresh");
        assert.equal(refresh.status, 200, `hosted session refresh returned ${refresh.status}`);
        const afterRefresh = await browserRequest(page, apiOrigin, "/auth/session");
        assert.equal(afterRefresh.status, 200, "refreshed browser session is not authenticated");
        assert.equal(afterRefresh.body?.method, sessionMethod, "refreshed session changed authority");

        await page.locator("[data-settings]").click();
        const logout = page.waitForResponse((response) => {
            const url = new URL(response.url());
            return url.origin === apiOrigin && url.pathname === "/auth/logout";
        }, { timeout: 30_000 });
        await page.locator("[data-settings-sign-out]").click();
        const logoutResponse = await logout;
        assert.equal(logoutResponse.status(), 204, `shipped logout returned ${logoutResponse.status()}`);
        await page.locator("[data-home-sign-in]").waitFor({ state: "visible", timeout: 30_000 });
        const afterLogout = await browserRequest(page, apiOrigin, "/auth/session");
        assert.equal(afterLogout.status, 401, "logout left the browser session authenticated");
        const remaining = await context.cookies(apiOrigin);
        assert.equal(
            remaining.some((cookie) => cookie.name === "gw_session"),
            false,
            "logout retained the HttpOnly session cookie",
        );

        return {
            loginStatus: observed.get("/auth/login"),
            callbackStatus: observed.get("/auth/callback"),
            refreshStatus: refresh.status,
            logoutStatus: logoutResponse.status(),
        };
    } finally {
        await context?.close().catch(() => {});
        await browser.close().catch(() => {});
    }
}
