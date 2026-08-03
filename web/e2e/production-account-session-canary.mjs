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
        await signIn.click();
        const callbackResponse = await callback;
        assert(
            [302, 303].includes(callbackResponse.status()),
            `OIDC callback returned ${callbackResponse.status()}`,
        );
        await page.waitForURL((url) => url.origin === frontendOrigin, {
            timeout: 30_000,
            waitUntil: "domcontentloaded",
        });
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
        assert.equal(beforeRefresh.body?.method, "oidc", "browser session is not OIDC-backed");
        const refresh = await browserRequest(page, apiOrigin, "/auth/refresh");
        assert.equal(refresh.status, 200, `hosted session refresh returned ${refresh.status}`);
        const afterRefresh = await browserRequest(page, apiOrigin, "/auth/session");
        assert.equal(afterRefresh.status, 200, "refreshed browser session is not authenticated");
        assert.equal(afterRefresh.body?.method, "oidc", "refreshed session changed authority");

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
