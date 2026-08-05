import assert from "node:assert/strict";
import test from "node:test";

import { runHostedAccountSession,
    CONSENT_ROLE_NAME,
} from "./production-account-session-canary.mjs";

function response(url, status) {
    return { url: () => url, status: () => status };
}

test("hosted session canary uses shipped sign-in and sign-out with no retained cookie", async () => {
    let authenticated = false;
    let suppliedStorage;
    const responseListeners = [];
    const waiters = [];
    const emit = (item) => {
        for (const listener of responseListeners) listener(item);
        for (const waiter of waiters.splice(0)) {
            if (waiter.predicate(item)) waiter.resolve(item);
            else waiters.push(waiter);
        }
    };
    const page = {
        on(event, listener) {
            if (event === "response") responseListeners.push(listener);
        },
        async goto() {},
        async waitForURL() {},
        waitForResponse(predicate) {
            return new Promise((resolve) => waiters.push({ predicate, resolve }));
        },
        locator(selector) {
            const control = {
                async waitFor() {},
                async count() { return 0; },
                first() { return control; },
                or(other) { return combineControls(control, other); },
                async click() {
                    if (selector === "[data-home-sign-in]") {
                        emit(response("https://auth.gaugewright.com/auth/login", 302));
                        authenticated = true;
                        emit(response("https://auth.gaugewright.com/auth/callback?state=secret", 302));
                    }
                    if (selector === "[data-settings-sign-out]") {
                        authenticated = false;
                        emit(response("https://auth.gaugewright.com/auth/logout", 204));
                    }
                },
            };
            return control;
        },
        getByRole() {
            const control = {
                async waitFor() {},
                async count() { return 0; },
                first() { return control; },
                or(other) { return combineControls(control, other); },
                async click() {},
            };
            return control;
        },
        async evaluate(_callback, { target }) {
            const path = new URL(target).pathname;
            if (path === "/auth/refresh") return { status: authenticated ? 200 : 401, body: null };
            if (path === "/auth/session") {
                return authenticated
                    ? { status: 200, body: { method: "oidc", label: "Single sign-on (OIDC)" } }
                    : { status: 401, body: null };
            }
            throw new Error(`unexpected browser request ${path}`);
        },
    };
    const context = {
        async newPage() { return page; },
        async cookies() {
            return authenticated
                ? [{ name: "gw_session", httpOnly: true, secure: true, sameSite: "Lax" }]
                : [];
        },
        async close() {},
    };
    const browser = {
        async newContext(options) {
            suppliedStorage = options.storageState;
            return context;
        },
        async close() {},
    };
    const browserType = { async launch() { return browser; } };
    const result = await runHostedAccountSession({
        GW_SYNTHETIC_API_ORIGIN: "https://auth.gaugewright.com",
        GW_SYNTHETIC_GAUGEDESK_ORIGIN: "https://desk.gaugewright.com",
        // This fixture signs in through a non-Google issuer, which the control
        // plane labels "oidc"; a Google issuer is labelled "google".
        GW_SYNTHETIC_OIDC_PROVIDER_ORIGIN: "https://accounts.example.test",
        GW_SYNTHETIC_OIDC_STORAGE_STATE: JSON.stringify({
            cookies: [
                { name: "provider", domain: "accounts.example.test" },
                { name: "gw_session", domain: ".gaugewright.com" },
            ],
            origins: [
                { origin: "https://accounts.example.test", localStorage: [] },
                { origin: "https://desk.gaugewright.com", localStorage: [] },
            ],
        }),
    }, browserType);

    assert.deepEqual(result, {
        loginStatus: 302,
        callbackStatus: 302,
        refreshStatus: 200,
        logoutStatus: 204,
    });
    assert.deepEqual(suppliedStorage.cookies, [
        { name: "provider", domain: "accounts.example.test" },
    ]);
    assert.deepEqual(suppliedStorage.origins, [
        { origin: "https://accounts.example.test", localStorage: [] },
    ]);
});

// A provider screen is {url, identifiers, consent}. Advancing past the last one
// emits the callback and returns the browser to the frontend, which is the
// production shape the canary must survive: a valid session that still presents
// a sole-account chooser and then a forced-consent screen.
function providerHarness({
    screens,
    apiOrigin,
    frontendOrigin,
    emitCallbackAtEnd = true,
    sessionMethod = "oidc",
}) {
    let index = -1;
    let url = `${frontendOrigin}/`;
    let authenticated = false;
    const responseListeners = [];
    const waiters = [];
    const clicked = [];
    const emit = (item) => {
        for (const listener of responseListeners) listener(item);
        for (const waiter of waiters.splice(0)) {
            if (waiter.predicate(item)) waiter.resolve(item);
            else waiters.push(waiter);
        }
    };
    const response = (target, status) => ({ url: () => target, status: () => status });
    const advance = () => {
        index += 1;
        if (index < screens.length) {
            url = screens[index].url;
            return;
        }
        if (!emitCallbackAtEnd) return;
        authenticated = true;
        emit(response(`${apiOrigin}/auth/callback?state=secret`, 302));
        url = `${frontendOrigin}/`;
    };
    const screen = () => (index >= 0 && index < screens.length ? screens[index] : null);

    const page = {
        url: () => url,
        on(event, listener) {
            if (event === "response") responseListeners.push(listener);
        },
        async goto() {},
        async waitForURL(predicate) {
            // Playwright hands the predicate a URL object, not a string.
            if (predicate(new URL(url))) return;
            throw new Error("waitForURL elapsed");
        },
        async waitForLoadState() {},
        waitForResponse(predicate) {
            return new Promise((resolve) => waiters.push({ predicate, resolve }));
        },
        locator(selector) {
            const count = () => {
                const current = screen();
                if (!current) return selector === "[data-home-sign-in]" ? 1 : 0;
                if (selector === "[data-identifier]") return current.identifiers ?? 0;
                if (selector.includes("submit_approve_access")) return current.consent ? 1 : 0;
                return 0;
            };
            const control = {
                async waitFor() {},
                async count() { return count(); },
                first() { return control; },
                or(other) { return combineControls(control, other); },
                async click() {
                    if (selector === "[data-home-sign-in]") {
                        emit(response(`${apiOrigin}/auth/login`, 302));
                        advance();
                        return;
                    }
                    clicked.push(selector);
                    advance();
                },
            };
            return control;
        },
        getByRole(role, options = {}) {
            const control = {
                async waitFor() {},
                async count() {
                    const current = screen();
                    return role === "button" && current?.roleConsent ? 1 : 0;
                },
                first() { return control; },
                or(other) { return combineControls(control, other); },
                async click() {
                    clicked.push(`role:${role}:${String(options.name ?? "")}`);
                    advance();
                },
            };
            return control;
        },
        async evaluate(_callback, { target }) {
            const path = new URL(target).pathname;
            if (path === "/auth/refresh") return { status: authenticated ? 200 : 401, body: null };
            if (path === "/auth/session") {
                return authenticated
                    ? { status: 200, body: { method: sessionMethod } }
                    : { status: 401, body: null };
            }
            throw new Error(`unexpected browser request ${path}`);
        },
    };
    // Sign-out is not the subject here; short-circuit it so each case isolates
    // the provider walk.
    page.locator = new Proxy(page.locator, {
        apply(target, thisArg, args) {
            const [selector] = args;
            if (selector === "[data-settings]" || selector === "[data-settings-sign-out]") {
                return {
                    async waitFor() {},
                    async count() { return 1; },
                    first() { return this; },
                    async click() {
                        if (selector !== "[data-settings-sign-out]") return;
                        authenticated = false;
                        emit(response(`${apiOrigin}/auth/logout`, 204));
                    },
                };
            }
            return Reflect.apply(target, thisArg, args);
        },
    });

    const context = {
        async newPage() { return page; },
        async cookies() {
            return authenticated
                ? [{ name: "gw_session", httpOnly: true, secure: true, sameSite: "Lax" }]
                : [];
        },
        async close() {},
    };
    return {
        clicked,
        browserType: {
            async launch() {
                return { async newContext() { return context; }, async close() {} };
            },
        },
    };
}

/** Model Playwright's Locator.or(): a combined locator whose matches are the
 * union, preferring the first operand's control when both match. */
function combineControls(a, b) {
    const combined = {
        async waitFor() {},
        async count() { return (await a.count()) + (await b.count()); },
        first() { return combined; },
        or(other) { return combineControls(combined, other); },
        async click() {
            if (await a.count()) return a.click();
            return b.click();
        },
    };
    return combined;
}

const PROVIDER = "https://accounts.example.test";
const API = "https://auth.gaugewright.com";
const FRONTEND = "https://desk.gaugewright.com";

function environmentFor() {
    return {
        GW_SYNTHETIC_API_ORIGIN: API,
        GW_SYNTHETIC_GAUGEDESK_ORIGIN: FRONTEND,
        GW_SYNTHETIC_OIDC_PROVIDER_ORIGIN: PROVIDER,
        GW_SYNTHETIC_OIDC_STORAGE_STATE: JSON.stringify({
            cookies: [{ name: "provider", domain: "accounts.example.test" }],
            origins: [{ origin: PROVIDER, localStorage: [] }],
        }),
    };
}

test("a risk interstitial whose confirm is a role-button is advanced to the callback", async () => {
    // Datacenter egress can draw `/v3/signin/challenge/ipp/consent`, whose
    // confirm control is a `role=\"button\"` element rather than a `<button>`;
    // the role engine must advance it like any consent screen.
    const harness = providerHarness({
        apiOrigin: API,
        frontendOrigin: FRONTEND,
        screens: [
            { url: `${PROVIDER}/v3/signin/accountchooser`, identifiers: 1 },
            { url: `${PROVIDER}/v3/signin/challenge/ipp/consent`, roleConsent: true },
        ],
    });
    const result = await runHostedAccountSession(environmentFor(), harness.browserType);
    assert.equal(result.callbackStatus, 302);
    assert.equal(result.logoutStatus, 204);
    assert.deepEqual(
        harness.clicked,
        ["[data-identifier]", "role:button:" + String(CONSENT_ROLE_NAME)],
        "the walk must advance the chooser and then the role-button interstitial",
    );
});

test("a sole-account chooser and forced consent are advanced to the callback", async () => {
    const harness = providerHarness({
        apiOrigin: API,
        frontendOrigin: FRONTEND,
        screens: [
            { url: `${PROVIDER}/v3/signin/accountchooser`, identifiers: 1 },
            { url: `${PROVIDER}/signin/oauth/consent`, consent: true },
        ],
    });
    const result = await runHostedAccountSession(environmentFor(), harness.browserType);
    assert.equal(result.callbackStatus, 302);
    assert.equal(result.logoutStatus, 204);
    assert.deepEqual(
        harness.clicked,
        ["[data-identifier]", "#submit_approve_access, [data-consent-continue], "
            + "button:has-text('Continue'), button:has-text('Allow')"],
        "the walk must advance the chooser and then the consent screen, in that order",
    );
});

test("a chooser offering no single account fails closed", async () => {
    for (const [identifiers, expected] of [[0, /unrecognised screen at \/v3\/signin\/accountchooser/], [2, /offered 2 accounts/]]) {
        const harness = providerHarness({
            apiOrigin: API,
            frontendOrigin: FRONTEND,
            emitCallbackAtEnd: false,
            screens: [{ url: `${PROVIDER}/v3/signin/accountchooser`, identifiers }],
        });
        await assert.rejects(
            runHostedAccountSession(environmentFor(), harness.browserType),
            expected,
            `a chooser offering ${identifiers} accounts must not be admitted`,
        );
    }
});

test("an unrecognised provider screen fails closed without echoing its content", async () => {
    const harness = providerHarness({
        apiOrigin: API,
        frontendOrigin: FRONTEND,
        emitCallbackAtEnd: false,
        screens: [{ url: `${PROVIDER}/signin/challenge/pwd` }],
    });
    await assert.rejects(
        runHostedAccountSession(environmentFor(), harness.browserType),
        (error) => {
            assert.match(error.message, /unrecognised screen at \/signin\/challenge\/pwd/);
            assert(!/accounts\.example\.test\/signin/.test(error.message));
            return true;
        },
    );
});

test("a navigation off the admitted origins fails closed", async () => {
    const harness = providerHarness({
        apiOrigin: API,
        frontendOrigin: FRONTEND,
        emitCallbackAtEnd: false,
        screens: [{ url: "https://phish.example/v3/signin/accountchooser", identifiers: 1 }],
    });
    await assert.rejects(
        runHostedAccountSession(environmentFor(), harness.browserType),
        /unadmitted origin https:\/\/phish\.example/,
    );
});

test("a provider that never returns to the callback fails with a provider diagnostic", async () => {
    const harness = providerHarness({
        apiOrigin: API,
        frontendOrigin: FRONTEND,
        emitCallbackAtEnd: false,
        screens: Array.from({ length: 8 }, () => ({
            url: `${PROVIDER}/v3/signin/accountchooser`,
            identifiers: 1,
        })),
    });
    await assert.rejects(
        runHostedAccountSession(environmentFor(), harness.browserType),
        /did not return through the callback within 6 provider steps/,
    );
});

test("the expected session authority follows the declared provider", async () => {
    // A Google-issued session is labelled "google" by the control plane, so a
    // canary that demanded "oidc" could never pass against the production IdP.
    const harness = providerHarness({
        apiOrigin: API,
        frontendOrigin: FRONTEND,
        screens: [{ url: "https://accounts.google.com/v3/signin/accountchooser", identifiers: 1 }],
    });
    const environment = {
        ...environmentFor(),
        GW_SYNTHETIC_OIDC_PROVIDER_ORIGIN: "https://accounts.google.com",
    };
    await assert.rejects(
        runHostedAccountSession(environment, harness.browserType),
        /reports oidc rather than the google authority/,
        "a Google sign-in must not be satisfied by a generic oidc label",
    );
});

test("a session that degrades to a local account fails closed", async () => {
    const harness = providerHarness({
        apiOrigin: API,
        frontendOrigin: FRONTEND,
        screens: [{ url: `${PROVIDER}/v3/signin/accountchooser`, identifiers: 1 }],
        sessionMethod: "local",
    });
    await assert.rejects(
        runHostedAccountSession(environmentFor(), harness.browserType),
        /reports local rather than the oidc authority/,
        "losing the SSO connection must not read as a healthy session",
    );
});
