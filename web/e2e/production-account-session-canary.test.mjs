import assert from "node:assert/strict";
import test from "node:test";

import { runHostedAccountSession } from "./production-account-session-canary.mjs";

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
            return {
                async waitFor() {},
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
