import assert from "node:assert/strict";
import test from "node:test";

import {
    independentAccountStorageState,
    runConsumerOidcLinkJourney,
} from "./production-consumer-oidc-link-canary.mjs";

const API = "https://auth.gaugewright.com";
const DESK = "https://desk.gaugewright.com";
const PROVIDER = "https://accounts.example.test";

function environment() {
    return {
        GW_SYNTHETIC_API_ORIGIN: API,
        GW_SYNTHETIC_GAUGEDESK_ORIGIN: DESK,
        GW_SYNTHETIC_OIDC_PROVIDER_ORIGIN: PROVIDER,
        GW_SYNTHETIC_LINK_OIDC_TOTP_SECRET: "JBSWY3DPEHPK3PXP",
        GW_SYNTHETIC_LINK_ACCOUNT_STORAGE_STATE: JSON.stringify({
            cookies: [
                { name: "gw_session", domain: ".gaugewright.com", httpOnly: true, secure: true },
                { name: "provider-leak", domain: "accounts.example.test" },
            ],
            origins: [{ origin: DESK, localStorage: [{ name: "discard", value: "me" }] }],
        }),
        GW_SYNTHETIC_LINK_OIDC_STORAGE_STATE: JSON.stringify({
            cookies: [
                { name: "provider", domain: "accounts.example.test" },
                { name: "gw_session", domain: ".gaugewright.com" },
            ],
            origins: [{ origin: PROVIDER, localStorage: [] }],
        }),
    };
}

function apiResponse(status, body = null) {
    return {
        status: () => status,
        text: async () => body === null ? "" : JSON.stringify(body),
    };
}

test("independent state retains only one protected GaugeDesk session", () => {
    assert.deepEqual(independentAccountStorageState(environment()), {
        cookies: [{
            name: "gw_session",
            domain: ".gaugewright.com",
            httpOnly: true,
            secure: true,
        }],
        origins: [],
    });
    const unsafe = environment();
    unsafe.GW_SYNTHETIC_LINK_ACCOUNT_STORAGE_STATE = JSON.stringify({
        cookies: [{ name: "gw_session", domain: ".gaugewright.com", secure: true }],
        origins: [],
    });
    assert.throws(() => independentAccountStorageState(unsafe), /HttpOnly/);
});

test("consumer OIDC journey links, removes, rereads, and revokes", async () => {
    let linked = false;
    let authenticated = true;
    let suppliedStorage;
    let callbackResolve;
    const calls = [];
    const request = {
        async fetch(url, options = {}) {
            const path = new URL(url).pathname;
            const method = options.method ?? "GET";
            calls.push({ path, method, data: options.data, headers: options.headers });
            if (!authenticated && path === "/gaugeapps/account-settings/sessions") {
                return apiResponse(401, { error: "signed out" });
            }
            if (path === "/gaugeapps/account-settings/sessions") {
                return apiResponse(200, {
                    session: {
                        id: "session:independent",
                        generation: linked ? "generation:two" : "generation:one",
                        app: "account-settings",
                        scope: { kind: "person", id: "person:one" },
                        pages: [{
                            id: "account",
                            commands: ["account.authenticator.remove"],
                        }],
                    },
                });
            }
            if (path === "/gaugeapps/account-settings/pages/account") {
                return apiResponse(200, {
                    page: {
                        resource_basis: linked ? "basis:two" : "basis:one",
                        model: {
                            authenticators: [
                                { id: "passkey:one", kind: "passkey" },
                                ...(linked ? [{
                                    id: "consumer:one",
                                    kind: "consumer-oidc",
                                    connection_id: "consumer-google",
                                }] : []),
                            ],
                        },
                    },
                });
            }
            if (path === "/auth/account/consumer-oidc/link/start") {
                return apiResponse(200, { authorization_url: `${PROVIDER}/authorize` });
            }
            if (path === "/gaugeapps/account-settings/commands") {
                assert.equal(options.data.client, "web");
                assert.equal(options.data.payload.id, "consumer:one");
                assert.equal(options.data.expected_basis, "basis:two");
                return apiResponse(200, {
                    receipt: { status: "proposed" },
                    proposal: { id: "proposal:remove" },
                });
            }
            if (path === "/gaugeapps/account-settings/proposals/proposal%3Aremove/review") {
                assert.equal(options.data.decision, "accept");
                linked = false;
                return apiResponse(200, { receipt: { status: "applied" } });
            }
            if (path === "/auth/logout") {
                authenticated = false;
                return apiResponse(204);
            }
            throw new Error(`unexpected ${method} ${path}`);
        },
    };
    const page = {
        waitForResponse() {
            return new Promise((resolve) => { callbackResolve = resolve; });
        },
        async goto(url) {
            assert.equal(url, `${PROVIDER}/authorize`);
        },
    };
    const context = {
        request,
        async newPage() { return page; },
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
    const result = await runConsumerOidcLinkJourney(
        environment(),
        browserType,
        {
            async advanceProvider(_page, admitted, isSettled, options) {
                assert.equal(admitted.provider, PROVIDER);
                assert.equal(options.totpSecret, "JBSWY3DPEHPK3PXP");
                linked = true;
                callbackResolve({ status: () => 200 });
                await Promise.resolve();
                assert.equal(isSettled(), true);
            },
        },
    );

    assert.deepEqual(result, {
        callbackStatus: 200,
        linkRemoved: true,
        sessionRevoked: true,
    });
    assert.deepEqual(suppliedStorage.cookies.map((cookie) => cookie.name), ["gw_session", "provider"]);
    assert.equal(calls.filter((call) => call.path === "/auth/logout").length, 1);
    assert.equal(linked, false);
    assert.equal(authenticated, false);
});
