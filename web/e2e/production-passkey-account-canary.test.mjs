import assert from "node:assert/strict";
import test from "node:test";

import {
    passkeyCanarySettings,
    pollInboxCode,
} from "./production-passkey-account-canary.mjs";

function environment() {
    return {
        GW_SYNTHETIC_API_ORIGIN: "https://auth.gaugewright.com",
        GW_SYNTHETIC_GAUGEDESK_ORIGIN: "https://desk.gaugewright.com",
        GW_SYNTHETIC_PASSKEY_EMAIL: "passkey-canary@example.test",
        GW_SYNTHETIC_PASSKEY_INBOX_URL: "https://inbox.example.test/latest",
        GW_SYNTHETIC_PASSKEY_INBOX_TOKEN: "inbox-token",
    };
}

test("passkey settings keep inbox credentials out of its URL", () => {
    const settings = passkeyCanarySettings(environment());
    assert.equal(settings.apiOrigin, "https://auth.gaugewright.com");
    assert.equal(settings.deskOrigin, "https://desk.gaugewright.com");
    assert.equal(settings.inbox.href, "https://inbox.example.test/latest");
    const unsafe = environment();
    unsafe.GW_SYNTHETIC_PASSKEY_INBOX_URL = "https://secret@inbox.example.test/latest";
    assert.throws(() => passkeyCanarySettings(unsafe), /must not contain credentials/);
});

test("inbox polling ignores absence and accepts one fresh purpose-bound code", async () => {
    const calls = [];
    const responses = [
        { status: 404 },
        {
            status: 200,
            body: {
                code: "12345678",
                purpose: "recovery",
                received_at: "2026-09-13T12:00:01.000Z",
            },
        },
    ];
    const code = await pollInboxCode({
        inbox: new URL("https://inbox.example.test/latest"),
        inboxToken: "inbox-token",
        purpose: "recovery",
        after: "2026-09-13T12:00:00.000Z",
        wait: async () => {},
        fetchImpl: async (url, options) => {
            calls.push({ url: url.href, options });
            const response = responses.shift();
            return {
                status: response.status,
                text: async () => JSON.stringify(response.body),
            };
        },
    });
    assert.equal(code, "12345678");
    assert.equal(calls.length, 2);
    assert.match(calls[0].url, /purpose=recovery/);
    assert.match(calls[0].url, /after=2026-09-13T12%3A00%3A00.000Z/);
    assert.equal(calls[0].options.headers.authorization, "Bearer inbox-token");
    assert(!calls[0].url.includes("passkey-canary"));
});

test("inbox polling rejects stale and over-shaped responses without echoing secrets", async () => {
    const response = (body) => async () => ({
        status: 200,
        text: async () => JSON.stringify(body),
    });
    await assert.rejects(() => pollInboxCode({
        inbox: new URL("https://inbox.example.test/latest"),
        inboxToken: "secret-token",
        purpose: "verification",
        after: "2026-09-13T12:00:00.000Z",
        fetchImpl: response({
            code: "87654321",
            purpose: "verification",
            received_at: "2026-09-13T11:59:59.000Z",
        }),
    }), /stale code/);
    await assert.rejects(() => pollInboxCode({
        inbox: new URL("https://inbox.example.test/latest"),
        inboxToken: "secret-token",
        purpose: "verification",
        after: "2026-09-13T12:00:00.000Z",
        fetchImpl: response({
            code: "87654321",
            purpose: "verification",
            received_at: "2026-09-13T12:00:01.000Z",
            recipient: "should-not-be-returned@example.test",
        }),
    }), /unexpected shape/);
    let invalid;
    try {
        await pollInboxCode({
            inbox: new URL("https://inbox.example.test/latest"),
            inboxToken: "secret-token",
            purpose: "verification",
            after: "2026-09-13T12:00:00.000Z",
            fetchImpl: response({
                code: "proof-that-must-not-be-logged",
                purpose: "verification",
                received_at: "2026-09-13T12:00:01.000Z",
            }),
        });
    } catch (error) {
        invalid = error;
    }
    assert(invalid instanceof Error);
    assert.match(invalid.message, /invalid code/);
    assert(!String(invalid.stack).includes("proof-that-must-not-be-logged"));
    assert(!String(invalid.stack).includes("secret-token"));
});
