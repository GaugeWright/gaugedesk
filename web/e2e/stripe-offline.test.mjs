import { test } from "node:test";
import assert from "node:assert/strict";
import { blocksStripeRequest, installStripeOffline } from "./stripe-offline.mjs";

test("Stripe domains are blocked without accepting lookalike hosts", () => {
    for (const value of ["https://stripe.com/", "https://connect-js.stripe.com/v1.0/connect.js", "http://a.b.stripe.com/", "https://STRIPE.COM./"]) assert.equal(blocksStripeRequest(value), true, value);
    for (const value of ["http://127.0.0.1:7662/", "https://notstripe.com/", "https://stripe.com.evil.test/", "https://stripe.com@local.test/", "data:text/plain,stripe.com"]) assert.equal(blocksStripeRequest(value), false, value);
    for (const value of ["not a URL", "https://[invalid"]) assert.equal(blocksStripeRequest(value), true, value);
});
test("the fixture installer has no model-live exception and only selects blocked routes", async () => {
    let matcher, handler;
    const previous = process.env.GW_E2E_LIVE;
    process.env.GW_E2E_LIVE = "1"; // Only this closed stub is invoked; no model/credential path.
    try {
        await installStripeOffline({ async route(m, h) { matcher = m; handler = h; } });
    } finally {
        if (previous === undefined) delete process.env.GW_E2E_LIVE;
        else process.env.GW_E2E_LIVE = previous;
    }
    assert.equal(matcher(new URL("https://connect-js.stripe.com/")), true);
    assert.equal(matcher(new URL("http://127.0.0.1/")), false);
    let reason;
    await handler({ async abort(value) { reason = value; } });
    assert.equal(reason, "blockedbyclient");
});
