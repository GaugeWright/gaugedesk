import assert from "node:assert/strict";
import test from "node:test";
import { managedInferencePresentation, subscriptionPresentation } from "./account-page-presentation.ts";

const model = {
    plan: { plan: "Managed", status: "active", included_tokens: 5000 },
    usage: { runs: 2, input_tokens: 800, output_tokens: 200, total_tokens: 1000, included_tokens: 5000, overage_tokens: 0 },
    billing: { customer_linked: true, verification: "verified", processor_mode: "live", subscription: { status: "active" }, configured_plan: { checkout_available: false } },
};
test("managed inference shows admitted token usage and actual plan standing", () => {
    assert.match(managedInferencePresentation(model).description, /1,000 tokens recorded/);
    for (const status of ["active", "suspended", "lapsed"]) {
        const presentation = managedInferencePresentation({ ...model, billing: { ...model.billing, subscription: { status } } });
        assert.ok(presentation.description.includes(status));
        assert.equal(presentation.action, "manage");
        assert.equal(presentation.available, true);
    }
});
test("unverified billing is not Free, active, or a reason to start another checkout", () => {
    for (const verification of ["unverified", "unavailable"]) {
        const billing = { ...model.billing, verification, subscription: null, configured_plan: { checkout_available: true } };
        assert.equal(subscriptionPresentation(billing).status, "Not verified");
        assert.equal(managedInferencePresentation({ ...model, billing }).available, false);
        assert.match(managedInferencePresentation({ ...model, billing }).description, /not verified/);
    }
    assert.match(managedInferencePresentation({ ...model, billing: { ...model.billing, processor_mode: "test" } }).description, /Test subscription/);
});
test("customer linkage controls the billing handoff, not existence of a plan", () => {
    assert.equal(managedInferencePresentation({ ...model, plan: null }).action, "manage");
    const unlinked = { ...model, plan: null, billing: { ...model.billing, customer_linked: false } };
    assert.equal(managedInferencePresentation(unlinked).action, "subscribe");
    assert.equal(managedInferencePresentation(unlinked).available, false);
    assert.match(managedInferencePresentation(unlinked).unavailableReason, /signup is not available/);
    assert.equal(managedInferencePresentation({ ...unlinked, billing: { ...unlinked.billing, configured_plan: { checkout_available: true } } }).available, true);
    assert.equal(managedInferencePresentation(model).unavailableReason, null);
});
