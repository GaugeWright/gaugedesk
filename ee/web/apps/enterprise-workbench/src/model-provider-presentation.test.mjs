import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import { MODEL_PROVIDER_REVIEW_COMMANDS, moneyInput, parseMoneyCap, parseTokenCap, summarizeProviderChange } from "./model-provider-presentation.ts";
import { providerReviewExamples, providerModel } from "./model-provider-review.fixture.mjs";
import { summarizeGaugeAppChange } from "./gaugeapp-review.ts";

test("caps retain exact integers, micro-units, explicit zero and uncapped", () => {
    assert.equal(parseTokenCap(""), null);
    assert.equal(parseTokenCap("0"), "0");
    assert.equal(parseTokenCap("18446744073709551615"), "18446744073709551615");
    assert.deepEqual(parseMoneyCap("18446744073709.551615", "EUR"), { currency: "EUR", micros: "18446744073709551615" });
    assert.equal(moneyInput("18446744073709551615"), "18446744073709.551615");
    assert.equal(moneyInput("0"), "0");
    assert.equal(parseMoneyCap("", "USD"), null);
    assert.deepEqual(parseMoneyCap("0.000001", "USD"), { currency: "USD", micros: "1" });
    for (const input of ["-1", "+1", "1e3", "01", "1.5", "18446744073709551616"]) assert.throws(() => parseTokenCap(input));
    for (const input of ["-1", "1,000", "1e3", "0.0000001", "18446744073709.551616"]) assert.throws(() => parseMoneyCap(input, "USD"));
    assert.throws(() => parseMoneyCap("1", "US"));
});
test("all executable organization metadata operations have a concrete summary", () => {
    assert.deepEqual(Object.keys(providerReviewExamples).sort(), Object.keys(MODEL_PROVIDER_REVIEW_COMMANDS).sort());
    const registry = readFileSync(new URL("../../../../../crates/app/src/model_provider_management.rs", import.meta.url), "utf8");
    const operations = [...registry.matchAll(/#\[serde\(rename = "(organization-provider\.[^"]+)"\)\]/g)].map((match) => match[1]);
    // The reducer retains the future organization OAuth metadata shape, but no
    // provider exchange/callback ceremony exists yet. It must not be reviewed
    // or advertised as an executable GaugeApp command until one does.
    const executable = operations.filter((operation) => operation !== "organization-provider.account.begin");
    assert.deepEqual(executable.sort(), Object.keys(MODEL_PROVIDER_REVIEW_COMMANDS).sort());
    for (const [command, [payload, model]] of Object.entries(providerReviewExamples)) assert.ok(summarizeProviderChange(command, payload, model).fields.length);
});
test("activation review states the actual check and refuses unknown historical proof", () => {
    const command = "organization-provider.version.activate";
    const [payload, model] = providerReviewExamples[command];
    const summary = summarizeProviderChange(command, payload, model);
    assert.equal(summary.fields.find((field) => field.label === "Check performed").value, "Model catalog read");
    assert.match(summary.note, /Inference access and billing have not been tested/);
    for (const verification of [null, { check: "inference_ready", observed_at: "3" }]) {
        const legacy = structuredClone(model); legacy.connections[0].versions[0].verification = verification;
        const result = summarizeGaugeAppChange({ app: "administration", page_id: "model-providers", command_id: command, payload, expected_basis: "basis" }, { id: "model-providers", version: 1, resource_basis: "basis", model: legacy });
        assert.ok(result.unavailable);
    }
});
test("cap review names exact subject and before/after values without resetting usage", () => {
    const command = "organization-provider.grant.cap.set";
    const [payload, model] = providerReviewExamples[command];
    const result = summarizeProviderChange(command, payload, model);
    assert.deepEqual(result.fields.find((field) => field.label === "Monthly tokens"), { label: "Monthly tokens", value: "0", before: "18446744073709551615" });
    assert.match(result.note, /Existing usage and reservations remain counted/);
    const project = structuredClone(model); project.grants[0].subject = { kind: "project", authority: "home-a", id: "project-a" };
    assert.match(summarizeProviderChange(command, payload, project).fields.find((f) => f.label === "Access for").value, /Project.*project-a.*home-a/);
    assert.deepEqual(project.grants[0].usage, model.grants[0].usage);
});
test("review rejects stale metadata, altered operations, unknown targets and hidden secret fields", () => {
    const command = "organization-provider.rename";
    for (const mutate of [p => p.expected_revision = "0", p => p.action.operation = "organization-provider.erase", p => p.action.arguments.connection = "missing", p => p.action.arguments.secret = "must-not-render", p => p.action.secret = "must-not-render", p => p.secret = "must-not-render"]) {
        const payload = structuredClone(providerReviewExamples[command][0]); mutate(payload);
        const result = summarizeGaugeAppChange({ app: "administration", page_id: "model-providers", command_id: command, payload, expected_basis: "basis" }, { id: "model-providers", version: 1, resource_basis: "basis", model: providerModel });
        assert.ok(result.unavailable); assert.doesNotMatch(JSON.stringify(result), /must-not-render/);
    }
});
test("new connection review must use the authority's operated provider choices", () => {
    const command = "organization-provider.api-key.add";
    const [payload, model] = providerReviewExamples[command];
    assert.throws(() => summarizeProviderChange(command, payload, { ...model, setup: { api_key_intake: true, providers: [] } }));
    const changed = structuredClone(payload); changed.action.arguments.policy.models = ["invented-model"];
    assert.throws(() => summarizeProviderChange(command, changed, model));
});
