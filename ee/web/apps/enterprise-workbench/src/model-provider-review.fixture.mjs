import { readFileSync } from "node:fs";
import { providerRequest } from "./model-provider-presentation.ts";

export const providerModel = JSON.parse(readFileSync(new URL("../../../../../crates/app/src/model_provider_management/projection/page.fixture.json", import.meta.url), "utf8"));
const connection = providerModel.connections[0];
providerModel.setup = { api_key_intake: true, providers: [{ provider: connection.provider, endpoint: connection.endpoint, authentication: "api_key", policy: connection.policy }] };
const grant = providerModel.grants[0];
const target = { connection: connection.id };
const args = {
    "api-key.add": { name: "Team API", provider: connection.provider, endpoint: connection.endpoint, policy: connection.policy, reconnects: null },
    rotate: target,
    "intake.cancel": { ...target, version: connection.versions[0].id },
    verify: { ...target, version: connection.versions[0].id },
    "version.activate": { ...target, version: connection.versions[0].id },
    rename: { ...target, name: "Shared research" },
    "model.approve": { ...target, policy: connection.policy },
    "default-model.set": { selection: { ...target, model: connection.policy.models[0] } },
    suspend: target, resume: target, revoke: target, erase: target,
    "grant.create": { ...target, subject: grant.subject, policy: grant.policy, audiences: grant.audiences, caps: grant.caps },
    "grant.cap.set": { grant: grant.id, caps: { tokens: "0", money: { currency: "USD", micros: "200000000" } } },
    "grant.suspend": { grant: grant.id }, "grant.resume": { grant: grant.id }, "grant.revoke": { grant: grant.id },
};
export const providerReviewExamples = Object.fromEntries(Object.entries(args).map(([suffix, args]) => {
    const command = `organization-provider.${suffix}`;
    return [command, [providerRequest(providerModel, command, args, "request-example"), providerModel]];
}));
