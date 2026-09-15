import type { ModelProvidersModel } from "@gaugewright/control-plane-client";
import type { ChangeSummary, ReviewField } from "./gaugeapp-review";

export type Providers = Extract<ModelProvidersModel, { availability: "available" }>;
export type ProviderConnection = Providers["connections"][number];
export type ProviderGrant = Providers["grants"][number];
export type ProviderPolicy = ProviderConnection["policy"];
export type ProviderCaps = ProviderGrant["caps"];

// Presentation only: the authority parses and admits every command again.
export const MODEL_PROVIDER_REVIEW_COMMANDS = {
    "organization-provider.api-key.add": ["administration", "model-providers", "Add organization API key"],
    "organization-provider.rotate": ["administration", "model-providers", "Replace organization key"],
    "organization-provider.intake.cancel": ["administration", "model-providers", "Cancel key setup"],
    "organization-provider.version.activate": ["administration", "model-providers", "Activate verified key"],
    "organization-provider.rename": ["administration", "model-providers", "Rename organization connection"],
    "organization-provider.model.approve": ["administration", "model-providers", "Change approved models"],
    "organization-provider.default-model.set": ["administration", "model-providers", "Change organization default model"],
    "organization-provider.suspend": ["administration", "model-providers", "Suspend organization connection"],
    "organization-provider.resume": ["administration", "model-providers", "Resume organization connection"],
    "organization-provider.revoke": ["administration", "model-providers", "Revoke organization connection"],
    "organization-provider.erase": ["administration", "model-providers", "Erase organization credentials"],
    "organization-provider.grant.create": ["administration", "model-providers", "Grant model access"],
    "organization-provider.grant.cap.set": ["administration", "model-providers", "Change monthly usage caps"],
    "organization-provider.grant.suspend": ["administration", "model-providers", "Suspend model access"],
    "organization-provider.grant.resume": ["administration", "model-providers", "Resume model access"],
    "organization-provider.grant.revoke": ["administration", "model-providers", "Revoke model access"],
} as const;
export type ProviderCommand = keyof typeof MODEL_PROVIDER_REVIEW_COMMANDS;
const U64 = 18446744073709551615n;
export function parseTokenCap(value: string): string | null {
    const input = value.trim();
    if (!input) return null;
    if (!/^(0|[1-9][0-9]*)$/.test(input) || input.length > 20 || BigInt(input) > U64) throw Error("Enter a whole token limit, or leave it blank for no token cap.");
    return input;
}
export function parseMoneyCap(value: string, currency: string): ProviderCaps["money"] {
    const input = value.trim();
    if (!input) return null;
    if (!/^[A-Z]{3}$/.test(currency)) throw Error("Enter a three-letter currency code.");
    if (!/^(0|[1-9][0-9]*)(\.[0-9]{1,6})?$/.test(input) || input.length > 27) throw Error("Enter a nonnegative amount with at most six decimal places.");
    const [whole, fraction = ""] = input.split(".");
    const micros = BigInt(whole!) * 1000000n + BigInt(fraction.padEnd(6, "0"));
    if (micros > U64) throw Error("The amount exceeds the supported limit.");
    return { currency, micros: micros.toString() };
}
export function moneyInput(micros: string): string {
    const digits = micros.padStart(7, "0");
    return `${digits.slice(0, -6)}.${digits.slice(-6)}`.replace(/0+$/, "").replace(/\.$/, "");
}
export const moneyLabel = (money: NonNullable<ProviderCaps["money"]>) => `${money.currency} ${moneyInput(money.micros)}`;
export const subjectLabel = (subject: ProviderGrant["subject"]) => subject.kind === "member" ? `Member · ${subject.id}` : `Project · ${subject.id} (${subject.authority})`;
export const terminalConnection = (connection: ProviderConnection) => connection.status === "revoked" || connection.status === "erased";
export function providerRequest(model: Providers, operation: ProviderCommand, args: Readonly<Record<string, unknown>>, idempotencyKey: string) {
    return { v: 1, expected_revision: model.management_revision, idempotency_key: idempotencyKey, action: { operation, arguments: args } };
}

type Data = Record<string, unknown>;
const record = (value: unknown): Data => {
    if (!value || typeof value !== "object" || Array.isArray(value)) throw Error("Missing record");
    return value as Data;
};
const closed = (value: unknown, fields: readonly string[]) => {
    const result = record(value);
    if (Object.keys(result).length !== fields.length || fields.some((key) => !Object.hasOwn(result, key))) throw Error("Unexpected fields");
    return result;
};
const text = (value: unknown): string => { if (typeof value !== "string" || !value.trim()) throw Error("Missing value"); return value; };
const list = (value: unknown): readonly unknown[] => { if (!Array.isArray(value)) throw Error("Missing list"); return value; };
const strings = (value: unknown) => list(value).map(text);
const exactCap = (value: unknown) => { const input = text(value); if (parseTokenCap(input) !== input) throw Error("Invalid limit"); return input; };
const readCaps = (value: unknown): ProviderCaps => {
    const caps = closed(value, ["tokens", "money"]);
    const money = caps.money === null ? null : closed(caps.money, ["currency", "micros"]);
    if (money && !/^[A-Z]{3}$/.test(text(money.currency))) throw Error("Invalid currency");
    return { tokens: caps.tokens === null ? null : exactCap(caps.tokens), money: money && { currency: text(money.currency), micros: exactCap(money.micros) } };
};
const readPolicy = (value: unknown): ProviderPolicy => {
    const policy = closed(value, ["models", "execution_classes"]);
    const models = strings(policy.models); const classes = strings(policy.execution_classes);
    if (!models.length || !classes.length || new Set(models).size !== models.length || new Set(classes).size !== classes.length || classes.some((v) => v !== "private_broker" && v !== "public_direct")) throw Error("Invalid policy");
    return { models, execution_classes: classes as ProviderPolicy["execution_classes"] };
};
const readSubject = (value: unknown): ProviderGrant["subject"] => {
    const subject = record(value);
    if (subject.kind === "member") { closed(subject, ["kind", "id"]); return { kind: "member", id: text(subject.id) }; }
    closed(subject, ["kind", "authority", "id"]);
    if (subject.kind !== "project") throw Error("Unknown subject");
    return { kind: "project", authority: text(subject.authority), id: text(subject.id) };
};

/** Safe, exact review of metadata; never render arbitrary credential payloads. */
export function summarizeProviderChange(command: ProviderCommand, payload: unknown, model: unknown): ChangeSummary {
    const request = closed(payload, ["v", "expected_revision", "idempotency_key", "action"]);
    const page = record(model);
    if (request.v !== 1 || page.availability !== "available" || request.expected_revision !== page.management_revision) throw Error("Provider page changed");
    exactCap(request.expected_revision); text(request.idempotency_key);
    const action = closed(request.action, ["operation", "arguments"]);
    if (action.operation !== command) throw Error("Operation mismatch");
    const args = record(action.arguments);
    const fields: ReviewField[] = [];
    const add = (label: string, value: string, before?: string) => fields.push({ label, value, ...(before !== undefined && before !== value ? { before } : {}) });
    const find = (rows: unknown, id: unknown): Data => { const key = text(id); const row = list(rows).map(record).find((row) => row.id === key); if (!row) throw Error("Missing target"); return row; };
    const connection = (id: unknown) => { const row = find(page.connections, id); add("Connection", `${text(row.name)} (${text(row.id)})`); return row; };
    const policyFields = (value: unknown, before?: unknown) => {
        const policy = readPolicy(value); const old = before === undefined ? undefined : readPolicy(before);
        add("Approved models", policy.models.join(", "), old?.models.join(", "));
        const classes = (p: ProviderPolicy) => p.execution_classes.map((v) => v === "private_broker" ? "Private broker" : "Public direct").join(", ");
        add("Execution", classes(policy), old && classes(old));
    };
    const capFields = (value: unknown, before?: unknown) => {
        const caps = readCaps(value); const old = before === undefined ? undefined : readCaps(before);
        add("Monthly tokens", caps.tokens ?? "No token cap", old && (old.tokens ?? "No token cap"));
        add("Monthly spend", caps.money ? moneyLabel(caps.money) : "No spend cap", old && (old.money ? moneyLabel(old.money) : "No spend cap"));
    };
    let note: string | undefined;
    if (command === "organization-provider.api-key.add") {
        closed(args, ["name", "provider", "endpoint", "policy", "reconnects"]);
        const setup = record(page.setup);
        const provider = list(setup.providers).map(record).find((p) => p.provider === args.provider && p.endpoint === args.endpoint && p.authentication === "api_key");
        if (!provider) throw Error("Provider unavailable");
        const proposed = readPolicy(args.policy); const allowed = readPolicy(provider.policy);
        if (proposed.models.some((v) => !allowed.models.includes(v)) || proposed.execution_classes.some((v) => !allowed.execution_classes.includes(v))) throw Error("Policy unavailable");
        add("Name", text(args.name)); add("Provider", text(args.provider)); add("Endpoint", text(args.endpoint)); policyFields(args.policy);
        if (args.reconnects !== null) connection(args.reconnects);
        note = "Creates a pending connection. Supply its credential separately, verify it, then activate. No model access is granted yet.";
    } else if (command === "organization-provider.default-model.set") {
        closed(args, ["selection"]);
        const selection = (value: unknown): string => {
            if (value === null) return "No organization default";
            const chosen = record(value); const row = find(page.connections, chosen.connection);
            if (!strings(record(row.policy).models).includes(text(chosen.model))) throw Error("Unknown model");
            return `${text(row.name)} · ${text(chosen.model)}`;
        };
        if (args.selection !== null) closed(args.selection, ["connection", "model"]);
        add("Default model", selection(args.selection), selection(page.default_model));
        note = "Applies in this organization's funding context. Personal defaults and access grants are unchanged.";
    } else if (command.startsWith("organization-provider.grant.")) {
        if (command.endsWith(".create")) {
            closed(args, ["connection", "subject", "policy", "audiences", "caps"]);
            connection(args.connection); const subject = readSubject(args.subject); add("Access for", subjectLabel(subject));
            policyFields(args.policy); const audiences = strings(args.audiences);
            if (!audiences.length || audiences.some((v) => !["member", "external_participant", "service", "public_session"].includes(v))) throw Error("Unknown audience");
            add("Audiences", audiences.join(", ")); capFields(args.caps);
            note = "Funding permission only; this does not grant project or data access. All applicable caps intersect and existing usage remains counted.";
        } else {
            closed(args, command.endsWith(".cap.set") ? ["grant", "caps"] : ["grant"]);
            const grant = find(page.grants, args.grant); connection(grant.connection);
            add("Access for", subjectLabel(readSubject(grant.subject))); add("Grant", text(grant.id));
            if (command.endsWith(".cap.set")) {
                capFields(args.caps, grant.caps);
                note = "Current UTC month. Blank is uncapped; zero permits no allowance. Existing usage and reservations remain counted; lowering a cap below them prevents new use. Models and audiences are unchanged.";
            } else {
                add("Status", command.endsWith(".suspend") ? "Suspended" : command.endsWith(".resume") ? "Active" : "Revoked", text(grant.status));
                note = "Changes this grant only. Other grants may still authorize use; previous usage is retained, not reset.";
            }
        }
    } else {
        const extras = command.endsWith(".rename") ? ["name"] : command.endsWith(".model.approve") ? ["policy"] : command.endsWith(".intake.cancel") || command.endsWith(".version.activate") ? ["version"] : [];
        closed(args, ["connection", ...extras]); const row = connection(args.connection);
        if (command.endsWith(".rename")) add("Name", text(args.name), text(row.name));
        else if (command.endsWith(".model.approve")) { policyFields(args.policy, row.policy); note = "Existing subject grants are not widened. Removing a model prevents new use even where a grant previously allowed it."; }
        else if (args.version !== undefined) {
            const version = find(row.versions, args.version); add("Key version", text(version.id));
            if (command.endsWith(".version.activate")) {
                const verification = record(version.verification);
                closed(verification, ["check", "observed_at"]);
                if (verification.check !== "model_catalog_read") throw Error("Candidate check is unavailable");
                add("Check performed", "Model catalog read");
            }
            add("Result", command.endsWith(".intake.cancel") ? "Cancel setup and erase candidate material" : "Make this verified version current");
            note = command.endsWith(".intake.cancel") ? "The current active version, if any, is unchanged." : "Inference access and billing have not been tested. Pending work using the old version must be readmitted. A suspended connection stays suspended.";
        } else {
            const effects: Record<string, string> = { rotate: "Start replacement key setup", suspend: "Suspend new use", resume: "Resume eligible use", revoke: "Permanently revoke future use", erase: "Erase stored credentials and stop future use" };
            add("Result", text(effects[command.split(".").at(-1)!]));
            note = command.endsWith(".rotate") ? "The current version remains selected until a verified replacement is explicitly activated." : command.endsWith(".erase") || command.endsWith(".revoke") ? "History is retained. This does not revoke the key at its provider or recall requests already sent." : "Usage and open reservations are retained. Access still requires a current grant and available allowance.";
        }
    }
    return { title: MODEL_PROVIDER_REVIEW_COMMANDS[command][2], fields, note };
}
