import { describe, expect, expectTypeOf, it } from "vitest";
import contract from "../../../../contracts/gaugeapps-page-actions.json";
import { readGaugeAppPage, type GaugeAppKind, type GaugeAppSession } from "./gaugeapp";
import { gaugeAppPageDefinitions, parseAccountGaugeAppPage, parseAdministrationGaugeAppPage, parseGaugeAppPage } from "./gaugeapp-page-models";
import { parseAccountSettingsModel, parseProviderConnectionsModel, parseSubscriptionBilling, parseManagedInferenceUsage } from "./gaugeapp-account-models";
import { commercialEmptyModels } from "./gaugeapp-commercial-models.fixture";
import { emptyProjectHosts } from "./gaugeapp-project-host-models.fixture";
import { administrationEmptyModels, cloudBackups, cloudBilling } from "./gaugeapp-administration-models.fixture";

const signIn = (provider: string) => ({ provider, linked: false, expires: null, expired: false, login: null });
const usage = { runs: 2, input_tokens: 800, output_tokens: 200, total_tokens: 1000, included_tokens: 5000, overage_tokens: 0, unattributed_runs: 0, unattributed_tokens: 0 };
const models = {
    account: {
        profile: { account_id: "person-a", display_name: null, avatar: null }, verified_contacts: [], authenticators: [],
        consumer_oidc: { available: true, connection_id: "consumer-google", label: "Google" },
        recovery: { batches: [] }, sessions: [], memberships: [{
            id: "organization-a", display_name: "Organization A", role: "owner",
            personal: false, provider_commercial: false,
            can_leave: false, leave_blocked_reason: "Transfer ownership or add another owner before leaving.",
        }], invitations: [],
        erasure: { available: true, confirmation: "ERASE MY ACCOUNT" as const, blocking_organizations: [] },
    },
    "provider-connections": {
        connections: [{
            id: "openai", provider: "openai", name: "OpenAI", kind: "api-key", endpoint_class: "provider-hosted",
            base_url: null, linked: true, status: "active", version: 1, execution_classes: ["private-home"],
            models: ["model-a"], linked_at_ms: null, last_verified_at_ms: null, verification: "unverified",
        }],
        default_model: { connection_id: "openai", model: "model-a" },
        subscription_sign_ins: { codex: signIn("openai-codex"), grok: signIn("xai-grok") },
        managed_inference: {
            plan: { plan: "Managed", status: "suspended", included_tokens: 5000 }, usage,
            billing: {
                customer_linked: false, subscription: null, freshness: "processor-reconciled", processor_mode: "live", verification: "unlinked",
                configured_plan: { name: "Managed", included_tokens: 5000, checkout_available: false },
                management: { plan_change: false, seats: false, cancellation: false },
                documents: {
                    invoices: [], estimate: null, refreshed_at: null,
                    history_complete: false, freshness: "not-refreshed",
                },
            },
        },
    },
    "trusted-devices": {
        devices: [{ id: "device-a", label: "Laptop", kind: "computer", subkey_pubkey: "public-key", status: "active", enrolled_at: 0, last_seen_ms: null, current: false }],
        pending_link: null, link_availability: { available: false, reason: "No recoverable root" },
    },
    "application-settings": {
        preferences: {
            appearance: { version: 1, interface_scale: "standard", contrast: "standard", motion: "system" },
            "attention.rules": "all",
        },
        ownership: { "attention.rules": "person", appearance: "person" },
        appearance_saved: true,
        managed: [],
    },
};
const page = (id: keyof typeof gaugeAppPageDefinitions, model: unknown = id === "model-providers" ? {availability: "unavailable", reason: "not_configured"} : id === "project-hosts" ? emptyProjectHosts : id in models ? models[id as keyof typeof models] : id in administrationEmptyModels ? administrationEmptyModels[id as keyof typeof administrationEmptyModels] : id in commercialEmptyModels ? commercialEmptyModels[id as keyof typeof commercialEmptyModels] : {}) => ({
    app: gaugeAppPageDefinitions[id][0],
    scope: { kind: id in models ? "person" as const : gaugeAppPageDefinitions[id][0] === "administration" ? "tenant" as const : "provider-tenant" as const, id: id in models ? "person-a" : "tenant-a" },
    id, read_model: gaugeAppPageDefinitions[id][1], version: 1, resource_basis: "basis-1", freshness: "live", model,
});

describe("GaugeApp page wire contracts", () => {
    it("requires membership leave controls to agree with the server-owned lifecycle", () => {
        const account = models.account;
        expect(parseAccountSettingsModel(account, "account").memberships[0]?.can_leave).toBe(false);
        const membership = account.memberships[0]!;
        expect(() => parseAccountSettingsModel({ ...account, memberships: [{ ...membership, can_leave: true }] }, "account")).toThrow(/leave_blocked_reason/);
        expect(() => parseAccountSettingsModel({ ...account, memberships: [{ ...membership, leave_blocked_reason: null }] }, "account")).toThrow(/leave_blocked_reason/);
        expect(() => parseAccountSettingsModel({ ...account, memberships: [{ ...membership, personal: true }] }, "account")).toThrow(/can_leave/);
    });
    it("requires authenticator removal controls to agree with the server-owned lifecycle", () => {
        const blocked = { id: "passkey-a", kind: "passkey", label: "Security key", created_at: 10, can_remove: false, remove_blocked_reason: "Add another passkey first." };
        const removable = { id: "oidc-a", kind: "enterprise-oidc", connection_id: "connection-a", linked_at: 11, can_remove: true, remove_blocked_reason: null };
        expect(parseAccountSettingsModel({ ...models.account, authenticators: [blocked, removable] }, "account").authenticators).toEqual([blocked, removable]);
        expect(() => parseAccountSettingsModel({ ...models.account, authenticators: [{ ...blocked, can_remove: true }] }, "account")).toThrow(/remove_blocked_reason/);
        expect(() => parseAccountSettingsModel({ ...models.account, authenticators: [{ ...removable, remove_blocked_reason: "Blocked" }] }, "account")).toThrow(/remove_blocked_reason/);
    });
    it("requires the server-owned account-erasure preflight", () => {
        expect(parseAccountSettingsModel(models.account, "account").erasure.available).toBe(true);
        expect(() => parseAccountSettingsModel({ ...models.account, erasure: { available: true, confirmation: "DELETE", blocking_organizations: [] } }, "account")).toThrow(/confirmation/);
        expect(() => parseAccountSettingsModel({ ...models.account, erasure: { available: true, confirmation: "ERASE MY ACCOUNT" } }, "account")).toThrow(/blocking_organizations/);
    });
    it("shares actual managed-usage field names with Administration", () => {
        const current = parseManagedInferenceUsage(usage, "usage");
        expect(current.total_tokens).toBe(1000);
        expect(current.included_tokens).toBe(5000);
        expect(() => parseManagedInferenceUsage({ included: 5000, used: 1000 }, "usage")).toThrow(/incompatible/);
    });
    it("requires mode-bound verified subscription evidence instead of an old callback snapshot", () => {
        const base = models["provider-connections"].managed_inference.billing;
        const subscription = { event_id: "evt_current", event_created: 1, subscription_id: "sub_current", customer_id: "cus_current", price_id: "price_current", subscription_item_id: "si_current", quantity: 3,
            status: "active", storage_bytes: 100, concurrent_agents: 2, retention_secs: 300, current_period_end: 2_000_000_000,
            processor_mode: "live", verified_at: 10, cancel_at_period_end: true };
        const current = { ...base, verification: "verified", customer_linked: true, subscription,
            management: { plan_change: true, seats: true, cancellation: false } };
        expect(parseSubscriptionBilling(current, "billing").subscription?.cancel_at_period_end).toBe(true);
        for (const replacement of [{ ...subscription, processor_mode: "test" }, { ...subscription, verified_at: 0 }, { ...subscription, verified_at: undefined }]) {
            expect(() => parseSubscriptionBilling({ ...current, subscription: replacement }, "billing")).toThrow(/incompatible/);
        }
        for (const verification of ["unlinked", "unverified", "unavailable"]) {
            expect(() => parseSubscriptionBilling({ ...current, verification }, "billing")).toThrow(/incompatible/);
            expect(parseSubscriptionBilling({ ...base, verification }, "billing").subscription).toBeNull();
            expect(() => parseSubscriptionBilling({ ...base, verification, customer_linked: true }, "billing")).toThrow(/verification/);
        }
        expect(() => parseSubscriptionBilling({ ...current, subscription: null }, "billing")).toThrow(/verification/);
        expect(() => parseSubscriptionBilling({ ...current, subscription: { ...subscription, quantity: 0 } }, "billing")).toThrow(/quantity/);
        expect(() => parseSubscriptionBilling({ ...current, management: { ...current.management, cancellation: true } }, "billing")).toThrow(/cancellation/);
    });
    it("names every accepted page in exactly its owning App", () => {
        expect(Object.fromEntries(contract.gaugeApps.flatMap((app) => app.pages.map((entry) =>
            [entry.id, [app.id, entry.readModel]])))).toEqual(gaugeAppPageDefinitions);
        expect(Object.keys(gaugeAppPageDefinitions)).toHaveLength(20);
    });

    for (const [id, [app]] of Object.entries(gaugeAppPageDefinitions)) {
        it(`validates the ${app}/${id} envelope`, () => {
            const input = page(id as keyof typeof gaugeAppPageDefinitions);
            expect(parseGaugeAppPage(input, app, id, input.scope).id).toBe(id);
            for (const override of [
                { id: "another-page" }, { read_model: "OtherPageV1" }, { version: 2 },
                { resource_basis: "" }, { freshness: null }, { model: [] },
                { app: "another-app" }, { scope: { ...input.scope, id: "another-scope" } },
            ]) expect(() => parseGaugeAppPage({ ...input, ...override }, app, id, input.scope)).toThrow(/incompatible/);
            expect(() => parseGaugeAppPage(input, (app === "administration" ? "account-settings" : "administration") as GaugeAppKind, id, input.scope)).toThrow(/page.id/);
        });
    }

    for (const [id, model] of Object.entries(models)) {
        it(`${id} cannot turn a missing field into an empty model`, () => {
            for (const key of Object.keys(model)) {
                const broken: Record<string, unknown> = { ...model };
                delete broken[key];
                expect(() => parseAccountGaugeAppPage(page(id as keyof typeof models, broken))).toThrow(/incompatible/);
            }
        });
    }

    for (const [id, model] of Object.entries(administrationEmptyModels)) {
        it(`${id} cannot turn a missing Administration field into an empty model`, () => {
            for (const key of Object.keys(model)) {
                const broken: Record<string, unknown> = { ...model };
                delete broken[key];
                expect(() => parseAdministrationGaugeAppPage(page(id as keyof typeof administrationEmptyModels, broken))).toThrow(/incompatible/);
            }
        });
    }

    it("distinguishes the local and Cloud backup projections and reads Cloud billing", () => {
        const local = parseAdministrationGaugeAppPage(page("backups"));
        if (local.id !== "backups" || !("backups" in local.model)) throw Error("wrong backup variant");
        expect(local.model.backups).toEqual([]);
        const hosted = parseAdministrationGaugeAppPage(page("backups", cloudBackups));
        if (hosted.id !== "backups" || !("points" in hosted.model)) throw Error("wrong backup variant");
        expect(hosted.model.points).toEqual([]);
        const plan = parseAdministrationGaugeAppPage(page("plans-services", cloudBilling));
        if (plan.id !== "plans-services") throw Error("wrong page");
        expect(plan.model.cloud?.processor_mode).toBe("test");
    });

    it("removes undeclared Administration fields after validating the producer shape", () => {
        const parsed = parseAdministrationGaugeAppPage(page("organization", {
            ...administrationEmptyModels.organization,
            unrecognized: "must-not-reach-the-panel",
        }));
        expect(parsed.model).not.toHaveProperty("unrecognized");
    });

    it("keeps real empty values and nullable state without inventing enrollment or a plan", () => {
        expect(parseAccountGaugeAppPage(page("account")).model).toEqual(models.account);
        const devices = parseAccountGaugeAppPage(page("trusted-devices"));
        if (devices.id !== "trusted-devices") throw Error("wrong page");
        expect(devices.model.devices[0]?.enrolled_at).toBe(0);
        expect(devices.model.devices[0]?.kind).toBe("computer");
        expect(devices.model.devices[0]?.last_seen_ms).toBeNull();
        expect(devices.model.pending_link).toBeNull();
        expect(devices.model.link_availability).toEqual({ available: false, reason: "No recoverable root" });
    });

    it("validates nested account identities and separate authenticator variants", () => {
        const model = { ...models.account, authenticators: [
            { id: "passkey-a", kind: "passkey", label: "Security key", created_at: 10, can_remove: false, remove_blocked_reason: "Add another passkey first." },
            { id: "oidc-a", kind: "enterprise-oidc", connection_id: "connection-a", linked_at: 11, can_remove: true, remove_blocked_reason: null },
        ], invitations: [{ tenant_id: "tenant-b", display_name: "Example", role: "member" }] };
        const parsed = parseAccountGaugeAppPage(page("account", model));
        expect(parsed.model).toEqual(model);
        expect(() => parseAccountGaugeAppPage(page("account", { ...model, invitations: [{ id: "tenant-b", display_name: "Example", role: "member" }] }))).toThrow(/tenant_id/);
        expect(() => parseAccountGaugeAppPage(page("account", { ...model, authenticators: [{ id: "passkey-a", kind: "passkey" }] }))).toThrow(/label/);
    });

    it("preserves typed usage and rejects the old fabricated used field", () => {
        const parsed = parseProviderConnectionsModel(models["provider-connections"], "model");
        expectTypeOf(parsed.managed_inference.usage.total_tokens).toEqualTypeOf<number>();
        expect(parsed.managed_inference.usage.total_tokens).toBe(1000);
        expect(parsed.managed_inference.plan?.status).toBe("suspended");
        const model = structuredClone(models["provider-connections"]);
        const brokenUsage: Record<string, unknown> = { ...model.managed_inference.usage, used: 1000 };
        delete brokenUsage.total_tokens;
        expect(() => parseProviderConnectionsModel({ ...model, managed_inference: { ...model.managed_inference, usage: brokenUsage } }, "model")).toThrow(/total_tokens/);
    });

    it("does not coerce flags, counts, or provider enums", () => {
        const model = models["provider-connections"];
        for (const override of [{ linked: "true" }, { version: -1 }, { version: 1.5 }, { verification: "ready" }, { models: [12] }]) {
            expect(() => parseProviderConnectionsModel({ ...model, connections: [{ ...model.connections[0], ...override }] }, "model")).toThrow(/incompatible/);
        }
    });

    it("does not turn an unknown device-link phase into a usable ceremony", () => {
        const pending = {
            id: "link-a", phase: "awaiting-acceptance", human_code: "ABCD-EF12", qr_payload: "gaugewright://auth/device-link",
            created_at_ms: 1000, expires_at_ms: 4000, device: { id: "phone-a", label: "Phone", kind: "phone" },
            sas: "123456", completed_at_ms: null,
        };
        const input = page("trusted-devices", { ...models["trusted-devices"], pending_link: pending });
        expect(parseAccountGaugeAppPage(input).model).toEqual(input.model);
        expect(() => parseAccountGaugeAppPage({ ...input, model: { ...models["trusted-devices"], pending_link: { ...pending, phase: "ready" } } })).toThrow(/phase/);
    });

    it("preserves structured preferences as data instead of stringifying them", () => {
        const parsed = parseAccountGaugeAppPage(page("application-settings"));
        if (parsed.id !== "application-settings") throw Error("wrong page");
        expect(parsed.model.preferences.appearance).toEqual({
            version: 1, interface_scale: "standard", contrast: "standard", motion: "system",
        });
    });

    it("rejects incomplete and future appearance documents", () => {
        const application = models["application-settings"];
        for (const appearance of [
            { version: 1, interface_scale: "standard", contrast: "standard" },
            { version: 2, interface_scale: "standard", contrast: "standard", motion: "system" },
            { version: 1, interface_scale: "compact", contrast: "standard", motion: "system" },
        ]) {
            expect(() => parseAccountGaugeAppPage(page("application-settings", {
                ...application,
                preferences: { ...application.preferences, appearance },
            }))).toThrow(/appearance/);
        }
    });

    it("drops undeclared fields and never echoes response values in validation errors", () => {
        const parsed = parseAccountGaugeAppPage(page("account", { ...models.account, unrecognized: "sensitive-example" }));
        expect(parsed.model).not.toHaveProperty("unrecognized");
        expect(() => parseAccountGaugeAppPage(page("account", { ...models.account, sessions: "sensitive-example" })))
            .toThrow("GaugeApp response is incompatible at page.model.sessions. Refresh or update GaugeDesk.");
    });

    it("validates at the HTTP boundary and infers an exact Account page model", async () => {
        const session = { app: "account-settings", id: "session", generation: "epoch", scope: { kind: "person", id: "person-a" } } as GaugeAppSession;
        const parsed = await readGaugeAppPage(async () => ({ page: page("provider-connections") }), session, "provider-connections");
        expectTypeOf(parsed.model.default_model).toEqualTypeOf<{ readonly connection_id: string; readonly model: string } | null>();
        expect(parsed.model.default_model?.connection_id).toBe("openai");
        await expect(readGaugeAppPage(async () => ({ page: page("trusted-devices") }), session, "account")).rejects.toThrow(/page.id/);
        await expect(readGaugeAppPage(async () => ({}), session, "account")).rejects.toThrow(/at page/);
    });
});

describe("account avatar", () => {
    const withAvatar = (avatar: unknown) => {
        const { avatar: _omitted, ...profile } = models.account.profile;
        return { ...models.account, profile: avatar === undefined ? profile : { ...profile, avatar } };
    };

    it("reads an absent avatar as none, so an authority that predates avatars stays compatible", () => {
        expect(parseAccountSettingsModel(withAvatar(undefined), "model").profile.avatar).toBeNull();
        expect(parseAccountSettingsModel(withAvatar(null), "model").profile.avatar).toBeNull();
    });

    it("admits only a PNG or JPEG data URI the authority re-encoded", () => {
        const jpeg = "data:image/jpeg;base64,/9j/4AAQSkZJRg==";
        expect(parseAccountSettingsModel(withAvatar(jpeg), "model").profile.avatar).toBe(jpeg);
        for (const refused of [
            "https://lh3.googleusercontent.com/a/photo=s96-c",
            "data:image/svg+xml;base64,PHN2Zy8+",
            "data:text/html;base64,PGgxPg==",
            "data:image/png;base64,not base64!",
            42,
        ]) {
            expect(() => parseAccountSettingsModel(withAvatar(refused), "model")).toThrow(/model\.profile\.avatar/);
        }
    });
});
