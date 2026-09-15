import { describe, expect, expectTypeOf, it } from "vitest";
import fixture from "../../../../crates/app/src/model_provider_management/projection/page.fixture.json";
import { modelProvidersUnavailableReason, parseModelProvidersModel } from "./gaugeapp-model-provider-models";
import { parseModelProvidersPage } from "./gaugeapp-page-models";
const sample = () => structuredClone(fixture);

describe("Model Providers authority projection", () => {
    it("accepts only explicit closed setup choices supplied by the service", () => {
        const connection = sample().connections[0]!;
        const option = { provider: connection.provider, endpoint: connection.endpoint, authentication: connection.authentication, verification_check: "model_catalog_read", policy: connection.policy };
        const value = { ...sample(), setup: { api_key_intake: true, providers: [option] } };
        const parsed = parseModelProvidersModel(value);
        expect(parsed.availability === "available" && parsed.setup.providers).toEqual([option]);
        for (const setup of [{ providers: [option] }, { api_key_intake: true }, { api_key_intake: "yes", providers: [option] }, { api_key_intake: true, providers: [{ ...option, credential: "do-not-render" }] }]) {
            expect(() => parseModelProvidersModel({ ...value, setup })).toThrow(/incompatible/);
        }
        for (const verification_check of [null, "model_catalog_read"] as const) {
            expect(parseModelProvidersModel({ ...value, setup: { api_key_intake: true, providers: [{ ...option, verification_check }] } }).availability).toBe("available");
        }
        for (const verification_check of [undefined, "inference_ready", true]) {
            expect(() => parseModelProvidersModel({ ...value, setup: { api_key_intake: true, providers: [{ ...option, verification_check }] } })).toThrow(/incompatible/);
        }
    });

    it("distinguishes an absent credential store from an empty connection list", () => {
        expect(modelProvidersUnavailableReason("not_configured")).toBe("This GaugeDesk service has no organization credential store configured.");
        expect(modelProvidersUnavailableReason("authority_unavailable")).toMatch(/unavailable/);
    });
    it("reads the exact event-derived Rust producer fixture without rounding", () => {
        const model = parseModelProvidersModel(sample());
        expect(model).toEqual(fixture);
        if (model.availability !== "available") throw Error("fixture is available");
        expectTypeOf(model.grants[0]!.caps.tokens).toEqualTypeOf<string | null>();
        expect(model.grants[0]!.caps.tokens).toBe("18446744073709551615");
        expect(model.grants[0]!.usage.reserved).toEqual({tokens: "5", money: [], unknown_money: true});
        expect(model.grants[0]!.usage.measured.tokens).toBe("0");
    });
    it("does not turn missing authority into empty connections or fictitious usage", () => {
        expect(parseModelProvidersModel({availability: "unavailable", reason: "not_configured"})).toEqual({availability: "unavailable", reason: "not_configured"});
        for (const value of [{}, {availability: "available"}, {availability: "unavailable"}, {availability: "unavailable", reason: "unknown"}, {availability: "unavailable", reason: "not_configured", connections: []}]) expect(() => parseModelProvidersModel(value)).toThrow(/incompatible/);
    });
    it("preserves unknown historical checks and rejects exaggerated or mistimed verification", () => {
        const legacy: any = sample(); legacy.connections[0].versions[0].verification = null;
        const parsed = parseModelProvidersModel(legacy);
        expect(parsed.availability === "available" && parsed.connections[0]!.versions[0]!.verification).toBeNull();
        for (const verification of [
            {check: "inference_ready", observed_at: "3"},
            {check: "model_catalog_read", observed_at: "0"},
            {check: "model_catalog_read", observed_at: "9"},
            {check: "model_catalog_read", observed_at: "1000"},
            {check: "model_catalog_read", observed_at: "3", provider_response: "must-not-echo"},
            {check: "model_catalog_read"},
        ]) {
            const value: any = sample(); value.connections[0].versions[0].verification = verification;
            expect(() => parseModelProvidersModel(value)).toThrow(/incompatible/);
        }
    });
    it("requires every producer field, including explicit nullable values", () => {
        for (const location of [[], ["binding"], ["period"], ["connections", 0], ["connections", 0, "versions", 0], ["connections", 0, "policy"], ["grants", 0], ["grants", 0, "subject"], ["grants", 0, "policy"], ["grants", 0, "caps"], ["grants", 0, "usage"], ["grants", 0, "usage", "reserved"]] as const) {
            const value = sample();
            const source = location.reduce<any>((item, key) => item[key], value);
            for (const key of Object.keys(source)) {
                const broken = sample(); const target = location.reduce<any>((item, key) => item[key], broken);
                delete target[key]; expect(() => parseModelProvidersModel(broken)).toThrow(/incompatible/);
            }
        }
    });
    it("rejects extra credential and work fields without echoing names or values", () => {
        for (const location of [[], ["binding"], ["connections", 0], ["connections", 0, "versions", 0], ["grants", 0], ["grants", 0, "usage", "reserved"]] as const) {
            const broken = sample(); const target = location.reduce<any>((item, key) => item[key], broken);
            target["prohibited-secret-name"] = "prohibited-secret-value";
            try { parseModelProvidersModel(broken); throw Error("did not reject"); } catch (error) {
                expect(String(error)).toMatch(/incompatible/); expect(String(error)).not.toMatch(/prohibited-secret/);
            }
        }
    });
    it("distinguishes zero from uncapped and retains totals wider than u64", () => {
        const value = sample(); value.grants[0]!.caps.tokens = "0";
        value.grants[0]!.usage.reserved.tokens = "36893488147419103230";
        const model = parseModelProvidersModel(value);
        expect(model.availability === "available" && model.grants[0]!.caps.tokens).toBe("0");
        expect(model.availability === "available" && model.grants[0]!.usage.reserved.tokens).toBe("36893488147419103230");
        expect(() => parseModelProvidersModel({...value, management_revision: "18446744073709551616"})).toThrow();
        for (const invalid of [12, 1.5, "01", "+1", "1e4", "-1", " 1", "340282366920938463463374607431768211456"]) {
            const broken: any = sample(); broken.grants[0].usage.reserved.tokens = invalid;
            expect(() => parseModelProvidersModel(broken)).toThrow(/incompatible/);
        }
        const uncapped: any = sample(); uncapped.grants[0].caps = {tokens:null,money:null};
        expect(parseModelProvidersModel(uncapped).availability).toBe("available");
    });
    it("rejects unknown references, duplicate rows and contradictory credential standing", () => {
        const mutations: ((value: any) => void)[] = [
            value => value.connections.push(value.connections[0]), value => value.grants.push(value.grants[0]),
            value => value.connections[0].versions.push(value.connections[0].versions[0]),
            value => value.connections[0].current_version = "missing",
            value => value.connections[0].versions[0].phase = "verified",
            value => value.connections[0].versions[0].material = "erased",
            value => value.connections[0].erasure_requested = true,
            value => value.connections[0].status = "pending",
            value => value.grants[0].connection = "missing",
            value => value.grants[0].audiences = ["service"],
            value => value.grants[0].policy.execution_classes = ["public_direct"],
            value => value.grants[0].usage.reserved.unknown_money = false,
            value => value.grants[0].usage.accounted_at_bound = {tokens:"3",money:[],unknown_money:true},
            value => value.period.month = 13,
            value => value.connections[0].endpoint = "https://provider.invalid/?credential=must-not-read",
        ];
        for (const mutate of mutations) { const value=sample(); mutate(value); expect(() => parseModelProvidersModel(value)).toThrow(/incompatible/); }
    });
    it("keeps an unavailable default visible without treating it as a usable route", () => {
        const value: any=sample(); value.default_model={connection:"connection-a",model:"model-a",available:true};
        expect(parseModelProvidersModel(value).availability).toBe("available");
        value.connections[0].status="suspended";
        expect(() => parseModelProvidersModel(value)).toThrow(/default_model.available/);
        value.default_model.available=false;
        const model=parseModelProvidersModel(value);
        expect(model.availability === "available" && model.default_model?.available).toBe(false);
    });
    it("binds the page to the exact selected organization", () => {
        const page={app:"administration",scope:{kind:"tenant",id:"example-organization"},id:"model-providers",read_model:"OrganizationModelProvidersPageV1",version:1,resource_basis:"basis",freshness:"live",model:sample()};
        expect(parseModelProvidersPage(page).model.availability).toBe("available");
        expect(() => parseModelProvidersPage({...page,scope:{kind:"tenant",id:"another-organization"}})).toThrow(/binding.organization/);
    });
});
