import type { GaugeAppKind, GaugeAppPageModel, GaugeAppScope } from "./gaugeapp";
import { accountPageModels, type AccountGaugeAppPageData, type AccountGaugeAppPageId } from "./gaugeapp-account-models";
import { administrationPageModels, type AdministrationDomainPageId, type AdministrationGaugeAppPageData } from "./gaugeapp-administration-models";
import { commercialPageModels, type CommercialGaugeAppPageData, type CommercialGaugeAppPageId } from "./gaugeapp-commercial-models";
import { invalidModel, objectValue, oneOf, shape, stringValue } from "./gaugeapp-model-validation";
import { parseProjectHostsModel, type ProjectHostsModel } from "./gaugeapp-project-host-models";
import { parseModelProvidersModel, type ModelProvidersModel } from "./gaugeapp-model-provider-models";

/** Protocol names only: never a dashboard description or client-side grant.
 * The contract test compares every entry with the accepted page inventory. */
export const gaugeAppPageDefinitions = {
    account: ["account-settings", "AccountSettingsPageV1"],
    "provider-connections": ["account-settings", "ProviderConnectionsPageV1"],
    "trusted-devices": ["account-settings", "TrustedDevicesPageV1"],
    "application-settings": ["account-settings", "ApplicationSettingsPageV1"],
    organization: ["administration", "OrganizationPageV1"],
    "plans-services": ["administration", "PlansServicesPageV1"],
    people: ["administration", "PeoplePageV1"],
    sessions: ["administration", "OrganizationSessionsPageV1"],
    "enterprise-identity": ["administration", "EnterpriseIdentityPageV1"],
    projects: ["administration", "AdministrationProjectsPageV1"],
    "model-providers": ["administration", "OrganizationModelProvidersPageV1"],
    "organization-policy": ["administration", "OrganizationPolicyPageV1"],
    "project-hosts": ["administration", "ProjectHostsPageV1"],
    backups: ["administration", "BackupsPageV1"],
    "software-policy": ["administration", "SoftwarePolicyPageV1"],
    billing: ["administration", "TenantBillingPageV1"],
    products: ["commercial-operations", "ProductsPageV1"],
    clients: ["commercial-operations", "ClientsPageV1"],
    engagements: ["commercial-operations", "EngagementsPageV1"],
    payments: ["commercial-operations", "CommercialPaymentsPageV1"],
} as const;
export type GaugeAppPageId = keyof typeof gaugeAppPageDefinitions;
export type ProjectHostsPage = GaugeAppPageModel<ProjectHostsModel> & { readonly id: "project-hosts"; readonly read_model: "ProjectHostsPageV1"; readonly version: 1 };
export type ModelProvidersPage = GaugeAppPageModel<ModelProvidersModel> & { readonly id: "model-providers"; readonly read_model: "OrganizationModelProvidersPageV1"; readonly version: 1 };
export type AdministrationGaugeAppPageDataAll = AdministrationGaugeAppPageData & {
    readonly "project-hosts": ProjectHostsModel;
    readonly "model-providers": ModelProvidersModel;
};
export type AdministrationGaugeAppPageId = AdministrationDomainPageId | "project-hosts" | "model-providers";
export type AdministrationGaugeAppPage<P extends AdministrationGaugeAppPageId = AdministrationGaugeAppPageId> = {
    readonly [K in P]: GaugeAppPageModel<AdministrationGaugeAppPageDataAll[K]> & {
        readonly id: K;
        readonly read_model: (typeof gaugeAppPageDefinitions)[K][1];
        readonly version: 1;
    };
}[P];
export type AccountGaugeAppPage<P extends AccountGaugeAppPageId = AccountGaugeAppPageId> = {
    readonly [K in P]: GaugeAppPageModel<AccountGaugeAppPageData[K]> & {
        readonly id: K;
        readonly read_model: (typeof gaugeAppPageDefinitions)[K][1];
        readonly version: 1;
    };
}[P];
export type CommercialGaugeAppPage<P extends CommercialGaugeAppPageId = CommercialGaugeAppPageId> = {
    readonly [K in P]: GaugeAppPageModel<CommercialGaugeAppPageData[K]> & {
        readonly id: K;
        readonly read_model: (typeof gaugeAppPageDefinitions)[K][1];
        readonly version: 1;
    };
}[P];

const readScope = shape({ kind: oneOf("person", "tenant", "provider-tenant"), id: stringValue });
function envelope(value: unknown, app: GaugeAppKind, expectedPageId: string, expectedScope: GaugeAppScope) {
    const page = objectValue(value, "page");
    if (!Object.hasOwn(gaugeAppPageDefinitions, expectedPageId)) return invalidModel("page.id");
    const id = expectedPageId as GaugeAppPageId;
    const [owner, readModel] = gaugeAppPageDefinitions[id];
    if (owner !== app || page.id !== expectedPageId) return invalidModel("page.id");
    if (page.app !== app) return invalidModel("page.app");
    const scope = readScope(page.scope, "page.scope");
    const kind = app === "account-settings" ? "person" : app === "administration" ? "tenant" : "provider-tenant";
    if (scope.kind !== kind || scope.kind !== expectedScope.kind || !scope.id.trim() || scope.id !== expectedScope.id) return invalidModel("page.scope");
    if (page.read_model !== readModel) return invalidModel("page.read_model");
    if (page.version !== 1) return invalidModel("page.version");
    const basis = stringValue(page.resource_basis, "page.resource_basis");
    const freshness = stringValue(page.freshness, "page.freshness");
    if (!basis.trim() || !freshness.trim()) return invalidModel("page.resource_basis/freshness");
    if (!Object.hasOwn(page, "model")) return invalidModel("page.model");
    return { app, scope, id, read_model: readModel, version: 1 as const, resource_basis: basis, freshness, model: page.model };
}

export function parseAccountGaugeAppPage(value: unknown): AccountGaugeAppPage {
    const input = objectValue(value, "page");
    const page = envelope(input, "account-settings", stringValue(input.id, "page.id"), readScope(input.scope, "page.scope"));
    switch (page.id) {
        case "account": {
            const model = accountPageModels.account(page.model, "page.model");
            if (model.profile.account_id !== page.scope.id) return invalidModel("page.model.profile.account_id");
            return { ...page, id: page.id, read_model: "AccountSettingsPageV1", model };
        }
        case "provider-connections": return { ...page, id: page.id, read_model: "ProviderConnectionsPageV1", model: accountPageModels[page.id](page.model, "page.model") };
        case "trusted-devices": return { ...page, id: page.id, read_model: "TrustedDevicesPageV1", model: accountPageModels[page.id](page.model, "page.model") };
        case "application-settings": return { ...page, id: page.id, read_model: "ApplicationSettingsPageV1", model: accountPageModels[page.id](page.model, "page.model") };
        default: return invalidModel("page.id");
    }
}

export function parseCommercialGaugeAppPage(value: unknown): CommercialGaugeAppPage {
    const input = objectValue(value, "page");
    const page = envelope(input, "commercial-operations", stringValue(input.id, "page.id"), readScope(input.scope, "page.scope"));
    switch (page.id) {
        case "products": return { ...page, id: page.id, read_model: "ProductsPageV1", model: commercialPageModels.products(page.model, "page.model") };
        case "clients": return { ...page, id: page.id, read_model: "ClientsPageV1", model: commercialPageModels.clients(page.model, "page.model") };
        case "engagements": return { ...page, id: page.id, read_model: "EngagementsPageV1", model: commercialPageModels.engagements(page.model, "page.model") };
        case "payments": return { ...page, id: page.id, read_model: "CommercialPaymentsPageV1", model: commercialPageModels.payments(page.model, "page.model") };
        default: return invalidModel("page.id");
    }
}

export function parseAdministrationGaugeAppPage(value: unknown): AdministrationGaugeAppPage {
    const input = objectValue(value, "page");
    const page = envelope(input, "administration", stringValue(input.id, "page.id"), readScope(input.scope, "page.scope"));
    switch (page.id) {
        case "organization": return { ...page, id: page.id, read_model: "OrganizationPageV1", model: administrationPageModels.organization(page.model, "page.model") };
        case "plans-services": return { ...page, id: page.id, read_model: "PlansServicesPageV1", model: administrationPageModels[page.id](page.model, "page.model") };
        case "people": return { ...page, id: page.id, read_model: "PeoplePageV1", model: administrationPageModels[page.id](page.model, "page.model") };
        case "sessions": return { ...page, id: page.id, read_model: "OrganizationSessionsPageV1", model: administrationPageModels[page.id](page.model, "page.model") };
        case "enterprise-identity": return { ...page, id: page.id, read_model: "EnterpriseIdentityPageV1", model: administrationPageModels[page.id](page.model, "page.model") };
        case "projects": return { ...page, id: page.id, read_model: "AdministrationProjectsPageV1", model: administrationPageModels[page.id](page.model, "page.model") };
        case "model-providers": return parseModelProvidersPage(page);
        case "organization-policy": return { ...page, id: page.id, read_model: "OrganizationPolicyPageV1", model: administrationPageModels[page.id](page.model, "page.model") };
        case "project-hosts": return parseProjectHostsPage(page);
        case "backups": return { ...page, id: page.id, read_model: "BackupsPageV1", model: administrationPageModels[page.id](page.model, "page.model") };
        case "software-policy": return { ...page, id: page.id, read_model: "SoftwarePolicyPageV1", model: administrationPageModels[page.id](page.model, "page.model") };
        case "billing": return { ...page, id: page.id, read_model: "TenantBillingPageV1", model: administrationPageModels[page.id](page.model, "page.model") };
        default: return invalidModel("page.id");
    }
}

export function parseGaugeAppPage(value: unknown, app: GaugeAppKind, expectedPageId: string, expectedScope: GaugeAppScope): GaugeAppPageModel {
    const page = envelope(value, app, expectedPageId, expectedScope);
    if (app === "account-settings") return parseAccountGaugeAppPage(page);
    if (app === "commercial-operations") return parseCommercialGaugeAppPage(page);
    return parseAdministrationGaugeAppPage(page);
}

export function parseModelProvidersPage(value: unknown): ModelProvidersPage {
    const input = objectValue(value, "page");
    const page = envelope(input, "administration", "model-providers", readScope(input.scope, "page.scope"));
    const model = parseModelProvidersModel(page.model, "page.model");
    if (model.availability === "available" && model.binding.organization !== page.scope.id) return invalidModel("page.model.binding.organization");
    return { ...page, id: "model-providers", read_model: "OrganizationModelProvidersPageV1", model };
}

export function parseProjectHostsPage(value: unknown): ProjectHostsPage {
    const input = objectValue(value, "page");
    const page = envelope(input, "administration", "project-hosts", readScope(input.scope, "page.scope"));
    const model = parseProjectHostsModel(page.model, "page.model");
    for (const host of model.homes) {
        if (host.kind === "cloud" && host.managed_policy.tenant_id !== page.scope.id) return invalidModel("page.model.homes.managed_policy.tenant_id");
    }
    return { ...page, id: "project-hosts", read_model: "ProjectHostsPageV1", model };
}
