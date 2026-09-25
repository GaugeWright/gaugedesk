import {
    type Accessor,
    createEffect,
    createMemo,
    createResource,
    createSignal,
    onCleanup,
    For,
    Show,
    type JSX,
} from "solid-js";
import {
    type AccountDeviceLinkStatus,
    parseAccountGaugeAppPage,
    parseAdministrationGaugeAppPage,
    parseCommercialGaugeAppPage,
    type CommercialArchetypeRef,
    type CommercialProduct,
    type CommercialClient,
    type CommercialEngagement,
    type CommercialRecipient,
    type CommercialProcessorEvent,
    type ProductsPageV1,
    type ClientsPageV1,
    type EngagementsPageV1,
    type CommercialPaymentsPageV1,
    type TrustedDevicesPageV1,
    parseAppearancePreference,
    engagementId,
    newIdempotencyKey,
    authenticationCredentialJSON,
    publicKeyCreationOptions,
    publicKeyRequestOptions,
    registrationCredentialJSON,
    RouteHttpError,
    type GaugeAppCommandResult,
    type GaugeAppKind,
    type GaugeAppAgentLiveFrame,
    type GaugeAppPageModel,
    type AdministrationGaugeAppPage,
    type AdministrationBillingPageV1,
    type BackupsPageV1,
    type EnterpriseIdentityPageV1,
    type OrganizationMember,
    type OrganizationPageV1,
    type OrganizationPolicyPageV1,
    type OrganizationSession,
    type SoftwarePolicyPageV1,
    type GaugeAppProposal,
    type GaugeAppScope,
    type GaugeAppSession,
} from "@gaugewright/control-plane-client";
import { EnterpriseControlPlane } from "@gaugewright/enterprise-client";
import { ProjectHostsPage } from "./ProjectHostsPage";
import { ModelProvidersPage } from "./ModelProvidersPage";
import {
    ChatPaneHeader,
    ChatPanel,
    ContextMenu,
    Icon,
    type MenuState,
    createGaugeAppResource,
    createGaugeAppOperations,
    createGaugeAppUpdateChannel,
    gaugeAppContextChanged,
    type GaugeAppOperation,
    createWorkbenchShellState,
    localTurnActivity,
    reduceTranscript,
    qrSvg,
    browserRecoveryHolder,
    ensureBrowserRecoveryHolder,
    rewrapBackupPointKey,
    ATTENTION_SIGNALS,
    ADVANCEMENT_RULES_SETTING,
    parseAdvancementScopes,
    parseAttentionRules,
    serializeAdvancementScopes,
    serializeAttentionRules,
    type AttentionLevel,
    type AttentionSignal,
    WorkbenchShell,
    type Session,
    type Transcript,
} from "@gaugewright/workbench-ui";
import type { ConnectElementTagName } from "@stripe/connect-js";
import { StripeEmbeddedComponent, type StripeAccountSession } from "./StripeEmbeddedComponent";
import { gaugeAppReviewControls, summarizeGaugeAppChange } from "./gaugeapp-review";
import { managedInferencePresentation, subscriptionPresentation } from "./account-page-presentation";
import { type PriceDraft, freshPrice, priceDrafts, pricePayloads, validPriceDraft, priceSummary, commercialMoney, commercialAmountInput, commercialAmountStep, commercialMinorAmount, engagementPresentation, agentChoice, initialLibraryAgent, paymentRefundRows, paymentModeDescription, paymentReadinessLabel, paymentInvoiceRows, paymentPayoutRows } from "./commercial-page-presentation";
import { pageFreshnessCaveat } from "./gaugeapp-page-presentation";
import {
    discardPendingDeviceLink,
    deviceLinkBrowserUrl,
    finalizeDeviceLink,
    generateDeviceLinkKey,
    hasPendingDeviceLink,
    prepareDeviceLinkCompletion,
    retainPendingDeviceLink,
    type DeviceLinkInvitation,
} from "./account-device-link";
import "./administration-gaugeapp.css";
import { AvatarFileError, avatarInitials, avatarUploadImage } from "./account-avatar-upload";

function GaugeAppChatMenu(props: { busy: boolean; hasMessages: boolean; onClear: () => void }) {
    const [menu, setMenu] = createSignal<MenuState | null>(null);
    return <div class="chat-options-anchor">
        <Show when={props.hasMessages}>
            <button type="button" class="chat-options-trigger" aria-label="Management chat menu"
                title="Management chat menu" aria-haspopup="menu" disabled={props.busy}
                onClick={(event) => {
                    const rect = event.currentTarget.getBoundingClientRect();
                    window.setTimeout(() => setMenu({ x: rect.left, y: rect.bottom, items: [
                        { label: "Clear chat", run: props.onClear },
                    ] }), 0);
                }}>
                <Icon name="menu" />
            </button>
        </Show>
        <ContextMenu menu={menu()} onClose={() => setMenu(null)} />
    </div>;
}
import { Notice, SectionHeading } from "./gaugeapp-design";

const PAGE_LABELS: Readonly<Record<string, string>> = {
    account: "Account Settings",
    "provider-connections": "Provider Connections",
    "trusted-devices": "Trusted Devices",
    "application-settings": "Application Settings",
    organization: "Organization",
    "plans-services": "Plans & services",
    people: "People",
    sessions: "Sessions",
    "enterprise-identity": "Enterprise Identity",
    projects: "Projects",
    "model-providers": "Model Providers",
    "organization-policy": "Organization Policy",
    "project-hosts": "Project Hosts",
    backups: "Backups",
    "software-policy": "Software policy",
    billing: "Billing",
    products: "Products",
    clients: "Clients",
    engagements: "Engagements",
    payments: "Payments",
};

const APP_LABELS: Readonly<Record<GaugeAppKind, string>> = {
    "account-settings": "Account Settings",
    administration: "Administration",
    "commercial-operations": "Commercial Operations",
};

/** Administration renames itself by what it is administering.
 *
 *  "Administration" over a person's own tenant reads as though an organization
 *  is involved, and a personal tenant has no members, identity provider or
 *  policy to administer — it has services, Project Hosts, recovery and billing.
 *  The prototype names the three cases apart and the pages differ accordingly;
 *  `admin-console.md` carries the same split in its availability table.
 */
function appLabel(app: GaugeAppKind, scope: GaugeAppScope | undefined): string {
    if (app !== "administration" || !scope) return APP_LABELS[app];
    return scope.kind === "person" || scope.id.startsWith("personal:") ? "Your Account" : "Administration";
}

const valueRecord = (value: unknown): Record<string, unknown> | null =>
    typeof value === "object" && value !== null && !Array.isArray(value)
        ? value as Record<string, unknown>
        : null;
const valueArray = (value: unknown): readonly unknown[] => Array.isArray(value) ? value : [];
const text = (value: unknown, fallback = "Not set") =>
    typeof value === "string" && value.trim() ? value : fallback;
const count = (value: unknown) => typeof value === "number" ? value : valueArray(value).length;

function Fact(props: { label: string; value: JSX.Element | string; note?: string }): JSX.Element {
    return <div class="gaugeapp-fact">
        <span>{props.label}</span>
        <strong>{props.value}</strong>
        <Show when={props.note}>{(note) => <small>{note()}</small>}</Show>
    </div>;
}

const distinctNote = (value: string | undefined, note: string | undefined): string | undefined =>
    note && note !== value ? note : undefined;

function ModelRows<T>(props: {
    values: readonly T[];
    empty: string;
    title: (record: T, index: number) => string;
    detail: (record: T) => string;
}): JSX.Element {
    return <Show when={props.values.length > 0} fallback={<p class="gaugeapp-empty">{props.empty}</p>}>
        <div class="gaugeapp-rows">
            <For each={props.values}>{(record, index) => {
                return <div class="gaugeapp-row">
                    <strong>{props.title(record, index())}</strong>
                    <span>{props.detail(record)}</span>
                </div>;
            }}</For>
        </div>
    </Show>;
}

const GOVERNED_ROLES = ["owner", "admin", "member", "viewer"] as const;
type GovernedRole = typeof GOVERNED_ROLES[number];
// Ownership is a separate reviewed lifecycle. The generic People role control
// must never mint or demote the one accountable owner.
const MEMBER_ROLES = ["admin", "auditor", "member", "viewer", "billing"] as const;
const PLACEMENT_OPERATORS = ["local", "counterparty", "neutral"] as const;
type PlacementOperator = typeof PLACEMENT_OPERATORS[number];

interface OrganizationPolicyDraft {
    readonly exportRoles: readonly GovernedRole[];
    readonly runRoles: readonly GovernedRole[];
    readonly requireMatchingRegion: boolean;
    readonly placementOperators: readonly PlacementOperator[];
    readonly requirePlacementApproval: boolean;
    readonly allowAutoUpgrade: boolean;
    readonly sessionLifetimeHours: number;
    readonly idleTimeoutMinutes: number;
    readonly auditGuaranteeDays: number;
    readonly preservedRules: readonly unknown[];
    readonly requireAttestedPlacement: boolean;
    readonly requireMfa: boolean;
    readonly residencyRegion: string | null;
}

const deniedFor = (ruleValue: unknown, action: "export" | "run"): GovernedRole | null => {
    const rule = valueRecord(ruleValue);
    const when = valueRecord(rule?.when);
    const require = valueRecord(rule?.require);
    const role = when?.ActorHasRole;
    return require?.DenyAction === action && GOVERNED_ROLES.includes(role as GovernedRole)
        ? role as GovernedRole
        : null;
};

const isMatchingRegionRule = (ruleValue: unknown): boolean => {
    const rule = valueRecord(ruleValue);
    return rule?.when === "Always" && rule.require === "RequireResourceRegionMatchesActor";
};

const organizationPolicyDraft = (model: OrganizationPolicyPageV1): OrganizationPolicyDraft => {
    const rules = model.resource.rules;
    const security = model.security;
    const exportDenied = new Set(rules.map((rule) => deniedFor(rule, "export")).filter(Boolean));
    const runDenied = new Set(rules.map((rule) => deniedFor(rule, "run")).filter(Boolean));
    const controlled = (rule: unknown) => deniedFor(rule, "export") !== null || deniedFor(rule, "run") !== null || isMatchingRegionRule(rule);
    return {
        exportRoles: GOVERNED_ROLES.filter((role) => !exportDenied.has(role)),
        runRoles: GOVERNED_ROLES.filter((role) => !runDenied.has(role)),
        requireMatchingRegion: rules.some(isMatchingRegionRule),
        placementOperators: model.placement.allowed_operators,
        requirePlacementApproval: model.archetype_approval.require_approval,
        allowAutoUpgrade: security?.allow_auto_upgrade ?? false,
        sessionLifetimeHours: security ? security.session_lifetime_secs / 3_600 : 0,
        idleTimeoutMinutes: security ? security.idle_timeout_secs / 60 : 0,
        auditGuaranteeDays: security && security.audit_retention_min_days > 0
            ? security.audit_retention_min_days : 365,
        preservedRules: rules.filter((rule) => !controlled(rule)),
        requireAttestedPlacement: model.placement.require_attested,
        requireMfa: security?.require_mfa ?? false,
        residencyRegion: security?.residency_region ?? null,
    };
};

const setMembership = <T extends string>(values: readonly T[], value: T, checked: boolean): readonly T[] =>
    checked ? [...new Set([...values, value])] : values.filter((candidate) => candidate !== value);

// PlacementPolicy uses an empty operator set as its open value: every
// operator is eligible until the organization narrows the axis. Present that
// meaning, not the serialized representation. Unchecking one operator from
// the open value materializes the other two as the explicit allow-list.
const setPlacementMembership = (
    values: readonly PlacementOperator[],
    value: PlacementOperator,
    checked: boolean,
): readonly PlacementOperator[] => {
    if (values.length === 0) {
        return checked ? [] : PLACEMENT_OPERATORS.filter((candidate) => candidate !== value);
    }
    const next = setMembership(values, value, checked);
    return next.length === PLACEMENT_OPERATORS.length ? [] : next;
};

function OrganizationPolicyEditor(props: {
    readonly page: AdministrationGaugeAppPage<"organization-policy">;
    readonly commands: readonly string[];
    readonly onSubmit: SubmitPageCommand;
}): JSX.Element {
    const initial = organizationPolicyDraft(props.page.model);
    const [baseline, setBaseline] = createSignal(initial);
    const [draft, setDraft] = createSignal(initial);
    createEffect(() => {
        props.page.resource_basis;
        const next = organizationPolicyDraft(props.page.model);
        setBaseline(next);
        setDraft(next);
    });
    const changed = createMemo(() => JSON.stringify(draft()) !== JSON.stringify(baseline()));
    const summary = createMemo(() => {
        const before = baseline();
        const after = draft();
        const changes: string[] = [];
        if (JSON.stringify(before.exportRoles) !== JSON.stringify(after.exportRoles)) changes.push(`Export roles: ${before.exportRoles.join(", ")} → ${after.exportRoles.join(", ") || "none"}`);
        if (JSON.stringify(before.runRoles) !== JSON.stringify(after.runRoles)) changes.push(`Run roles: ${before.runRoles.join(", ")} → ${after.runRoles.join(", ") || "none"}`);
        if (before.requireMatchingRegion !== after.requireMatchingRegion) changes.push(`Matching region: ${before.requireMatchingRegion ? "required" : "not required"} → ${after.requireMatchingRegion ? "required" : "not required"}`);
        if (JSON.stringify(before.placementOperators) !== JSON.stringify(after.placementOperators)) changes.push(`Eligible Project Hosts: ${before.placementOperators.join(", ") || "all"} → ${after.placementOperators.join(", ") || "all"}`);
        if (before.requirePlacementApproval !== after.requirePlacementApproval) changes.push(`New placements: ${before.requirePlacementApproval ? "approval required" : "admitted"} → ${after.requirePlacementApproval ? "approval required" : "admitted"}`);
        if (before.allowAutoUpgrade !== after.allowAutoUpgrade) changes.push(`Publisher upgrades: ${before.allowAutoUpgrade ? "may apply" : "stay pinned"} → ${after.allowAutoUpgrade ? "may apply" : "stay pinned"}`);
        if (before.sessionLifetimeHours !== after.sessionLifetimeHours) changes.push(`Session lifetime: ${before.sessionLifetimeHours || "unset"} → ${after.sessionLifetimeHours || "unset"} hours`);
        if (before.idleTimeoutMinutes !== after.idleTimeoutMinutes) changes.push(`Idle timeout: ${before.idleTimeoutMinutes || "unset"} → ${after.idleTimeoutMinutes || "unset"} minutes`);
        if (before.auditGuaranteeDays !== after.auditGuaranteeDays) changes.push(`History guarantee: ${before.auditGuaranteeDays} → ${after.auditGuaranteeDays} days`);
        return changes;
    });
    const payload = (): Readonly<Record<string, unknown>> => {
        const value = draft();
        const rules = [...value.preservedRules];
        for (const role of GOVERNED_ROLES) {
            if (!value.exportRoles.includes(role)) rules.push({ when: { ActorHasRole: role }, require: { DenyAction: "export" } });
            if (!value.runRoles.includes(role)) rules.push({ when: { ActorHasRole: role }, require: { DenyAction: "run" } });
        }
        if (value.requireMatchingRegion) rules.push({ when: "Always", require: "RequireResourceRegionMatchesActor" });
        return {
            resource: { rules },
            security: {
                require_mfa: value.requireMfa,
                session_lifetime_secs: Math.max(0, Math.round(value.sessionLifetimeHours * 3_600)),
                idle_timeout_secs: Math.max(0, Math.round(value.idleTimeoutMinutes * 60)),
                residency_region: value.residencyRegion,
                audit_retention_min_days: Math.max(1, Math.round(value.auditGuaranteeDays)),
                allow_auto_upgrade: value.allowAutoUpgrade,
            },
            placement: {
                require_attested: value.requireAttestedPlacement,
                allowed_operators: value.placementOperators,
            },
            archetype_approval: { require_approval: value.requirePlacementApproval },
        };
    };
    return <>
        <Notice tone="neutral">These settings add organization-wide restrictions after project access and resource consent. Changes are reviewed and applied as one policy revision.</Notice>
        <section class="gaugeapp-panel gaugeapp-policy-grid">
            <div class="gaugeapp-policy-group"><h2>Resource access &amp; export</h2><p>Organization policy can narrow a project grant; it never creates access.</p>
                <fieldset><legend>Roles allowed to export</legend><For each={GOVERNED_ROLES}>{(role) => <label><input type="checkbox" checked={draft().exportRoles.includes(role)} onChange={(event) => setDraft((value) => ({ ...value, exportRoles: setMembership(value.exportRoles, role, event.currentTarget.checked) }))} />{role}</label>}</For></fieldset>
                <fieldset><legend>Roles allowed to start Agent runs</legend><For each={GOVERNED_ROLES}>{(role) => <label><input type="checkbox" checked={draft().runRoles.includes(role)} onChange={(event) => setDraft((value) => ({ ...value, runRoles: setMembership(value.runRoles, role, event.currentTarget.checked) }))} />{role}</label>}</For></fieldset>
                <label class="gaugeapp-check"><input type="checkbox" checked={draft().requireMatchingRegion} onChange={(event) => setDraft((value) => ({ ...value, requireMatchingRegion: event.currentTarget.checked }))} />Require the resource and member to have matching regions</label>
            </div>
            <div class="gaugeapp-policy-group"><h2>Shared execution boundaries</h2><p>Eligible operators remain subject to every project and resource grant.</p>
                <fieldset><legend>Eligible Project Host operators</legend><For each={PLACEMENT_OPERATORS}>{(operator) => <label><input type="checkbox" checked={draft().placementOperators.length === 0 || draft().placementOperators.includes(operator)} onChange={(event) => setDraft((value) => ({ ...value, placementOperators: setPlacementMembership(value.placementOperators, operator, event.currentTarget.checked) }))} />{{ local: "Run owner", counterparty: "Counterparty", neutral: "Neutral provider" }[operator]}</label>}</For></fieldset>
            </div>
            <div class="gaugeapp-policy-group"><h2>Agent changes</h2>
                <label class="gaugeapp-check"><input type="checkbox" checked={draft().requirePlacementApproval} onChange={(event) => setDraft((value) => ({ ...value, requirePlacementApproval: event.currentTarget.checked }))} />Require approval for newly added Agents</label>
                <label class="gaugeapp-check"><input type="checkbox" checked={draft().allowAutoUpgrade} onChange={(event) => setDraft((value) => ({ ...value, allowAutoUpgrade: event.currentTarget.checked }))} />Allow publisher-requested upgrades to apply automatically</label>
            </div>
            <div class="gaugeapp-policy-group"><h2>Sessions &amp; history</h2>
                <div class="gaugeapp-policy-numbers"><label><span>Maximum session (hours)</span><input type="number" min="0" step="1" value={draft().sessionLifetimeHours} onInput={(event) => setDraft((value) => ({ ...value, sessionLifetimeHours: Number(event.currentTarget.value) || 0 }))} /></label><label><span>Idle timeout (minutes)</span><input type="number" min="0" step="1" value={draft().idleTimeoutMinutes} onInput={(event) => setDraft((value) => ({ ...value, idleTimeoutMinutes: Number(event.currentTarget.value) || 0 }))} /></label><label><span>Minimum history guarantee (days)</span><input type="number" min="1" step="1" value={draft().auditGuaranteeDays} onInput={(event) => setDraft((value) => ({ ...value, auditGuaranteeDays: Number(event.currentTarget.value) || 1 }))} /></label></div>
            </div>
        </section>
        <section class="gaugeapp-panel gaugeapp-change-summary" aria-live="polite">
            <div><h2>Policy changes</h2><Show when={changed()} fallback={<p>No unsaved changes.</p>}><ul><For each={summary()}>{(item) => <li>{item}</li>}</For></ul></Show></div>
            <div class="gaugeapp-actions"><button type="button" disabled={!changed()} onClick={() => setDraft(baseline())}>Discard</button><button type="button" class="primary" disabled={!changed() || !props.commands.includes("organization-policy.set")} onClick={() => void props.onSubmit("organization-policy.set", payload())}>Apply changes</button></div>
        </section>
    </>;
}

interface SoftwarePolicyDraft {
    readonly minimumVersion: string;
    readonly minimumProtocol: number;
    readonly allowedChannels: readonly string[];
    readonly graceUntil: string;
}

const softwarePolicyDraft = (model: SoftwarePolicyPageV1): SoftwarePolicyDraft => {
    const millis = model.grace_until_unix_ms ?? 0;
    const date = millis > 0 ? new Date(millis) : null;
    return {
        minimumVersion: model.minimum_version,
        minimumProtocol: model.minimum_protocol,
        allowedChannels: model.allowed_channels,
        graceUntil: date && !Number.isNaN(date.valueOf()) ? date.toISOString().slice(0, 16) : "",
    };
};

function SoftwarePolicyEditor(props: {
    readonly page: AdministrationGaugeAppPage<"software-policy">;
    readonly commands: readonly string[];
    readonly onSubmit: SubmitPageCommand;
}): JSX.Element {
    const initial = softwarePolicyDraft(props.page.model);
    const [baseline, setBaseline] = createSignal(initial);
    const [draft, setDraft] = createSignal(initial);
    createEffect(() => {
        props.page.resource_basis;
        const next = softwarePolicyDraft(props.page.model);
        setBaseline(next);
        setDraft(next);
    });
    const changed = createMemo(() => JSON.stringify(draft()) !== JSON.stringify(baseline()));
    const summary = createMemo(() => {
        const before = baseline();
        const after = draft();
        return [
            before.minimumVersion !== after.minimumVersion ? `Minimum build: ${before.minimumVersion || "none"} → ${after.minimumVersion || "none"}` : "",
            before.minimumProtocol !== after.minimumProtocol ? `Minimum protocol: ${before.minimumProtocol || "none"} → ${after.minimumProtocol || "none"}` : "",
            JSON.stringify(before.allowedChannels) !== JSON.stringify(after.allowedChannels) ? `Channels: ${before.allowedChannels.join(", ") || "all"} → ${after.allowedChannels.join(", ") || "all"}` : "",
            before.graceUntil !== after.graceUntil ? `Grace deadline: ${before.graceUntil || "immediate"} → ${after.graceUntil || "immediate"}` : "",
        ].filter(Boolean);
    });
    const submit = () => props.onSubmit("software-policy.set", {
        minimum_version: draft().minimumVersion.trim(),
        minimum_protocol: Math.max(0, Math.round(draft().minimumProtocol)),
        allowed_channels: draft().allowedChannels,
        grace_until_unix_ms: draft().graceUntil ? new Date(draft().graceUntil).valueOf() : null,
    });
    return <>
        <section class="gaugeapp-panel gaugeapp-policy-group">
            <h2>Client admission</h2><p>Reported build information is compatibility evidence, not device attestation.</p>
            <div class="gaugeapp-policy-numbers"><label><span>Minimum GaugeDesk build</span><input placeholder="0.4.5" value={draft().minimumVersion} onInput={(event) => setDraft((value) => ({ ...value, minimumVersion: event.currentTarget.value }))} /></label><label><span>Minimum protocol</span><input type="number" min="0" step="1" value={draft().minimumProtocol} onInput={(event) => setDraft((value) => ({ ...value, minimumProtocol: Number(event.currentTarget.value) || 0 }))} /></label><label><span>Grace deadline</span><input type="datetime-local" value={draft().graceUntil} onInput={(event) => setDraft((value) => ({ ...value, graceUntil: event.currentTarget.value }))} /></label></div>
            <fieldset><legend>Permitted release channels</legend><For each={["stable", "beta", "dev"]}>{(channel) => <label><input type="checkbox" checked={draft().allowedChannels.includes(channel)} onChange={(event) => setDraft((value) => ({ ...value, allowedChannels: setMembership(value.allowedChannels, channel, event.currentTarget.checked) }))} />{channel}</label>}</For></fieldset>
        </section>
        <section class="gaugeapp-panel gaugeapp-policy-group">
            <h2>Sessions this policy reaches</h2>
            <Show
                when={props.page.model.affected_sessions.length}
                fallback={<p>No signed-in session is warned or blocked by the policy in force.</p>}
            >
                {/* The server's own verdict against the policy in force, not a
                    count this page worked out. A draft above changes nothing
                    here until it is applied, which is what keeps the list an
                    answer rather than a guess. */}
                <p>{props.page.model.affected_sessions.length} session{props.page.model.affected_sessions.length === 1 ? " is" : "s are"} warned or blocked by the policy in force. Applying a stricter build or protocol can only widen this.</p>
                <ul class="gaugeapp-policy-affected">
                    <For each={props.page.model.affected_sessions}>{(session) => <li>
                        <strong>{session.person.label}</strong>
                        <span> · {session.client_label}{session.client.version ? ` ${session.client.version}` : ""}{session.client.channel ? ` (${session.client.channel})` : ""}</span>
                        <span classList={{ "gaugeapp-policy-blocked": session.software_status === "blocked" }}> · {session.software_status === "blocked" ? "Blocked" : "Warned"}</span>
                        <Show when={session.current}><span> · this session</span></Show>
                        <p>{session.software_reason}</p>
                    </li>}</For>
                </ul>
            </Show>
        </section>
        <section class="gaugeapp-panel gaugeapp-change-summary" aria-live="polite">
            <div><h2>Software policy changes</h2><Show when={changed()} fallback={<p>No unsaved changes.</p>}><ul><For each={summary()}>{(item) => <li>{item}</li>}</For></ul></Show></div>
            <div class="gaugeapp-actions"><button type="button" disabled={!changed()} onClick={() => setDraft(baseline())}>Discard</button><button type="button" class="primary" disabled={!changed() || !props.commands.includes("software-policy.set")} onClick={() => void submit()}>Apply changes</button></div>
        </section>
    </>;
}

function PeoplePage(props: {
    readonly page: AdministrationGaugeAppPage<"people">;
    readonly commands: readonly string[];
    readonly onSubmit: SubmitPageCommand;
}): JSX.Element {
    const model = () => props.page.model;
    const members = () => model().members;
    const invitations = () => model().invitations;
    const projects = () => model().projects;
    const grants = () => model().grants;
    const sessions = () => model().sessions;
    const [adding, setAdding] = createSignal(false);
    const [invitationEmails, setInvitationEmails] = createSignal("");
    const [role, setRole] = createSignal("member");
    const [selectedId, setSelectedId] = createSignal("");
    const [roleDrafts, setRoleDrafts] = createSignal<Record<string, string>>({});
    const [projectDraft, setProjectDraft] = createSignal("");
    const [selectedSessionId, setSelectedSessionId] = createSignal("");
    const selected = createMemo(() => members().find((member) => member.id === selectedId()) ?? null);
    const statusMembers = (status: string) => members().filter((member) => member.status === status);
    const memberName = (member: OrganizationMember) => member.email || member.authority || "Unknown account";
    const roleValue = (member: OrganizationMember) => roleDrafts()[member.id] ?? member.role;
    const updateRole = (member: OrganizationMember) => void props.onSubmit("people.role.change", {
        id: member.id,
        role: roleValue(member),
    });
    const parsedInvitationEmails = () => invitationEmails()
        .split(/[\n,;]+/)
        .map((value) => value.trim())
        .filter(Boolean);
    const submitInvitation = async () => {
        await props.onSubmit("people.invitation.create", {
            emails: parsedInvitationEmails(),
            role: role(),
        });
        setInvitationEmails("");
        setRole("member");
        setAdding(false);
    };
    const projectName = (id: string) => {
        const project = projects().find((candidate) => candidate.id === id);
        return project ? project.name : id;
    };
    const selectedGrants = createMemo(() => {
        const member = selected();
        if (!member) return [];
        return grants().filter((grant) => grant.authority === member.authority);
    });
    const selectedSessions = createMemo(() => {
        const member = selected();
        if (!member) return [];
        return sessions().filter((session) => session.person.authority === member.authority);
    });
    const selectedSession = createMemo(() => selectedSessions().find((session) => session.id === selectedSessionId()) ?? null);
    createEffect(() => {
        selectedId();
        setSelectedSessionId("");
    });
    const availableProjects = createMemo(() => {
        const granted = new Set(selectedGrants().map((grant) => grant.project_id));
        return projects().filter((project) => {
            return !project.is_personal && !granted.has(project.id);
        });
    });
    const memberRows = (values: readonly OrganizationMember[], empty: string) => <Show when={values.length > 0} fallback={<p class="gaugeapp-empty">{empty}</p>}>
        <div class="gaugeapp-people-list">
            <For each={values}>{(member) => {
                const id = member.id;
                const scim = member.managed_by_scim;
                return <div class="gaugeapp-person-row">
                    <button type="button" class="gaugeapp-person-identity" onClick={() => setSelectedId(id)}>
                        <strong>{memberName(member)}</strong>
                        <Show when={member.authority && member.authority !== memberName(member)}>
                            <span>{member.authority}</span>
                        </Show>
                    </button>
                    <Show when={!scim && member.status !== "deprovisioned" && member.role !== "owner"} fallback={<span class="gaugeapp-person-role">{scim ? "Identity provider" : member.role}</span>}>
                        <div class="gaugeapp-person-role-edit">
                            <select value={roleValue(member)} onChange={(event) => setRoleDrafts((drafts) => ({ ...drafts, [id]: event.currentTarget.value }))}>
                                <For each={MEMBER_ROLES}>{(candidate) => <option value={candidate}>{candidate}</option>}</For>
                            </select>
                            <button type="button" disabled={roleValue(member) === member.role || !props.commands.includes("people.role.change")} onClick={() => updateRole(member)}>Save</button>
                        </div>
                    </Show>
                    <div class="gaugeapp-row-actions">
                        <Show when={member.status === "invited"}><CommandButton command="people.invitation.cancel" commands={props.commands} label="Cancel" danger payload={{ id }} onSubmit={props.onSubmit} /></Show>
                        <Show when={member.status === "active" && !scim && member.role !== "owner"}><CommandButton command="people.member.deactivate" commands={props.commands} label="Deactivate" danger payload={{ id }} onSubmit={props.onSubmit} /></Show>
                        <Show when={member.status === "deprovisioned" && !scim}><CommandButton command="people.member.reactivate" commands={props.commands} label="Reactivate" payload={{ id }} onSubmit={props.onSubmit} /></Show>
                        <button type="button" onClick={() => setSelectedId(id)}>View</button>
                    </div>
                </div>;
            }}</For>
        </div>
    </Show>;
    return <>
        <Notice tone="neutral">{props.page.model.members.some((member: { readonly managed_by_scim: boolean }) => member.managed_by_scim)
            ? "People managed by your identity provider are configured in Enterprise Identity."
            : "Direct invitations and fixed roles are included. Identity-provider-managed membership requires Enterprise controls."}</Notice>
        <section class="gaugeapp-panel gaugeapp-section-stack">
            <div class="gaugeapp-section-head"><div><h2>People</h2><p>{statusMembers("active").length} active · {statusMembers("invited").length + invitations().filter((invitation) => ["pending", "expired"].includes(text(invitation.status, ""))).length} invited</p></div><Show when={props.commands.includes("people.invitation.create")}><button type="button" onClick={() => setAdding((value) => !value)}>{adding() ? "Cancel" : "Invite"}</button></Show></div>
            <Show when={adding()}><div class="gaugeapp-people-invite">
                <label class="wide"><span>Email addresses</span><textarea rows="3" value={invitationEmails()} onInput={(event) => setInvitationEmails(event.currentTarget.value)} placeholder={"name@company.com\nanother@company.com"} /></label>
                <label><span>Role</span><select value={role()} onChange={(event) => setRole(event.currentTarget.value)}><For each={MEMBER_ROLES}>{(candidate) => <option value={candidate}>{candidate}</option>}</For></select></label>
                <button type="button" disabled={parsedInvitationEmails().length === 0} onClick={() => void submitInvitation()}>Create invitations</button>
                <small>Invitation links are shown once after approval. Send each link to its addressed recipient.</small>
            </div></Show>
            {memberRows(statusMembers("active"), "No active members.")}
            <Show when={invitations().some((invitation) => ["pending", "expired"].includes(text(invitation.status, "")))}>
                <div class="gaugeapp-subsection-label">Invited</div>
                <div class="gaugeapp-people-list"><For each={invitations().filter((invitation) => ["pending", "expired"].includes(text(invitation.status, "")))}>{(invitation) => {
                    const id = invitation.id;
                    const expired = invitation.status === "expired";
                    return <div class="gaugeapp-person-row">
                        <div class="gaugeapp-person-identity"><strong>{invitation.email || "Invitation"}</strong><span>{expired ? "Link expired" : `Expires ${new Date(invitation.expires_at_ms).toLocaleDateString()}`}</span></div>
                        <span class="gaugeapp-person-role">{invitation.role}</span>
                        <div class="gaugeapp-row-actions">
                            <CommandButton command="people.invitation.resend" commands={props.commands} label={expired ? "Renew link" : "Resend"} payload={{ id }} onSubmit={props.onSubmit} />
                            <CommandButton command="people.invitation.cancel" commands={props.commands} label="Cancel" danger payload={{ id }} onSubmit={props.onSubmit} />
                        </div>
                    </div>;
                }}</For></div>
            </Show>
            <Show when={statusMembers("invited").length > 0}><div class="gaugeapp-subsection-label">Invited accounts</div>{memberRows(statusMembers("invited"), "")}</Show>
            <Show when={statusMembers("deprovisioned").length > 0}><div class="gaugeapp-subsection-label">Deprovisioned</div>{memberRows(statusMembers("deprovisioned"), "")}</Show>
        </section>

        <Show when={selected()}>{(member) => {
            const memberAuthority = () => member().authority;
            return <section class="gaugeapp-panel gaugeapp-member-detail">
                <header><div><span class="gaugeapp-eyebrow">Member</span><h2>{memberName(member())}</h2></div><button type="button" onClick={() => setSelectedId("")}>Close</button></header>
                <div class="gaugeapp-detail-facts"><Fact label="Role" value={member().role} /><Fact label="Status" value={member().status} /><Fact label="Project grants" value={String(selectedGrants().length)} /><Fact label="Active sessions" value={String(selectedSessions().length)} /></div>
                <div class="gaugeapp-member-projects">
                    <div class="gaugeapp-section-head"><div><h2>Explicit project access</h2><p>Owners and admins already reach all organization projects.</p></div></div>
                    <For each={selectedGrants()}>{(grant) => <div class="gaugeapp-summary-row"><div><strong>{projectName(grant.project_id)}</strong><span>{grant.project_id}</span></div><CommandButton command="project-access.revoke" commands={props.commands} label="Revoke" danger payload={{ authority: memberAuthority(), project_id: grant.project_id }} onSubmit={props.onSubmit} /></div>}</For>
                    <Show when={member().status === "active" && !["owner", "admin"].includes(member().role) && availableProjects().length > 0}>
                        <div class="gaugeapp-inline-form"><label><span>Add project access</span><select value={projectDraft()} onChange={(event) => setProjectDraft(event.currentTarget.value)}><option value="">Choose project</option><For each={availableProjects()}>{(project) => <option value={project.id}>{project.name || project.id}</option>}</For></select></label><CommandButton command="project-access.grant" commands={props.commands} label="Grant" disabled={!projectDraft()} payload={{ authority: memberAuthority(), project_id: projectDraft() }} onSubmit={props.onSubmit} /></div>
                    </Show>
                </div>
                <div class="gaugeapp-member-projects">
                    <div class="gaugeapp-section-head"><div><h2>Organization sessions</h2><p>Current client access for this member; Trusted Devices are managed separately.</p></div></div>
                    <Show when={selectedSessions().length > 0} fallback={<p class="gaugeapp-empty">No active organization sessions.</p>}>
                        <div class="gaugeapp-session-list">
                            <For each={selectedSessions()}>{(session) => <div class="gaugeapp-session-row">
                                <button type="button" class="gaugeapp-session-identity" onClick={() => setSelectedSessionId(session.id)}>
                                    <strong>{session.client_label || "GaugeDesk client"}{session.current ? " · this session" : ""}</strong>
                                    <span>{sessionBuild(session)}</span>
                                </button>
                                <div class="gaugeapp-session-posture"><strong>{session.state === "recovery_only" ? "Recovery only" : "Active"}</strong><span>{sessionFreshness(session.idle_ms)}</span></div>
                                <button type="button" onClick={() => setSelectedSessionId(session.id)}>View</button>
                            </div>}</For>
                        </div>
                    </Show>
                    <Show when={selectedSession()}>{(session) => {
                        const client = () => session().client;
                        return <div class="gaugeapp-session-inline-detail">
                            <div class="gaugeapp-detail-facts">
                                <Fact label="Access" value={session().state === "recovery_only" ? "Recovery only" : "Active"} note={session().software_reason || "No software-policy restriction"} />
                                <Fact label="Last seen" value={sessionFreshness(session().idle_ms)} note={sessionTimestamp(session().last_seen_unix_ms)} />
                                <Fact label="Build" value={client().version ?? "Not reported"} />
                                <Fact label="Protocol" value={client().protocol === null ? "Not reported" : String(client().protocol)} />
                            </div>
                            <button type="button" onClick={() => setSelectedSessionId("")}>Close session detail</button>
                        </div>;
                    }}</Show>
                </div>
            </section>;
        }}</Show>
    </>;
}

const sessionFreshness = (value: number): string => {
    if (value < 60_000) return "Seen just now";
    const minutes = Math.floor(value / 60_000);
    if (minutes < 60) return `Seen ${minutes}m ago`;
    const hours = Math.floor(minutes / 60);
    if (hours < 24) return `Seen ${hours}h ago`;
    return `Seen ${Math.floor(hours / 24)}d ago`;
};

const sessionTimestamp = (value: number): string => {
    if (value <= 0) return "Unknown";
    const date = new Date(value);
    return Number.isNaN(date.valueOf()) ? "Unknown" : date.toLocaleString();
};

const sessionBuild = (session: OrganizationSession): string => {
    const client = session.client;
    const parts = [
        client.version ? `build ${client.version}` : "build not reported",
        client.protocol !== null ? `protocol ${client.protocol}` : "protocol not reported",
    ];
    return parts.join(" · ");
};

function SessionsPage(props: {
    readonly page: AdministrationGaugeAppPage<"sessions">;
    readonly commands: readonly string[];
    readonly onSubmit: SubmitPageCommand;
}): JSX.Element {
    const sessions = () => props.page.model.sessions;
    const [selectedId, setSelectedId] = createSignal("");
    const selected = createMemo(() => sessions().find((session) => session.id === selectedId()) ?? null);
    const state = (session: OrganizationSession) => session.state === "recovery_only" ? "Recovery only" : "Active";
    const recoveryCount = () => sessions().filter((session) => session.state === "recovery_only").length;

    return <>
        <Notice tone="neutral">These are active GaugeDesk sessions. Commercial clients are in Commercial Operations.</Notice>
        <section class="gaugeapp-panel gaugeapp-section-stack">
            <div class="gaugeapp-section-head"><div><h2>Organization sessions</h2><p>{sessions().length} admitted · {recoveryCount()} recovery only</p></div></div>
            <Show when={sessions().length > 0} fallback={<p class="gaugeapp-empty">No admitted organization sessions.</p>}>
                <div class="gaugeapp-session-list">
                    <For each={sessions()}>{(session) => {
                        const id = session.id;
                        return <div class="gaugeapp-session-row">
                            <button type="button" class="gaugeapp-session-identity" onClick={() => setSelectedId(id)}>
                                <strong>{session.person.label || session.person.authority || "Unknown person"}{session.current ? " · this session" : ""}</strong>
                                <span>{session.client_label || "GaugeDesk client"} · {sessionBuild(session)}</span>
                            </button>
                            <div class="gaugeapp-session-posture"><strong>{state(session)}</strong><span>{sessionFreshness(session.idle_ms)}</span></div>
                            <div class="gaugeapp-row-actions">
                                <button type="button" onClick={() => setSelectedId(id)}>View</button>
                            </div>
                        </div>;
                    }}</For>
                </div>
            </Show>
        </section>
        <Show when={selected()}>{(session) => {
            const client = () => session().client;
            return <section class="gaugeapp-panel gaugeapp-member-detail">
                <header><div><span class="gaugeapp-eyebrow">Organization session</span><h2>{session().client_label || "GaugeDesk client"}</h2></div><button type="button" onClick={() => setSelectedId("")}>Close</button></header>
                <div class="gaugeapp-detail-facts">
                    <Fact label="Person" value={session().person.label || session().person.authority} />
                    <Fact label="Access" value={state(session())} note={session().software_reason || "No software-policy evidence"} />
                    <Fact label="Last seen" value={sessionFreshness(session().idle_ms)} note={sessionTimestamp(session().last_seen_unix_ms)} />
                    <Fact label="Client" value={session().client_label || "GaugeDesk client"} note={client().channel ?? "Channel not reported"} />
                    <Fact label="Build" value={client().version ?? "Not reported"} />
                    <Fact label="Protocol" value={client().protocol === null ? "Not reported" : String(client().protocol)} />
                </div>
                <div class="gaugeapp-session-detail-action"><p>Revoking ends this client's access to this organization. It does not remove the person's Trusted Device or affect other organizations.</p><CommandButton command="organization-session.revoke" commands={props.commands} label="Revoke session" danger payload={{ id: session().id }} onSubmit={props.onSubmit} /></div>
            </section>;
        }}</Show>
    </>;
}

interface OrganizationDomainChallenge {
    readonly domain: string;
    readonly record_name: string;
    readonly record_type: "TXT";
    readonly value: string;
}

function OrganizationPage(props: {
    readonly page: AdministrationGaugeAppPage<"organization">;
    readonly session: GaugeAppSession;
    readonly commands: readonly string[];
    readonly onSubmit: SubmitPageCommand;
    readonly api: EnterpriseControlPlane;
}): JSX.Element {
    return <Show when={props.page.model} fallback={<section class="gaugeapp-panel"><p class="gaugeapp-empty">Organization identity has not been configured.</p></section>}>
        {(model) => <OrganizationPageReady {...props} model={model()} />}
    </Show>;
}

function OrganizationPageReady(props: {
    readonly page: AdministrationGaugeAppPage<"organization">;
    readonly model: Exclude<OrganizationPageV1, null>;
    readonly session: GaugeAppSession;
    readonly commands: readonly string[];
    readonly onSubmit: SubmitPageCommand;
    readonly api: EnterpriseControlPlane;
}): JSX.Element {
    const model = () => props.model;
    const [editingName, setEditingName] = createSignal(false);
    const [displayName, setDisplayName] = createSignal(model().display_name);
    const [transferringOwnership, setTransferringOwnership] = createSignal(false);
    const [nextOwnerId, setNextOwnerId] = createSignal("");
    const [deletingOrganization, setDeletingOrganization] = createSignal(false);
    const [deleteConfirmation, setDeleteConfirmation] = createSignal("");
    const [addingDomain, setAddingDomain] = createSignal(false);
    const [domain, setDomain] = createSignal("");
    const [challenge, setChallenge] = createSignal<OrganizationDomainChallenge | null>(null);
    const [challengeError, setChallengeError] = createSignal("");
    const [loadingChallenge, setLoadingChallenge] = createSignal(false);
    createEffect(() => {
        props.page.resource_basis;
        setDisplayName(model().display_name);
        setNextOwnerId("");
        setDeletingOrganization(false);
        setDeleteConfirmation("");
    });
    const inspectDomain = async (candidate: string) => {
        setChallengeError("");
        setLoadingChallenge(true);
        try {
            const value = await props.api.administrationDomainChallenge(props.session, candidate);
            setAddingDomain(true);
            setDomain(value.domain);
            setChallenge(value);
        } catch (error) {
            setChallengeError(error instanceof Error ? error.message : String(error));
        } finally {
            setLoadingChallenge(false);
        }
    };
    const closeDomain = () => {
        setDomain("");
        setAddingDomain(false);
        setChallenge(null);
        setChallengeError("");
    };
    return <>
        <section class="gaugeapp-panel gaugeapp-section-stack">
            <div class="gaugeapp-section-head">
                <div><h2>Organization identity</h2><p>The name shown across GaugeDesk and the authority that owns this organization.</p></div>
                <div class="gaugeapp-row-actions">
                    <Show when={!editingName() && props.commands.includes("organization.display-name.set")}>
                        <button type="button" onClick={() => setEditingName(true)}>Edit name</button>
                    </Show>
                    <Show when={props.commands.includes("organization.ownership.transfer")}>
                        <button
                            type="button"
                            disabled={model().ownership_candidates.length === 0}
                            title={model().ownership_candidates.length === 0 ? "Add another active member before transferring ownership" : undefined}
                            onClick={() => setTransferringOwnership((value) => !value)}
                        >Transfer ownership</button>
                    </Show>
                </div>
            </div>
            <Show when={editingName()} fallback={
                <div class="gaugeapp-identity-summary">
                    <Fact label="Display name" value={model().display_name || "Organization not configured"} />
                    <Fact label="Type" value={model().kind} />
                    <Fact
                        label="Owner"
                        value={model().owner?.label ?? "Owner unavailable"}
                        note={distinctNote(
                            model().owner?.label,
                            model().owner?.email || model().owner?.authority,
                        )}
                    />
                </div>
            }>
                <form class="gaugeapp-inline-form" onSubmit={(event) => {
                    event.preventDefault();
                    void props.onSubmit("organization.display-name.set", { display_name: displayName() }).then(() => setEditingName(false));
                }}>
                    <label><span>Display name</span><input required maxLength={120} value={displayName()} onInput={(event) => setDisplayName(event.currentTarget.value)} /></label>
                    <div class="gaugeapp-actions"><button type="button" onClick={() => { setDisplayName(model().display_name); setEditingName(false); }}>Cancel</button><button type="submit" class="primary" disabled={!displayName().trim() || displayName().trim() === model().display_name}>Save</button></div>
                </form>
            </Show>
            <Show when={transferringOwnership()}>
                <form class="gaugeapp-inline-form" onSubmit={(event) => {
                    event.preventDefault();
                    void props.onSubmit("organization.ownership.transfer", { id: nextOwnerId() })
                        .then(() => setTransferringOwnership(false));
                }}>
                    <label><span>New owner</span><select required value={nextOwnerId()} onChange={(event) => setNextOwnerId(event.currentTarget.value)}><option value="">Choose an active member</option><For each={model().ownership_candidates}>{(candidate) => <option value={candidate.id}>{candidate.label} · {candidate.role}</option>}</For></select></label>
                    <p>The new owner receives organization lifecycle authority. Your role becomes admin.</p>
                    <div class="gaugeapp-actions"><button type="button" onClick={() => { setNextOwnerId(""); setTransferringOwnership(false); }}>Cancel</button><button type="submit" class="primary" disabled={!nextOwnerId()}>Prepare transfer</button></div>
                </form>
            </Show>
        </section>

        <section class="gaugeapp-panel gaugeapp-section-stack">
            <div class="gaugeapp-section-head">
                <div><h2>Domains</h2><p>A verified domain may admit corporate sign-in when Enterprise Identity is configured. A domain admits nobody until its DNS proof is published and verified.</p></div>
                <Show when={props.commands.includes("organization.domain.add") && !addingDomain()}>
                    <button type="button" onClick={() => { setAddingDomain(true); setDomain(""); setChallengeError(""); }}>Add domain</button>
                </Show>
            </div>
            <Show when={model().domains.length > 0} fallback={<p class="gaugeapp-empty">No domains have been added.</p>}>
                <div class="gaugeapp-domain-list">
                    <For each={model().domains}>{(entry) => <div class="gaugeapp-domain-row" data-status={entry.status}>
                        <div><strong>{entry.domain}</strong><span>{entry.status === "pending" ? "awaiting DNS proof" : "verified"}</span></div>
                        <div class="gaugeapp-row-actions">
                            <Show when={entry.status === "pending"}>
                                <CommandButton command="organization.domain.verify" commands={props.commands} label="Verify DNS" payload={{ domain: entry.domain }} onSubmit={props.onSubmit} />
                            </Show>
                            <button type="button" disabled={loadingChallenge()} onClick={() => void inspectDomain(entry.domain)}>Inspect</button>
                            <CommandButton command="organization.domain.remove" commands={props.commands} label="Remove" danger payload={{ domain: entry.domain }} onSubmit={props.onSubmit} />
                        </div>
                        {/* The claim is server-held, so the record to publish is
                            part of the page rather than something the
                            administrator has to reopen a dialog to see again. */}
                        <Show when={entry.challenge}>{(record) => <dl class="gaugeapp-domain-proof">
                            <div><dt>Name</dt><dd><code>{record().record_name}</code></dd></div>
                            <div><dt>Type</dt><dd><code>{record().record_type}</code></dd></div>
                            <div><dt>Value</dt><dd><code>{record().value}</code></dd></div>
                        </dl>}</Show>
                    </div>}</For>
                </div>
            </Show>
            <Show when={props.commands.includes("organization.domain.add") && addingDomain() && !challenge()}>
                <form class="gaugeapp-inline-form" onSubmit={(event) => {
                    event.preventDefault();
                    void props.onSubmit("organization.domain.add", { domain: domain().trim() })
                        .then(() => closeDomain());
                }}>
                    <label><span>Domain to add</span><input type="text" inputMode="url" placeholder="example.com" required value={domain()} onInput={(event) => setDomain(event.currentTarget.value)} /></label>
                    <p>Adding records the claim and shows the TXT record to publish. It grants nothing on its own — verification is a separate reviewed step.</p>
                    <div class="gaugeapp-actions"><button type="button" onClick={closeDomain}>Cancel</button><button type="submit" class="primary" disabled={!domain().trim()}>Add domain</button></div>
                </form>
            </Show>
            <Show when={challengeError()}>{(message) => <p class="gaugeapp-unavailable" role="alert">{message()}</p>}</Show>
            <Show when={challenge()}>{(record) => <div class="gaugeapp-domain-challenge">
                <header><div><span class="gaugeapp-eyebrow">DNS verification</span><strong>{record().domain}</strong></div><button type="button" onClick={closeDomain}>Close</button></header>
                <p>Add this TXT record at your DNS provider. After it is visible publicly, ask GaugeDesk to verify it.</p>
                <dl><div><dt>Name</dt><dd><code>{record().record_name}</code></dd></div><div><dt>Value</dt><dd><code>{record().value}</code></dd></div></dl>
                <div class="gaugeapp-actions"><button type="button" onClick={() => void navigator.clipboard.writeText(record().value)}>Copy value</button><CommandButton command="organization.domain.verify" commands={props.commands} label="Verify DNS" payload={{ domain: record().domain }} onSubmit={props.onSubmit} /></div>
            </div>}</Show>
        </section>
        <Show when={props.commands.includes("organization.delete")}>
            <section class="gaugeapp-panel gaugeapp-section-stack gaugeapp-danger-zone">
                <div class="gaugeapp-section-head">
                    <div><h2>Delete organization</h2><p>First remove other members, end organization services and plans, close active engagements, and erase shared model connections.</p></div>
                    <Show when={!deletingOrganization()}>
                        <button type="button" class="danger" onClick={() => setDeletingOrganization(true)}>Delete</button>
                    </Show>
                </div>
                <Show when={deletingOrganization()}>
                    <form class="gaugeapp-inline-form" onSubmit={(event) => {
                        event.preventDefault();
                        void props.onSubmit("organization.delete", { confirmation: deleteConfirmation() });
                    }}>
                        <p>This removes <strong>{model().display_name}</strong>, ends access, and destroys its GaugeDesk content key. Required billing and audit evidence may be retained. This cannot be undone.</p>
                        <label><span>Enter {model().display_name} to confirm</span><input required value={deleteConfirmation()} onInput={(event) => setDeleteConfirmation(event.currentTarget.value)} /></label>
                        <div class="gaugeapp-actions"><button type="button" onClick={() => { setDeleteConfirmation(""); setDeletingOrganization(false); }}>Cancel</button><button type="submit" class="danger" disabled={deleteConfirmation().trim() !== model().display_name.trim()}>Continue</button></div>
                    </form>
                </Show>
            </section>
        </Show>
    </>;
}

function AdministrationPage(props: { page: GaugeAppPageModel; session: GaugeAppSession; commands: readonly string[]; onSubmit: SubmitPageCommand; api: EnterpriseControlPlane; onRefresh: () => Promise<void>; onOpenProject?: (project: { readonly id: string; readonly name: string }) => void; onOpenGaugeApp?: (app: GaugeAppKind, page: string) => void }): JSX.Element {
    const typedPage = createMemo(() => parseAdministrationGaugeAppPage(props.page));
    const page = () => typedPage().id;
    const organization = () => { const value = typedPage(); return value.id === "organization" ? value : undefined; };
    const plans = () => { const value = typedPage(); return value.id === "plans-services" ? value : undefined; };
    const billing = () => { const value = typedPage(); return value.id === "billing" ? value : undefined; };
    const people = () => { const value = typedPage(); return value.id === "people" ? value : undefined; };
    const sessions = () => { const value = typedPage(); return value.id === "sessions" ? value : undefined; };
    const identity = () => { const value = typedPage(); return value.id === "enterprise-identity" ? value : undefined; };
    const projects = () => { const value = typedPage(); return value.id === "projects" ? value : undefined; };
    const providers = () => { const value = typedPage(); return value.id === "model-providers" ? value : undefined; };
    const policy = () => { const value = typedPage(); return value.id === "organization-policy" ? value : undefined; };
    const hosts = () => { const value = typedPage(); return value.id === "project-hosts" ? value : undefined; };
    const backups = () => { const value = typedPage(); return value.id === "backups" ? value : undefined; };
    const software = () => { const value = typedPage(); return value.id === "software-policy" ? value : undefined; };
    return <article class="gaugeapp-page" data-gaugeapp-page={page()}>
        <header class="gaugeapp-page-head">
            <div>
                <span class="gaugeapp-eyebrow">{appLabel("administration", props.session.scope)}</span>
                <h1>{PAGE_LABELS[page()] ?? page()}</h1>
            </div>
            <Show when={pageFreshnessCaveat(typedPage().freshness)}>{(caveat) => <span class="gaugeapp-freshness">{caveat()}</span>}</Show>
        </header>

        <Show when={organization()}>{(value) => <OrganizationPage page={value()} session={props.session} commands={props.commands} onSubmit={props.onSubmit} api={props.api} />}</Show>

        <Show when={plans()}>{(value) => <PlansServicesPage model={value().model} commands={props.commands} onSubmit={props.onSubmit} onOpenGaugeApp={props.onOpenGaugeApp} />}</Show>

        <Show when={billing()}>{(value) => <BillingPage model={value().model} commands={props.commands} onSubmit={props.onSubmit} />}</Show>

        <Show when={people()}>{(value) => <PeoplePage page={value()} commands={props.commands} onSubmit={props.onSubmit} />}</Show>

        <Show when={sessions()}>{(value) => <SessionsPage page={value()} commands={props.commands} onSubmit={props.onSubmit} />}</Show>

        <Show when={identity()}>{(value) => <EnterpriseIdentityPage model={value().model} resourceBasis={value().resource_basis} session={props.session} commands={props.commands} onSubmit={props.onSubmit} api={props.api} onRefresh={props.onRefresh} onOpenGaugeApp={props.onOpenGaugeApp} />}</Show>

        <Show when={projects()}>{(value) => <ProjectsPage
            page={value()}
            commands={props.commands}
            onSubmit={props.onSubmit}
            onOpenProject={props.onOpenProject}
        />}</Show>

        <Show when={providers()}>{(value) => <ModelProvidersPage {...props} page={value()} />}</Show>

        <Show when={policy()}>{(value) => <OrganizationPolicyEditor page={value()} commands={props.commands} onSubmit={props.onSubmit} />}</Show>

        <Show when={hosts()}>{(value) => <ProjectHostsPage page={value()} commands={props.commands} onSubmit={props.onSubmit} onOpenProject={props.onOpenProject} />}</Show>

        <Show when={backups()}>{(value) => <BackupsPage model={value().model} session={props.session} commands={props.commands} onSubmit={props.onSubmit} api={props.api} />}</Show>

        <Show when={software()}>{(value) => <SoftwarePolicyEditor page={value()} commands={props.commands} onSubmit={props.onSubmit} />}</Show>
    </article>;
}

function ProjectsPage(props: {
    readonly page: AdministrationGaugeAppPage<"projects">;
    readonly commands: readonly string[];
    readonly onSubmit: SubmitPageCommand;
    readonly onOpenProject?: (project: { readonly id: string; readonly name: string }) => void;
}): JSX.Element {
    const model = () => props.page.model;
    const [creating, setCreating] = createSignal(false);
    const [name, setName] = createSignal("");
    const [selectedId, setSelectedId] = createSignal("");
    const selected = () => model().projects.find((project) => project.id === selectedId());
    createEffect(() => {
        props.page.resource_basis;
        setCreating(false);
        setName("");
        if (!model().projects.some((project) => project.id === selectedId())) setSelectedId("");
    });
    const submit = async () => {
        const value = name().trim();
        if (!value) return;
        await props.onSubmit("project.create", { name: value });
    };
    return <section class="gaugeapp-panel gaugeapp-section-stack">
        <Notice tone="neutral">Administration discovers and inspects the projects this organization governs. Every change still resolves to the project’s authoritative Home; this page does not become a second project authority.</Notice>
        <div class="gaugeapp-section-head">
            <div>
                <h2>Projects <small>{model().projects.length}</small></h2>
                <Show when={model().home} fallback={<p>Project Host unavailable</p>}>
                    {(home) => <p>{home().label} · {home().state}</p>}
                </Show>
            </div>
            <Show when={model().can_create && props.commands.includes("project.create") && !creating()}>
                <button type="button" onClick={() => setCreating(true)}>New project</button>
            </Show>
        </div>
        <Show when={model().state === "unavailable"}>
            <p class="gaugeapp-unavailable">{model().reason ?? "The selected Project Host is unavailable."}</p>
        </Show>
        <Show when={creating()}>
            <form class="gaugeapp-project-create" onSubmit={(event) => { event.preventDefault(); void submit(); }}>
                <label><span>Project name</span><input autofocus maxlength="120" required value={name()} onInput={(event) => setName(event.currentTarget.value)} /></label>
                <div class="gaugeapp-actions"><button type="button" onClick={() => { setCreating(false); setName(""); }}>Cancel</button><button type="submit" class="primary" disabled={!name().trim()}>Create</button></div>
            </form>
        </Show>
        <Show when={model().projects.length > 0} fallback={<Show when={model().state === "live" && !creating()}><p class="gaugeapp-empty">No governed projects yet.</p></Show>}>
            <div class="gaugeapp-project-list">
                <For each={model().projects}>{(project) => <div class="gaugeapp-project-row" classList={{ selected: selectedId() === project.id }}>
                    <button type="button" class="gaugeapp-project-name" onClick={() => setSelectedId(selectedId() === project.id ? "" : project.id)}>
                        <strong>{project.name}</strong>
                        <span>{project.home.label}</span>
                    </button>
                    <span><b>{project.access_grants}</b><small>grants</small></span>
                    <span><b>{project.agent_placements}</b><small>Agents</small></span>
                    <span><b>{project.work_targets}</b><small>targets</small></span>
                    <button type="button" onClick={() => setSelectedId(selectedId() === project.id ? "" : project.id)}>{selectedId() === project.id ? "Close" : "View"}</button>
                </div>}</For>
            </div>
        </Show>
        <Show when={selected()}>{(project) => <div class="gaugeapp-project-detail">
            <header><div><span class="gaugeapp-eyebrow">Project</span><h3>{project().name}</h3></div><button type="button" onClick={() => setSelectedId("")}>Close</button></header>
            <div class="gaugeapp-detail-facts">
                <Fact label="Project Host" value={project().home.label} />
                <Fact label="Access" value={`${project().access_grants} direct grant${project().access_grants === 1 ? "" : "s"}`} note={project().is_personal ? "Personal never permits sharing or handoff" : "Owners and administrators retain organization-wide access"} />
                <Fact label="Agents" value={String(project().agent_placements)} note={project().pending_placements ? `${project().pending_placements} awaiting acceptance` : "No pending placements"} />
                <Fact label="Work targets" value={String(project().work_targets)} note={project().network_isolated ? "Network isolated" : "Network access open"} />
            </div>
            {/* The three statements a governance page has to make and this one
                did not: Administration can discover and inspect a project, but
                the authoritative Home still owns it. Without them the page reads
                as a second project authority, which ADR 0171 says it is not. */}
            <SectionHeading title="Authority" />
            <div class="gaugeapp-detail-facts">
                <Fact label="Project settings" value="Owned by the authoritative Home" note="Administration routes commands there" />
                <Fact label="Organization policy" value="Restrict-only" note="the project cannot widen the tenant floor" />
                <Fact label="Move project" value="Deliberate Home handoff" note="never a mutable region or Project Host field" />
            </div>
            <div class="gaugeapp-project-detail-foot">
                <span>{project().freshness === "home-live" ? "Live from the Project Host" : "Project Host data is not current"}</span>
                <Show when={props.onOpenProject}><button type="button" class="primary" onClick={() => props.onOpenProject?.({ id: project().id, name: project().name })}>Open</button></Show>
            </div>
        </div>}</Show>
    </section>;
}

type CloudBackupsPage = Extract<BackupsPageV1, { readonly points: readonly unknown[] }>;

function BackupsPage(props: {
    model: BackupsPageV1;
    session: GaugeAppSession;
    commands: readonly string[];
    onSubmit: SubmitPageCommand;
    api: EnterpriseControlPlane;
}): JSX.Element {
    if (!("points" in props.model)) {
        return <section class="gaugeapp-panel gaugeapp-section-stack">
            <div class="gaugeapp-section-head"><div><h2>Protection</h2><p>Backup management is available from the account that owns this Project Host.</p></div></div>
            <div class="gaugeapp-backup-summary">
                <Fact label="Recovery points" value={String(props.model.backups.length)} />
                <Fact label="Recovery holders" value={String(props.model.recovery_recipients.length)} />
            </div>
        </section>;
    }
    return <CloudBackupsPageView {...props} model={props.model} />;
}

function CloudBackupsPageView(props: {
    model: CloudBackupsPage;
    session: GaugeAppSession;
    commands: readonly string[];
    onSubmit: SubmitPageCommand;
    api: EnterpriseControlPlane;
}): JSX.Element {
    const tenant = () => props.session.scope.id;
    const facility = () => props.model.facility;
    const host = () => props.model.project_host;
    const enabled = () => facility()?.status === "active";
    const hostActive = () => host()?.home_lifecycle === "active";
    const hostErased = () => host()?.home_lifecycle === "erased";
    const latestPoint = () => [...props.model.points].sort((a, b) => b.created_at - a.created_at)[0];
    const pointLabel = (handle: string) => {
        const point = props.model.points.find((candidate) => candidate.handle === handle);
        return point ? new Date(point.created_at * 1_000).toLocaleString() : handle;
    };
    const [scheduleDays, setScheduleDays] = createSignal(facility()?.config.schedule_days ?? 1);
    const [retentionDays, setRetentionDays] = createSignal(facility()?.config.retention_days ?? 30);
    const [working, setWorking] = createSignal("");
    const [error, setError] = createSignal("");
    const [localHolder, { refetch: refetchLocalHolder }] = createResource(
        tenant,
        async (scope) => browserRecoveryHolder(scope).catch(() => null),
    );
    createEffect(() => {
        const config = facility()?.config;
        if (config) {
            setScheduleDays(config.schedule_days);
            setRetentionDays(config.retention_days);
        }
    });
    const localRegistered = () => {
        const holder = localHolder();
        return holder ? props.model.recipients.some((recipient) => recipient.id === holder.id) : false;
    };
    const run = async (label: string, action: () => Promise<unknown>) => {
        if (working()) return;
        setWorking(label);
        setError("");
        try {
            await action();
        } catch (cause) {
            if (cause instanceof DOMException && cause.name === "AbortError") return;
            setError(cause instanceof Error ? cause.message : `Could not ${label}.`);
        } finally {
            setWorking("");
        }
    };
    const addThisDevice = () => run("add this recovery holder", async () => {
        const holder = await ensureBrowserRecoveryHolder(tenant());
        await refetchLocalHolder();
        await props.onSubmit("backups.recovery-holder.add", {
            id: holder.id,
            label: "This GaugeDesk device",
            public_key: holder.publicKey,
        });
    });
    const saveSchedule = (event: SubmitEvent) => {
        event.preventDefault();
        void run("save the backup schedule", () => props.onSubmit("backups.schedule.set", {
            schedule_days: scheduleDays(),
            retention_days: retentionDays(),
        }));
    };
    const finishRestore = (receiver: CloudBackupsPage["restore_receivers"][number]) => run("complete the restore", async () => {
        const holder = await browserRecoveryHolder(tenant());
        if (!props.model.recipients.some((recipient) => recipient.id === holder.id)) {
            throw new Error("This device is not an enrolled recovery holder for this account.");
        }
        const material = await props.api.backupRestoreMaterial(tenant(), receiver.point_handle, holder.id);
        const receiverWrap = await rewrapBackupPointKey(
            tenant(),
            receiver.point_handle,
            material.wrap,
            { id: receiver.id, publicKey: receiver.public_key },
        );
        await props.onSubmit("backups.restore.complete", {
            point_handle: receiver.point_handle,
            receiver_id: receiver.id,
            receiver_wrap: receiverWrap,
        });
    });
    const status = () => enabled() ? "On" : facility() ? "Paused" : "Off";

    return <>
        <Notice tone="neutral">A backup is of the project Homes on this managed Project Host. Recovery opens only with a holder key kept on a trusted device; no GaugeWright service can open one.</Notice>
        <section class="gaugeapp-panel gaugeapp-section-stack">
            <div class="gaugeapp-section-head">
                <div><h2>Protection</h2><p>{enabled() ? "Encrypted recovery points are being retained." : "No new recovery points will be scheduled."}</p></div>
                <Show when={enabled()} fallback={<CommandButton command="backups.enable" commands={props.commands} label="Turn on" disabled={!hostActive() || props.model.recipients.length === 0} payload={{ schedule_days: scheduleDays(), retention_days: retentionDays() }} onSubmit={props.onSubmit} />}>
                    <CommandButton command="backups.disable" commands={props.commands} label="Pause" danger onSubmit={props.onSubmit} />
                </Show>
            </div>
            <div class="gaugeapp-backup-summary">
                <Fact label="Backups" value={status()} note={host()?.home_lifecycle ? `Project Host ${host()!.home_lifecycle}` : "No managed Project Host"} />
                <Fact label="Coverage" value={host()?.name ?? "Not available"} note={host() ? undefined : "Add a managed Project Host first"} />
                <Fact label="Schedule" value={facility() ? `Every ${facility()!.config.schedule_days} day${facility()!.config.schedule_days === 1 ? "" : "s"}` : "Not set"} note={facility() ? `Keep ${facility()!.config.retention_days} days` : undefined} />
                <Fact label="Latest point" value={latestPoint() ? new Date(latestPoint()!.created_at * 1_000).toLocaleString() : "None yet"} note={latestPoint() ? compactBytes(latestPoint()!.bytes) : undefined} />
            </div>
            <Show when={!host()}><p class="gaugeapp-unavailable">Backups need a managed Project Host. Add one from Project Hosts first.</p></Show>
            <Show when={host() && !hostActive() && !hostErased()}><p class="gaugeapp-unavailable">This Project Host must be active before backups can be changed or created.</p></Show>
            <Show when={!enabled() && props.model.recipients.length === 0 && hostActive()}><p class="gaugeapp-backup-note">Add this device as a recovery holder before turning on backups.</p></Show>
        </section>

        <Show when={facility()}>
            <section class="gaugeapp-panel gaugeapp-section-stack">
                <div class="gaugeapp-section-head"><div><h2>Schedule & retention</h2><p>Applies to future recovery points.</p></div></div>
                <form class="gaugeapp-backup-schedule" onSubmit={saveSchedule}>
                    <label><span>Back up every</span><span class="gaugeapp-number-unit"><input aria-label="Backup interval in days" type="number" min="1" max="365" required value={scheduleDays()} onInput={(event) => setScheduleDays(event.currentTarget.valueAsNumber)} /><span>days</span></span></label>
                    <label><span>Keep each point for</span><span class="gaugeapp-number-unit"><input aria-label="Backup retention in days" type="number" min="1" max="3650" required value={retentionDays()} onInput={(event) => setRetentionDays(event.currentTarget.valueAsNumber)} /><span>days</span></span></label>
                    <button type="submit" disabled={!props.commands.includes("backups.schedule.set") || Boolean(working())}>Save</button>
                </form>
            </section>
        </Show>

        <section class="gaugeapp-panel gaugeapp-section-stack">
            <div class="gaugeapp-section-head">
                <div><h2>Recovery holders</h2><p>{props.model.recipients.length} device{props.model.recipients.length === 1 ? "" : "s"} can unlock a restore.</p></div>
                <Show when={props.commands.includes("backups.recovery-holder.add") && !localHolder.loading && !localRegistered()}><button type="button" disabled={Boolean(working())} onClick={() => void addThisDevice()}>{working() === "add this recovery holder" ? "Preparing…" : "Add this device"}</button></Show>
            </div>
            <Show when={props.model.recipients.length > 0} fallback={<p class="gaugeapp-empty">No recovery holder is enrolled.</p>}>
                <div class="gaugeapp-backup-list">
                    <For each={props.model.recipients}>{(recipient) => <div class="gaugeapp-backup-row">
                        <div><strong>{recipient.label || "Recovery device"}</strong><span>{localHolder()?.id === recipient.id ? "This device · key held locally" : "Recovery key held by another device"}</span></div>
                        <CommandButton command="backups.recovery-holder.remove" commands={props.commands} label="Remove" danger disabled={Boolean(working())} payload={{ id: recipient.id }} onSubmit={props.onSubmit} />
                    </div>}</For>
                </div>
            </Show>
        </section>

        <section class="gaugeapp-panel gaugeapp-section-stack">
            <div class="gaugeapp-section-head">
                <div><h2>Recovery points</h2><p>{props.model.points.length} retained.</p></div>
                <CommandButton command="backups.point.create" commands={props.commands} label="Create point" disabled={!enabled() || !hostActive()} onSubmit={props.onSubmit} />
            </div>
            <Show when={props.model.restore_receivers.length > 0}>
                <div class="gaugeapp-backup-pending">
                    <For each={props.model.restore_receivers}>{(receiver) => <div>
                        <span><strong>Restore ready to finish</strong><small>{pointLabel(receiver.point_handle)}</small></span>
                        <button type="button" class="primary" disabled={Boolean(working())} onClick={() => void finishRestore(receiver)}>{working() === "complete the restore" ? "Restoring…" : "Continue"}</button>
                    </div>}</For>
                </div>
            </Show>
            <Show when={props.model.points.length > 0} fallback={<p class="gaugeapp-empty">No recovery points yet.</p>}>
                <div class="gaugeapp-backup-list">
                    <For each={[...props.model.points].sort((a, b) => b.created_at - a.created_at)}>{(point) => <div class="gaugeapp-backup-row">
                        <div><strong>{new Date(point.created_at * 1_000).toLocaleString()}</strong><span>{compactBytes(point.bytes)}</span></div>
                        <Show when={hostErased()}><CommandButton command="backups.restore" commands={props.commands} label="Restore" danger payload={{ point_handle: point.handle }} onSubmit={props.onSubmit} /></Show>
                    </div>}</For>
                </div>
            </Show>
            <Show when={props.model.points.length > 0 && !hostErased()}><p class="gaugeapp-backup-note">Restore becomes available if this Project Host enters recovery.</p></Show>
            <Show when={error()}>{(message) => <p class="gaugeapp-unavailable" role="alert">{message()}</p>}</Show>
        </section>
    </>;
}

function compactNumber(value: unknown): string {
    return typeof value === "number" ? new Intl.NumberFormat().format(value) : "—";
}

function compactBytes(value: unknown): string {
    if (typeof value !== "number") return "—";
    if (value < 1_024) return `${value} B`;
    const units = ["KB", "MB", "GB", "TB"];
    let amount = value / 1_024;
    let unit = 0;
    while (amount >= 1_024 && unit < units.length - 1) {
        amount /= 1_024;
        unit += 1;
    }
    return `${amount >= 10 ? amount.toFixed(0) : amount.toFixed(1)} ${units[unit]}`;
}

function planRenewal(value: unknown): string {
    return typeof value === "number"
        ? new Date(value * 1_000).toLocaleDateString()
        : "Available after enrollment";
}

type TenantServiceView = AdministrationBillingPageV1["services"][number];

const TENANT_SERVICE_PRESENTATION = {
    "commercial-operations": {
        name: "Commercial Operations",
        description: "Products, engagements, client payments, and Stripe Connect.",
    },
    "enterprise-controls": {
        name: "Enterprise controls",
        description: "Enterprise identity, governed access, and organization policy.",
    },
} as const;

function TenantServiceRow(props: {
    service: TenantServiceView;
    commands: readonly string[];
    onSubmit: SubmitPageCommand;
    onOpenGaugeApp?: (app: GaugeAppKind, page: string) => void;
}): JSX.Element {
    const presentation = () => TENANT_SERVICE_PRESENTATION[props.service.id];
    const status = () => props.service.status === "not-added" ? "Not added"
        : props.service.status === "removal-scheduled" ? `Ends ${planRenewal(props.service.removal_effective_at_ms === null ? null : props.service.removal_effective_at_ms / 1_000)}`
            : props.service.status === "ended" ? "Ended"
                : "Active";
    const configure = async () => {
        const response = await props.onSubmit("subscription.service.configure", { service: props.service.id });
        const destination = valueRecord(valueRecord(response.result)?.destination);
        const app = destination?.app;
        const page = destination?.page;
        if ((app === "administration" || app === "commercial-operations") && typeof page === "string") {
            props.onOpenGaugeApp?.(app, page);
        }
    };
    return <article class="gaugeapp-tenant-service-row">
        <div>
            <strong>{presentation().name}</strong>
            <span>{presentation().description}</span>
        </div>
        <span class={`gaugeapp-service-status gaugeapp-service-status-${props.service.status}`}>{status()}</span>
        <div class="gaugeapp-actions">
            <Show when={props.service.status === "not-added" || props.service.status === "ended"}>
                <button type="button" class="primary" disabled={!props.commands.includes("subscription.service.add")} onClick={() => void props.onSubmit("subscription.service.add", { service: props.service.id }).catch(ignoreRetiredAction)}>Add</button>
            </Show>
            <Show when={props.service.status === "active" || props.service.status === "removal-scheduled"}>
                <button type="button" disabled={!props.commands.includes("subscription.service.configure")} onClick={() => void configure().catch(ignoreRetiredAction)}>Open</button>
            </Show>
            <Show when={props.service.status === "active"}>
                <button type="button" disabled={!props.commands.includes("subscription.service.remove-scheduled")} onClick={() => void props.onSubmit("subscription.service.remove-scheduled", { service: props.service.id }).catch(ignoreRetiredAction)}>Schedule removal</button>
            </Show>
            <Show when={props.service.status === "removal-scheduled"}>
                <button type="button" class="primary" disabled={!props.commands.includes("subscription.service.remove-cancel")} onClick={() => void props.onSubmit("subscription.service.remove-cancel", { service: props.service.id }).catch(ignoreRetiredAction)}>Keep</button>
            </Show>
        </div>
    </article>;
}

function PlansServicesPage(props: { model: AdministrationBillingPageV1; commands: readonly string[]; onSubmit: SubmitPageCommand; onOpenGaugeApp?: (app: GaugeAppKind, page: string) => void }): JSX.Element {
    if (!props.model.cloud) return <section class="gaugeapp-panel gaugeapp-section-stack">
        <div class="gaugeapp-section-head"><div><h2>Local service</h2><p class="gaugeapp-unavailable">Paid managed services are not configured on this GaugeDesk service.</p></div></div>
        <div class="gaugeapp-plan-metrics"><Fact label="Seats in use" value={String(props.model.seats_used)} /><Fact label="Managed inference" value={props.model.billing?.managed_inference?.status ?? "Not enrolled"} /></div>
    </section>;
    const cloud = () => props.model.cloud!;
    const usage = () => props.model.managed_usage;
    const presentation = () => subscriptionPresentation(cloud());
    const subscription = () => cloud().subscription;
    const planEnded = () => subscription()?.status === "lapsed";
    const configured = () => cloud().configured_plan;
    const customerLinked = () => cloud().customer_linked === true;
    const planName = () => props.model.billing?.plan || configured().name || "GaugeDesk Cloud";
    const status = () => presentation().status;
    const serviceStatus = () => planEnded() ? "Not enrolled" : status();
    const checkoutAvailable = () => presentation().canManage;
    const hostedCapacity = () => {
        const current = subscription();
        if (!current) return "—";
        const retention = typeof current.retention_secs === "number"
            ? `${Math.round(current.retention_secs / 86_400)} days`
            : "—";
        return `${compactNumber(current.concurrent_agents)} agents · ${compactBytes(current.storage_bytes)} · ${retention}`;
    };
    const [editingSeats, setEditingSeats] = createSignal(false);
    const [seatQuantity, setSeatQuantity] = createSignal("");
    const [confirmingCancellation, setConfirmingCancellation] = createSignal(false);
    const purchasedSeats = () => subscription()?.quantity ?? null;
    const parsedSeatQuantity = () => Number(seatQuantity());
    const seatsValid = () => Number.isSafeInteger(parsedSeatQuantity())
        && parsedSeatQuantity() >= Math.max(1, props.model.seats_used)
        && parsedSeatQuantity() <= 10_000
        && parsedSeatQuantity() !== purchasedSeats();
    const beginSeatChange = () => {
        setSeatQuantity(String(purchasedSeats() ?? Math.max(1, props.model.seats_used)));
        setEditingSeats(true);
    };
    const submitSeatChange = async () => {
        await props.onSubmit("subscription.seats.change", { quantity: parsedSeatQuantity() });
        setEditingSeats(false);
    };
    const submitCancellation = async () => {
        await props.onSubmit("subscription.cancellation.schedule", {});
        setConfirmingCancellation(false);
    };
    return <>
        <section class="gaugeapp-panel gaugeapp-section-stack">
            <div class="gaugeapp-section-head gaugeapp-plan-head">
                <div>
                    <span class="gaugeapp-eyebrow">Current plan</span>
                    <h2>{presentation().blocked ? "Not verified" : planEnded() ? "Free" : subscription() ? planName() : "Free"}</h2>
                    <p>{presentation().issue ?? (planEnded()
                        ? `${planName()} ended${subscription()?.current_period_end ? ` ${planRenewal(subscription()!.current_period_end)}` : ""}. Re-enroll to restore managed inference and hosted Project Home capacity.`
                        : subscription() ? `${presentation().mode ? `${presentation().mode} · ` : ""}${status()} · billing and payment details stay in Stripe` : "Local and self-hosted project work remains available without a paid plan.")}</p>
                </div>
                <CommandButton
                    command="subscription.plan.change"
                    commands={props.commands}
                    label={planEnded() ? "Re-enroll" : customerLinked() ? "Manage plan" : "Start plan"}
                    payload={{ quantity: 1 }}
                    disabled={!checkoutAvailable()}
                    onSubmit={props.onSubmit}
                />
            </div>
            <Show when={!props.commands.includes("subscription.plan.change") || !checkoutAvailable()}>
                <p class="gaugeapp-host-note">Plan changes are unavailable on this GaugeDesk service. Current standing remains visible here.</p>
            </Show>
            <Show when={!planEnded() ? subscription() : null} fallback={
                <Show when={!presentation().blocked}><div class="gaugeapp-plan-offer">
                    <div><strong>{planName()}</strong><span>Managed inference and a hosted Project Home.</span></div>
                    <dl><div><dt>Managed inference</dt><dd>{compactNumber(configured().included_tokens)} included tokens</dd></div><div><dt>Enrollment</dt><dd>{configured().checkout_available === true ? "Available" : "Unavailable on this server"}</dd></div></dl>
                </div></Show>
            }>{(current) => <>
                <div class="gaugeapp-plan-metrics">
                    <Fact label="Purchased seats" value={compactNumber(current().quantity)} />
                    <Fact label="Seats in use" value={compactNumber(props.model.seats_used)} />
                </div>
                <Show when={cloud().management.seats}>
                    <div class="gaugeapp-plan-control">
                        <div><strong>Seat capacity</strong><span>Set the number of organization members the plan can cover.</span></div>
                        <Show when={!editingSeats()} fallback={
                            <form onSubmit={(event) => { event.preventDefault(); void submitSeatChange().catch(ignoreRetiredAction); }}>
                                <label><span>Seats</span><input type="number" min={Math.max(1, props.model.seats_used)} max="10000" step="1" value={seatQuantity()} onInput={(event) => setSeatQuantity(event.currentTarget.value)} /></label>
                                <div class="gaugeapp-actions"><button type="button" onClick={() => setEditingSeats(false)}>Cancel</button><button type="submit" disabled={!seatsValid()}>Continue</button></div>
                            </form>
                        }><button type="button" onClick={beginSeatChange}>Manage seats</button></Show>
                    </div>
                </Show>
            </>}</Show>
        </section>
        <section class="gaugeapp-panel gaugeapp-section-stack">
            <div class="gaugeapp-section-head"><div><h2>Included services</h2></div></div>
            <div class="gaugeapp-summary-row"><div><strong>Managed inference</strong><span>{serviceStatus()}</span></div><strong>{presentation().blocked ? "—" : `${compactNumber(usage().included_tokens)} tokens`}</strong></div>
            <Show when={subscription() && !planEnded()}><div class="gaugeapp-summary-row"><div><strong>Hosted Project Home</strong><span>{hostedCapacity()}</span></div><strong>{status()}</strong></div></Show>
        </section>
        <section class="gaugeapp-panel gaugeapp-section-stack">
            <div class="gaugeapp-section-head"><div><h2>Organization services</h2><p>Add or remove these independently from seat capacity.</p></div></div>
            <Show when={!subscription() || planEnded()}>
                <p class="gaugeapp-host-note">An active GaugeDesk Cloud plan is required before adding organization services.</p>
            </Show>
            <div class="gaugeapp-tenant-service-list">
                <For each={props.model.services}>{(service) => <TenantServiceRow service={service} commands={props.commands} onSubmit={props.onSubmit} onOpenGaugeApp={props.onOpenGaugeApp} />}</For>
            </div>
        </section>
        <Show when={subscription() && !planEnded() ? subscription() : null}>{(current) => <section class="gaugeapp-panel gaugeapp-section-stack">
            <Show when={current().cancel_at_period_end}>
                <Notice tone="neutral"><strong>Plan change scheduled.</strong> Managed rights remain active until the end of the paid period; nothing is removed before then, and membership, roles and project access are unchanged.</Notice>
            </Show>
            <div class="gaugeapp-section-head"><div><h2>Renewal</h2><p>{current().cancel_at_period_end ? `Access ends ${planRenewal(current().current_period_end)}.` : `Renews ${planRenewal(current().current_period_end)}.`}</p></div></div>
            <Show when={current().cancel_at_period_end} fallback={
                <Show when={cloud().management.cancellation}>
                    <div class="gaugeapp-plan-control gaugeapp-plan-control-danger">
                        <div><strong>End managed service</strong><span>Keep access through the current paid period, then return to Free.</span></div>
                        <Show when={!confirmingCancellation()} fallback={
                            <div class="gaugeapp-plan-confirm"><p>Schedule cancellation for {planRenewal(current().current_period_end)}? Stripe will confirm the effective date before anything changes.</p><div class="gaugeapp-actions"><button type="button" onClick={() => setConfirmingCancellation(false)}>Keep plan</button><button type="button" class="gaugeapp-danger" onClick={() => void submitCancellation().catch(ignoreRetiredAction)}>Continue</button></div></div>
                        }><button type="button" onClick={() => setConfirmingCancellation(true)}>Schedule cancellation</button></Show>
                    </div>
                </Show>
            }><div class="gaugeapp-summary-row"><div><strong>Cancellation scheduled</strong><span>Managed rights remain active until the end of the paid period.</span></div><strong>{planRenewal(current().current_period_end)}</strong></div></Show>
        </section>}</Show>
    </>;
}

function BillingContact(props: { model: AdministrationBillingPageV1; commands: readonly string[]; onSubmit: SubmitPageCommand }): JSX.Element {
    const contact = () => props.model.billing_contact;
    const [editing, setEditing] = createSignal(false);
    const [name, setName] = createSignal("");
    const [email, setEmail] = createSignal("");
    const begin = () => {
        setName(contact()?.name ?? "");
        setEmail(contact()?.email ?? "");
        setEditing(true);
    };
    const submit = async () => {
        await props.onSubmit("billing.contact.set", { name: name().trim(), email: email().trim() });
        setEditing(false);
    };
    return <section class="gaugeapp-panel gaugeapp-section-stack">
        <div class="gaugeapp-section-head gaugeapp-plan-head">
            <div><h2>Billing contact</h2><p>Receives plan and invoice notices from GaugeWright.</p></div>
            <Show when={!editing() && props.commands.includes("billing.contact.set")}><button type="button" onClick={begin}>{contact() ? "Edit" : "Add"}</button></Show>
        </div>
        <Show when={editing()} fallback={
            <div class="gaugeapp-plan-metrics">
                <Fact label="Name" value={contact()?.name ?? "Not set"} />
                <Fact label="Email" value={contact()?.email ?? "Not set"} />
            </div>
        }>
            <form class="gaugeapp-provider-form" onSubmit={(event) => { event.preventDefault(); void submit().catch(ignoreRetiredAction); }}>
                <label><span>Name</span><input required maxlength="120" value={name()} onInput={(event) => setName(event.currentTarget.value)} /></label>
                <label><span>Email</span><input required type="email" maxlength="320" value={email()} onInput={(event) => setEmail(event.currentTarget.value)} /></label>
                <div class="gaugeapp-form-actions"><button type="button" onClick={() => setEditing(false)}>Cancel</button><button type="submit" disabled={!name().trim() || !email().trim()}>Continue</button></div>
            </form>
        </Show>
    </section>;
}

function billingDocumentDate(value: number | null): string {
    return value === null ? "—" : new Date(value * 1_000).toLocaleDateString();
}

function BillingDocuments(props: { model: AdministrationBillingPageV1; commands: readonly string[]; onSubmit: SubmitPageCommand }): JSX.Element {
    const documents = () => props.model.cloud!.documents;
    const estimate = () => documents().estimate;
    const canRefresh = () => props.commands.includes("billing.documents.refresh");
    const freshness = () => {
        if (documents().freshness === "unavailable" || (!canRefresh() && documents().refreshed_at === null)) return "Billing documents are temporarily unavailable.";
        if (documents().refreshed_at === null) return "Retrieve the current estimate and recent invoices from Stripe.";
        const suffix = documents().history_complete ? "" : " · showing the 10 most recent invoices";
        return `Updated ${billingDocumentDate(documents().refreshed_at)}${suffix}`;
    };
    return <section class="gaugeapp-panel gaugeapp-section-stack gaugeapp-billing-documents">
        <div class="gaugeapp-section-head gaugeapp-plan-head">
            <div><h2>Billing documents</h2><p>{freshness()}</p></div>
            <CommandButton command="billing.documents.refresh" commands={props.commands} label={documents().refreshed_at === null ? "Retrieve" : "Refresh"} onSubmit={props.onSubmit} />
        </div>
        <Show when={estimate()}>{(current) => <div class="gaugeapp-billing-estimate">
            <div class="gaugeapp-billing-estimate-head">
                <div><span class="gaugeapp-eyebrow">Current estimate</span><strong>{commercialMoney(current().amount_due_cents, current().currency)}</strong></div>
                <span>{billingDocumentDate(current().period_start)}–{billingDocumentDate(current().period_end)}</span>
            </div>
            <div class="gaugeapp-billing-lines"><For each={current().lines}>{(line) => <div class="gaugeapp-billing-line">
                <span>{line.description ?? "Billing adjustment"}</span><strong>{commercialMoney(line.amount_cents, line.currency)}</strong>
            </div>}</For></div>
            <Show when={!current().lines_complete}><p class="gaugeapp-quiet">Open billing in Stripe to inspect the remaining lines.</p></Show>
        </div>}</Show>
        <div class="gaugeapp-billing-history">
            <div class="gaugeapp-editor-section-head"><div><strong>Invoices</strong><span>Recent plan invoices from Stripe.</span></div></div>
            <Show when={documents().invoices.length > 0} fallback={<p class="gaugeapp-empty">No plan invoices retrieved.</p>}>
                <For each={documents().invoices}>{(invoice) => <div class="gaugeapp-billing-invoice">
                    <div><strong>{billingDocumentDate(invoice.created_at)}</strong><span>{invoice.status} · {commercialMoney(invoice.total_cents, invoice.currency)}</span></div>
                    <div class="gaugeapp-document-actions">
                        <Show when={safeExternalUrl(invoice.hosted_invoice_url)}>{(url) => <a href={url()} target="_blank" rel="noreferrer">View</a>}</Show>
                        <Show when={safeExternalUrl(invoice.invoice_pdf)}>{(url) => <a href={url()} target="_blank" rel="noreferrer">Download</a>}</Show>
                    </div>
                </div>}</For>
            </Show>
        </div>
    </section>;
}

function BillingPage(props: { model: AdministrationBillingPageV1; commands: readonly string[]; onSubmit: SubmitPageCommand }): JSX.Element {
    if (!props.model.cloud) return <>
        <section class="gaugeapp-panel gaugeapp-section-stack">
            <div class="gaugeapp-section-head"><div><h2>Billing</h2><p>No processor-backed billing service is configured on this GaugeDesk service.</p></div></div>
            <div class="gaugeapp-plan-metrics"><Fact label="Purchased seats" value={String(props.model.billing?.seats ?? 0)} /><Fact label="Seats in use" value={String(props.model.seats_used)} /></div>
        </section>
        <BillingContact {...props} />
    </>;
    const cloud = () => props.model.cloud!;
    const presentation = () => subscriptionPresentation(cloud());
    const usage = () => props.model.managed_usage;
    const customerLinked = () => cloud().customer_linked === true;
    const paymentManagementAvailable = () => props.commands.includes("billing.payment-method.begin")
        || props.commands.includes("billing.customer-portal.begin");
    return <>
        <Notice tone="neutral">Plan, seat, and organization-service changes are managed under Plans &amp; services. Billing contains payment and accounting records only.</Notice>
        <section class="gaugeapp-panel gaugeapp-section-stack">
            <div class="gaugeapp-section-head gaugeapp-plan-head">
                <div><h2>Payment</h2><p>{presentation().issue ?? (presentation().mode ? "Test billing · no live payment account." : "Card and bank details are collected and retained by Stripe.")}</p></div>
                <Show when={customerLinked()}>
                    <div class="gaugeapp-actions">
                        <CommandButton command="billing.payment-method.begin" commands={props.commands} label="Update payment" onSubmit={props.onSubmit} />
                        <CommandButton command="billing.customer-portal.begin" commands={props.commands} label="Open billing" onSubmit={props.onSubmit} />
                    </div>
                </Show>
            </div>
            <div class="gaugeapp-plan-metrics">
                <Fact label="Billing account" value={presentation().blocked ? "Not verified" : customerLinked() ? "Linked" : "Not created"} />
                <Fact label="Payment method" value={presentation().blocked ? "Unknown" : customerLinked() ? "Managed in Stripe" : "Not required"} />
            </div>
            <Show when={customerLinked() && !paymentManagementAvailable()}>
                <p class="gaugeapp-unavailable">Payment management is temporarily unavailable.</p>
            </Show>
        </section>
        <BillingContact {...props} />
        <BillingDocuments {...props} />
        <section class="gaugeapp-panel gaugeapp-section-stack">
            <div class="gaugeapp-section-head"><div><h2>Managed inference usage</h2><p>Recorded managed inference usage.</p></div></div>
            <div class="gaugeapp-plan-metrics">
                <Fact label="Included tokens" value={compactNumber(usage().included_tokens)} />
                <Fact label="Used tokens" value={compactNumber(usage().total_tokens)} />
            </div>
            <Show when={usage().unattributed_runs > 0}>
                <p>{compactNumber(usage().unattributed_tokens)} older tokens remain in usage history but are not assigned to this billing period.</p>
            </Show>
        </section>
    </>;
}

const SCIM_ROLES = ["member", "viewer", "auditor", "billing"] as const;

const scimErrorMessage = (code: EnterpriseIdentityPageV1["scim"]["status"]["errors"][number]["code"]): string => ({
    "invalid-user-name": "Send a non-empty, bounded userName.",
    "unsupported-change": "GaugeDesk currently accepts activation and deactivation changes only.",
    "unknown-user": "Provision this user before sending an update.",
    "seat-capacity": "Add a seat or deprovision another member, then retry from your identity provider.",
})[code];

type IdentityValidation = {
    readonly revision: string;
    readonly status: "ready" | "needs-attention";
    readonly code: string;
};

const identityValidationMessage = (validation: IdentityValidation): string => ({
    "oidc-discovery-ready": "Discovery and signing keys loaded. A browser sign-in has not been tested.",
    "saml-metadata-ready": "Metadata contains a sign-in service and signing certificate. A browser sign-in has not been tested.",
    "oidc-discovery-unreachable": "The issuer or its signing keys could not be reached. Check the issuer and your identity provider’s network access.",
    "oidc-configuration-incomplete": "The saved OIDC connection is missing an issuer or client ID.",
    "validation-task-failed": "Validation could not finish. Try again; if it repeats, check the server logs.",
    "metadata-empty": "Paste the IdP metadata document.",
    "metadata-too-large": "The IdP metadata document is larger than 512 KiB.",
    "metadata-doctype-forbidden": "Remove the document type from the IdP metadata.",
    "metadata-too-deep": "The IdP metadata is nested too deeply.",
    "metadata-malformed": "The IdP metadata is not well-formed XML.",
    "metadata-missing-entity-id": "The IdP metadata does not identify its entity.",
    "metadata-missing-idp": "The document has no SAML 2.0 IdP descriptor.",
    "metadata-ambiguous-idp": "The document describes more than one IdP. Export metadata for one application.",
    "metadata-missing-sign-in-service": "The document has no HTTP-Redirect or HTTP-POST sign-in service.",
    "metadata-missing-signing-certificate": "The document has no assertion-signing certificate.",
})[validation.code] ?? "The server could not validate this configuration.";

const ADMISSION_LABELS = {
    "invited-only": "Invited people only",
    "verified-domain-jit": "Verified company email",
    scim: "SCIM-provisioned people",
} as const;

const ADMISSION_HELP = {
    "invited-only": "A corporate subject must match a pending invitation.",
    "verified-domain-jit": "A verified email on one of your verified domains may join as a member.",
    scim: "A person must already exist in the SCIM directory before first sign-in.",
} as const;

function EnterpriseIdentityPage(props: { model: EnterpriseIdentityPageV1; resourceBasis: string; session: GaugeAppSession; commands: readonly string[]; onSubmit: SubmitPageCommand; api: EnterpriseControlPlane; onRefresh: () => Promise<void>; onOpenGaugeApp?: (app: GaugeAppKind, page: string) => void }): JSX.Element {
    const connection = () => props.model.sso;
    const browserTest = () => props.model.browser_test;
    const integration = () => props.model.integration;
    const scim = () => props.model.scim;
    const scimErrors = () => scim().status.errors;
    const lastScimSync = () => {
        const value = scim().status.last_sync_at_ms;
        return value === null ? "No sync received" : sessionTimestamp(value);
    };
    const mappings = () => props.model.group_mappings;
    const [editingConnection, setEditingConnection] = createSignal(false);
    const [protocol, setProtocol] = createSignal("oidc");
    const [issuer, setIssuer] = createSignal("");
    const [audiences, setAudiences] = createSignal("");
    const [metadata, setMetadata] = createSignal("");
    const [subjectClaim, setSubjectClaim] = createSignal("sub");
    const [emailClaim, setEmailClaim] = createSignal("");
    const [rolesClaim, setRolesClaim] = createSignal("");
    const [validation, setValidation] = createSignal<IdentityValidation>();
    const [validating, setValidating] = createSignal(false);
    const [testingSignIn, setTestingSignIn] = createSignal(false);
    const [testLaunchUrl, setTestLaunchUrl] = createSignal<string>();
    const [editingCredential, setEditingCredential] = createSignal(false);
    const [clientSecret, setClientSecret] = createSignal("");
    const [savingCredential, setSavingCredential] = createSignal(false);
    const [credentialStatus, setCredentialStatus] = createSignal("");
    const [admissionMode, setAdmissionMode] = createSignal<keyof typeof ADMISSION_LABELS>(props.model.admission_mode ?? "invited-only");
    const [editingGroup, setEditingGroup] = createSignal<string | null>(null);
    const [mappingOpen, setMappingOpen] = createSignal(false);
    const [group, setGroup] = createSignal("");
    const [role, setRole] = createSignal("member");
    const [team, setTeam] = createSignal("");
    createEffect(() => setAdmissionMode(props.model.admission_mode ?? "invited-only"));
    const enforcementChecks = () => [
        [props.model.enforcement.connection_configured, "Connection configured"],
        [props.model.enforcement.domain_verified, "Company domain verified"],
        [props.model.enforcement.browser_test_current, "Browser sign-in tested"],
        [props.model.enforcement.admission_configured, "Member admission configured"],
        [props.model.enforcement.owner_subject_linked, "Owner corporate sign-in linked"],
        [props.model.enforcement.owner_recovery_ready, "Owner passkey and recovery codes ready"],
    ] as const;
    const beginConnection = () => {
        const current = connection();
        setProtocol(current?.protocol ?? "oidc");
        setIssuer(current?.issuer ?? "");
        setAudiences(current?.audiences.join(", ") ?? "");
        const claims = current?.claim_mapping;
        setSubjectClaim(claims?.subject_claim ?? "sub");
        setEmailClaim(claims?.email_claim ?? "");
        setRolesClaim(claims?.roles_claim ?? "");
        setMetadata("");
        setValidation(undefined);
        setEditingConnection(true);
    };
    const validateConnection = async () => {
        setValidating(true);
        try {
            const response = await props.onSubmit("enterprise-identity.connection.validate", {});
            const result = valueRecord(response.result);
            if (
                result?.kind !== "enterprise-identity-configuration-validation"
                || typeof result.connection_revision !== "string"
                || (result.status !== "ready" && result.status !== "needs-attention")
                || typeof result.code !== "string"
            ) throw new Error("The server returned an invalid validation result.");
            setValidation({
                revision: result.connection_revision,
                status: result.status,
                code: result.code,
            });
        } finally {
            setValidating(false);
        }
    };
    const currentValidation = () => {
        const result = validation();
        return result && result.revision === connection()?.revision ? result : undefined;
    };
    const testSignIn = async () => {
        const popup = window.open("", "gaugedesk-enterprise-sign-in-test", "popup,width=520,height=720");
        setTestingSignIn(true);
        setTestLaunchUrl(undefined);
        try {
            const response = await props.onSubmit("enterprise-identity.test.begin", {});
            const result = valueRecord(response.result);
            if (
                result?.kind !== "enterprise-identity-browser-test-launch"
                || (result.protocol !== "oidc" && result.protocol !== "saml")
                || typeof result.connection_revision !== "string"
                || typeof result.authorize_url !== "string"
            ) throw new Error("The server returned an invalid sign-in test launch.");
            if (popup) {
                popup.location.replace(result.authorize_url);
                popup.focus();
            } else {
                setTestLaunchUrl(result.authorize_url);
            }
        } catch (error) {
            popup?.close();
            throw error;
        } finally {
            setTestingSignIn(false);
        }
    };
    const beginMapping = (mapping?: EnterpriseIdentityPageV1["group_mappings"][number]) => {
        const id = mapping?.group ?? null;
        setEditingGroup(id);
        setGroup(id ?? "");
        setRole(mapping?.role ?? "member");
        setTeam(mapping?.team ?? "");
        setMappingOpen(true);
    };
    const closeMapping = () => {
        setMappingOpen(false);
        setEditingGroup(null);
    };
    const copy = (value: unknown) => {
        if (typeof value === "string" && value) void navigator.clipboard.writeText(value);
    };
    const submitConnection = (event: SubmitEvent) => {
        event.preventDefault();
        const optional = (value: string) => value.trim() || null;
        void props.onSubmit("enterprise-identity.connection.set", {
            protocol: protocol(),
            issuer: issuer().trim(),
            audiences: audiences().split(",").map((value) => value.trim()).filter(Boolean),
            metadata: metadata().trim(),
            enforce_sso: false,
            claim_mapping: {
                subject_claim: protocol() === "oidc" ? optional(subjectClaim()) : null,
                email_claim: protocol() === "saml" ? optional(emailClaim()) : null,
                roles_claim: optional(rolesClaim()),
                region_claim: null,
                tenant_claim: null,
            },
        }).then(() => setEditingConnection(false));
    };
    const submitCredential = async (event: SubmitEvent) => {
        event.preventDefault();
        const current = connection();
        if (!current || !clientSecret()) return;
        setSavingCredential(true);
        setCredentialStatus("");
        const secret = clientSecret();
        setClientSecret("");
        try {
            await props.api.submitOrganizationSsoCredential({
                session_id: props.session.id,
                generation: props.session.generation,
                app: "administration",
                scope: props.session.scope,
                page_id: "enterprise-identity",
                command_id: "enterprise-identity.connection.credential.set",
                expected_basis: props.resourceBasis,
                idempotency_key: newIdempotencyKey(),
                payload: { connection_revision: current.revision },
                client: "web",
            }, secret);
            setEditingCredential(false);
            await props.onRefresh();
        } catch (error) {
            setCredentialStatus(`Could not save client secret: ${error instanceof Error ? error.message : String(error)}`);
        } finally {
            setSavingCredential(false);
        }
    };
    const removeCredential = async () => {
        const current = connection();
        if (!current) return;
        setSavingCredential(true);
        setCredentialStatus("");
        try {
            await props.api.submitOrganizationSsoCredential({
                session_id: props.session.id,
                generation: props.session.generation,
                app: "administration",
                scope: props.session.scope,
                page_id: "enterprise-identity",
                command_id: "enterprise-identity.connection.credential.remove",
                expected_basis: props.resourceBasis,
                idempotency_key: newIdempotencyKey(),
                payload: { connection_revision: current.revision },
                client: "web",
            });
            setEditingCredential(false);
            await props.onRefresh();
        } catch (error) {
            setCredentialStatus(`Could not remove client secret: ${error instanceof Error ? error.message : String(error)}`);
        } finally {
            setSavingCredential(false);
        }
    };
    return <>
        <Notice tone={connection() ? "neutral" : "warn"}>{connection()
            ? "SCIM owns the lifecycle of directory-managed members. A credential is revealed only once after its reviewed rotation command is admitted; it never enters this page, the agent, or a configuration diff."
            : "No corporate identity provider is connected. Verify a company domain before enabling just-in-time membership, and test the connection before enforcing SSO."}</Notice>
        <section class="gaugeapp-panel gaugeapp-section-stack">
            <div class="gaugeapp-section-head gaugeapp-plan-head">
                <div><h2>Corporate sign-in</h2><p>{connection() ? "Connection configured; enforcement remains separate." : "Connect an OIDC or SAML identity provider."}</p></div>
                <Show when={!editingConnection()}><div class="gaugeapp-row-actions">
                    <Show when={connection() && props.commands.includes("enterprise-identity.test.begin")}><button type="button" disabled={testingSignIn()} onClick={() => void testSignIn().catch(ignoreRetiredAction)}>{testingSignIn() ? "Starting…" : browserTest() ? "Test again" : "Test sign-in"}</button></Show>
                    <Show when={connection() && props.commands.includes("enterprise-identity.connection.validate")}><button type="button" disabled={validating()} onClick={() => void validateConnection().catch(ignoreRetiredAction)}>{validating() ? "Validating…" : "Validate"}</button></Show>
                    <Show when={props.commands.includes("enterprise-identity.connection.set")}><button type="button" onClick={beginConnection}>{connection() ? "Edit" : "Set up"}</button></Show>
                </div></Show>
            </div>
            <Show when={!editingConnection()}>
                <div class="gaugeapp-identity-summary">
                    <Fact label="Connection" value={connection() ? "Configured" : "Not configured"} />
                    <Fact label="Protocol" value={text(connection()?.protocol, "—").toUpperCase()} />
                    <Fact label="Browser test" value={browserTest() ? `Passed ${sessionTimestamp(browserTest()!.tested_at_ms)}` : "Not run"} />
                    <Fact label="Enforcement" value={connection()?.enforce_sso === true ? "Required" : "Not required"} />
                </div>
            </Show>
            <Show when={!editingConnection() && connection()?.protocol === "oidc"}>
                <div class="gaugeapp-summary-row">
                    <div><strong>Client secret</strong><span>{connection()?.client_secret_configured ? "Saved securely for this organization" : "Not set — use this for a public PKCE client"}</span></div>
                    <Show when={props.commands.includes("enterprise-identity.connection.credential.set")}>
                        <button type="button" onClick={() => setEditingCredential((value) => !value)}>{connection()?.client_secret_configured ? "Replace" : "Add"}</button>
                    </Show>
                </div>
                <Show when={editingCredential()}>
                    <form class="gaugeapp-provider-form" onSubmit={(event) => void submitCredential(event)}>
                        <label class="wide"><span>OIDC client secret</span><input required type="password" autocomplete="new-password" value={clientSecret()} onInput={(event) => setClientSecret(event.currentTarget.value)} /></label>
                        <p class="wide gaugeapp-form-note">Write-only. GaugeDesk encrypts it for this organization and never shows it again.</p>
                        <div class="gaugeapp-form-actions">
                            <Show when={connection()?.client_secret_configured && props.commands.includes("enterprise-identity.connection.credential.remove")}><button type="button" disabled={savingCredential()} onClick={() => void removeCredential()}>Remove</button></Show>
                            <button type="button" onClick={() => { setClientSecret(""); setEditingCredential(false); }}>Cancel</button>
                            <button type="submit" disabled={savingCredential() || !clientSecret()}>{savingCredential() ? "Saving…" : "Save secret"}</button>
                        </div>
                    </form>
                </Show>
                <Show when={credentialStatus()}>{(message) => <p class="gaugeapp-status" role="status">{message()}</p>}</Show>
            </Show>
            <Show when={testLaunchUrl()}>{(url) => <div class="gaugeapp-callout gaugeapp-identity-validation" data-status="ready" role="status"><div><strong>Popup blocked</strong><span>Open the identity provider to continue the isolated sign-in test.</span></div><a href={url()} target="_blank" rel="noreferrer">Continue test</a></div>}</Show>
            <Show when={browserTest()}>{(result) => <div class="gaugeapp-callout gaugeapp-identity-validation" data-status="ready"><div><strong>Browser sign-in verified</strong><span>{text(result().subject)} · {result().mapped_roles.length ? `Mapped roles: ${result().mapped_roles.join(", ")}` : "No role claim mapped"}</span></div></div>}</Show>
            <Show when={currentValidation()}>{(result) => <div class="gaugeapp-callout gaugeapp-identity-validation" data-status={result().status} role="status"><div><strong>{result().status === "ready" ? "Configuration is valid" : "Configuration needs attention"}</strong><span>{identityValidationMessage(result())}</span></div></div>}</Show>
            <Show when={editingConnection()}>
                <form class="gaugeapp-provider-form" onSubmit={submitConnection}>
                    <label><span>Protocol</span><select value={protocol()} onChange={(event) => setProtocol(event.currentTarget.value)}><option value="oidc">OIDC</option><option value="saml">SAML</option></select></label>
                    <Show when={protocol() === "oidc"}>
                        <label><span>Issuer</span><input required type="url" value={issuer()} onInput={(event) => setIssuer(event.currentTarget.value)} placeholder="https://idp.example.com" /></label>
                        <label class="wide"><span>Client ID</span><input required value={audiences()} onInput={(event) => setAudiences(event.currentTarget.value)} placeholder="One or more, separated by commas" /></label>
                    </Show>
                    <Show when={protocol() === "saml"}>
                        <label class="wide"><span>IdP metadata XML</span><textarea required rows={6} value={metadata()} onInput={(event) => setMetadata(event.currentTarget.value)} placeholder="Paste the IdP metadata document" /></label>
                        <p class="wide gaugeapp-form-note">GaugeDesk validates the metadata here. Requiring corporate sign-in still needs a separate successful browser test.</p>
                    </Show>
                    <Show when={protocol() === "oidc"} fallback={<div class="gaugeapp-form-note"><strong>Subject</strong><span>The signed SAML NameID identifies the subject.</span></div>}><label><span>Subject claim</span><input value={subjectClaim()} onInput={(event) => setSubjectClaim(event.currentTarget.value)} /></label></Show>
                    <Show when={protocol() === "saml"}><label><span>Email attribute</span><input value={emailClaim()} onInput={(event) => setEmailClaim(event.currentTarget.value)} placeholder="Leave blank when NameID is the email" /></label></Show>
                    <label><span>{protocol() === "saml" ? "Groups / roles attribute" : "Groups / roles claim"}</span><input value={rolesClaim()} onInput={(event) => setRolesClaim(event.currentTarget.value)} placeholder="Optional" /></label>
                    <div class="gaugeapp-identity-values wide">
                        <Show when={protocol() === "oidc"}><IdentityValue label="Redirect URI" value={integration().oidc.redirect_uri} onCopy={copy} /></Show>
                        <Show when={protocol() === "saml"}><IdentityValue label="SP entity ID" value={integration().saml.sp_entity_id} onCopy={copy} /><IdentityValue label="ACS URL" value={integration().saml.acs_url} onCopy={copy} /><IdentityValue label="SP metadata" value={integration().saml.metadata_url} onCopy={copy} /></Show>
                    </div>
                    <div class="gaugeapp-form-actions"><button type="button" onClick={() => setEditingConnection(false)}>Cancel</button><button type="submit">Save connection</button></div>
                </form>
            </Show>
            <div class="gaugeapp-summary-row"><div><strong>Verified domains</strong><span>{props.model.verified_domains.length ? props.model.verified_domains.join(", ") : "None"}</span></div><strong>{props.model.verified_domains.length}</strong></div>
        </section>

        <section class="gaugeapp-panel gaugeapp-section-stack">
            <div class="gaugeapp-section-head"><div><h2>Member admission</h2><p>Control who may enter this organization after corporate sign-in.</p></div></div>
            <form class="gaugeapp-admission-control" onSubmit={(event) => {
                event.preventDefault();
                void props.onSubmit("enterprise-identity.admission-mode.set", { mode: admissionMode() });
            }}>
                <label><span>Who can join</span><select value={admissionMode()} onChange={(event) => setAdmissionMode(event.currentTarget.value as keyof typeof ADMISSION_LABELS)}><For each={Object.entries(ADMISSION_LABELS)}>{([value, label]) => <option value={value}>{label}</option>}</For></select></label>
                <p>{ADMISSION_HELP[admissionMode()]}</p>
                <Show when={props.commands.includes("enterprise-identity.admission-mode.set")}><button type="submit" disabled={admissionMode() === props.model.admission_mode}>Save</button></Show>
            </form>
            <div class="gaugeapp-summary-row"><div><strong>Owner corporate sign-in</strong><span>{props.model.current_owner.subject_linked ? "Linked to this GaugeDesk account" : props.model.current_owner.passkey_session ? "Ready to link after a successful test sign-in" : "Sign in with a passkey, then run Test sign-in"}</span></div><Show when={props.model.current_owner.is_owner && !props.model.current_owner.subject_linked && props.commands.includes("enterprise-identity.owner-subject.link")}><button type="button" disabled={!props.model.current_owner.passkey_session || !props.model.enforcement.browser_test_current} onClick={() => void props.onSubmit("enterprise-identity.owner-subject.link", {})}>Link</button></Show></div>
            <div class="gaugeapp-summary-row"><div><strong>Independent owner recovery</strong><span>{props.model.enforcement.owner_recovery_ready ? "An active owner has a passkey and unused recovery codes" : props.model.current_owner.is_owner ? "Set up your account passkey and recovery codes before requiring SSO" : "An active owner must set up a passkey and recovery codes"}</span></div><Show when={!props.model.enforcement.owner_recovery_ready && props.model.current_owner.is_owner && props.onOpenGaugeApp}><button type="button" onClick={() => props.onOpenGaugeApp?.("account-settings", "account")}>Set up recovery</button></Show></div>
            <div class="gaugeapp-summary-row"><div><strong>Require SSO for members</strong><span>{props.model.enforcement.required ? "Enabled" : props.model.enforcement.ready ? "Ready to enable" : "Complete the checks below"}</span></div><Show when={props.commands.includes(props.model.enforcement.required ? "enterprise-identity.enforcement.disable" : "enterprise-identity.enforcement.enable")}><button type="button" disabled={!props.model.enforcement.required && !props.model.enforcement.ready} onClick={() => void props.onSubmit(props.model.enforcement.required ? "enterprise-identity.enforcement.disable" : "enterprise-identity.enforcement.enable", {})}>{props.model.enforcement.required ? "Stop requiring" : "Require SSO"}</button></Show></div>
            <Show when={!props.model.enforcement.ready && !props.model.enforcement.required}>
                <div class="gaugeapp-readiness-list" aria-label="SSO enforcement readiness"><For each={enforcementChecks()}>{([ready, label]) => <div data-ready={ready ? "true" : "false"}><span aria-hidden="true">{ready ? "✓" : "○"}</span><span>{label}</span></div>}</For></div>
            </Show>
            <Show when={props.model.enforcement.ready && !props.model.enforcement.second_owner_present}><div class="gaugeapp-callout"><div><strong>Add a second owner</strong><span>Recommended before requiring SSO, but not a hard gate.</span></div></div></Show>
        </section>

        <section class="gaugeapp-panel gaugeapp-section-stack">
            <div class="gaugeapp-section-head gaugeapp-plan-head">
                <div><h2>SCIM provisioning</h2><p>{text(scim().base_url, "Base URL unavailable")}</p></div>
                <CommandButton
                    command={scim().credential_configured === true ? "enterprise-identity.scim-credential.rotate" : "enterprise-identity.scim-credential.issue"}
                    commands={props.commands}
                    label={scim().credential_configured === true ? "Rotate credential" : "Issue credential"}
                    onSubmit={props.onSubmit}
                />
            </div>
            <div class="gaugeapp-summary-row"><div><strong>Provisioning credential</strong><span>{scim().credential_configured === true ? "Active" : "Not issued"}</span></div><strong>{mappings().length} mapping{mappings().length === 1 ? "" : "s"}</strong></div>
            <div class="gaugeapp-summary-row"><div><strong>Last successful sync</strong><span>{lastScimSync()}</span></div><strong>{scimErrors().length ? `${scimErrors().length} need attention` : "No errors"}</strong></div>
            <Show when={scimErrors().length > 0}>
                <div class="gaugeapp-rows" aria-label="SCIM sync errors"><For each={scimErrors()}>{(error) => <div class="gaugeapp-row">
                    <strong>{error.subject ?? "Provisioning request"}</strong>
                    <span>{error.operation === "provision" ? "Provision" : error.operation === "update" ? "Update" : "Deprovision"} · {sessionTimestamp(error.observed_at_ms)} · {scimErrorMessage(error.code)}</span>
                </div>}</For></div>
            </Show>
        </section>

        <section class="gaugeapp-panel gaugeapp-section-stack">
            <div class="gaugeapp-section-head"><div><h2>Group mappings</h2></div><Show when={!mappingOpen() && props.commands.includes("enterprise-identity.group-mapping.add")}><button type="button" onClick={() => beginMapping()}>Add mapping</button></Show></div>
            <Show when={mappingOpen()}>
                <form class="gaugeapp-inline-form gaugeapp-inline-form-wide" onSubmit={(event) => {
                    event.preventDefault();
                    const command = editingGroup() ? "enterprise-identity.group-mapping.edit" : "enterprise-identity.group-mapping.add";
                    void props.onSubmit(command, { group: group().trim(), role: role(), team: team().trim() || null }).then(closeMapping);
                }}>
                    <label><span>IdP group</span><input required readOnly={Boolean(editingGroup())} value={group()} onInput={(event) => setGroup(event.currentTarget.value)} /></label>
                    <label><span>Workspace role</span><select value={role()} onChange={(event) => setRole(event.currentTarget.value)}><For each={SCIM_ROLES}>{(value) => <option value={value}>{value}</option>}</For></select></label>
                    <label><span>Team</span><input value={team()} onInput={(event) => setTeam(event.currentTarget.value)} placeholder="Optional" /></label>
                    <div class="gaugeapp-actions"><button type="button" onClick={closeMapping}>Cancel</button><button type="submit">{editingGroup() ? "Save" : "Add"}</button></div>
                </form>
            </Show>
            <Show when={mappings().length > 0} fallback={<p class="gaugeapp-empty">No group mappings.</p>}>
                <div class="gaugeapp-domain-list"><For each={mappings()}>{(mapping) => <div class="gaugeapp-domain-row"><div><strong>{text(mapping.group)}</strong><span>{text(mapping.role)}{mapping.team ? ` · ${text(mapping.team)}` : ""}</span></div><div class="gaugeapp-row-actions"><Show when={props.commands.includes("enterprise-identity.group-mapping.edit")}><button type="button" onClick={() => beginMapping(mapping)}>Edit</button></Show><CommandButton command="enterprise-identity.group-mapping.remove" commands={props.commands} label="Remove" danger payload={{ group: text(mapping.group) }} onSubmit={props.onSubmit} /></div></div>}</For></div>
            </Show>
        </section>
    </>;
}

function IdentityValue(props: { label: string; value: unknown; onCopy: (value: unknown) => void }): JSX.Element {
    return <div><span>{props.label}</span><code>{text(props.value, "Unavailable")}</code><button type="button" onClick={() => props.onCopy(props.value)}>Copy</button></div>;
}

type SubmitPageCommand = (
    commandId: string,
    payload: Readonly<Record<string, unknown>>,
) => Promise<GaugeAppCommandResult>;

// At an event-handler boundary, a disposed view has no error to present.
// Keep rejecting to async callers so redirects and follow-up commands stop.
function ignoreRetiredAction(error: unknown): void {
    if (!(error instanceof DOMException && error.name === "AbortError")) throw error;
}

// The workspace controller has already placed these failures in the visible
// page status. Event handlers have no later caller to reject to.
function ignoreReportedAction(): void {}

type SubmitPageSecret = (
    commandId: "provider-connection.api-key.add" | "provider-connection.compatible.add",
    payload: Readonly<Record<string, unknown>>,
    secret: string,
) => Promise<GaugeAppCommandResult>;

export interface OrganizationInvitationAccess {
    readonly tenant_id: string;
    readonly invitation_id: string;
    readonly proof: string;
}

function PageHeading(props: { app: GaugeAppKind; page: GaugeAppPageModel; scope?: GaugeAppScope }): JSX.Element {
    return <header class="gaugeapp-page-head">
        <div>
            <span class="gaugeapp-eyebrow">{appLabel(props.app, props.scope)}</span>
            <h1>{PAGE_LABELS[props.page.id] ?? props.page.id}</h1>
        </div>
        <Show when={pageFreshnessCaveat(props.page.freshness)}>{(caveat) => <span class="gaugeapp-freshness">{caveat()}</span>}</Show>
    </header>;
}

function CommandButton(props: {
    command: string;
    commands: readonly string[];
    label: string;
    payload?: Readonly<Record<string, unknown>>;
    danger?: boolean;
    disabled?: boolean;
    onSubmit: SubmitPageCommand;
}): JSX.Element {
    return <Show when={props.commands.includes(props.command)}>
        <button
            type="button"
            disabled={props.disabled}
            classList={{ "gaugeapp-danger": props.danger }}
            onClick={() => void props.onSubmit(props.command, props.payload ?? {}).catch(ignoreRetiredAction)}
        >{props.label}</button>
    </Show>;
}

function AccountPage(props: {
    page: GaugeAppPageModel;
    commands: readonly string[];
    onSubmit: SubmitPageCommand;
    onSubmitSecret: SubmitPageSecret;
    api: EnterpriseControlPlane;
    onRefresh: () => Promise<void>;
    deviceLinkInvitation?: DeviceLinkInvitation | null;
    onDeviceLinkClaimed?: () => void;
    organizationInvitation?: OrganizationInvitationAccess | null;
    onOrganizationInvitationResponded?: () => void;
    openExternal?: (url: string) => Promise<boolean>;
}): JSX.Element {
    const typedPage = createMemo(() => parseAccountGaugeAppPage(props.page));
    const account = () => { const page = typedPage(); return page.id === "account" ? page.model : null; };
    const providers = () => { const page = typedPage(); return page.id === "provider-connections" ? page.model : null; };
    const devices = () => { const page = typedPage(); return page.id === "trusted-devices" ? page.model : null; };
    const settings = () => { const page = typedPage(); return page.id === "application-settings" ? page.model : null; };
    const attentionRules = () => parseAttentionRules(JSON.stringify(settings()?.preferences["attention.rules"] ?? null));
    const appearance = () => parseAppearancePreference(settings()?.preferences.appearance, "application-settings.appearance");
    const [displayName, setDisplayName] = createSignal("");
    const [erasureConfirmation, setErasureConfirmation] = createSignal("");
    const [confirmingErasure, setConfirmingErasure] = createSignal(false);
    const [deviceNames, setDeviceNames] = createSignal<Record<string, string>>({});
    const [addingConnection, setAddingConnection] = createSignal(false);
    const [providerKind, setProviderKind] = createSignal("openai");
    const [providerName, setProviderName] = createSignal("");
    const [providerSecret, setProviderSecret] = createSignal("");
    onCleanup(() => setProviderSecret(""));
    const [providerEndpoint, setProviderEndpoint] = createSignal("");
    const [providerModels, setProviderModels] = createSignal("");
    const [defaultModel, setDefaultModel] = createSignal("");
    const [renamingConnection, setRenamingConnection] = createSignal<{ id: string; label: string } | null>(null);
    const [joinCode, setJoinCode] = createSignal("");
    const [joinName, setJoinName] = createSignal("This device");
    const [joinKind, setJoinKind] = createSignal<"computer" | "phone" | "tablet">("computer");
    const [joinStatus, setJoinStatus] = createSignal<AccountDeviceLinkStatus | null>(null);
    const [joinMessage, setJoinMessage] = createSignal("");
    const [joining, setJoining] = createSignal(false);
    const [invitationResponseError, setInvitationResponseError] = createSignal("");
    const [respondingToInvitation, setRespondingToInvitation] = createSignal(false);
    const [linkingConsumer, setLinkingConsumer] = createSignal(false);
    const [consumerLinkUrl, setConsumerLinkUrl] = createSignal("");
    const [consumerLinkMessage, setConsumerLinkMessage] = createSignal("");
    const [avatarBusy, setAvatarBusy] = createSignal(false);
    const [avatarMessage, setAvatarMessage] = createSignal("");
    const [avatarLinkUrl, setAvatarLinkUrl] = createSignal("");
    let avatarInput: HTMLInputElement | undefined;
    const [advancementPath, setAdvancementPath] = createSignal("");
    const [advancementMessage, setAdvancementMessage] = createSignal("");
    const [projectHostSettings, { refetch: refetchProjectHostSettings }] = createGaugeAppResource(
        () => props.page.id === "application-settings" ? props.page.resource_basis : false,
        String,
        async () => props.api.projectHostAccountSettings(),
    );
    const advancementPaths = () => parseAdvancementScopes(
        projectHostSettings()?.[ADVANCEMENT_RULES_SETTING],
    );
    const [invitationPreview] = createResource(
        () => props.organizationInvitation ?? null,
        (access) => props.api.previewOrganizationInvitation(access),
    );
    const respondToInvitation = async (decision: "accept" | "decline") => {
        const access = props.organizationInvitation;
        if (!access) return;
        setRespondingToInvitation(true);
        setInvitationResponseError("");
        try {
            await props.api.respondOrganizationInvitation(access, decision, newIdempotencyKey());
            props.onOrganizationInvitationResponded?.();
            await props.onRefresh();
        } catch (error) {
            setInvitationResponseError(error instanceof Error ? error.message : String(error));
        } finally {
            setRespondingToInvitation(false);
        }
    };
    let pollingDeviceLink = "";
    createEffect(() => {
        props.page.resource_basis;
        setDisplayName(account()?.profile.display_name ?? "");
        const selected = providers()?.default_model;
        setDefaultModel(selected
            ? JSON.stringify([selected.connection_id, selected.model])
            : "");
    });
    createEffect(() => {
        const invitation = props.deviceLinkInvitation;
        if (props.page.id === "trusted-devices" && invitation) setJoinCode(invitation.code);
    });
    const saveDeviceName = (record: TrustedDevicesPageV1["devices"][number]) => {
        const id = text(record.id, "");
        const label = deviceNames()[id] ?? text(record.label, "");
        if (id && label.trim()) void props.onSubmit("trusted-device.rename", { id, label });
    };
    const connections = () => providers()?.connections ?? [];
    const setAttention = (signal: AttentionSignal, level: AttentionLevel) => {
        const next = { ...attentionRules(), [signal]: level };
        return props.onSubmit("application-settings.attention.set", {
            value: JSON.parse(serializeAttentionRules(next)) as unknown,
        });
    };
    const setAppearance = (field: "interface_scale" | "contrast" | "motion", value: string) => {
        const current = appearance();
        return props.onSubmit("application-settings.appearance.set", {
            value: { ...current, [field]: value },
        });
    };
    const writeAdvancementPaths = async (paths: readonly string[]) => {
        setAdvancementMessage("");
        try {
            await props.api.setProjectHostAccountSetting(
                ADVANCEMENT_RULES_SETTING,
                serializeAdvancementScopes(paths),
            );
            await refetchProjectHostSettings();
        } catch (error) {
            setAdvancementMessage(error instanceof Error ? error.message : String(error));
        }
    };
    const addAdvancementPath = () => {
        const path = advancementPath().trim();
        if (!path || path === "**" || advancementPaths().includes(path)) return;
        setAdvancementPath("");
        void writeAdvancementPaths([...advancementPaths(), path]);
    };
    const closeConnectionForm = () => { setProviderSecret(""); setAddingConnection(false); };
    const canAddApiKey = () => props.commands.includes("provider-connection.api-key.add");
    const canAddCompatible = () => props.commands.includes("provider-connection.compatible.add");
    const canAddConnection = () => canAddApiKey() || canAddCompatible();
    const toggleConnectionForm = () => {
        if (addingConnection()) return closeConnectionForm();
        setProviderKind(canAddApiKey() ? "openai" : "openai-generic");
        setAddingConnection(true);
    };
    const modelChoices = () => connections()
        .filter((connection) => connection.status === "active" && connection.verification === "reachable")
        .flatMap((connection) =>
        connection.models.map((model) => ({
            value: JSON.stringify([connection.id, model]),
            label: `${model} · ${connection.name || connection.provider}`,
        })));
    const submitConnection = async () => {
        const provider = providerKind();
        const compatible = provider === "openai-generic";
        const models = providerModels().split(/[\n,]/).map((model) => model.trim()).filter(Boolean);
        const secret = providerSecret();
        setProviderSecret("");
        await props.onSubmitSecret(
            compatible ? "provider-connection.compatible.add" : "provider-connection.api-key.add",
            {
                provider,
                label: providerName().trim(),
                ...(compatible ? { base_url: providerEndpoint().trim(), models } : {}),
            },
            secret,
        );
        setProviderEndpoint("");
        setProviderModels("");
        setProviderName("");
        setAddingConnection(false);
    };
    const saveDefaultModel = () => {
        if (!defaultModel()) return;
        const [connectionId, modelName] = JSON.parse(defaultModel()) as [string, string];
        void props.onSubmit("provider-connection.default-model.set", {
            connection_id: connectionId,
            model: modelName,
        });
    };
    const linkConsumerOidc = async () => {
        setLinkingConsumer(true);
        setConsumerLinkUrl("");
        setConsumerLinkMessage("");
        try {
            const url = await props.api.startConsumerOidcLink();
            setConsumerLinkUrl(url);
            const opened = await props.openExternal?.(url) ?? false;
            setConsumerLinkMessage(opened
                ? "Finish linking in your browser, then refresh these methods."
                : "Your browser did not open. Copy the secure link to continue.");
        } catch (error) {
            setConsumerLinkMessage(error instanceof Error ? error.message : String(error));
        } finally {
            setLinkingConsumer(false);
        }
    };
    // The photo re-fetch is Google's: of the consumer entrances, only Google's
    // token carries a picture (DR-0189, DR-0195), so it is offered only when
    // that exact connection is linked — not for any consumer sign-in.
    const pictureProviderLinked = () => {
        const connection = account()?.consumer_oidc.connection_id;
        return Boolean(connection && account()?.authenticators.some((record) =>
            record.kind === "consumer-oidc" && record.connection_id === connection));
    };
    const uploadAvatar = async (file: File | undefined) => {
        if (!file) return;
        setAvatarBusy(true);
        setAvatarMessage("");
        setAvatarLinkUrl("");
        try {
            const image = await avatarUploadImage(file);
            await props.onSubmit("account.avatar.set", { image });
        } catch (error) {
            if (error instanceof AvatarFileError) setAvatarMessage(error.message);
            else ignoreReportedAction();
        } finally {
            setAvatarBusy(false);
            if (avatarInput) avatarInput.value = "";
        }
    };
    const useProviderAvatar = async () => {
        setAvatarBusy(true);
        setAvatarMessage("");
        setAvatarLinkUrl("");
        try {
            const url = await props.api.startConsumerOidcAvatar();
            setAvatarLinkUrl(url);
            const opened = await props.openExternal?.(url) ?? false;
            setAvatarMessage(opened
                ? `Finish in your browser, then refresh to see your ${account()?.consumer_oidc.label ?? "Google"} photo.`
                : "Your browser did not open. Copy the secure link to continue.");
        } catch (error) {
            setAvatarMessage(error instanceof Error ? error.message : String(error));
        } finally {
            setAvatarBusy(false);
        }
    };
    const openManagedInference = async (action: "subscribe" | "manage") => {
        const response = await props.onSubmit("managed-inference.plan.change", { action });
        const url = text(valueRecord(response.result)?.url, "");
        if (url) window.location.assign(url);
    };
    const beginSubscription = async (provider: "openai-codex" | "xai-grok") => {
        const response = await props.onSubmit("provider-connection.subscription.begin", { provider });
        const login = valueRecord(valueRecord(response.result)?.login);
        const verificationUrl = text(login?.verification_url, "");
        if (verificationUrl) window.open(verificationUrl, "_blank", "noopener,noreferrer");
    };
    const pendingDeviceLink = () => devices()?.pending_link ?? null;
    const finishDeviceLink = async (status: AccountDeviceLinkStatus) => {
        const prepared = await prepareDeviceLinkCompletion(status);
        const completed = await props.api.completeAccountDeviceLink(
            status.link.id,
            prepared.completion,
            prepared.idempotencyKey,
        );
        await finalizeDeviceLink(completed.link);
        setJoinStatus(completed);
        setJoinMessage("This device is linked.");
        await props.onRefresh();
    };
    const pollDeviceLink = async (id: string) => {
        if (pollingDeviceLink === id) return;
        pollingDeviceLink = id;
        try {
            while (pollingDeviceLink === id) {
                const status = await props.api.readAccountDeviceLink(id);
                setJoinStatus(status);
                if (status.link.phase === "authorized") {
                    await finishDeviceLink(status);
                    return;
                }
                if (status.terminal) {
                    if (status.link.phase !== "enrolled") await discardPendingDeviceLink(id);
                    setJoinMessage(status.link.phase === "enrolled" ? "This device is linked." : `Device link ${status.link.phase}.`);
                    return;
                }
                await new Promise((resolve) => window.setTimeout(resolve, 1_000));
            }
        } catch (error) {
            setJoinMessage(error instanceof Error ? error.message : String(error));
        } finally {
            if (pollingDeviceLink === id) pollingDeviceLink = "";
        }
    };
    const joinThisDevice = async () => {
        setJoining(true);
        setJoinMessage("Creating a device key…");
        try {
            const key = await generateDeviceLinkKey();
            const claimed = await props.api.claimAccountDeviceLink({
                id: props.deviceLinkInvitation?.id,
                human_code: joinCode().trim(),
                label: joinName().trim(),
                kind: joinKind(),
                subkey_pubkey: key.publicKey,
            }, newIdempotencyKey());
            await retainPendingDeviceLink(claimed.link.id, key);
            props.onDeviceLinkClaimed?.();
            setJoinStatus(claimed);
            setJoinMessage("Compare the six-digit code on both devices.");
            void pollDeviceLink(claimed.link.id);
        } catch (error) {
            setJoinMessage(error instanceof Error ? error.message : String(error));
        } finally {
            setJoining(false);
        }
    };
    createEffect(() => {
        if (props.page.id !== "trusted-devices") return;
        const link = pendingDeviceLink();
        if (!link) return;
        if (link.phase === "rejected" || link.phase === "canceled" || link.phase === "expired") {
            void discardPendingDeviceLink(link.id).catch(() => undefined);
            return;
        }
        if (link.phase === "enrolled") return;
        void hasPendingDeviceLink(link.id).then((present) => {
            if (present) void pollDeviceLink(link.id);
        });
    });
    return <article class="gaugeapp-page" data-gaugeapp-page={props.page.id}>
        <PageHeading app="account-settings" page={props.page} />

        <Show when={props.page.id === "account"}>
            <Show when={props.organizationInvitation}>
                <section class="gaugeapp-panel gaugeapp-invitation-response">
                    <Show when={!invitationPreview.loading} fallback={<p class="gaugeapp-loading">Opening invitation…</p>}>
                        <Show when={!invitationPreview.error && valueRecord(invitationPreview()?.invitation)} fallback={<div><strong>This invitation link cannot be opened.</strong><span>Ask an organization administrator for a new link.</span></div>}>
                            {(preview) => <>
                                <div><span class="gaugeapp-eyebrow">Organization invitation</span><strong>{text(preview().display_name, "Organization")}</strong><span>Join as {text(preview().role, "member")} · addressed to {text(preview().email, "this recipient")}</span><Show when={!Boolean(preview().account_matches)}><span role="alert">This invitation is for another account. Sign out, sign in with the GaugeDesk account that has this verified email, then open the invitation link again.</span></Show></div>
                                <div class="gaugeapp-actions">
                                    {/* Signed in as the wrong account, Accept and Decline are
                                        disabled; without this the way to the right account was
                                        a Sessions panel further down the page. */}
                                    <Show when={!Boolean(preview().account_matches)}>
                                        <CommandButton command="account.session.revoke-current" commands={props.commands} label="Sign out" payload={{}} onSubmit={props.onSubmit} />
                                    </Show>
                                    <button type="button" disabled={respondingToInvitation() || !Boolean(preview().can_respond)} onClick={() => void respondToInvitation("decline")}>Decline</button>
                                    <button type="button" class="primary" disabled={respondingToInvitation() || !Boolean(preview().can_respond)} onClick={() => void respondToInvitation("accept")}>{respondingToInvitation() ? "Responding…" : "Accept"}</button>
                                </div>
                            </>}
                        </Show>
                    </Show>
                    <Show when={invitationResponseError()}>{(message) => <p role="alert">{message()}</p>}</Show>
                </section>
            </Show>
            <section class="gaugeapp-panel gaugeapp-section-stack">
                <div class="gaugeapp-section-head"><div><h2>Profile</h2><p>The name and photo shown across GaugeDesk.</p></div></div>
                <div class="gaugeapp-avatar-row" data-account-avatar-editor>
                    <Show
                        when={account()?.profile.avatar}
                        fallback={<span class="gaugeapp-avatar gaugeapp-avatar-initials" aria-hidden="true">{avatarInitials(displayName() || account()?.verified_contacts[0]?.email || "")}</span>}
                    >
                        {(src) => <img class="gaugeapp-avatar" src={src()} alt="Your photo" />}
                    </Show>
                    <div class="gaugeapp-actions">
                        <input
                            ref={avatarInput}
                            type="file"
                            accept="image/png,image/jpeg,image/webp,image/gif"
                            hidden
                            onChange={(event) => void uploadAvatar(event.currentTarget.files?.[0])}
                        />
                        <button type="button" disabled={avatarBusy() || !props.commands.includes("account.avatar.set")} onClick={() => avatarInput?.click()}>
                            {account()?.profile.avatar ? "Change photo" : "Upload photo"}
                        </button>
                        <Show when={account()?.consumer_oidc.available && pictureProviderLinked()}>
                            <button type="button" disabled={avatarBusy()} onClick={() => void useProviderAvatar()}>{`Use ${account()?.consumer_oidc.label ?? "Google"} photo`}</button>
                        </Show>
                        <Show when={account()?.profile.avatar}>
                            <button type="button" disabled={avatarBusy() || !props.commands.includes("account.avatar.remove")} onClick={() => void props.onSubmit("account.avatar.remove", {}).catch(ignoreReportedAction)}>Remove photo</button>
                        </Show>
                    </div>
                </div>
                <Show when={avatarMessage()}>{(message) => <div class="gaugeapp-inline-notice" role="status"><span>{message()}</span><div class="gaugeapp-actions"><Show when={avatarLinkUrl()}>{(url) => <button type="button" onClick={() => void navigator.clipboard.writeText(url())}>Copy link</button>}</Show><Show when={avatarLinkUrl()}><button type="button" onClick={() => void props.onRefresh()}>Refresh</button></Show></div></div>}</Show>
                <form class="gaugeapp-inline-form" onSubmit={(event) => {
                    event.preventDefault();
                    void props.onSubmit("account.profile.set", { display_name: displayName() }).catch(ignoreReportedAction);
                }}>
                    <label><span>Display name</span><input value={displayName()} onInput={(event) => setDisplayName(event.currentTarget.value)} /></label>
                    <button type="submit" disabled={!props.commands.includes("account.profile.set") || !displayName().trim()}>Save</button>
                </form>
            </section>
            <section class="gaugeapp-panel gaugeapp-section-stack">
                <div class="gaugeapp-section-head">
                    <div><h2>Sign-in methods</h2><p>Keep at least one independent way to enter your account.</p></div>
                    <div class="gaugeapp-actions">
                        <CommandButton command="account.authenticator.begin-add" commands={props.commands} label="Add passkey" onSubmit={props.onSubmit} payload={{ display_name: displayName() }} />
                        <Show when={account()?.consumer_oidc.available && !account()?.authenticators.some((record) => record.kind === "consumer-oidc")}>
                            <button type="button" disabled={linkingConsumer()} onClick={() => void linkConsumerOidc()}>{linkingConsumer() ? "Opening…" : `Link ${account()?.consumer_oidc.label ?? "Google"}`}</button>
                        </Show>
                    </div>
                </div>
                <Show when={consumerLinkMessage()}>{(message) => <div class="gaugeapp-inline-notice" role="status"><span>{message()}</span><div class="gaugeapp-actions"><Show when={consumerLinkUrl()}>{(url) => <button type="button" onClick={() => void navigator.clipboard.writeText(url())}>Copy link</button>}</Show><button type="button" onClick={() => void props.onRefresh()}>Refresh</button></div></div>}</Show>
                <Show when={(account()?.authenticators.length ?? 0) > 0} fallback={<p class="gaugeapp-empty">No additional authenticators.</p>}>
                    <div class="gaugeapp-rows"><For each={account()?.authenticators ?? []}>{(record) => {
                        const passkey = record.kind === "passkey";
                        return <div class="gaugeapp-row gaugeapp-row-action">
                            <div><strong>{passkey ? record.label : record.kind === "consumer-oidc" ? "Google" : "Corporate sign-in"}</strong><span>{passkey ? "Passkey" : record.connection_id}</span></div>
                            <Show when={record.can_remove}
                                fallback={<span class="gaugeapp-row-note">{record.remove_blocked_reason}</span>}>
                                <CommandButton command="account.authenticator.remove" commands={props.commands} label="Remove" danger
                                    payload={{ id: record.id, kind: passkey ? "passkey" : "external" }} onSubmit={props.onSubmit} />
                            </Show>
                        </div>;
                    }}</For></div>
                </Show>
                <div class="gaugeapp-section-head">
                    <div><h2>Recovery codes</h2><p>New codes are shown once and replace every previous batch.</p></div>
                    <CommandButton command="account.recovery-codes.reissue" commands={props.commands} label="Issue new codes" onSubmit={props.onSubmit} />
                </div>
                <ModelRows values={account()?.recovery.batches ?? []} empty="No active recovery-code batch."
                    title={(record) => `${record.remaining_codes} codes remaining`}
                    detail={(record) => record.created_at > 0 ? `Created ${new Date(record.created_at * 1000).toLocaleDateString()}` : "Created date unavailable"} />
            </section>
            <section class="gaugeapp-panel gaugeapp-section-stack">
                <div class="gaugeapp-section-head">
                    <div><h2>Sessions</h2><p>Revoke a session you no longer recognize.</p></div>
                    <Show when={account()?.sessions.some((record) => record.current) && account()?.sessions.some((record) => !record.current)}>
                        <CommandButton command="account.session.revoke-others" commands={props.commands} label="Sign out other sessions" onSubmit={props.onSubmit} />
                    </Show>
                </div>
                <Show when={(account()?.sessions.length ?? 0) > 0} fallback={<p class="gaugeapp-empty">No active hosted sessions.</p>}>
                    <div class="gaugeapp-rows"><For each={account()?.sessions ?? []}>{(record) => {
                        const id = text(record.id, "");
                        const current = record.current === true;
                        return <div class="gaugeapp-row gaugeapp-row-action">
                            <div><strong>{current ? "This session" : text(record.method, "Session")}</strong><span>{text(record.method, "Unknown method")}</span></div>
                            <CommandButton command={current ? "account.session.revoke-current" : "account.session.revoke"}
                                commands={props.commands} label="Sign out" danger payload={current ? {} : { id }} onSubmit={props.onSubmit} />
                        </div>;
                    }}</For></div>
                </Show>
            </section>
            <section class="gaugeapp-panel gaugeapp-section-stack">
                <div class="gaugeapp-section-head"><div><h2>Organizations</h2><p>Your memberships and pending invitations.</p></div></div>
                <Show when={(account()?.memberships.length ?? 0) > 0} fallback={<p class="gaugeapp-empty">No organization memberships.</p>}>
                    <div class="gaugeapp-rows"><For each={account()?.memberships ?? []}>{(record) => <div class="gaugeapp-row gaugeapp-row-action">
                        <div>
                            <strong>{text(record.display_name, text(record.id, "Organization"))}</strong>
                            <span>{text(record.role, "member")}{record.personal === true ? " · Personal" : ""}</span>
                        </div>
                        <Show when={record.can_leave} fallback={<Show when={!record.personal && record.leave_blocked_reason}><span class="gaugeapp-row-note">{record.leave_blocked_reason}</span></Show>}>
                            <CommandButton command="account.membership.leave" commands={props.commands} label="Leave" danger
                                payload={{ tenant_id: record.id }} onSubmit={props.onSubmit} />
                        </Show>
                    </div>}</For></div>
                </Show>
                <Show when={(account()?.invitations.length ?? 0) > 0}>
                    <div class="gaugeapp-rows"><For each={account()?.invitations ?? []}>{(record) => {
                        const tenantId = record.tenant_id;
                        return <div class="gaugeapp-row gaugeapp-row-action">
                            <div><strong>{text(record.display_name, "Organization invitation")}</strong><span>{text(record.role, "member")}</span></div>
                            <div class="gaugeapp-actions">
                                <CommandButton command="account.invitation.decline" commands={props.commands} label="Decline" payload={{ tenant_id: tenantId }} onSubmit={props.onSubmit} />
                                <CommandButton command="account.invitation.accept" commands={props.commands} label="Accept" payload={{ tenant_id: tenantId }} onSubmit={props.onSubmit} />
                            </div>
                        </div>;
                    }}</For></div>
                </Show>
            </section>
            <section class="gaugeapp-panel gaugeapp-section-stack gaugeapp-danger-zone">
                <div class="gaugeapp-section-head">
                    <div><h2>Delete account</h2><p>Permanently remove your GaugeDesk account and its private content.</p></div>
                    <Show when={!confirmingErasure()}>
                        <button type="button" class="danger"
                            disabled={!props.commands.includes("account.erase") || !account()?.erasure.available || (account()?.erasure.blocking_organizations.length ?? 0) > 0}
                            onClick={() => setConfirmingErasure(true)}>Delete</button>
                    </Show>
                </div>
                <Show when={!account()?.erasure.available}>
                    <p class="gaugeapp-unavailable">Account deletion is unavailable until this server has completed account-content custody setup.</p>
                </Show>
                <Show when={(account()?.erasure.blocking_organizations.length ?? 0) > 0}>
                    <div class="gaugeapp-inline-notice" role="status"><span>Transfer ownership or delete these organizations first: {account()?.erasure.blocking_organizations.join(", ")}</span></div>
                </Show>
                <Show when={confirmingErasure()}>
                    <form class="gaugeapp-inline-form" onSubmit={(event) => {
                        event.preventDefault();
                        void props.onSubmit("account.erase", { confirmation: erasureConfirmation() })
                            .then(() => { setErasureConfirmation(""); setConfirmingErasure(false); })
                            .catch(ignoreReportedAction);
                    }}>
                        <label><span>Enter {account()?.erasure.confirmation} to continue</span><input required autocomplete="off" value={erasureConfirmation()} onInput={(event) => setErasureConfirmation(event.currentTarget.value)} /></label>
                        <div class="gaugeapp-actions"><button type="button" onClick={() => { setErasureConfirmation(""); setConfirmingErasure(false); }}>Cancel</button><button type="submit" class="danger" disabled={erasureConfirmation() !== account()?.erasure.confirmation}>Continue</button></div>
                    </form>
                </Show>
            </section>
        </Show>

        <Show when={props.page.id === "provider-connections"}>
            <section class="gaugeapp-panel gaugeapp-section-stack">
                <div class="gaugeapp-section-head"><div><h2>Connections</h2><p>Your keys stay sealed; provider account tokens never pass through the browser.</p></div><Show when={canAddConnection()}><button type="button" onClick={toggleConnectionForm}>{addingConnection() ? "Close" : "Add connection"}</button></Show></div>
                <Show when={addingConnection()}><form class="gaugeapp-provider-form" onSubmit={(event) => { event.preventDefault(); void submitConnection().catch(ignoreReportedAction); }}>
                    <label><span>Connection type</span><select value={providerKind()} onChange={(event) => setProviderKind(event.currentTarget.value)}><Show when={canAddApiKey()}><option value="openai">OpenAI API key</option><option value="anthropic">Anthropic API key</option></Show><Show when={canAddCompatible()}><option value="openai-generic">OpenAI-compatible endpoint</option></Show></select></label>
                    <label><span>Name</span><input value={providerName()} placeholder="Optional label" onInput={(event) => setProviderName(event.currentTarget.value)} /></label>
                    <Show when={providerKind() === "openai-generic"}><label class="wide"><span>Endpoint</span><input type="url" value={providerEndpoint()} placeholder="https://models.example/v1" onInput={(event) => setProviderEndpoint(event.currentTarget.value)} /></label><label class="wide"><span>Models</span><input value={providerModels()} placeholder="model-one, model-two" onInput={(event) => setProviderModels(event.currentTarget.value)} /></label></Show>
                    <label class="wide"><span>API key</span><input type="password" autocomplete="off" value={providerSecret()} onInput={(event) => setProviderSecret(event.currentTarget.value)} /></label>
                    <div class="gaugeapp-form-actions"><button type="button" onClick={closeConnectionForm}>Cancel</button><button type="submit" disabled={!providerSecret().trim() || (providerKind() === "openai-generic" && (!providerEndpoint().trim() || !providerModels().trim()))}>Connect</button></div>
                </form></Show>
                <Show when={connections().length > 0} fallback={<p class="gaugeapp-empty">No provider connections yet.</p>}><div class="gaugeapp-provider-list"><For each={connections()}>{(connection) => {
                    const id = text(connection.id, "");
                    const editing = () => renamingConnection()?.id === id;
                    const active = () => connection.status === "active";
                    return <div class="gaugeapp-provider-row">
                        <Show when={editing()} fallback={<div><strong>{text(connection.name, text(connection.provider, "Provider"))}</strong><span>{text(connection.provider, "Provider")}</span></div>}>
                            <input aria-label={`Rename ${text(connection.name, "connection")}`} value={renamingConnection()?.label ?? ""} onInput={(event) => setRenamingConnection({ id, label: event.currentTarget.value })} />
                        </Show>
                        <span class={`gaugeapp-connection-state ${active() ? text(connection.verification, "unverified") : "revoked"}`}>{active() ? text(connection.verification, "unverified") : "revoked"}</span>
                        <div class="gaugeapp-card-actions">
                            <Show when={editing()} fallback={<button type="button" disabled={!active() || !props.commands.includes("provider-connection.rename")} onClick={() => setRenamingConnection({ id, label: text(connection.name, "") })}>Rename</button>}><button type="button" disabled={!active() || !props.commands.includes("provider-connection.rename") || !renamingConnection()?.label.trim()} onClick={() => { const draft = renamingConnection(); if (draft) void props.onSubmit("provider-connection.rename", draft); setRenamingConnection(null); }}>Save</button></Show>
                            <button type="button" disabled={!active() || !props.commands.includes("provider-connection.verify")} onClick={() => void props.onSubmit("provider-connection.verify", { id })}>Verify</button>
                            <CommandButton command="provider-connection.revoke" commands={props.commands} label="Revoke" danger disabled={!active()} payload={{ id }} onSubmit={props.onSubmit} />
                        </div>
                    </div>;
                }}</For></div></Show>
            </section>
            <section class="gaugeapp-panel gaugeapp-section-stack">
                <div class="gaugeapp-section-head"><div><h2>Provider accounts</h2><p>Use an existing subscription instead of an API key.</p></div></div>
                <For each={[
                    ["openai-codex", "ChatGPT / Codex", providers()?.subscription_sign_ins.codex],
                    ["xai-grok", "Grok", providers()?.subscription_sign_ins.grok],
                ] as const}>{([provider, label, status]) => {
                    const login = () => status?.login;
                    const linked = () => status?.linked === true;
                    const pending = () => ["pending", "cancelling"].includes(text(login()?.status, ""));
                    return <div class="gaugeapp-provider-account-row">
                        <div><strong>{label}</strong><span>{linked() ? "Connected" : pending() ? "Waiting for provider" : "Not connected"}</span></div>
                        <Show when={login()?.user_code}><code>{text(login()?.user_code, "")}</code></Show>
                        <div class="gaugeapp-card-actions">
                            <Show when={pending()} fallback={<Show when={linked()} fallback={<button type="button" disabled={!props.commands.includes("provider-connection.subscription.begin")} onClick={() => void beginSubscription(provider)}>Sign in</button>}><button type="button" disabled={!props.commands.includes("provider-connection.subscription.complete")} onClick={() => void props.onSubmit("provider-connection.subscription.complete", { provider, action: "status" })}>Refresh status</button></Show>}>
                                <Show when={login()?.verification_url}><a href={text(login()?.verification_url, "#")} target="_blank" rel="noreferrer">Open</a></Show>
                                <button type="button" disabled={!props.commands.includes("provider-connection.subscription.complete")} onClick={() => void props.onSubmit("provider-connection.subscription.complete", { provider, action: "status" })}>I finished</button>
                                <button type="button" disabled={!props.commands.includes("provider-connection.subscription.complete")} onClick={() => void props.onSubmit("provider-connection.subscription.complete", { provider, action: "cancel" })}>Cancel</button>
                            </Show>
                        </div>
                    </div>;
                }}</For>
            </section>
            <section class="gaugeapp-panel gaugeapp-section-stack">
                <div class="gaugeapp-section-head"><div><h2>Default model</h2><p>Used when a project does not select another admitted connection.</p></div></div>
                <form class="gaugeapp-inline-form" onSubmit={(event) => { event.preventDefault(); saveDefaultModel(); }}>
                    <label><span>Model</span><select value={defaultModel()} onChange={(event) => setDefaultModel(event.currentTarget.value)}><option value="" selected={!defaultModel()}>Choose a verified model</option><For each={modelChoices()}>{(choice) => <option value={choice.value} selected={defaultModel() === choice.value}>{choice.label}</option>}</For></select></label>
                    <button type="submit" disabled={!defaultModel() || !props.commands.includes("provider-connection.default-model.set")}>Save</button>
                </form>
            </section>
            <section class="gaugeapp-panel gaugeapp-section-stack">
                <Show when={providers()?.managed_inference}>{(managed) => {
                    const presentation = () => managedInferencePresentation(managed());
                    return <><div class="gaugeapp-section-head"><div><h2>Managed inference</h2><p>{presentation().description}</p></div><button type="button" disabled={!props.commands.includes("managed-inference.plan.change") || !presentation().available} aria-describedby={presentation().unavailableReason ? "managed-inference-unavailable" : undefined} onClick={() => void openManagedInference(presentation().action)}>{presentation().label}</button></div><Show when={presentation().unavailableReason}>{(reason) => <p id="managed-inference-unavailable" class="gaugeapp-empty">{reason()}</p>}</Show></>;
                }}</Show>
            </section>
        </Show>

        <Show when={props.page.id === "trusted-devices"}>
            <section class="gaugeapp-panel gaugeapp-section-stack">
                <div class="gaugeapp-section-head"><div><h2>Trusted devices</h2><p>Computers and phones admitted to act as you.</p></div></div>
                {/* Third of the three things a person has to keep apart, beside
                    Project Hosts and project Homes. A device acts as you and
                    reaches a Home; it never holds one. */}
                <Notice tone="neutral"><strong>Trusted Devices are account clients, not Project Hosts.</strong> They act as you, discover opaque project routes, and ask each project Home for access. Project data stays on its Project Host.</Notice>
                <Show when={(devices()?.devices.length ?? 0) > 0} fallback={<p class="gaugeapp-empty">No trusted devices are registered.</p>}>
                    <div class="gaugeapp-rows"><For each={devices()?.devices ?? []}>{(record) => {
                        const id = text(record.id, "");
                        const name = () => deviceNames()[id] ?? (record.label || "Device");
                        const enrolled = typeof record.enrolled_at === "number" && record.enrolled_at > 0
                            ? `Linked ${new Date(record.enrolled_at * 1_000).toLocaleDateString()}`
                            : "Enrollment date unavailable";
                        const kind = record.kind === "unknown"
                            ? "Device"
                            : `${record.kind.charAt(0).toUpperCase()}${record.kind.slice(1)}`;
                        const lastSeen = record.last_seen_ms
                            ? `Seen ${new Date(record.last_seen_ms).toLocaleString([], { dateStyle: "medium", timeStyle: "short" })}`
                            : "No session activity";
                        const revoked = record.status === "revoked";
                        return <div class="gaugeapp-device-edit">
                            <div><input aria-label={`Name ${name()}`} value={name()} disabled={revoked} onInput={(event) => setDeviceNames((values) => ({ ...values, [id]: event.currentTarget.value }))} /><small>{kind} · {enrolled}</small></div>
                            <div class="gaugeapp-device-access"><strong>{record.current ? "This session" : text(record.status, "unknown")}</strong><small>{lastSeen}</small></div>
                            <div class="gaugeapp-card-actions"><button type="button" disabled={revoked || !props.commands.includes("trusted-device.rename") || !name().trim()} onClick={() => saveDeviceName(record)}>Save</button>
                            <CommandButton command="trusted-device.revoke" commands={props.commands} label="Revoke" danger disabled={revoked} payload={{ id }} onSubmit={props.onSubmit} /></div>
                        </div>;
                    }}</For></div>
                </Show>
            </section>
            <section class="gaugeapp-panel gaugeapp-section-stack">
                <div class="gaugeapp-section-head"><div><h2>Link a device</h2><p>Start here on a device you already trust.</p></div>
                    <Show when={!pendingDeviceLink() || pendingDeviceLink()?.phase === "enrolled" || pendingDeviceLink()?.phase === "rejected" || pendingDeviceLink()?.phase === "canceled" || pendingDeviceLink()?.phase === "expired"}>
                        <button type="button" disabled={!props.commands.includes("trusted-device.link.begin") || devices()?.link_availability.available !== true} onClick={() => void props.onSubmit("trusted-device.link.begin", {})}>New code</button>
                    </Show>
                </div>
                <Show when={devices()?.link_availability.available !== true}>
                    <p class="gaugeapp-unavailable">{devices()?.link_availability.available === false ? devices()?.link_availability.reason : "Device linking is unavailable for this account."}</p>
                </Show>
                <Show when={pendingDeviceLink()}>{(link) => <div class="gaugeapp-device-link">
                    <Show when={link().phase === "waiting-for-device"}>
                        <div class="gaugeapp-device-link-code">
                            <div class="gaugeapp-device-qr" innerHTML={qrSvg(deviceLinkBrowserUrl({ id: link().id, code: link().human_code }, window.location.href), 3)} />
                            <div><span>Enter on the new device</span><strong>{link().human_code}</strong><small>Expires {new Date(link().expires_at_ms).toLocaleTimeString([], { hour: "numeric", minute: "2-digit" })}</small></div>
                        </div>
                        <p>Waiting for the new device to prove its key.</p>
                        <div class="gaugeapp-detail-actions gaugeapp-detail-actions-end"><CommandButton command="trusted-device.link.cancel" commands={props.commands} label="Cancel" payload={{ id: link().id }} onSubmit={props.onSubmit} /></div>
                    </Show>
                    <Show when={link().phase === "awaiting-acceptance"}>
                        <div class="gaugeapp-device-compare"><div><span>{link().device?.label ?? "New device"}</span><small>{link().device?.kind ?? "device"}</small></div><div><span>Compare on both devices</span><strong>{link().sas}</strong></div></div>
                        <p>Accept only if the six digits match exactly.</p>
                        <div class="gaugeapp-detail-actions gaugeapp-detail-actions-end">
                            <CommandButton command="trusted-device.link.reject" commands={props.commands} label="Does not match" danger payload={{ id: link().id }} onSubmit={props.onSubmit} />
                            <CommandButton command="trusted-device.link.accept" commands={props.commands} label="Codes match — accept" payload={{ id: link().id }} onSubmit={props.onSubmit} />
                        </div>
                    </Show>
                    <Show when={link().phase === "authorized"}>
                        <div class="gaugeapp-device-compare"><div><span>{link().device?.label ?? "New device"}</span><small>Accepted</small></div><div><span>Waiting for completion</span><strong>{link().sas}</strong></div></div>
                        <p>The account key was sealed to that device. It must verify and open it before enrollment completes.</p>
                        <div class="gaugeapp-detail-actions gaugeapp-detail-actions-end"><CommandButton command="trusted-device.link.cancel" commands={props.commands} label="Cancel" danger payload={{ id: link().id }} onSubmit={props.onSubmit} /></div>
                    </Show>
                    <Show when={link().phase === "enrolled"}><p class="gaugeapp-success">{link().device?.label ?? "Device"} is linked.</p></Show>
                    <Show when={link().phase === "rejected"}><p class="gaugeapp-empty">The device was rejected. No account material was admitted.</p></Show>
                    <Show when={link().phase === "canceled"}><p class="gaugeapp-empty">The device link was canceled.</p></Show>
                    <Show when={link().phase === "expired"}><p class="gaugeapp-empty">The device code expired. Start a new one when both devices are ready.</p></Show>
                </div>}</Show>
            </section>
            <section class="gaugeapp-panel gaugeapp-section-stack">
                <div class="gaugeapp-section-head"><div><h2>On the new device</h2><p>Enter the code from a device that already belongs to this account.</p></div></div>
                <form class="gaugeapp-device-join" onSubmit={(event) => { event.preventDefault(); void joinThisDevice(); }}>
                    <label><span>Link code</span><input autocomplete="one-time-code" value={joinCode()} placeholder="ABCD-EF12" onInput={(event) => setJoinCode(event.currentTarget.value.toUpperCase())} /></label>
                    <label><span>Device name</span><input value={joinName()} onInput={(event) => setJoinName(event.currentTarget.value)} /></label>
                    <label><span>Kind</span><select value={joinKind()} onChange={(event) => setJoinKind(event.currentTarget.value as "computer" | "phone" | "tablet")}><option value="computer">Computer</option><option value="phone">Phone</option><option value="tablet">Tablet</option></select></label>
                    <button type="submit" disabled={joining() || !joinCode().trim() || !joinName().trim()}>{joining() ? "Linking…" : "Continue"}</button>
                </form>
                <Show when={joinStatus()}>{(status) => <div class="gaugeapp-device-join-status"><span>{status().link.device?.label ?? "This device"}</span><strong>{status().link.sas ?? status().link.phase}</strong><small>{status().link.phase === "awaiting-acceptance" ? "Compare this code with the trusted device." : status().link.phase}</small></div>}</Show>
                <Show when={joinMessage()}>{(message) => <p class="gaugeapp-empty" role="status">{message()}</p>}</Show>
            </section>
        </Show>

        <Show when={props.page.id === "application-settings"}>
            <section class="gaugeapp-panel gaugeapp-section-stack">
                <div class="gaugeapp-section-head"><div><h2>Appearance & accessibility</h2><p>These choices follow your account and apply to the whole Desk.</p></div><span>{settings()?.appearance_saved ? "Saved for your account" : "Using product defaults"}</span></div>
                <div class="gaugeapp-setting-row">
                    <div><strong>Interface size</strong><span>Increase controls and text without changing document zoom.</span></div>
                    <select aria-label="Interface size" value={appearance().interface_scale} disabled={!props.commands.includes("application-settings.appearance.set")} onChange={(event) => void setAppearance("interface_scale", event.currentTarget.value)}>
                        <option value="standard">Standard</option><option value="large">Large</option>
                    </select>
                </div>
                <div class="gaugeapp-setting-row">
                    <div><strong>Contrast</strong><span>Strengthen boundaries and secondary text throughout Desk.</span></div>
                    <select aria-label="Contrast" value={appearance().contrast} disabled={!props.commands.includes("application-settings.appearance.set")} onChange={(event) => void setAppearance("contrast", event.currentTarget.value)}>
                        <option value="standard">Standard</option><option value="high">High</option>
                    </select>
                </div>
                <div class="gaugeapp-setting-row">
                    <div><strong>Motion</strong><span>Follow the device preference or minimize interface animation.</span></div>
                    <select aria-label="Motion" value={appearance().motion} disabled={!props.commands.includes("application-settings.appearance.set")} onChange={(event) => void setAppearance("motion", event.currentTarget.value)}>
                        <option value="system">Use device setting</option><option value="reduced">Reduce motion</option>
                    </select>
                </div>
            </section>
            <section class="gaugeapp-panel gaugeapp-section-stack">
                <div class="gaugeapp-section-head"><div><h2>Attention</h2><p>Choose which events should interrupt you. These choices follow your account across Desk clients.</p></div></div>
                <For each={ATTENTION_SIGNALS}>{(meta) => <div class="gaugeapp-setting-row gaugeapp-attention-row">
                    <div><strong>{meta.label}</strong><span>{meta.hint}</span></div>
                    <select
                        aria-label={meta.label}
                        value={attentionRules()[meta.signal]}
                        disabled={!props.commands.includes("application-settings.attention.set")}
                        onChange={(event) => void setAttention(meta.signal, event.currentTarget.value as AttentionLevel)}
                    >
                        <option value="queue">Task bar</option>
                        <option value="badge">Badge only</option>
                        <option value="mute">Transcript only</option>
                    </select>
                </div>}</For>
            </section>
            <section class="gaugeapp-panel gaugeapp-section-stack">
                <div class="gaugeapp-section-head"><div><h2>Automatic keep</h2><p>On the current Project Host, keep turns that only change these paths.</p></div></div>
                <Show when={projectHostSettings()} fallback={<>
                    <p class="gaugeapp-unavailable" role="alert">{projectHostSettings.loading ? "Loading Project Host settings…" : "The current Project Host’s settings are unavailable."}</p>
                    <Show when={!projectHostSettings.loading}><div class="gaugeapp-actions"><button type="button" onClick={() => void refetchProjectHostSettings().catch(() => undefined)}>Retry</button></div></Show>
                </>}>
                    <ul class="gaugeapp-setting-chips">
                        <For each={advancementPaths()} fallback={<li class="gaugeapp-empty">Off — every changed turn waits for review.</li>}>
                            {(path) => <li><code>{path}</code><button type="button" aria-label={`Remove ${path}`} onClick={() => void writeAdvancementPaths(advancementPaths().filter((candidate) => candidate !== path))}>Remove</button></li>}
                        </For>
                    </ul>
                    <form class="gaugeapp-inline-form" onSubmit={(event) => { event.preventDefault(); addAdvancementPath(); }}>
                        <label><span>Path or glob</span><input value={advancementPath()} placeholder="docs/**" onInput={(event) => setAdvancementPath(event.currentTarget.value)} /></label>
                        <button type="submit" disabled={!advancementPath().trim() || advancementPath().trim() === "**" || advancementPaths().includes(advancementPath().trim())}>Add</button>
                    </form>
                    <p class="gaugeapp-setting-note">Permission changes and turns that read externally governed content still wait.</p>
                    <Show when={advancementMessage()}>{(message) => <p class="gaugeapp-unavailable" role="status">Could not update this Project Host: {message()}</p>}</Show>
                </Show>
            </section>
        </Show>
    </article>;
}

type LibraryAgent = CommercialArchetypeRef;

interface ServiceDraft {
    readonly id: string;
    readonly label: string;
    readonly cadence: string;
    readonly description: string;
}

const freshService = (): ServiceDraft => ({
    id: `service-${crypto.randomUUID()}`, label: "", cadence: "", description: "",
});

function PriceFields(props: {
    readonly prices: readonly PriceDraft[];
    readonly onChange: (id: string, patch: Partial<PriceDraft>) => void;
    readonly onRemove: (id: string) => void;
}): JSX.Element {
    return <div class="gaugeapp-editor-rows"><For each={props.prices}>{(price) => <div class="gaugeapp-price-row">
        <label><span>Label</span><input value={price.label} onInput={(event) => props.onChange(price.id, { label: event.currentTarget.value })} /></label>
        <label><span>Type</span><select value={price.kind} onChange={(event) => props.onChange(price.id, { kind: event.currentTarget.value as PriceDraft["kind"] })}><option value="one-time">One time</option><option value="recurring">Recurring</option><option value="per-seat">Per seat</option><option value="metered-usage">Metered usage</option><option value="cost-plus">Cost plus</option></select></label>
        <label><span>{price.kind === "cost-plus" ? "Markup %" : "Amount"}</span><input type="number" min="0" step={price.kind === "cost-plus" ? "0.01" : commercialAmountStep(price.currency)} value={price.amount} onInput={(event) => props.onChange(price.id, { amount: event.currentTarget.value })} /></label>
        <label><span>Currency</span><input maxlength="3" aria-label={`Currency for ${price.label}`} value={price.currency.toUpperCase()} onInput={(event) => props.onChange(price.id, { currency: event.currentTarget.value.toLowerCase() })} /></label>
        <Show when={price.kind !== "one-time"}><label><span>Cadence</span><select value={price.cadence} onChange={(event) => props.onChange(price.id, { cadence: event.currentTarget.value as PriceDraft["cadence"] })}><Show when={price.kind === "metered-usage" || price.kind === "cost-plus"}><option value="">As used</option></Show><option value="monthly">Monthly</option><option value="annual">Annual</option></select></label></Show>
        <Show when={price.kind === "metered-usage"}><label><span>Unit</span><input value={price.unit} onInput={(event) => props.onChange(price.id, { unit: event.currentTarget.value })} /></label></Show>
        <label><span>Collect</span><select value={price.collection} onChange={(event) => props.onChange(price.id, { collection: event.currentTarget.value as PriceDraft["collection"] })}><option value="in-advance">In advance</option><option value="in-arrears">In arrears</option></select></label>
        <Show when={price.kind === "per-seat" || price.kind === "metered-usage"}><label><span>Minimum</span><input type="number" min="0" value={price.minimum} onInput={(event) => props.onChange(price.id, { minimum: event.currentTarget.value })} /></label><label><span>Maximum</span><input type="number" min="0" value={price.maximum} onInput={(event) => props.onChange(price.id, { maximum: event.currentTarget.value })} /></label></Show>
        <button type="button" class="gaugeapp-icon-action" aria-label={`Remove ${price.label}`} disabled={props.prices.length === 1} onClick={() => props.onRemove(price.id)}>Remove</button>
    </div>}</For></div>;
}

function ProductEditor(props: {
    readonly product?: CommercialProduct;
    readonly agents: readonly LibraryAgent[];
    readonly commands: readonly string[];
    readonly onSubmit: SubmitPageCommand;
    readonly onClose: () => void;
}): JSX.Element {
    const commercial = props.product?.commercial;
    const currentArchetype = commercial?.archetype;
    const initialAgent = initialLibraryAgent(props.agents, currentArchetype);
    const [choice, setChoice] = createSignal(initialAgent ? agentChoice(initialAgent) : "");
    const selectedAgent = createMemo(() => props.agents.find((agent) => agentChoice(agent) === choice()));
    const [listingTitle, setListingTitle] = createSignal(text(commercial?.listing_title, initialAgent?.name ?? ""));
    const [description, setDescription] = createSignal(text(commercial?.description, ""));
    const [versionPolicy, setVersionPolicy] = createSignal(text(commercial?.sale_version_policy, "current-at-proposal"));
    const [delivery, setDelivery] = createSignal(text(commercial?.delivery, initialAgent?.kind === "panel-agent" ? "provider-hosted-panel" : "customer-project-placement"));
    const initialPrices = priceDrafts(commercial?.prices ?? []);
    const [prices, setPrices] = createSignal<readonly PriceDraft[]>(initialPrices.length > 0 ? initialPrices : [freshPrice()]);
    const initialServices = (commercial?.service_obligations ?? []).map((service): ServiceDraft => {
        return {
            id: text(service.id, `service-${crypto.randomUUID()}`),
            label: text(service.label, ""),
            cadence: text(service.cadence, ""),
            description: text(service.description, ""),
        };
    });
    const [services, setServices] = createSignal<readonly ServiceDraft[]>(initialServices);
    const updatePrice = (id: string, patch: Partial<PriceDraft>) => setPrices((values) =>
        values.map((price) => price.id === id ? { ...price, ...patch } : price));
    const updateService = (id: string, patch: Partial<ServiceDraft>) => setServices((values) =>
        values.map((service) => service.id === id ? { ...service, ...patch } : service));
    createEffect(() => {
        if (selectedAgent()?.kind !== "panel-agent" && delivery() === "provider-hosted-panel") {
            setDelivery("customer-project-placement");
        }
    });
    const valid = createMemo(() => Boolean(
        selectedAgent() && listingTitle().trim() && prices().length > 0 &&
        prices().every(validPriceDraft) && new Set(prices().map((price) => price.currency.toLowerCase())).size === 1 &&
        services().every((service) => service.label.trim()),
    ));
    const submit = async () => {
        const agent = selectedAgent();
        if (!agent || !valid()) return;
        const revision = {
            archetype: agent,
            sale_version_policy: versionPolicy(),
            listing_title: listingTitle().trim(),
            description: description().trim(),
            prices: pricePayloads(prices()),
            delivery: delivery(),
            service_obligations: services().map((service) => ({
                id: service.id,
                label: service.label.trim(),
                description: service.description.trim(),
                ...(service.cadence.trim() ? { cadence: service.cadence.trim() } : {}),
            })),
        };
        const id = typeof props.product?.id === "string" ? props.product.id : `product-${crypto.randomUUID()}`;
        await props.onSubmit(props.product ? "commercial-product.revise" : "commercial-product.create", { id, revision });
        props.onClose();
    };
    return <form class="gaugeapp-editor" onSubmit={(event) => { event.preventDefault(); void submit(); }}>
        <header class="gaugeapp-editor-head">
            <div><span>{props.product ? "Edit commercial revision" : "New product"}</span><strong>{listingTitle() || "Untitled product"}</strong></div>
            <button type="button" onClick={props.onClose}>Close</button>
        </header>
        <div class="gaugeapp-editor-grid gaugeapp-editor-grid-primary">
            <label><span>Library Agent</span><input list="commercial-library-agents" value={choice()} onInput={(event) => setChoice(event.currentTarget.value)} /></label>
            <Show when={currentArchetype && !selectedAgent()}><p class="gaugeapp-unavailable">The original Agent version is not available in Library. Choose an available Agent explicitly to save a revision.</p></Show>
            <datalist id="commercial-library-agents"><For each={props.agents}>{(agent) => <option value={agentChoice(agent)} />}</For></datalist>
            <label><span>Version</span><select value={versionPolicy()} onChange={(event) => setVersionPolicy(event.currentTarget.value)}><option value="current-at-proposal">Current when proposed</option><option value="pinned-version">Pin version {selectedAgent()?.version ?? ""}</option></select></label>
            <label><span>Listing title</span><input maxlength="120" value={listingTitle()} onInput={(event) => setListingTitle(event.currentTarget.value)} /></label>
            <label><span>Delivery</span><select value={delivery()} onChange={(event) => setDelivery(event.currentTarget.value)}><Show when={selectedAgent()?.kind === "panel-agent"}><option value="provider-hosted-panel">Provider-hosted Panel</option></Show><option value="customer-project-placement">Install in one customer project</option></select></label>
            <label class="gaugeapp-field-wide"><span>Description</span><textarea maxlength="500" rows="2" value={description()} onInput={(event) => setDescription(event.currentTarget.value)} /></label>
        </div>
        <section class="gaugeapp-editor-section">
            <div class="gaugeapp-editor-section-head"><div><strong>Pricing</strong><span>One currency per product.</span></div><button type="button" onClick={() => setPrices((values) => [...values, freshPrice(values[0]?.currency)])}>Add charge</button></div>
            <PriceFields prices={prices()} onChange={updatePrice} onRemove={(id) => setPrices((values) => values.filter((candidate) => candidate.id !== id))} />
        </section>
        <section class="gaugeapp-editor-section">
            <div class="gaugeapp-editor-section-head"><div><strong>Services included</strong><span>Promises included with every engagement.</span></div><button type="button" onClick={() => setServices((values) => [...values, freshService()])}>Add service</button></div>
            <Show when={services().length > 0} fallback={<p class="gaugeapp-empty">No service obligations included.</p>}><div class="gaugeapp-editor-rows"><For each={services()}>{(service) => <div class="gaugeapp-service-row">
                <label><span>Service</span><input value={service.label} onInput={(event) => updateService(service.id, { label: event.currentTarget.value })} /></label>
                <label><span>Cadence</span><input placeholder="Optional" value={service.cadence} onInput={(event) => updateService(service.id, { cadence: event.currentTarget.value as PriceDraft["cadence"] })} /></label>
                <label><span>Description</span><input value={service.description} onInput={(event) => updateService(service.id, { description: event.currentTarget.value })} /></label>
                <button type="button" class="gaugeapp-icon-action" aria-label={`Remove ${service.label}`} onClick={() => setServices((values) => values.filter((candidate) => candidate.id !== service.id))}>Remove</button>
            </div>}</For></div></Show>
        </section>
        <footer class="gaugeapp-editor-actions"><button type="button" onClick={props.onClose}>Cancel</button><button type="submit" class="primary" disabled={!valid() || !props.commands.includes(props.product ? "commercial-product.revise" : "commercial-product.create")}>{props.product ? "Save revision" : "Create product"}</button></footer>
    </form>;
}

function ProductDetail(props: {
    readonly product: CommercialProduct;
    readonly onEdit: () => void;
    readonly canEdit: boolean;
}): JSX.Element {
    const commercial = () => props.product.commercial;
    const archetype = () => commercial().archetype;
    const counts = () => props.product.engagement_counts;
    return <section class="gaugeapp-product-detail">
        <header><div><span>{text(archetype().kind, "Agent")}</span><h3>{text(commercial().listing_title, "Untitled product")}</h3><p>{text(commercial().description, "No description.")}</p></div><button type="button" disabled={!props.canEdit} onClick={props.onEdit}>Edit</button></header>
        <div class="gaugeapp-detail-facts"><Fact label="Agent" value={`${text(archetype().name)} · v${text(archetype().version)}`} /><Fact label="Price" value={priceSummary(commercial().prices)} /><Fact label="Delivery" value={text(commercial().delivery)} /><Fact label="Activity" value={`${count(counts().active)} active · ${count(counts().open)} open · ${count(counts().closed)} closed`} /></div>
        <Show when={commercial().service_obligations.length > 0}><div class="gaugeapp-detail-list"><strong>Services included</strong><For each={commercial().service_obligations}>{(service) => { return <span>{text(service.label)}<Show when={service.cadence}> · {text(service.cadence)}</Show></span>; }}</For></div></Show>
    </section>;
}

function ClientEditor(props: {
    readonly entry?: CommercialClient;
    readonly commands: readonly string[];
    readonly onSubmit: SubmitPageCommand;
    readonly onClose: () => void;
}): JSX.Element {
    const client = props.entry?.client;
    const [name, setName] = createSignal(text(client?.display_name, ""));
    const [billingReference, setBillingReference] = createSignal(text(client?.billing_reference, ""));
    const command = props.entry ? "commercial-client.edit" : "commercial-client.create";
    const submit = async () => {
        if (!name().trim()) return;
        await props.onSubmit(command, {
            id: text(client?.id, `client-${crypto.randomUUID()}`),
            display_name: name().trim(),
            billing_reference: billingReference().trim() || null,
        });
        props.onClose();
    };
    return <form class="gaugeapp-editor gaugeapp-client-editor" onSubmit={(event) => { event.preventDefault(); void submit(); }}>
        <header class="gaugeapp-editor-head"><div><span>{props.entry ? "Edit client" : "New client"}</span><strong>{name() || "Client"}</strong></div><button type="button" onClick={props.onClose}>Close</button></header>
        <div class="gaugeapp-editor-grid">
            <label><span>Name</span><input maxlength="120" value={name()} onInput={(event) => setName(event.currentTarget.value)} /></label>
            <label><span>Billing reference</span><input maxlength="160" placeholder="Optional internal or processor reference" value={billingReference()} onInput={(event) => setBillingReference(event.currentTarget.value)} /></label>
        </div>
        <footer class="gaugeapp-editor-actions"><button type="button" onClick={props.onClose}>Cancel</button><button type="submit" class="primary" disabled={!name().trim() || !props.commands.includes(command)}>{props.entry ? "Save client" : "Add client"}</button></footer>
    </form>;
}

function ClientDetail(props: {
    readonly entry: CommercialClient;
    readonly commands: readonly string[];
    readonly onSubmit: SubmitPageCommand;
    readonly onEdit: () => void;
}): JSX.Element {
    const client = () => props.entry.client;
    const counts = () => props.entry.engagement_counts;
    return <section class="gaugeapp-client-detail">
        <header><div><span>{text(client().status, "active")}</span><h3>{text(client().display_name, "Client")}</h3></div><div class="gaugeapp-card-actions"><CommandButton command="commercial-engagements.read-by-client" commands={props.commands} label="Engagements" payload={{ client_id: text(client().id, "") }} onSubmit={props.onSubmit} /><CommandButton command="commercial-payments.read-by-client" commands={props.commands} label="Payments" payload={{ client_id: text(client().id, "") }} onSubmit={props.onSubmit} /><button type="button" disabled={client().status === "closed" || !props.commands.includes("commercial-client.edit")} onClick={props.onEdit}>Edit</button></div></header>
        <div class="gaugeapp-detail-facts"><Fact label="Billing reference" value={text(client().billing_reference, "None")} /><Fact label="Engagements" value={`${count(counts().active)} active · ${count(counts().open)} open · ${count(counts().closed)} closed`} /></div>
        <Show when={props.entry.participant_references.length > 0}><div class="gaugeapp-detail-list"><strong>Referenced participants</strong><For each={props.entry.participant_references}>{(value) => { return <span>{value.kind === "manual" ? `${text(value.name)} · ${text(value.email)}` : text(value.account_id, "Account")}</span>; }}</For></div></Show>
        <Show when={client().status !== "closed"}><div class="gaugeapp-detail-actions gaugeapp-detail-actions-end"><CommandButton command="commercial-client.close" commands={props.commands} label="Close client" danger payload={{ id: text(client().id, "") }} onSubmit={props.onSubmit} /></div></Show>
    </section>;
}

interface RecipientDraft {
    readonly id: string;
    readonly kind: "manual" | "account";
    readonly name: string;
    readonly email: string;
    readonly accountId: string;
    readonly purpose: string;
}

const freshRecipient = (purpose: string): RecipientDraft => ({
    id: `recipient-${crypto.randomUUID()}`,
    kind: "manual",
    name: "",
    email: "",
    accountId: "",
    purpose,
});

const recipientDraft = (recipient: CommercialRecipient | undefined, purpose: string): RecipientDraft => {
    return {
        id: `recipient-${crypto.randomUUID()}`,
        kind: recipient?.kind ?? "manual",
        name: recipient?.kind === "manual" ? recipient.name : "",
        email: recipient?.kind === "manual" ? recipient.email : "",
        accountId: recipient?.kind === "account" ? recipient.account_id : "",
        purpose: recipient?.purpose ?? purpose,
    };
};

const recipientPayload = (recipient: RecipientDraft): Record<string, unknown> => recipient.kind === "account"
    ? { kind: "account", account_id: recipient.accountId.trim(), purpose: recipient.purpose.trim() }
    : { kind: "manual", name: recipient.name.trim(), email: recipient.email.trim(), purpose: recipient.purpose.trim() };

const validRecipient = (recipient: RecipientDraft) => recipient.kind === "account"
    ? Boolean(recipient.accountId.trim())
    : Boolean(recipient.name.trim() && recipient.email.includes("@"));

const dateInput = (value: unknown, fallbackDays: number): string => {
    const date = new Date(typeof value === "number" ? value : Date.now() + fallbackDays * 86_400_000);
    return Number.isNaN(date.valueOf()) ? "" : date.toISOString().slice(0, 10);
};

const dateMillis = (value: string, endOfDay = false): number => {
    const suffix = endOfDay ? "T23:59:59.999Z" : "T00:00:00.000Z";
    return Date.parse(`${value}${suffix}`);
};

function RecipientFields(props: {
    readonly recipient: RecipientDraft;
    readonly label: string;
    readonly onChange: (patch: Partial<RecipientDraft>) => void;
    readonly onRemove?: () => void;
}): JSX.Element {
    return <div class="gaugeapp-recipient-row">
        <label><span>{props.label}</span><select value={props.recipient.kind} onChange={(event) => props.onChange({ kind: event.currentTarget.value as RecipientDraft["kind"] })}><option value="manual">Email</option><option value="account">Account</option></select></label>
        <Show when={props.recipient.kind === "manual"} fallback={<label><span>Account ID</span><input value={props.recipient.accountId} onInput={(event) => props.onChange({ accountId: event.currentTarget.value })} /></label>}>
            <label><span>Name</span><input value={props.recipient.name} onInput={(event) => props.onChange({ name: event.currentTarget.value })} /></label>
            <label><span>Email</span><input type="email" value={props.recipient.email} onInput={(event) => props.onChange({ email: event.currentTarget.value })} /></label>
        </Show>
        <label><span>Purpose</span><input value={props.recipient.purpose} onInput={(event) => props.onChange({ purpose: event.currentTarget.value })} /></label>
        <Show when={props.onRemove}><button type="button" class="gaugeapp-icon-action" onClick={() => props.onRemove?.()}>Remove</button></Show>
    </div>;
}

function EngagementEditor(props: {
    readonly engagement?: CommercialEngagement;
    readonly products: readonly CommercialProduct[];
    readonly clients: readonly CommercialClient[];
    readonly commands: readonly string[];
    readonly onSubmit: SubmitPageCommand;
    readonly onClose: () => void;
}): JSX.Element {
    const existingTerms = props.engagement?.terms;
    const firstClient = props.clients.find((entry) => entry.client.status === "active")?.client;
    const [clientId, setClientId] = createSignal(text(props.engagement?.client_id, text(firstClient?.id, "")));
    const [productId, setProductId] = createSignal(text(props.engagement?.product_id, text(props.products[0]?.id, "")));
    const selectedProduct = createMemo(() => props.products.find((product) => product.id === productId()));
    const exactProduct = createMemo(() => props.engagement?.product_commercial ?? selectedProduct()?.commercial);
    const productPrices = createMemo(() => exactProduct()?.prices ?? []);
    const initialOverrides = priceDrafts(existingTerms?.price_overrides ?? []);
    const [customPricing, setCustomPricing] = createSignal(initialOverrides.length > 0);
    const [overridePrices, setOverridePrices] = createSignal<readonly PriceDraft[]>(initialOverrides);
    const [seats, setSeats] = createSignal(typeof existingTerms?.seats === "number" ? String(existingTerms?.seats) : "");
    const [discount, setDiscount] = createSignal(typeof existingTerms?.discount_basis_points === "number" ? String(existingTerms?.discount_basis_points / 100) : "0");
    const [termMonths, setTermMonths] = createSignal(typeof existingTerms?.term_months === "number" ? String(existingTerms?.term_months) : "");
    const [startRule, setStartRule] = createSignal(text(existingTerms?.start_rule, "on-acceptance"));
    const [startDate, setStartDate] = createSignal(dateInput(existingTerms?.start_at_ms, 0));
    const [renewal, setRenewal] = createSignal(text(existingTerms?.renewal, "none"));
    const [paymentTerms, setPaymentTerms] = createSignal(typeof existingTerms?.payment_terms_days === "number" ? String(existingTerms?.payment_terms_days) : "30");
    const [validUntil, setValidUntil] = createSignal(dateInput(existingTerms?.valid_until_ms, 30));
    const [clientNote, setClientNote] = createSignal(text(existingTerms?.client_note, ""));
    const initialRecipients = (existingTerms?.proposal_recipients ?? []).map((value) => recipientDraft(value, "proposal"));
    const [recipients, setRecipients] = createSignal<readonly RecipientDraft[]>(initialRecipients.length > 0 ? initialRecipients : [freshRecipient("proposal")]);
    const [billingRecipient, setBillingRecipient] = createSignal(recipientDraft(existingTerms?.billing_recipient, "billing"));
    const updateRecipient = (id: string, patch: Partial<RecipientDraft>) => setRecipients((values) =>
        values.map((recipient) => recipient.id === id ? { ...recipient, ...patch } : recipient));
    const updateOverridePrice = (id: string, patch: Partial<PriceDraft>) => setOverridePrices((values) =>
        values.map((price) => price.id === id ? { ...price, ...patch } : price));
    const toggleCustomPricing = () => {
        if (!customPricing() && overridePrices().length === 0) {
            const inherited = priceDrafts(productPrices());
            setOverridePrices(inherited.length > 0 ? inherited : [freshPrice()]);
        }
        setCustomPricing((value) => !value);
    };
    const valid = createMemo(() => Boolean(
        clientId() && productId() && validUntil() && Number(paymentTerms()) >= 0 &&
        recipients().length > 0 && recipients().every(validRecipient) && validRecipient(billingRecipient()) &&
        (!customPricing() || (overridePrices().length > 0 && overridePrices().every(validPriceDraft))),
    ));
    const stage = text(props.engagement?.stage, "draft");
    const command = props.engagement
        ? stage === "sent" ? "commercial-engagement.proposal.revise" : "commercial-engagement.proposal.save"
        : "commercial-engagement.proposal.create";
    const submit = async () => {
        if (!valid()) return;
        const terms: Record<string, unknown> = {
            discount_basis_points: Math.round(Number(discount() || 0) * 100),
            price_overrides: customPricing() ? pricePayloads(overridePrices()) : [],
            start_rule: startRule(),
            renewal: renewal(),
            payment_terms_days: Number(paymentTerms()),
            valid_until_ms: dateMillis(validUntil(), true),
            proposal_recipients: recipients().map(recipientPayload),
            billing_recipient: recipientPayload(billingRecipient()),
            client_note: clientNote().trim(),
        };
        if (seats()) terms.seats = Number(seats());
        if (termMonths()) terms.term_months = Number(termMonths());
        if (startRule() === "fixed-date") terms.start_at_ms = dateMillis(startDate());
        const id = text(props.engagement?.id, `engagement-${crypto.randomUUID()}`);
        const payload = props.engagement ? { id, terms } : { id, client_id: clientId(), product_id: productId(), terms };
        await props.onSubmit(command, payload);
        props.onClose();
    };
    return <form class="gaugeapp-editor gaugeapp-engagement-editor" onSubmit={(event) => { event.preventDefault(); void submit(); }}>
        <header class="gaugeapp-editor-head"><div><span>{props.engagement ? stage === "sent" ? "Revise proposal" : "Edit draft" : "New proposal"}</span><strong>{text(props.clients.find((value) => value.client.id === clientId())?.client.display_name, "Choose a client")}</strong></div><button type="button" onClick={props.onClose}>Close</button></header>
        <div class="gaugeapp-editor-grid">
            <label><span>Client</span><select disabled={Boolean(props.engagement)} value={clientId()} onChange={(event) => setClientId(event.currentTarget.value)}><For each={props.clients.filter((entry) => props.engagement || entry.client.status === "active")}>{(value) => { const client = value.client; return <option value={text(client?.id, "")}>{text(client?.display_name, "Client")}</option>; }}</For></select></label>
            <label><span>Product</span><select disabled={Boolean(props.engagement)} value={productId()} onChange={(event) => setProductId(event.currentTarget.value)}><For each={props.products}>{(product) => <option value={text(product.id, "")}>{text(product.commercial.listing_title, "Product")}</option>}</For></select></label>
            <label><span>Seats</span><input type="number" min="1" placeholder="Optional" value={seats()} onInput={(event) => setSeats(event.currentTarget.value)} /></label>
            <label><span>Discount %</span><input type="number" min="0" max="100" step="0.01" value={discount()} onInput={(event) => setDiscount(event.currentTarget.value)} /></label>
            <label><span>Term</span><select value={termMonths()} onChange={(event) => setTermMonths(event.currentTarget.value)}><option value="">No fixed term</option><option value="1">1 month</option><option value="3">3 months</option><option value="6">6 months</option><option value="12">12 months</option><option value="24">24 months</option></select></label>
            <label><span>Renewal</span><select value={renewal()} onChange={(event) => setRenewal(event.currentTarget.value)}><option value="none">No renewal</option><option value="month-to-month">Month to month</option><option value="annual">Annual</option></select></label>
            <label><span>Starts</span><select value={startRule()} onChange={(event) => setStartRule(event.currentTarget.value)}><option value="on-acceptance">On acceptance</option><option value="fixed-date">On a fixed date</option></select></label>
            <Show when={startRule() === "fixed-date"}><label><span>Start date</span><input type="date" value={startDate()} onInput={(event) => setStartDate(event.currentTarget.value)} /></label></Show>
            <label><span>Payment due</span><div class="gaugeapp-input-suffix"><input type="number" min="0" max="365" value={paymentTerms()} onInput={(event) => setPaymentTerms(event.currentTarget.value)} /><span>days</span></div></label>
            <label><span>Proposal valid through</span><input type="date" value={validUntil()} onInput={(event) => setValidUntil(event.currentTarget.value)} /></label>
            <label class="gaugeapp-field-wide"><span>Client note</span><textarea maxlength="1000" rows="2" value={clientNote()} onInput={(event) => setClientNote(event.currentTarget.value)} /></label>
        </div>
        <section class="gaugeapp-editor-section">
            <div class="gaugeapp-editor-section-head"><div><strong>Pricing</strong><span>{customPricing() ? "This engagement has its own complete price." : "Uses the selected product revision."}</span></div><button type="button" onClick={toggleCustomPricing}>{customPricing() ? "Use product price" : "Customize"}</button></div>
            <Show when={customPricing()} fallback={<div class="gaugeapp-price-inheritance"><span>Product price</span><strong>{priceSummary(productPrices())}</strong></div>}>
                <PriceFields prices={overridePrices()} onChange={updateOverridePrice} onRemove={(id) => setOverridePrices((values) => values.filter((candidate) => candidate.id !== id))} />
                <div class="gaugeapp-editor-inline-actions"><button type="button" onClick={() => setOverridePrices((values) => [...values, freshPrice(values[0]?.currency)])}>Add charge</button></div>
            </Show>
        </section>
        <section class="gaugeapp-editor-section">
            <div class="gaugeapp-editor-section-head"><div><strong>Proposal recipients</strong><span>Everyone who should receive the proposal.</span></div><button type="button" onClick={() => setRecipients((values) => [...values, freshRecipient("proposal")])}>Add recipient</button></div>
            <div class="gaugeapp-editor-rows"><For each={recipients()}>{(recipient) => <RecipientFields recipient={recipient} label="Recipient type" onChange={(patch) => updateRecipient(recipient.id, patch)} onRemove={recipients().length > 1 ? () => setRecipients((values) => values.filter((candidate) => candidate.id !== recipient.id)) : undefined} />}</For></div>
        </section>
        <section class="gaugeapp-editor-section">
            <div class="gaugeapp-editor-section-head"><div><strong>Billing recipient</strong><span>The person who receives invoices.</span></div></div>
            <RecipientFields recipient={billingRecipient()} label="Recipient type" onChange={(patch) => setBillingRecipient((recipient) => ({ ...recipient, ...patch }))} />
        </section>
        <footer class="gaugeapp-editor-actions"><button type="button" onClick={props.onClose}>Cancel</button><button type="submit" class="primary" disabled={!valid() || !props.commands.includes(command)}>{props.engagement ? stage === "sent" ? "Create revised draft" : "Save draft" : "Create draft"}</button></footer>
    </form>;
}

const engagementGroup = (stage: string) => stage === "draft" || stage === "sent"
    ? "Open proposals"
    : stage === "accepted" || stage === "active" ? "Active engagements" : "Closed";

function EntitlementControls(props: {
    readonly engagement: CommercialEngagement;
    readonly commands: readonly string[];
    readonly onSubmit: SubmitPageCommand;
    readonly allowActivation: boolean;
}): JSX.Element {
    const status = () => text(props.engagement.entitlement, "inactive");
    return <div class="gaugeapp-operation-row">
        <div><strong>Entitlement</strong><span>{status()}</span></div>
        <div class="gaugeapp-detail-actions">
            <Show when={props.allowActivation && props.engagement.placement_ref && status() !== "active" && status() !== "revoked"}>
                <CommandButton command="commercial-engagement.entitlement.activate" commands={props.commands} label={status() === "suspended" ? "Resume access" : "Activate access"} payload={{ id: text(props.engagement.id, ""), entitlement_ref: text(props.engagement.entitlement_ref, `entitlement-${crypto.randomUUID()}`) }} onSubmit={props.onSubmit} />
            </Show>
            <Show when={status() === "active"}>
                <CommandButton command="commercial-engagement.entitlement.suspend" commands={props.commands} label="Suspend" payload={{ id: text(props.engagement.id, "") }} onSubmit={props.onSubmit} />
            </Show>
            <Show when={status() === "active" || status() === "suspended"}>
                <CommandButton command="commercial-engagement.entitlement.revoke" commands={props.commands} label="Revoke" danger payload={{ id: text(props.engagement.id, "") }} onSubmit={props.onSubmit} />
            </Show>
        </div>
    </div>;
}

function EngagementDetail(props: {
    readonly engagement: CommercialEngagement;
    readonly product?: CommercialProduct;
    readonly client?: CommercialClient;
    readonly commands: readonly string[];
    readonly onSubmit: SubmitPageCommand;
    readonly onEdit: () => void;
}): JSX.Element {
    const stage = () => text(props.engagement.stage, "draft");
    const presentation = () => engagementPresentation(props.engagement);
    const terms = () => presentation().terms;
    const commercial = () => presentation().product;
    const [placementRef, setPlacementRef] = createSignal(text(props.engagement.placement_ref, ""));
    const billingEmail = () => { const billing = terms().billing_recipient; return billing.kind === "manual" ? billing.email : ""; };
    return <section class="gaugeapp-engagement-detail">
        <header><div><span>{stage()}</span><h3>{text(props.client?.client.display_name, "Client")} · {text(commercial().listing_title, "Product")}</h3><p>{presentation().summary}<Show when={terms().price_overrides.length > 0}> · custom for this engagement</Show></p></div><div class="gaugeapp-card-actions"><Show when={stage() !== "draft"}><CommandButton command="commercial-engagement.proposal-delivery.read" commands={props.commands} label="Delivery" payload={{ id: text(props.engagement.id, "") }} onSubmit={props.onSubmit} /></Show><Show when={["accepted", "active", "closed"].includes(stage())}><CommandButton command="commercial-engagement.agreement.read" commands={props.commands} label="Agreement" payload={{ id: text(props.engagement.id, "") }} onSubmit={props.onSubmit} /><CommandButton command="commercial-engagement.payments.read" commands={props.commands} label="Payments" payload={{ id: text(props.engagement.id, "") }} onSubmit={props.onSubmit} /></Show></div></header>
        <div class="gaugeapp-detail-facts"><Fact label="Proposal revision" value={String(props.engagement.proposal_revision ?? "—")} /><Fact label="Valid through" value={typeof terms().valid_until_ms === "number" ? new Date(Number(terms().valid_until_ms)).toLocaleDateString() : "Not set"} /><Fact label="Access" value={text(props.engagement.entitlement, "inactive")} /><Fact label="Payments" value={String(props.engagement.payment_refs.length)} /></div>
        <Show when={stage() === "draft"}><div class="gaugeapp-detail-actions"><button type="button" onClick={props.onEdit}>Edit</button><CommandButton command="commercial-engagement.proposal.send" commands={props.commands} label="Send proposal" payload={{ id: text(props.engagement.id, ""), sent_at_ms: Date.now() }} onSubmit={props.onSubmit} /><CommandButton command="commercial-engagement.proposal.discard" commands={props.commands} label="Discard" danger payload={{ id: text(props.engagement.id, "") }} onSubmit={props.onSubmit} /></div></Show>
        <Show when={stage() === "sent"}><div class="gaugeapp-callout"><div><strong>Awaiting client</strong><span>Acceptance must come from an exact proposal recipient; provider controls cannot accept on the client’s behalf.</span></div><div class="gaugeapp-detail-actions"><button type="button" onClick={props.onEdit}>Revise</button><CommandButton command="commercial-engagement.proposal.resend" commands={props.commands} label="Resend" payload={{ id: text(props.engagement.id, ""), sent_at_ms: Date.now() }} onSubmit={props.onSubmit} /><CommandButton command="commercial-engagement.proposal.withdraw" commands={props.commands} label="Withdraw" danger payload={{ id: text(props.engagement.id, "") }} onSubmit={props.onSubmit} /></div></div></Show>
        <Show when={stage() === "withdrawn" || stage() === "expired"}><p class="gaugeapp-empty">{stage() === "withdrawn" ? "This proposal was withdrawn." : "This proposal expired."} No agreement or technical access was created.</p></Show>
        <Show when={stage() === "accepted" || stage() === "active"}><div class="gaugeapp-engagement-operations">
            <div class="gaugeapp-operation-row"><div><strong>Technical access</strong><span>Link the exact customer project placement or Panel deployment.</span></div><input value={placementRef()} placeholder="Placement or deployment reference" onInput={(event) => setPlacementRef(event.currentTarget.value)} /><CommandButton command="commercial-engagement.placement.link" commands={props.commands} label={props.engagement.placement_ref ? "Update link" : "Link access"} payload={{ id: text(props.engagement.id, ""), placement_ref: placementRef() }} onSubmit={props.onSubmit} /></div>
            <EntitlementControls engagement={props.engagement} commands={props.commands} onSubmit={props.onSubmit} allowActivation />
            <Show when={billingEmail()}><div class="gaugeapp-operation-row"><div><strong>Invoice</strong><span>{billingEmail()}</span></div><CommandButton command="commercial-engagement.invoice.issue" commands={props.commands} label="Issue invoice" payload={{ id: `invoice-${crypto.randomUUID()}`, engagement_id: text(props.engagement.id, ""), billing_email: billingEmail(), days_until_due: Number(terms().payment_terms_days ?? 30) }} onSubmit={props.onSubmit} /></div></Show>
            <div class="gaugeapp-detail-actions gaugeapp-detail-actions-end"><CommandButton command="commercial-engagement.close" commands={props.commands} label="Close engagement" danger payload={{ id: text(props.engagement.id, "") }} onSubmit={props.onSubmit} /></div>
        </div></Show>
        <Show when={stage() === "closed" && (props.engagement.entitlement === "active" || props.engagement.entitlement === "suspended")}>
            <div class="gaugeapp-engagement-operations">
                <EntitlementControls engagement={props.engagement} commands={props.commands} onSubmit={props.onSubmit} allowActivation={false} />
            </div>
        </Show>
        <Show when={stage() === "closed"}><p class="gaugeapp-empty">This engagement is closed. Its agreement, payment references, and any remaining technical-access controls stay here.</p></Show>
    </section>;
}

const safeExternalUrl = (value: unknown): string | null => {
    if (typeof value !== "string") return null;
    try {
        const parsed = new URL(value);
        return parsed.protocol === "https:" ? parsed.href : null;
    } catch {
        return null;
    }
};

const proposalDeliveryUrl = (tenant: string, deliveryValue: unknown): string | null => {
    const delivery = valueRecord(deliveryValue);
    if (!delivery || typeof delivery.delivery_id !== "string" || typeof delivery.engagement_id !== "string" || typeof delivery.proof !== "string") return null;
    const url = new URL(window.location.href);
    url.searchParams.delete("gaugeapp");
    url.searchParams.delete("page");
    url.searchParams.delete("tenant");
    url.searchParams.set("proposal_tenant", tenant);
    url.searchParams.set("proposal", delivery.engagement_id);
    url.searchParams.set("delivery", delivery.delivery_id);
    url.hash = new URLSearchParams({ proposal_proof: delivery.proof }).toString();
    return url.toString();
};

const proposalRecipientLabel = (deliveryValue: unknown): string => {
    const recipient = valueRecord(valueRecord(deliveryValue)?.recipient) ?? {};
    return recipient.kind === "manual"
        ? `${text(recipient.name, "Recipient")} · ${text(recipient.email)}`
        : text(recipient.account_id, "GaugeDesk recipient");
};

const proposalDeliveryStatus = (resultValue: unknown): Readonly<Record<string, unknown>> | null => {
    const result = valueRecord(resultValue);
    return result && typeof result.engagement_id === "string" && Array.isArray(result.deliveries)
        ? result
        : null;
};

type CommercialEvidence = Readonly<{
    kind: "agreement" | "client-engagements" | "client-payments" | "engagement-payments";
    result: Readonly<Record<string, unknown>>;
}>;

const commercialEvidence = (resultValue: unknown): CommercialEvidence | null => {
    const result = valueRecord(resultValue);
    if (!result) return null;
    if (typeof result.engagement_id === "string" && Object.hasOwn(result, "agreement")) return { kind: "agreement", result };
    if (typeof result.client_id === "string" && Array.isArray(result.engagements)) return { kind: "client-engagements", result };
    if (Array.isArray(result.transactions) && Array.isArray(result.invoices) && Array.isArray(result.refunds)) {
        if (typeof result.engagement_id === "string") return { kind: "engagement-payments", result };
        if (typeof result.client_id === "string") return { kind: "client-payments", result };
    }
    return null;
};

function CommercialEvidenceResult(props: { readonly evidence: CommercialEvidence; readonly onDone: () => void }): JSX.Element {
    const result = () => props.evidence.result;
    const agreement = () => valueRecord(result().agreement);
    const acceptedBy = () => valueRecord(agreement()?.accepted_by);
    const product = () => valueRecord(agreement()?.product);
    const terms = () => valueRecord(agreement()?.terms);
    const transactions = () => valueArray(result().transactions);
    const invoices = () => valueArray(result().invoices);
    const refunds = () => valueArray(result().refunds);
    const title = () => props.evidence.kind === "agreement" ? "Accepted agreement"
        : props.evidence.kind === "client-engagements" ? "Client engagements"
            : props.evidence.kind === "client-payments" ? "Client payments" : "Engagement payments";
    return <section class="gaugeapp-one-time gaugeapp-commercial-evidence" aria-label={title()}>
        <div><strong>{title()}</strong><span>{text(result().engagement_id ?? result().client_id)}</span></div>
        <Show when={props.evidence.kind === "agreement"}>
            <Show when={agreement()} fallback={<span>No accepted agreement is recorded.</span>}><div class="gaugeapp-evidence-facts"><span>{text(product()?.listing_title, "Product")}</span><span>{acceptedBy()?.kind === "manual" ? `${text(acceptedBy()?.name, "Recipient")} · ${text(acceptedBy()?.email)}` : text(acceptedBy()?.account_id, "GaugeDesk recipient")}</span><span>{typeof agreement()?.accepted_at_ms === "number" ? `Accepted ${new Date(agreement()!.accepted_at_ms as number).toLocaleString()}` : "Acceptance time unavailable"}</span><span>{terms()?.renewal === "none" ? "No renewal" : text(terms()?.renewal, "Renewal unavailable")}</span></div></Show>
        </Show>
        <Show when={props.evidence.kind === "client-engagements"}>
            <div class="gaugeapp-evidence-list"><Show when={valueArray(result().engagements).length > 0} fallback={<span>No engagements.</span>}><For each={valueArray(result().engagements)}>{(value) => <span><strong>{text(valueRecord(value)?.id, "Engagement")}</strong> · {text(valueRecord(value)?.stage, "unknown")}</span>}</For></Show></div>
        </Show>
        <Show when={props.evidence.kind === "client-payments" || props.evidence.kind === "engagement-payments"}>
            <div class="gaugeapp-evidence-facts"><span>{count(transactions().length)} transactions</span><span>{count(invoices().length)} invoices</span><span>{count(refunds().length)} refunds</span><Show when={Array.isArray(result().payment_refs)}><span>{count(valueArray(result().payment_refs).length)} recorded references</span></Show></div>
        </Show>
        <button type="button" onClick={props.onDone}>Done</button>
    </section>;
}

const organizationInvitationUrl = (deliveryValue: unknown): string | null => {
    const delivery = valueRecord(deliveryValue);
    if (!delivery
        || typeof delivery.tenant_id !== "string"
        || typeof delivery.invitation_id !== "string"
        || typeof delivery.proof !== "string") return null;
    const url = new URL(window.location.href);
    url.searchParams.set("gaugeapp", "account-settings");
    url.searchParams.set("page", "account");
    url.searchParams.delete("tenant");
    url.searchParams.set("organization_invitation_tenant", delivery.tenant_id);
    url.searchParams.set("organization_invitation", delivery.invitation_id);
    url.hash = new URLSearchParams({ organization_invitation_proof: delivery.proof }).toString();
    return url.toString();
};

function PaymentsPage(props: {
    readonly model: CommercialPaymentsPageV1;
    readonly commands: readonly string[];
    readonly onSubmit: SubmitPageCommand;
}): JSX.Element {
    const processor = () => props.model.processor;
    const engagements = () => props.model.engagements;
    const billable = () => engagements().filter((engagement) => ["sent", "accepted", "active"].includes(text(engagement.stage, "")));
    const [component, setComponent] = createSignal<ConnectElementTagName | null>(null);
    const [checkoutEngagement, setCheckoutEngagement] = createSignal(text(billable()[0]?.id, ""));
    const [invoiceEngagement, setInvoiceEngagement] = createSignal(text(billable()[0]?.id, ""));
    const [invoiceEmail, setInvoiceEmail] = createSignal("");
    const [invoiceDueDays, setInvoiceDueDays] = createSignal("30");
    const [actionResult, setActionResult] = createSignal<Record<string, unknown> | null>(null);
    const [selectedTransaction, setSelectedTransaction] = createSignal<CommercialProcessorEvent | null>(null);
    const [refundAmount, setRefundAmount] = createSignal("");
    const [refundReason, setRefundReason] = createSignal("");
    createEffect(() => {
        const engagement = billable().find((value) => value.id === invoiceEngagement());
        const billing = engagement?.terms.billing_recipient;
        setInvoiceEmail(billing?.kind === "manual" ? billing.email : "");
    });
    const createAccountSession = async (requested: ConnectElementTagName): Promise<StripeAccountSession> => {
        const response = await props.onSubmit("commercial-payments.connect-component.open", {
            component: requested.replaceAll("-", "_"),
        });
        const result = valueRecord(response.result);
        if (!result || typeof result.client_secret !== "string" || typeof result.publishable_key !== "string") {
            throw new Error("Stripe did not return an Account Session.");
        }
        return {
            client_secret: result.client_secret,
            publishable_key: result.publishable_key,
            component: requested,
        };
    };
    const runResultCommand = async (command: string, payload: Readonly<Record<string, unknown>>) => {
        const response = await props.onSubmit(command, payload);
        setActionResult(valueRecord(response.result));
    };
    return <section class="gaugeapp-panel gaugeapp-section-stack gaugeapp-payments">
        <div class="gaugeapp-section-head"><div><h2>Payment account</h2><p>{paymentModeDescription(props.model.processor_mode)}</p></div><Show when={!processor().connected}><CommandButton command="commercial-payments.connect.begin" commands={props.commands} label="Set up payments" onSubmit={props.onSubmit} /></Show></div>
        {/* The prototype opens this page by saying what the current readiness
            lets you do, because "charges_ready: false" does not tell a person
            whether they can still prepare an engagement. It can: readiness
            gates checkout and invoices, not preparation. */}
        <Notice tone={processor().connected && processor().charges_ready ? "neutral" : "warn"}>{
            !processor().connected
                ? "Payment readiness gates checkout and invoices, not the ability to prepare products, clients, and engagements. Connect a payment account when you are ready to charge."
                : !processor().charges_ready
                    ? "Products, clients and engagements can be prepared now. Checkout links and invoices wait until Stripe finishes verifying this account."
                    : processor().payouts_ready
                        ? "Charges and payouts are both active. The organization remains merchant of record."
                        : "Charges are active and payouts are not. Money collected is held until the external account is verified."
        }</Notice>
        <div class="gaugeapp-payment-readiness">
            <Fact label="Payment account" value={processor().connected ? "Connected" : "Not connected"} />
            <Fact label="Collect charges" value={paymentReadinessLabel(processor().connected, processor().charges_ready)} />
            <Fact label="Receive payouts" value={paymentReadinessLabel(processor().connected, processor().payouts_ready)} />
            <Fact label="Last verified" value={processor().verified_at === null ? (processor().connected ? "Not yet verified" : "—") : sessionTimestamp(processor().verified_at! * 1_000)} />
        </div>
        {/* Before handing a provider to Stripe, say what activation does and what
            Stripe will ask for. The prototype makes this its onboarding step;
            the built page went straight to the embedded component, which asks
            for tax and ownership details with no statement of why. */}
        <Show when={!processor().connected}>
            <SectionHeading title="Before connecting" />
            <div class="gaugeapp-detail-facts">
                <Fact label="Stripe collects" value="Business identity and representatives" note="address, ownership, and tax details" />
                <Fact label="Money movement" value="Bank account and payout schedule" note="held by Stripe, never by GaugeDesk" />
                <Fact label="Customer-facing" value="Statement descriptor and support contact" note="what a client sees on a charge" />
            </div>
            <SectionHeading title="Activation gates" />
            <div class="gaugeapp-detail-facts">
                <Fact label="Onboarding" value="Details submitted" note="Stripe-hosted collection complete" />
                <Fact label="Payments" value="Charges enabled" note="checkout links and invoices become available" />
                <Fact label="Payouts" value="External account verified" note="collected money can leave Stripe" />
            </div>
            <p class="gaugeapp-payment-note">This organization remains merchant of record. Activation adds no storefront, no client entitlement, and no project access.</p>
        </Show>
        <Show when={processor().connected}>
            <div class="gaugeapp-stripe-tools" aria-label="Stripe financial tools"><For each={[
                ["account-onboarding", "Onboarding"],
                ["notification-banner", "Required actions"],
                ["account-management", "Account"],
                ["payments", "Disputes"],
                ["payouts", "Payouts"],
                ["documents", "Documents"],
            ] as const}>{([id, label]) => <button type="button" aria-pressed={component() === id} onClick={() => setComponent(id)}>{label}</button>}</For></div>
            <Show keyed when={component()} fallback={<p class="gaugeapp-empty">Choose a Stripe tool to manage verification, account details, disputes, payouts, or documents.</p>}>{(active) => <StripeEmbeddedComponent component={active} createAccountSession={() => createAccountSession(active)} />}</Show>
        </Show>
        <For each={props.model.currency_totals}>{(total) => <div class="gaugeapp-payment-totals" aria-label={`${total.currency.toUpperCase()} payment totals`}><Fact label="Gross collected" value={commercialMoney(total.gross_cents, total.currency)} /><Fact label="Refunded" value={commercialMoney(total.refunded_cents, total.currency)} /><Fact label="Pending refunds" value={commercialMoney(total.pending_refund_cents, total.currency)} /><Fact label="Platform fees" value={commercialMoney(total.platform_fees_cents, total.currency)} /></div>}</For>
        <p class="gaugeapp-payment-note">Recorded transactions do not represent an available balance, payout total, or net revenue.</p>
        <Show when={processor().charges_ready && billable().length > 0}>
            <section class="gaugeapp-payment-actions">
                <div><strong>Collect payment</strong><span>Every charge remains bound to one engagement.</span></div>
                <label><span>Engagement</span><select value={checkoutEngagement()} onChange={(event) => setCheckoutEngagement(event.currentTarget.value)}><For each={billable()}>{(engagement) => <option value={text(engagement.id, "")}>{text(engagement.id, "Engagement")}</option>}</For></select></label>
                <button type="button" disabled={!checkoutEngagement() || !props.commands.includes("commercial-payments.checkout.create")} onClick={() => void runResultCommand("commercial-payments.checkout.create", { engagement_id: checkoutEngagement() })}>Create checkout</button>
                <label><span>Invoice engagement</span><select value={invoiceEngagement()} onChange={(event) => setInvoiceEngagement(event.currentTarget.value)}><For each={billable()}>{(engagement) => <option value={text(engagement.id, "")}>{text(engagement.id, "Engagement")}</option>}</For></select></label>
                <label><span>Billing email</span><input type="email" value={invoiceEmail()} onInput={(event) => setInvoiceEmail(event.currentTarget.value)} /></label>
                <label><span>Due in days</span><input type="number" min="1" max="90" value={invoiceDueDays()} onInput={(event) => setInvoiceDueDays(event.currentTarget.value)} /></label>
                <button type="button" disabled={!invoiceEngagement() || !invoiceEmail().includes("@") || !props.commands.includes("commercial-payments.invoice.issue")} onClick={() => void runResultCommand("commercial-payments.invoice.issue", { id: `invoice-${crypto.randomUUID()}`, engagement_id: invoiceEngagement(), billing_email: invoiceEmail(), days_until_due: Number(invoiceDueDays()) })}>Issue invoice</button>
            </section>
        </Show>
        <Show when={safeExternalUrl(actionResult()?.url)}>{(url) => <div class="gaugeapp-action-result"><div><strong>Checkout ready</strong><span>Share this Stripe-hosted page with the client.</span></div><a href={url()} target="_blank" rel="noreferrer">Open checkout</a><button type="button" onClick={() => setActionResult(null)}>Dismiss</button></div>}</Show>
        <Show when={safeExternalUrl(actionResult()?.hosted_invoice_url)}>{(url) => <div class="gaugeapp-action-result"><div><strong>Invoice issued</strong><span>{text(actionResult()?.status, "open")}</span></div><a href={url()} target="_blank" rel="noreferrer">Open invoice</a><button type="button" onClick={() => setActionResult(null)}>Dismiss</button></div>}</Show>
        <section class="gaugeapp-payment-ledger"><div class="gaugeapp-editor-section-head"><div><strong>Transactions</strong><span>Payment events recorded from Stripe.</span></div></div><Show when={props.model.transactions.length > 0} fallback={<p class="gaugeapp-empty">No successful transactions observed.</p>}><div class="gaugeapp-rows"><For each={props.model.transactions}>{(transaction) => { return <div class="gaugeapp-row gaugeapp-row-action"><div><strong>{text(transaction.object_id, "Payment")}</strong><span>{commercialMoney(transaction.amount_cents, transaction.currency)} · {text(transaction.status, "unknown")}</span></div><button type="button" disabled={!props.commands.includes("commercial-payments.payment.read")} onClick={() => void props.onSubmit("commercial-payments.payment.read", { id: transaction.object_id }).then(() => { setSelectedTransaction(transaction); setRefundAmount(commercialAmountInput(transaction.amount_cents, transaction.currency)); })}>View</button></div>; }}</For></div></Show></section>
        <Show keyed when={selectedTransaction()}>{(transaction) => <section class="gaugeapp-payment-detail"><header><div><span>Payment</span><strong>{text(transaction.object_id, "Payment")}</strong></div><button type="button" onClick={() => setSelectedTransaction(null)}>Close</button></header><div class="gaugeapp-detail-facts"><Fact label="Amount" value={commercialMoney(transaction.amount_cents, transaction.currency)} /><Fact label="Status" value={text(transaction.status)} /><Fact label="Engagement" value={text(transaction.engagement_id)} /><Fact label="Client" value={text(transaction.client_id)} /></div><Show when={transaction.status === "succeeded"}><div class="gaugeapp-refund-row"><label><span>Refund amount {transaction.currency.toUpperCase()}</span><input type="number" min={commercialAmountStep(transaction.currency)} step={commercialAmountStep(transaction.currency)} value={refundAmount()} onInput={(event) => setRefundAmount(event.currentTarget.value)} /></label><label><span>Reason</span><input value={refundReason()} onInput={(event) => setRefundReason(event.currentTarget.value)} /></label><button type="button" class="gaugeapp-danger" disabled={!props.commands.includes("commercial-payments.payment.refund") || (commercialMinorAmount(refundAmount(), transaction.currency) ?? 0) <= 0} onClick={() => { const amount = commercialMinorAmount(refundAmount(), transaction.currency); if (amount !== null) void props.onSubmit("commercial-payments.payment.refund", { id: `refund-${crypto.randomUUID()}`, transaction_id: text(transaction.object_id, ""), amount_cents: amount, reason: refundReason().trim() }); }}>Refund</button></div></Show></section>}</Show>
        <section class="gaugeapp-payment-ledger">
            <div class="gaugeapp-editor-section-head"><div><strong>Invoices</strong></div></div>
            <Show when={props.model.processor_invoices.length > 0} fallback={<p class="gaugeapp-empty">No invoices issued.</p>}>
                <div class="gaugeapp-rows"><For each={paymentInvoiceRows(props.model)}>{(invoice) =>
                    <div class="gaugeapp-row gaugeapp-invoice-row">
                        <div class="gaugeapp-invoice-heading"><strong>{invoice.object_id}</strong><span>{invoice.label}</span></div>
                        <Show when={safeExternalUrl(invoice.url)}>{(href) => <a href={href()} target="_blank" rel="noreferrer">Open</a>}</Show>
                        <Show when={invoice.currency !== null}>
                            <div class="gaugeapp-invoice-amounts">
                                <Fact label="Total" value={commercialMoney(invoice.total_cents, invoice.currency)} />
                                <Fact label="Due" value={commercialMoney(invoice.amount_due_cents, invoice.currency)} />
                                <Fact label="Paid" value={commercialMoney(invoice.amount_paid_cents, invoice.currency)} />
                                <Fact label="Remaining" value={commercialMoney(invoice.amount_remaining_cents, invoice.currency)} />
                            </div>
                        </Show>
                    </div>
                }</For></div>
            </Show>
        </section>
        <section class="gaugeapp-payment-ledger"><div class="gaugeapp-editor-section-head"><div><strong>Refunds</strong></div></div><ModelRows values={paymentRefundRows(props.model)} empty="No refunds observed." title={(record) => record.id} detail={(record) => `${record.amount} · ${record.status}`} /></section>
        <section class="gaugeapp-payment-ledger"><div class="gaugeapp-editor-section-head"><div><strong>Payouts</strong></div></div><ModelRows values={paymentPayoutRows(props.model)} empty="No payouts observed." title={(record) => record.id} detail={(record) => record.detail} /></section>
    </section>;
}

type CommercialPanelActions = { commands: readonly string[]; onSubmit: SubmitPageCommand };

function ProductsPage(props: CommercialPanelActions & { model: ProductsPageV1 }): JSX.Element {
    const [editor, setEditor] = createSignal<CommercialProduct | "new" | null>(null);
    const [selectedId, setSelectedId] = createSignal<string | null>(null);
    const selected = () => props.model.products.find((product) => product.id === selectedId());
    return <section class="gaugeapp-panel gaugeapp-section-stack">
        <div class="gaugeapp-section-head"><div><h2>Products</h2><p>Commercial revisions of Agents from this organization’s Library.</p></div><button type="button" disabled={!props.commands.includes("commercial-product.create") || !props.model.library.archetypes.length} onClick={() => setEditor("new")}>New product</button></div>
        <Show when={props.model.library.availability === "unavailable"}><p class="gaugeapp-unavailable">{props.model.library.reason}</p></Show>
        <Show keyed when={editor()}>{(value) => <ProductEditor product={value === "new" ? undefined : value} agents={props.model.library.archetypes} commands={props.commands} onSubmit={props.onSubmit} onClose={() => setEditor(null)} />}</Show>
        <Show when={!editor()}>
            <Show when={props.model.products.length} fallback={<p class="gaugeapp-empty">No products yet. Choose an Agent from Library to start.</p>}>
                <div class="gaugeapp-catalog"><For each={props.model.products}>{(product) => <article class="gaugeapp-catalog-card">
                    <header><div><strong>{product.commercial.listing_title}</strong><span>{product.commercial.archetype.kind === "panel-agent" ? "Panel agent" : "Agent"}</span></div><div class="gaugeapp-card-actions"><button type="button" disabled={!props.commands.includes("commercial-product.read")} onClick={() => void props.onSubmit("commercial-product.read", { id: product.id }).then(() => setSelectedId(product.id))}>View</button><button type="button" disabled={!props.commands.includes("commercial-product.revise")} onClick={() => setEditor(product)}>Edit</button></div></header>
                    <p>{product.commercial.description || "No listing description."}</p>
                    <div class="gaugeapp-card-facts"><span>{priceSummary(product.commercial.prices)}</span><span>{product.engagement_counts.active} active · {product.engagement_counts.open} open · {product.engagement_counts.closed} closed</span></div>
                </article>}</For></div>
            </Show>
            <Show keyed when={selected()}>{(product) => <ProductDetail product={product} canEdit={props.commands.includes("commercial-product.revise")} onEdit={() => setEditor(product)} />}</Show>
        </Show>
    </section>;
}

function ClientsPage(props: CommercialPanelActions & { model: ClientsPageV1 }): JSX.Element {
    const [editor, setEditor] = createSignal<CommercialClient | "new" | null>(null);
    const [selectedId, setSelectedId] = createSignal<string | null>(null);
    const selected = () => props.model.clients.find((entry) => entry.client.id === selectedId());
    return <section class="gaugeapp-panel gaugeapp-section-stack">
        <div class="gaugeapp-section-head"><div><h2>Clients</h2><p>Contracting identities; participants remain with their engagements and projects.</p></div><button type="button" disabled={!props.commands.includes("commercial-client.create")} onClick={() => setEditor("new")}>New client</button></div>
        <Show keyed when={editor()}>{(value) => <ClientEditor entry={value === "new" ? undefined : value} commands={props.commands} onSubmit={props.onSubmit} onClose={() => setEditor(null)} />}</Show>
        <Show when={!editor()}>
            <Show when={props.model.clients.length} fallback={<p class="gaugeapp-empty">No clients yet.</p>}>
                <div class="gaugeapp-client-list"><For each={props.model.clients}>{(entry) => <article class="gaugeapp-client-card">
                    <div><strong>{entry.client.display_name}</strong><span>{entry.client.status}</span></div>
                    <span>{entry.engagement_counts.active} active · {entry.engagement_counts.open} open · {entry.engagement_counts.closed} closed</span>
                    <div class="gaugeapp-card-actions"><button type="button" disabled={!props.commands.includes("commercial-client.read")} onClick={() => void props.onSubmit("commercial-client.read", { id: entry.client.id }).then(() => setSelectedId(entry.client.id))}>View</button><button type="button" disabled={entry.client.status === "closed" || !props.commands.includes("commercial-client.edit")} onClick={() => setEditor(entry)}>Edit</button></div>
                </article>}</For></div>
            </Show>
            <Show keyed when={selected()}>{(entry) => <ClientDetail entry={entry} commands={props.commands} onSubmit={props.onSubmit} onEdit={() => setEditor(entry)} />}</Show>
        </Show>
    </section>;
}

function EngagementsPage(props: CommercialPanelActions & { model: EngagementsPageV1 }): JSX.Element {
    const [editor, setEditor] = createSignal<CommercialEngagement | "new" | null>(null);
    const [selectedId, setSelectedId] = createSignal<string | null>(null);
    const selected = () => props.model.engagements.find((engagement) => engagement.id === selectedId());
    const client = (id: string) => props.model.clients.find((entry) => entry.client.id === id);
    return <section class="gaugeapp-panel gaugeapp-section-stack">
        <div class="gaugeapp-section-head"><div><h2>Engagements</h2><p>Proposals, agreements, access, and billing.</p></div><button type="button" disabled={!props.commands.includes("commercial-engagement.proposal.create") || !props.model.products.length || !props.model.clients.some((entry) => entry.client.status === "active")} onClick={() => setEditor("new")}>New proposal</button></div>
        <Show keyed when={editor()}>{(value) => <EngagementEditor engagement={value === "new" ? undefined : value} products={props.model.products} clients={props.model.clients} commands={props.commands} onSubmit={props.onSubmit} onClose={() => setEditor(null)} />}</Show>
        <Show when={!editor()}>
            <Show when={props.model.engagements.length} fallback={<p class="gaugeapp-empty">No engagements yet. Add a client and product, then create a proposal.</p>}>
                <For each={["Open proposals", "Active engagements", "Closed"]}>{(group) => {
                    const engagements = () => props.model.engagements.filter((entry) => engagementGroup(entry.stage) === group);
                    return <Show when={engagements().length}><div class="gaugeapp-engagement-group"><h3>{group}</h3><div class="gaugeapp-engagement-list"><For each={engagements()}>{(engagement) => {
                        const presentation = () => engagementPresentation(engagement);
                        return <article class="gaugeapp-engagement-card"><div><strong>{client(engagement.client_id)?.client.display_name ?? engagement.client_id}</strong><span>{presentation().product.listing_title}</span></div><span class="gaugeapp-stage">{engagement.stage}</span><span>{presentation().summary}</span><button type="button" onClick={() => setSelectedId(engagement.id)}>View</button></article>;
                    }}</For></div></div></Show>;
                }}</For>
            </Show>
            <Show keyed when={selected()}>{(engagement) => <EngagementDetail engagement={engagement} client={client(engagement.client_id)} commands={props.commands} onSubmit={props.onSubmit} onEdit={() => setEditor(engagement)} />}</Show>
        </Show>
    </section>;
}

function CommercialPage(props: CommercialPanelActions & { page: GaugeAppPageModel }): JSX.Element {
    const page = createMemo(() => parseCommercialGaugeAppPage(props.page));
    const products = () => { const value = page(); return value.id === "products" ? value.model : undefined; };
    const clients = () => { const value = page(); return value.id === "clients" ? value.model : undefined; };
    const engagements = () => { const value = page(); return value.id === "engagements" ? value.model : undefined; };
    const payments = () => { const value = page(); return value.id === "payments" ? value.model : undefined; };
    return <article class="gaugeapp-page" data-gaugeapp-page={page().id}>
        <PageHeading app="commercial-operations" page={page()} />
        <Show when={products()}>{(model) => <ProductsPage model={model()} commands={props.commands} onSubmit={props.onSubmit} />}</Show>
        <Show when={clients()}>{(model) => <ClientsPage model={model()} commands={props.commands} onSubmit={props.onSubmit} />}</Show>
        <Show when={engagements()}>{(model) => <EngagementsPage model={model()} commands={props.commands} onSubmit={props.onSubmit} />}</Show>
        <Show when={payments()}>{(model) => <PaymentsPage model={model()} commands={props.commands} onSubmit={props.onSubmit} />}</Show>
    </article>;
}

function GaugeAppPage(props: {
    app: GaugeAppKind;
    session: GaugeAppSession;
    page: GaugeAppPageModel;
    commands: readonly string[];
    onSubmit: SubmitPageCommand;
    onSubmitSecret: SubmitPageSecret;
    api: EnterpriseControlPlane;
    onRefresh: () => Promise<void>;
    deviceLinkInvitation?: DeviceLinkInvitation | null;
    onDeviceLinkClaimed?: () => void;
    organizationInvitation?: OrganizationInvitationAccess | null;
    onOrganizationInvitationResponded?: () => void;
    openExternal?: (url: string) => Promise<boolean>;
    onOpenProject?: (project: { readonly id: string; readonly name: string }) => void;
    onOpenGaugeApp?: (app: GaugeAppKind, page: string) => void;
}): JSX.Element {
    if (props.app === "account-settings") return <AccountPage page={props.page} commands={props.commands} onSubmit={props.onSubmit} onSubmitSecret={props.onSubmitSecret} api={props.api} onRefresh={props.onRefresh} deviceLinkInvitation={props.deviceLinkInvitation} onDeviceLinkClaimed={props.onDeviceLinkClaimed} organizationInvitation={props.organizationInvitation} onOrganizationInvitationResponded={props.onOrganizationInvitationResponded} openExternal={props.openExternal} />;
    if (props.app === "commercial-operations") return <CommercialPage page={props.page} commands={props.commands} onSubmit={props.onSubmit} />;
    return <AdministrationPage page={props.page} session={props.session} commands={props.commands} onSubmit={props.onSubmit} api={props.api} onRefresh={props.onRefresh} onOpenProject={props.onOpenProject} onOpenGaugeApp={props.onOpenGaugeApp} />;
}

function ProposalList(props: {
    proposals: readonly GaugeAppProposal[];
    page: GaugeAppPageModel;
    busy: boolean;
    onReview: (proposal: GaugeAppProposal, decision: "accept" | "reject") => void;
}): JSX.Element {
    const pending = () => props.proposals.filter((proposal) =>
        proposal.page_id === props.page.id && gaugeAppReviewControls(proposal.status).visible);
    return <Show when={pending().length > 0}>
        <section class="gaugeapp-proposals" aria-label="Pending changes">
            <h2>Pending changes</h2>
            <For each={pending()}>{(proposal) => {
                const summary = createMemo(() => summarizeGaugeAppChange(proposal, props.page));
                const controls = () => gaugeAppReviewControls(proposal.status);
                return <article class="gaugeapp-proposal" aria-label={summary().title}>
                <header><strong>{summary().title}</strong><span>Prepared by {proposal.actor}</span></header>
                <dl class="gaugeapp-review-fields"><For each={summary().fields}>{(field) => <div>
                    <dt>{field.label}</dt><dd>
                        <Show when={field.before}><span class="gaugeapp-review-before">{field.before} → </span></Show>
                        <Show when={field.expanded} fallback={field.value}><details><summary>View proposed metadata</summary><pre>{field.value}</pre></details></Show>
                    </dd>
                </div>}</For></dl>
                <Show when={summary().note}>{(note) => <p>{note()}</p>}</Show>
                <Show when={summary().unavailable}>{(message) => <p role="alert">{message()}</p>}</Show>
                <Show when={controls().confirmationPending}><p role="status">Approved. Waiting for confirmation from the service.</p></Show>
                <div class="gaugeapp-actions">
                    <Show when={controls().canDiscard}><button type="button" disabled={props.busy} onClick={() => props.onReview(proposal, "reject")}>Discard</button></Show>
                    <button type="button" class="primary" disabled={props.busy || (!controls().confirmationPending && !!summary().unavailable)} onClick={() => props.onReview(proposal, "accept")}>{controls().actionLabel}</button>
                </div>
            </article>;
            }}</For>
        </section>
    </Show>;
}

export interface GaugeAppWorkspaceController {
    readonly app: GaugeAppKind;
    readonly admitted: Accessor<boolean>;
    readonly session: Accessor<GaugeAppSession | undefined> & { readonly error?: unknown };
    readonly selectedPage: Accessor<string>;
    readonly page: Accessor<GaugeAppPageModel | undefined>;
    readonly openPage: (pageId: string) => void;
    readonly refresh: () => Promise<void>;
    readonly chat: (controls: { readonly mobile: boolean; readonly onCollapse: () => void }) => JSX.Element;
    readonly content: () => JSX.Element;
    readonly menu: () => JSX.Element;
    readonly onNewChat: () => void;
}

const FRESH_AUTHORIZATION_COMMANDS = new Set([
    "account.erase",
    "organization.ownership.transfer",
    "organization.delete",
    "enterprise-identity.owner-subject.link",
    "enterprise-identity.enforcement.enable",
    "enterprise-identity.enforcement.disable",
]);

export function createGaugeAppWorkspace(options: {
    api: EnterpriseControlPlane;
    app: GaugeAppKind;
    enabled: Accessor<boolean>;
    active: Accessor<boolean>;
    scope: Accessor<GaugeAppScope | undefined>;
    onPageChange?: (pageId: string) => void;
    deviceLinkInvitation?: Accessor<DeviceLinkInvitation | null>;
    onDeviceLinkClaimed?: () => void;
    organizationInvitation?: Accessor<OrganizationInvitationAccess | null>;
    onOrganizationInvitationResponded?: () => void;
    openExternal?: (url: string) => Promise<boolean>;
    onAccountErased?: () => void | Promise<void>;
    onOrganizationDeleted?: (tenantId: string) => void | Promise<void>;
    onOpenProject?: (project: { readonly id: string; readonly name: string }) => void;
    onOpenGaugeApp?: (app: GaugeAppKind, page: string) => void;
    onTenantServicesChanged?: () => void | Promise<void>;
    updateIntervalMs?: number;
    updateRetryMs?: number;
}): GaugeAppWorkspaceController {
    const [selectedPage, setSelectedPage] = createSignal("");
    const [statusResult, setStatusResult] = createSignal<{ owner: GaugeAppOperation; value: string }>();
    const [transientResult, setTransientResult] = createSignal<{ owner: GaugeAppOperation; value: unknown }>();
    const status = () => { const result = statusResult(); return result?.owner.current() ? result.value : ""; };
    const oneTimeResult = () => { const result = transientResult(); return result?.owner.current() ? result.value : undefined; };
    const setOneTimeResult = (_: undefined) => setTransientResult(undefined);
    const setStatus = (owner: GaugeAppOperation, value: string) => { if (owner.current()) setStatusResult({ owner, value }); };
    const openPage = (pageId: string) => {
        setSelectedPage(pageId);
        options.onPageChange?.(pageId);
    };
    const sessionSource = createMemo(() => options.enabled()
        ? { scope: options.scope() }
        : null);
    const navigation = createGaugeAppOperations(() => {
        const source = sessionSource();
        return source && options.active() ? JSON.stringify([options.app, source.scope?.kind, source.scope?.id]) : undefined;
    });
    const [session, { refetch: refetchSession }] = createGaugeAppResource(sessionSource,
        ({ scope }) => JSON.stringify([options.app, scope?.kind, scope?.id]),
        ({ scope }) => options.api.openGaugeApp(options.app, scope));
    // Admission stays available to the global menus while another surface is
    // selected. Only the displayed App owns page/agent request lifetimes.
    const visibleSession = createMemo(() => options.active() ? session() : undefined);
    createEffect(() => {
        const admitted = session();
        if (!admitted) return;
        if (!admitted.pages.some((page) => page.id === selectedPage())) {
            setSelectedPage(admitted.pages[0]?.id ?? "");
        }
    });
    const pageSource = createMemo(() => {
        const admitted = visibleSession();
        const pageId = selectedPage();
        return admitted && pageId ? { admitted, pageId } : null;
    });
    const sessionKey = (admitted: GaugeAppSession) => JSON.stringify([
        admitted.app, admitted.actor, admitted.scope, admitted.id, admitted.generation,
    ]);
    // Projection revisions/cursors are not authorization epochs. A normal
    // post-command refresh must not discard a newly issued one-time result.
    const authorizationKey = createMemo(() => {
        const admitted = visibleSession();
        return admitted ? JSON.stringify([sessionKey(admitted), admitted.capabilities,
            admitted.commands, admitted.pages.map(({ id, availability, commands }) => ({ id, availability, commands }))]) : undefined;
    });
    const sessionOperations = createGaugeAppOperations(authorizationKey);
    const [page, { refetch: refetchPage }] = createGaugeAppResource(pageSource,
        ({ admitted, pageId }) => `${sessionKey(admitted)}:${pageId}`,
        ({ admitted, pageId }) => options.api.readGaugeAppPage(admitted, pageId));
    const pageOperations = createGaugeAppOperations(() => {
        const authority = authorizationKey();
        return authority && page() ? JSON.stringify([authority, selectedPage()]) : undefined;
    });
    const busy = () => sessionOperations.busy() || pageOperations.busy() || liveActive();
    const clearTransient = () => { setTransientResult(undefined); setStatusResult(undefined); };
    createEffect(() => { pageOperations.identity(); clearTransient(); });
    onCleanup(clearTransient);
    const [proposals, { refetch: refetchProposals }] = createGaugeAppResource(visibleSession, sessionKey,
        (admitted) => options.api.gaugeAppProposals(admitted));
    const [messages, { refetch: refetchMessages }] = createGaugeAppResource(visibleSession, sessionKey,
        (admitted) => options.api.gaugeAppAgentMessages(admitted));
    const [liveFrames, setLiveFrames] = createSignal<readonly GaugeAppAgentLiveFrame[]>([]);
    const [liveActive, setLiveActive] = createSignal(false);
    const [confirmingClear, setConfirmingClear] = createSignal(false);
    const [clearError, setClearError] = createSignal("");
    const [updatesDelayed, setUpdatesDelayed] = createSignal(false);
    createEffect(() => {
        sessionOperations.identity();
        setConfirmingClear(false);
        setClearError("");
    });
    createEffect(() => {
        const admitted = visibleSession();
        const visit = sessionOperations.identity();
        setLiveFrames([]);
        setLiveActive(false);
        if (!admitted) return;

        let disposed = false;
        let closeStream: (() => void) | undefined;
        let reconnect: ReturnType<typeof setTimeout> | undefined;
        let cursor: string | undefined;
        let turnId: string | undefined;
        let sequence: number | undefined;
        const seen = new Set<string>();
        const current = () => !disposed && sessionOperations.identity() === visit;
        const connect = () => {
            if (!current()) return;
            closeStream = options.api.gaugeAppAgentEvents(
                admitted,
                (frame) => {
                    if (!current() || seen.has(frame.cursor)) return;
                    if (turnId !== frame.turn_id) {
                        turnId = frame.turn_id;
                        sequence = undefined;
                        seen.clear();
                        setLiveFrames([]);
                    }
                    if (sequence !== undefined && frame.sequence > sequence + 1) {
                        // The bounded server buffer has moved past our cursor.
                        // Rebuild the operational tail instead of joining it to
                        // a view whose missing middle could look authoritative.
                        seen.clear();
                        setLiveFrames([]);
                    }
                    seen.add(frame.cursor);
                    cursor = frame.cursor;
                    sequence = frame.sequence;
                    setLiveFrames((frames) => [...frames, frame]);
                    const terminal = frame.event.type === "settled"
                        || frame.event.type === "stopped"
                        || frame.event.type === "failed";
                    setLiveActive(!terminal);
                    if (terminal) {
                        const settledTurn = frame.turn_id;
                        void Promise.all([refetchMessages(), refetchProposals()]).then(() => {
                            if (current() && turnId === settledTurn) setLiveFrames([]);
                        }).catch(() => undefined);
                    }
                },
                cursor,
                undefined,
                () => {
                    if (!current()) return;
                    reconnect = setTimeout(connect, 1_000);
                },
            );
        };
        connect();
        onCleanup(() => {
            disposed = true;
            if (reconnect !== undefined) clearTimeout(reconnect);
            closeStream?.();
        });
    });
    const transcript = createMemo<Transcript>(() => ({
        openText: null,
        lines: (messages()?.messages ?? []).map((message) => ({
            seq: message.sequence,
            tier: "admitted" as const,
            kind: message.role,
            text: message.text,
        })),
    }));
    const liveTranscript = createMemo<Transcript>(() => liveFrames().reduce((current, frame) => {
        const event = frame.event;
        if (event.type === "text") return reduceTranscript(current, event);
        if (event.type === "tool") {
            return reduceTranscript(current, {
                type: "tool",
                tool: event.tool,
                call_id: event.call_id,
                mediated: true,
            });
        }
        if (event.type === "tool-result") {
            return reduceTranscript(current, {
                type: "toolresult",
                call_id: event.call_id,
                ok: event.ok,
            });
        }
        return current;
    }, transcript()));
    const refresh = async () => {
        // Admission also feeds global navigation while this workspace is not
        // the displayed surface. In that state there is no page/chat request
        // lifetime to own, so renew only the session. This is what lets a
        // newly linked native account recover an initial signed-out refusal.
        if (!options.active()) {
            await refetchSession();
            return;
        }
        const request = navigation.begin();
        try {
            await refetchSession();
            request.assertCurrent();
            await Promise.all([refetchPage(), refetchProposals(), refetchMessages()]);
            request.assertCurrent();
        } finally { request.finish(); }
    };
    const retry = () => { void refresh().catch(() => undefined); };
    const updateChannel = createGaugeAppUpdateChannel({
        session: visibleSession,
        read: (admitted, after) => options.api.readGaugeAppUpdates(admitted, after),
        apply: async () => { await refresh(); },
        recover: async (_admitted, error) => {
            if (!(error instanceof RouteHttpError) || (error.status !== 401 && error.status !== 403)) return;
            // Authorization epochs are server-owned. A refused update cursor is
            // repaired only by a fresh admission; failure hides the old session
            // through createGaugeAppResource instead of leaving revoked data live.
            try { await refetchSession(); } catch { /* session.error owns the unavailable state */ }
        },
        onDelayedChange: setUpdatesDelayed,
        intervalMs: options.updateIntervalMs,
        retryMs: options.updateRetryMs,
    });
    createEffect(() => {
        if (visibleSession()) updateChannel.start();
        else updateChannel.stop();
    });
    onCleanup(updateChannel.dispose);
    const send = async (message: string, _images: readonly unknown[] = [], composedId?: string) => {
        const admitted = session();
        if (!admitted) throw new Error(`${APP_LABELS[options.app]} is not admitted`);
        const request = sessionOperations.begin();
        try {
            const turn = await options.api.sendGaugeAppAgentMessage(
                admitted,
                message,
                composedId ?? newIdempotencyKey(),
            );
            request.assertCurrent();
            await Promise.all([refetchMessages(), refetchProposals()]);
            request.assertCurrent();
            if (turn.proposals.length) {
                openPage(turn.proposals[0].page_id);
                setStatus(request, `${turn.proposals.length} ${turn.proposals.length === 1 ? "change" : "changes"} ready to review`);
            }
        } catch (error) {
            if (!request.current()) throw gaugeAppContextChanged();
            if (error instanceof RouteHttpError && error.status === 499) {
                await refetchMessages();
                request.assertCurrent();
                return;
            }
            throw error;
        } finally {
            request.finish();
        }
    };
    const stop = async () => {
        const admitted = visibleSession();
        if (!admitted) throw new Error(`${APP_LABELS[options.app]} is not admitted`);
        const visit = sessionOperations.identity();
        await options.api.stopGaugeAppAgentTurn(admitted);
        if (sessionOperations.identity() !== visit) throw gaugeAppContextChanged();
    };
    const clearConversation = async () => {
        const admitted = visibleSession();
        if (!admitted) throw new Error(`${APP_LABELS[options.app]} is not admitted`);
        const request = sessionOperations.begin();
        setClearError("");
        try {
            await options.api.eraseGaugeAppAgentTranscript(admitted, newIdempotencyKey());
            request.assertCurrent();
            setLiveFrames([]);
            setLiveActive(false);
            await refetchMessages();
            request.assertCurrent();
            setConfirmingClear(false);
        } catch (error) {
            if (!request.current()) throw gaugeAppContextChanged();
            setClearError(error instanceof Error ? error.message : String(error));
        } finally {
            request.finish();
        }
    };
    const chatSession = createMemo<Session | undefined>(() => {
        const admitted = visibleSession();
        if (!admitted) return undefined;
        const visit = sessionOperations.identity();
        return {
            api: { getTree: async () => [], getFile: async () => "", putFile: async () => undefined },
            engagementId: () => engagementId(admitted.id),
            worktreeRev: () => admitted.update_cursor,
            selectedFile: () => null,
            selectFile: () => undefined,
            diff: () => "",
            mergePhase: () => null,
            mergeConflicted: () => false,
            chatKind: () => "work",
            methodName: () => APP_LABELS[options.app],
            transcript: liveTranscript,
            busy,
            turnActivity: localTurnActivity(busy, liveTranscript),
            composerCapabilities: () => ({ queue: false, steer: false, stop: true, hold: false, fork: false, attachments: [] }),
            canCommand: () => true,
            merge: () => undefined,
            onContentSaved: () => undefined,
            send: ((...args: Parameters<typeof send>) => {
                if (sessionOperations.identity() !== visit) throw gaugeAppContextChanged();
                return send(...args);
            }) as Session["send"],
            appliesComposedIdOnce: true,
            stop,
        };
    });
    const review = async (proposal: GaugeAppProposal, decision: "accept" | "reject") => {
        const admitted = session();
        if (!admitted || busy()) return;
        const request = pageOperations.begin();
        setStatus(request, decision === "accept" ? "Applying change…" : "Discarding change…");
        try {
            let authorizationProof: string | undefined;
            if (decision === "accept" && FRESH_AUTHORIZATION_COMMANDS.has(proposal.command_id)) {
                if (!navigator.credentials?.get) throw new Error("This browser cannot verify account passkeys.");
                setStatus(request, "Confirm with your account passkey…");
                const ceremony = await options.api.startAccountAuthorization(proposal.command_id);
                request.assertCurrent();
                const credential = await navigator.credentials.get({
                    publicKey: publicKeyRequestOptions(ceremony.public_key),
                    signal: request.signal,
                });
                request.assertCurrent();
                if (!(credential instanceof PublicKeyCredential)) throw new Error("Passkey verification was cancelled.");
                authorizationProof = await options.api.finishAccountAuthorization(
                    ceremony.ceremony_id,
                    authenticationCredentialJSON(credential),
                );
                request.assertCurrent();
                setStatus(request, "Applying change…");
            }
            const reviewKey = newIdempotencyKey();
            const callReview = () => options.api.reviewGaugeAppProposal(
                admitted, proposal.id, decision, reviewKey, authorizationProof,
            );
            let response;
            try {
                response = await callReview();
            } catch (error) {
                if (decision !== "accept" || proposal.command_id !== "account.erase") throw error;
                // The fence may have won before a response was lost. One exact
                // possession-bound retry is safe and remains server-authoritative.
                setStatus(request, "Checking account deletion…");
                await new Promise((resolve) => window.setTimeout(resolve, 300));
                request.assertCurrent();
                response = await callReview();
            }
            request.assertCurrent();
            while (
                decision === "accept"
                && proposal.command_id === "account.erase"
                && response.receipt.status === "applying"
            ) {
                setStatus(request, "Deleting account…");
                await new Promise((resolve) => window.setTimeout(resolve, 300));
                request.assertCurrent();
                try {
                    response = await callReview();
                } catch {
                    // A fenced account has no ordinary session with which to
                    // start over. Retain the exact retry coordinate and keep
                    // checking until this view is left or authority responds.
                    setStatus(request, "Reconnecting to account deletion…");
                    continue;
                }
                request.assertCurrent();
            }
            setTransientResult({ owner: request, value: response.result });
            setStatus(request, response.receipt.status === "applying" ? "Approved; waiting for service confirmation" : decision === "accept" ? "Change applied" : "Change discarded");
            if (
                decision === "accept"
                && proposal.command_id === "account.erase"
                && response.receipt.status === "applied"
            ) {
                setStatus(request, "Account deleted");
                await options.onAccountErased?.();
                return;
            }
            if (
                decision === "accept"
                && proposal.command_id === "organization.delete"
                && response.receipt.status === "applied"
            ) {
                await options.onOrganizationDeleted?.(admitted.scope.id);
                return;
            }
            await refresh();
            if (
                decision === "accept"
                && response.receipt.status === "applied"
                && proposal.command_id.startsWith("subscription.service.")
            ) {
                await options.onTenantServicesChanged?.();
            }
        } catch (error) {
            if (!request.current()) return;
            setStatus(request, `Could not review change: ${String(error)}`);
            // A server may have durably accepted the review before the response
            // was lost. Refresh its status without inventing success or reverting
            // it to an editable/discardable local proposal.
            try { await refetchProposals(); } catch { /* Keep the visible error. */ }
        } finally {
            request.finish();
        }
    };
    const submit: SubmitPageCommand = async (commandId, payload) => {
        const admitted = session();
        const current = page();
        if (!admitted || !current) throw new Error(`${APP_LABELS[options.app]} page is not ready`);
        const request = pageOperations.begin();
        const transientStripeSession = [
            "commercial-payments.connect.continue",
            "commercial-payments.connect-component.open",
            "commercial-payments.processor-documents.open",
            "commercial-payments.processor-support.open",
        ].includes(commandId);
        const submitOnce = async (id: string, body: Readonly<Record<string, unknown>>) => {
            request.assertCurrent();
            const response = await options.api.submitGaugeAppCommand({
                session_id: admitted.id,
                generation: admitted.generation,
                app: options.app,
                scope: admitted.scope,
                page_id: current.id,
                command_id: id,
                expected_basis: current.resource_basis,
                idempotency_key: newIdempotencyKey(),
                payload: body,
                client: "web",
            });
            // Stripe Account Session secrets belong only to the mounted Connect
            // component. Do not retain them in the generic one-time-result UI.
            request.assertCurrent();
            if (!transientStripeSession) setTransientResult({ owner: request, value: response.result });
            return response;
        };
        setStatus(request, "Applying change…");
        try {
            let response = await submitOnce(commandId, payload);
            request.assertCurrent();
            if (commandId === "account.authenticator.begin-add") {
                const result = valueRecord(response.result) ?? {};
                if (!navigator.credentials?.create) throw new Error("This browser cannot create passkeys.");
                setStatus(request, "Waiting for your passkey…");
                const credential = await navigator.credentials.create({ publicKey: publicKeyCreationOptions(result.public_key), signal: request.signal });
                request.assertCurrent();
                if (!(credential instanceof PublicKeyCredential)) throw new Error("Passkey creation was cancelled.");
                response = await submitOnce("account.authenticator.complete-add", {
                    ceremony_id: text(result.ceremony_id, ""),
                    label: "Passkey",
                    attestation: registrationCredentialJSON(credential),
                });
            }
            if (response.receipt.status === "proposed") {
                setStatus(request, "Change prepared for review");
                await refetchProposals();
            } else if (transientStripeSession) {
                // Refetching would remount the embedded component and immediately
                // replace the short-lived session it just requested.
                setStatus(request, "Stripe tool ready");
            } else {
                setStatus(request, "Change applied");
                await refetchSession();
                request.assertCurrent();
                await Promise.all([refetchPage(), refetchProposals()]);
            }
            request.assertCurrent();
            return response;
        } catch (error) {
            if (!request.current()) throw gaugeAppContextChanged();
            setStatus(request, `Could not apply change: ${error instanceof Error ? error.message : String(error)}`);
            throw error;
        } finally {
            request.finish();
        }
    };
    const submitSecret: SubmitPageSecret = async (commandId, payload, secret) => {
        const admitted = session();
        const current = page();
        if (!admitted || !current || options.app !== "account-settings") {
            throw new Error("Provider Connections is not ready");
        }
        const request = pageOperations.begin();
        setStatus(request, "Connecting provider…");
        try {
            const response = await options.api.submitAccountProviderSecret({
                session_id: admitted.id,
                generation: admitted.generation,
                app: "account-settings",
                scope: admitted.scope,
                page_id: current.id,
                command_id: commandId,
                expected_basis: current.resource_basis,
                idempotency_key: newIdempotencyKey(),
                payload,
                client: "web",
            }, secret);
            request.assertCurrent();
            setStatus(request, "Provider connected");
            await refetchSession();
            request.assertCurrent();
            await refetchPage();
            request.assertCurrent();
            return response;
        } catch (error) {
            if (!request.current()) throw gaugeAppContextChanged();
            setStatus(request, `Could not connect provider: ${error instanceof Error ? error.message : String(error)}`);
            throw error;
        } finally {
            request.finish();
        }
    };
    const chat = (controls: { readonly mobile: boolean; readonly onCollapse: () => void }) => <Show keyed when={sessionOperations.identity()}><Show when={chatSession()} fallback={<p class="gaugeapp-loading">Opening {APP_LABELS[options.app]}…</p>}>
            {(active) => <>
                <ChatPaneHeader
                    branch={APP_LABELS[options.app]}
                    kind="management"
                    statusLabel={busy() ? "Working" : "Ready"}
                    mobile={controls.mobile}
                    onCollapse={controls.onCollapse}
                    menu={<GaugeAppChatMenu
                        busy={busy()}
                        hasMessages={(messages()?.messages.length ?? 0) > 0}
                        onClear={() => setConfirmingClear(true)}
                    />}
                />
                <Show when={confirmingClear()}>
                    <div class="gaugeapp-chat-clear" role="alert">
                        <span>Clear this conversation? Its messages cannot be recovered.</span>
                        <div>
                            <button type="button" disabled={busy()} onClick={() => setConfirmingClear(false)}>Cancel</button>
                            <button type="button" class="danger" disabled={busy()} onClick={() => void clearConversation()}>Clear conversation</button>
                        </div>
                    </div>
                </Show>
                <Show when={clearError()}>{(message) => <p class="gaugeapp-chat-error" role="alert">Could not clear this conversation: {message()}</p>}</Show>
                <ChatPanel
                    session={active()}
                    bare
                    agentName={APP_LABELS[options.app]}
                    composerPlaceholder={`ask ${APP_LABELS[options.app].toLowerCase()}…`}
                />
                <Show when={messages.error}><p class="gaugeapp-loading" role="alert">Could not load this conversation. <button type="button" onClick={retry}>Retry</button></p></Show>
            </>}
        </Show></Show>;
    const content = () => <main class="gaugeapp-content">
            <Show when={updatesDelayed()}><p class="gaugeapp-loading gaugeapp-update-delayed" role="status">
                Updates are delayed. Showing the last loaded data. <button type="button" onClick={retry}>Refresh</button>
            </p></Show>
            <Show when={status()}>{(message) => <p class="gaugeapp-status" role="status">{message()}</p>}</Show>
            <Show when={safeExternalUrl(valueRecord(oneTimeResult())?.url)}>{(url) => {
                const destination = text(valueRecord(oneTimeResult())?.destination, "stripe");
                const label = destination === "checkout" ? "Checkout ready"
                    : destination === "payment_method" ? "Payment settings ready"
                        : destination === "subscription_seats" ? "Seat change ready"
                            : destination === "subscription_cancellation" ? "Cancellation confirmation ready"
                                : "Billing portal ready";
                return <section class="gaugeapp-one-time" aria-label="Stripe handoff">
                    <div><strong>{label}</strong><span>Continue securely in Stripe. Return here when finished.</span></div>
                    <span />
                    <div class="gaugeapp-actions"><a href={url()} target="_blank" rel="noreferrer">Continue in Stripe</a><button type="button" onClick={() => void retry()}>Refresh status</button><button type="button" onClick={() => setOneTimeResult(undefined)}>Dismiss</button></div>
                </section>;
            }}</Show>
            <Show when={typeof valueRecord(oneTimeResult())?.token === "string" ? valueRecord(oneTimeResult())?.token as string : null}>{(token) => <section class="gaugeapp-one-time" aria-label="New SCIM credential">
                <div><strong>Save the SCIM credential now</strong><span>It will not be shown again. Rotating it revokes the previous value.</span></div>
                <code>{token()}</code>
                <div class="gaugeapp-actions"><button type="button" onClick={() => void navigator.clipboard.writeText(token())}>Copy</button><button type="button" onClick={() => setOneTimeResult(undefined)}>I saved it</button></div>
            </section>}</Show>
            <Show when={valueArray(valueRecord(oneTimeResult())?.recovery_codes).length > 0}>
                <section class="gaugeapp-one-time" aria-label="New recovery codes">
                    <div><strong>Save these recovery codes now</strong><span>They will not be shown again.</span></div>
                    <code>{valueArray(valueRecord(oneTimeResult())?.recovery_codes).join("\n")}</code>
                    <button type="button" onClick={() => setOneTimeResult(undefined)}>I saved them</button>
                </section>
            </Show>
            <Show when={valueArray(valueRecord(oneTimeResult())?.delivery_links).length > 0}>
                <section class="gaugeapp-one-time gaugeapp-delivery-links" aria-label={valueRecord(oneTimeResult())?.delivery_kind === "organization-invitation" ? "Organization invitation links" : "Proposal delivery links"}>
                    <div><strong>{valueRecord(oneTimeResult())?.delivery_kind === "organization-invitation" ? "Invitation links ready" : "Proposal links ready"}</strong><span>Each link is addressed to one recipient and is shown only now. Resending replaces it.</span></div>
                    <div class="gaugeapp-delivery-link-list"><For each={valueArray(valueRecord(oneTimeResult())?.delivery_links)}>{(delivery) => {
                        const organizationInvitation = valueRecord(oneTimeResult())?.delivery_kind === "organization-invitation";
                        const url = organizationInvitation
                            ? organizationInvitationUrl(delivery)
                            : proposalDeliveryUrl(session()?.scope.id ?? "", delivery);
                        return <div><span>{organizationInvitation ? text(valueRecord(delivery)?.email, "Recipient") : proposalRecipientLabel(delivery)}</span><Show when={url}>{(href) => <div class="gaugeapp-actions"><button type="button" onClick={() => void navigator.clipboard.writeText(href())}>Copy link</button><a href={href()} target="_blank" rel="noreferrer">Open</a></div>}</Show></div>;
                    }}</For></div>
                    <button type="button" onClick={() => setOneTimeResult(undefined)}>Done</button>
                </section>
            </Show>
            <Show when={proposalDeliveryStatus(oneTimeResult())}>{(result) => <section class="gaugeapp-one-time gaugeapp-delivery-links" aria-label="Proposal delivery status">
                <div><strong>Proposal delivery</strong><span>{typeof result().sent_at_ms === "number" ? `Sent ${new Date(result().sent_at_ms as number).toLocaleString()}` : "Not sent"}</span></div>
                <div class="gaugeapp-delivery-link-list"><Show when={valueArray(result().deliveries).length > 0} fallback={<span>No links are recorded for this proposal revision.</span>}><For each={valueArray(result().deliveries)}>{(delivery) => <div><span>{proposalRecipientLabel(delivery)}</span><strong>{valueRecord(delivery)?.accepted === true ? "Accepted" : "Link issued"}</strong></div>}</For></Show></div>
                <button type="button" onClick={() => setOneTimeResult(undefined)}>Done</button>
            </section>}</Show>
            <Show when={commercialEvidence(oneTimeResult())}>{(evidence) => <CommercialEvidenceResult evidence={evidence()} onDone={() => setOneTimeResult(undefined)} />}</Show>
            <Show when={session.error}>
                <p class="gaugeapp-loading" role="alert">{APP_LABELS[options.app]} is unavailable. Project work remains available. <button type="button" onClick={retry}>Retry</button></p>
            </Show>
            <Show keyed when={pageOperations.identity()}>{(visit) => {
                // A disposed panel must not invoke a callback against whichever
                // scope happens to be selected when its own async work finishes.
                const assertVisit = () => { if (pageOperations.identity() !== visit || visit.key === undefined) throw gaugeAppContextChanged(); };
                const scopedSubmit: SubmitPageCommand = (...args) => { assertVisit(); return submit(...args); };
                const scopedSecret: SubmitPageSecret = (...args) => { assertVisit(); return submitSecret(...args); };
                const scopedRefresh = () => { assertVisit(); return refresh(); };
                return <Show when={page()} fallback={<p class="gaugeapp-loading" role={page.error ? "alert" : "status"}>
                <Show when={page.error} fallback={<>Loading {PAGE_LABELS[selectedPage()] ?? "page"}…</>}>
                    This page is unavailable. <button type="button" onClick={retry}>Retry</button>
                </Show>
            </p>}>
                {(current) => <>
                    <GaugeAppPage
                        app={options.app}
                        session={session()!}
                        page={current()}
                        commands={session()?.pages.find((grant) => grant.id === current().id)?.commands ?? []}
                        onSubmit={scopedSubmit}
                        onSubmitSecret={scopedSecret}
                        api={options.api}
                        onRefresh={scopedRefresh}
                        deviceLinkInvitation={options.deviceLinkInvitation?.() ?? null}
                        onDeviceLinkClaimed={options.onDeviceLinkClaimed}
                        organizationInvitation={options.organizationInvitation?.() ?? null}
                        onOrganizationInvitationResponded={options.onOrganizationInvitationResponded}
                        openExternal={options.openExternal}
                        onOpenProject={options.onOpenProject}
                        onOpenGaugeApp={options.onOpenGaugeApp}
                    />
                    <ProposalList
                        proposals={proposals() ?? []}
                        page={current()}
                        busy={busy()}
                        onReview={(proposal, decision) => { assertVisit(); void review(proposal, decision); }}
                    />
                    <Show when={proposals.error}><p class="gaugeapp-loading" role="alert">Could not load pending changes. <button type="button" onClick={retry}>Retry</button></p></Show>
                </>}
            </Show>;
            }}</Show>
        </main>;
    const menu = () => <nav class="gaugeapp-menu" aria-label={`${APP_LABELS[options.app]} pages`}>
            <h2>Menu</h2>
            <For each={session()?.pages ?? []}>{(grant) => <button
                type="button"
                classList={{ active: selectedPage() === grant.id }}
                aria-current={selectedPage() === grant.id ? "page" : undefined}
                onClick={() => openPage(grant.id)}
            >
                <span>{PAGE_LABELS[grant.id] ?? grant.id}</span>
                <Show when={pageFreshnessCaveat(grant.freshness)}>{(caveat) => <small>{caveat()}</small>}</Show>
            </button>}</For>
        </nav>;
    return {
        app: options.app,
        admitted: () => Boolean(session()),
        session,
        selectedPage,
        page,
        openPage,
        refresh,
        chat,
        content,
        menu,
        onNewChat: () => undefined,
    };
}

/** Transitional standalone mount retained only for deep conformance tests while
 * EnterpriseWorkbench moves all three Apps into the ordinary shell. */
export function AdministrationGaugeApp(props: {
    api: EnterpriseControlPlane;
    onReturnToWork: () => void;
}): JSX.Element {
    const controller = createGaugeAppWorkspace({
        api: props.api,
        app: "administration",
        enabled: () => true,
        active: () => true,
        scope: () => undefined,
    });
    const shell = createWorkbenchShellState({
        storagePrefix: "ui.gaugeapp.administration",
        selection: () => ({ chatSelected: true, fileSelected: Boolean(controller.selectedPage()) }),
    });
    return <WorkbenchShell
        state={shell}
        titles={{
            nav: "Navigate",
            chat: `${appLabel(controller.app, controller.session()?.scope)} agent`,
            content: appLabel(controller.app, controller.session()?.scope),
            files: "Menu",
        }}
        headings={{ chat: false, content: false, files: false }}
        nav={() => <div class="gaugeapp-nav"><button type="button" class="gaugeapp-back" data-admin-return onClick={props.onReturnToWork}>← Work</button></div>}
        chat={() => controller.chat({ mobile: shell.isMobile(), onCollapse: () => shell.setCollapsed("chat", true) })}
        content={controller.content}
        files={controller.menu}
        onNewChat={() => shell.openPane("chat", { chatSelected: true, fileSelected: true })}
    />;
}
