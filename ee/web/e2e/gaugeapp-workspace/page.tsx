import { createEffect, createSignal, onCleanup } from "solid-js";
import { render } from "solid-js/web";
import { createGaugeAppWorkspace } from "../../apps/enterprise-workbench/src/AdministrationGaugeApp";
import { applyAppearancePreference, resetAppearancePreference } from "../../apps/enterprise-workbench/src/appearance-preference";
import { gaugeAppPageDefinitions, RouteHttpError, type AccountDeviceLinkStatus, type AppearancePreferenceV1, type CommercialEngagement, type CommercialProduct, type CommercialProductRevision, type ProviderConnectionModel, type GaugeAppAgentLiveFrame, type GaugeAppKind, type GaugeAppPageModel, type GaugeAppProposal, type GaugeAppScope, type GaugeAppSession, type GaugeAppUpdateSnapshot } from "@gaugewright/control-plane-client";
import type { EnterpriseControlPlane } from "@gaugewright/enterprise-client";
import { administrationEmptyModels } from "../../../../web/packages/control-plane-client/src/gaugeapp-administration-models.fixture";
import { commercialEmptyModels, commercialTestEngagement, commercialTestRevision } from "../../../../web/packages/control-plane-client/src/gaugeapp-commercial-models.fixture";
import { AccountEntry, createWorkbenchShellState, OpenSettingsMenu, type OpenSettingsMenuApi, WorkbenchShell } from "../../../../web/packages/workbench-ui/src";
import { MobileGaugeAppSurface } from "../../../../web/apps/mobile-web/src/MobileApp";
import "../../../../web/packages/workbench-ui/src/styles.css";

function RecoveryEntryHarness() {
    const [completed, setCompleted] = createSignal("");
    const [attempts, setAttempts] = createSignal(0);
    return <main style="max-width:720px;margin:64px auto;padding:20px">
        <AccountEntry
            personalLabel="Continue with Google"
            onPersonal={() => undefined}
            recovery={{
                start: async () => ({ challengeId: `challenge-${attempts() + 1}`, expiresIn: 600 }),
                finish: async (_challengeId, _emailCode, recoveryCode) => {
                    setAttempts((value) => value + 1);
                    if (recoveryCode === "FAIL") throw new Error("Those recovery proofs were not accepted. Start again with a new email code.");
                },
                complete: () => setCompleted("Account recovered"),
            }}
            workEmailAction="/__fixture/work-email"
        />
        <output hidden aria-label="Recovery result">{completed()}</output>
        <output hidden aria-label="Recovery attempts">{attempts()}</output>
    </main>;
}

function AccountMenuHarness(props: { state: "signed-out" | "signed-in"; fail?: boolean }) {
    const [result, setResult] = createSignal("");
    return <main style="max-width:320px;margin:64px auto;padding:20px">
        <OpenSettingsMenu
            api={{} as OpenSettingsMenuApi}
            composition="desktop"
            identity={() => props.state === "signed-in"
                ? { name: "Ada Lovelace", email: "ada@example.test", edition: "Personal" }
                : null}
            gaugeAppActions={() => []}
            onSignIn={async () => {
                if (props.fail) throw new Error("Account service unavailable. Try again.");
                setResult("Account sign-in requested");
            }}
            onSignOut={async () => {
                if (props.fail) throw new Error("Sign out could not be completed. Try again.");
                setResult("Account sign-out requested");
            }}
            version="0.4.9"
        />
        <output aria-label="Account entry result">{result()}</output>
    </main>;
}

const fixtureEncoder = new TextEncoder();
const fixtureHex = (value: ArrayBuffer | ArrayBufferView) => {
    const bytes = value instanceof ArrayBuffer
        ? new Uint8Array(value)
        : new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
    return [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");
};
const fixtureBytes = (value: string) => Uint8Array.from(value.match(/.{2}/g) ?? [], (byte) => Number.parseInt(byte, 16));
const fixtureBuffer = (value: Uint8Array) => Uint8Array.from(value).buffer;
const fixtureJoin = (...values: readonly Uint8Array[]) => {
    const result = new Uint8Array(values.reduce((size, value) => size + value.byteLength, 0));
    let offset = 0;
    for (const value of values) { result.set(value, offset); offset += value.byteLength; }
    return result;
};
const fixtureU64 = (value: number) => {
    const result = new Uint8Array(8);
    new DataView(result.buffer).setBigUint64(0, BigInt(value), false);
    return result;
};

interface FixtureDeviceAuthority {
    readonly rootPrivate: CryptoKey;
    readonly rootPublic: string;
    readonly accountKey: Uint8Array;
}

async function createFixtureDeviceAuthority(): Promise<FixtureDeviceAuthority> {
    const root = await crypto.subtle.generateKey(
        { name: "ECDSA", namedCurve: "P-256" },
        true,
        ["sign", "verify"],
    ) as CryptoKeyPair;
    const accountKey = crypto.getRandomValues(new Uint8Array(32));
    return {
        rootPrivate: root.privateKey,
        rootPublic: fixtureHex(await crypto.subtle.exportKey("raw", root.publicKey)),
        accountKey,
    };
}

async function createFixtureDeviceAuthorization(
    authority: FixtureDeviceAuthority,
    linkId: string,
    subkey: string,
): Promise<{ authorization: NonNullable<AccountDeviceLinkStatus["authorization"]>; challenge: string }> {
    const expiry = Math.floor(Date.now() / 1_000) + 600;
    const delegationMaterial = fixtureEncoder.encode(`gaugewright-device-delegation::v1::root=${authority.rootPublic}::sub=${subkey}::exp=${expiry}`);
    const signature = await crypto.subtle.sign(
        { name: "ECDSA", hash: "SHA-256" }, authority.rootPrivate, delegationMaterial,
    );
    const recipient = await crypto.subtle.importKey(
        "raw", fixtureBuffer(fixtureBytes(subkey)), { name: "ECDH", namedCurve: "P-256" }, false, [],
    );
    const ephemeral = await crypto.subtle.generateKey(
        { name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"],
    ) as CryptoKeyPair;
    const shared = new Uint8Array(await crypto.subtle.deriveBits(
        { name: "ECDH", public: recipient }, ephemeral.privateKey, 256,
    ));
    const encryptionKey = await crypto.subtle.digest(
        "SHA-256",
        fixtureBuffer(fixtureJoin(fixtureEncoder.encode("gaugewright/acct-1/device-enroll/ecies/v1"), shared)),
    );
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encrypted = new Uint8Array(await crypto.subtle.encrypt(
        { name: "AES-GCM", iv, tagLength: 128 },
        await crypto.subtle.importKey("raw", encryptionKey, "AES-GCM", false, ["encrypt"]),
        fixtureBuffer(authority.accountKey),
    ));
    const challenge = `gaugewright-device-enrollment-complete::v1::link=${linkId}::root=${authority.rootPublic}::sub=${subkey}::exp=${expiry}`;
    return {
        authorization: {
            delegation: {
                subkey,
                authority_root: authority.rootPublic,
                expiry,
                signature: [...new Uint8Array(signature)],
            },
            sealed_key: {
                ephemeral_pubkey: fixtureHex(await crypto.subtle.exportKey("raw", ephemeral.publicKey)),
                ciphertext: fixtureHex(fixtureJoin(iv, encrypted)),
            },
        },
        challenge,
    };
}

async function verifyFixtureDeviceCompletion(
    authority: FixtureDeviceAuthority,
    subkey: string,
    challenge: string,
    completion: { readonly account_key_proof: string; readonly signature: string },
): Promise<void> {
    const material = fixtureEncoder.encode(challenge);
    const expectedProof = fixtureHex(await crypto.subtle.digest(
        "SHA-256",
        fixtureBuffer(fixtureJoin(
            fixtureEncoder.encode("gaugewright-device-enrollment-account-key-proof::v1"),
            authority.accountKey,
            fixtureU64(material.byteLength),
            material,
        )),
    ));
    const device = await crypto.subtle.importKey(
        "raw", fixtureBuffer(fixtureBytes(subkey)), { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"],
    );
    const signed = await crypto.subtle.verify(
        { name: "ECDSA", hash: "SHA-256" },
        device,
        fixtureBuffer(fixtureBytes(completion.signature)),
        material,
    );
    if (completion.account_key_proof !== expectedProof || !signed) throw new Error("Fixture refused device completion proof.");
}

interface FixtureDeviceLink {
    readonly id: string;
    readonly phase: "waiting-for-device" | "awaiting-acceptance" | "authorized" | "enrolled" | "rejected" | "canceled";
    readonly human_code: string;
    readonly qr_payload: string;
    readonly created_at_ms: number;
    readonly expires_at_ms: number;
    readonly device: { readonly id: string; readonly label: string; readonly kind: "computer" | "phone" | "tablet" } | null;
    readonly sas: string | null;
    readonly completed_at_ms: number | null;
    readonly subkey?: string;
    readonly authorization?: NonNullable<AccountDeviceLinkStatus["authorization"]>;
    readonly challenge?: string;
}

interface FixtureAccountLifecycleState {
    readonly display_name: string;
    readonly authenticator_ids: readonly string[];
    readonly consumer_oidc_id: string;
    readonly consumer_oidc_pending: boolean;
    readonly consumer_oidc_linked: boolean;
    readonly recovery_batches: readonly { readonly id: string; readonly created_at: number; readonly remaining_codes: number }[];
    readonly session_ids: readonly string[];
    readonly membership_ids: readonly string[];
    readonly invitations: readonly { readonly tenant_id: string; readonly display_name: string; readonly role: string }[];
}

// Only authority replies and timing are synthetic. Tests click the production
// page/menu/chat controls and exercise the actual workspace controller.
function Harness() {
    const query = new URLSearchParams(location.search);
    const app = (query.get("app") ?? "administration") as GaugeAppKind;
    const actualShell = query.get("shell") === "1";
    const mobileSurface = query.get("mobile-surface") === "1";
    const allPages = query.get("all-pages") === "1";
    const actionablePages = query.get("actionable-pages") === "1";
    const persistentAgent = query.get("persistent-agent") === "1";
    const streamingAgent = query.get("stream-agent") === "1";
    const persistentRun = query.get("run")?.trim() || "default";
    const identityMode = query.get("identity");
    // Seeds the Organization page with a domain at each stage, so the pending
    // claim and the record it asks the administrator to publish can be driven
    // in the real page rather than only asserted against the server.
    const domainState = query.get("domains");
    const projectHostMode = query.get("project-host") === "managed";
    const deviceLinkMode = query.get("device-link") === "1";
    const providerLifecycleMode = query.get("provider-lifecycle") === "1";
    const accountLifecycleMode = query.get("account-lifecycle") === "1";
    const accountErasureMode = query.get("account-erasure") === "1";
    const accountErasureBlocked = query.get("erasure-blocked") === "1";
    const projectHostSettingsMode = query.get("project-host-settings") === "1";
    const appearanceMode = query.get("appearance") === "1";
    const subscriptionLifecycleMode = query.get("subscription-lifecycle") === "1";
    const billingUnavailableMode = query.get("billing-unavailable") === "1";
    const commercialLifecycle = query.get("commercial-lifecycle");
    const commercialCurrency = query.get("currency") === "jpy" ? "jpy" : null;
    const identityConfigured = identityMode === "configured" || identityMode === "lifecycle";
    const [scopeId, setScopeId] = createSignal("A");
    const [enabled, setEnabled] = createSignal(true);
    const [active, setActive] = createSignal(true);
    const [generation, setGeneration] = createSignal(1);
    const [refreshTick, setRefreshTick] = createSignal(0);
    const [hold, setHold] = createSignal(false);
    const [pending, setPending] = createSignal<Array<{ resolve: () => void; reject: () => void }>>([]);
    const [calls, setCalls] = createSignal<unknown[]>([]);
    const [stripe, setStripe] = createSignal<string[]>([]);
    const [denyReads, setDenyReads] = createSignal(false);
    const [denyUpdates, setDenyUpdates] = createSignal(query.get("updates") === "down");
    const [denyActions, setDenyActions] = createSignal(false);
    const [reviewNext, setReviewNext] = createSignal(false);
    const [serverRevision, setServerRevision] = createSignal(0);
    const [identitySecretConfigured, setIdentitySecretConfigured] = createSignal(false);
    const [identityTested, setIdentityTested] = createSignal(false);
    const [identityAdmission, setIdentityAdmission] = createSignal<"invited-only" | "verified-domain-jit" | "scim" | null>(null);
    const [identityOwnerLinked, setIdentityOwnerLinked] = createSignal(false);
    const [identityEnforced, setIdentityEnforced] = createSignal(false);
    const [projectHostLifecycle, setProjectHostLifecycle] = createSignal<"active" | "retention" | "deleted">("active");
    const [commercialProductRevision, setCommercialProductRevision] = createSignal(1);
    const [commercialProductTitle, setCommercialProductTitle] = createSignal(commercialTestRevision.listing_title);
    const [commercialCreatedProduct, setCommercialCreatedProduct] = createSignal<CommercialProduct | null>(null);
    const [commercialClientName, setCommercialClientName] = createSignal("Cosmos Design");
    const [commercialClientBillingReference, setCommercialClientBillingReference] = createSignal<string | null>("COSMOS-001");
    const [commercialClientStatus, setCommercialClientStatus] = createSignal<"active" | "closed">("active");
    const [commercialEngagementTerms, setCommercialEngagementTerms] = createSignal(commercialTestEngagement.terms);
    const [commercialEngagementPresent, setCommercialEngagementPresent] = createSignal(true);
    const [commercialProposalRevision, setCommercialProposalRevision] = createSignal(1);
    const [commercialEngagementStage, setCommercialEngagementStage] = createSignal<"draft" | "sent" | "withdrawn" | "accepted" | "active" | "closed">(commercialLifecycle === "accepted" ? "accepted" : "draft");
    const [commercialCreatedEngagement, setCommercialCreatedEngagement] = createSignal<CommercialEngagement | null>(null);
    const [commercialPlacement, setCommercialPlacement] = createSignal<string | null>(null);
    const [commercialEntitlement, setCommercialEntitlement] = createSignal<"inactive" | "active" | "suspended" | "revoked">("inactive");
    const [subscriptionStanding, setSubscriptionStanding] = createSignal<"lapsed" | "active">("lapsed");
    const [fixtureDeviceLink, setFixtureDeviceLink] = createSignal<FixtureDeviceLink | null>(null);
    const [fixtureLinkedDevice, setFixtureLinkedDevice] = createSignal<FixtureDeviceLink["device"]>(null);
    const [fixtureProviderConnections, setFixtureProviderConnections] = createSignal<ProviderConnectionModel[]>([]);
    const [fixtureDefaultModel, setFixtureDefaultModel] = createSignal<{ connection_id: string; model: string } | null>(null);
    const [fixtureAppearance, setFixtureAppearance] = createSignal<AppearancePreferenceV1>({
        version: 1, interface_scale: "standard", contrast: "standard", motion: "system",
    });
    const [fixtureAppearanceSaved, setFixtureAppearanceSaved] = createSignal(false);
    const accountLifecycleKey = query.get("run")?.trim() || "A";
    const [fixtureAccount, setFixtureAccount] = createSignal<FixtureAccountLifecycleState | null>(null);
    const [accountErased, setAccountErased] = createSignal(false);
    const [erasureReviewAttempts, setErasureReviewAttempts] = createSignal(0);
    const accountLifecycleUrl = `/__fixture/account-lifecycle?key=${encodeURIComponent(accountLifecycleKey)}`;
    const projectHostSettingsUrl = `/__fixture/project-host-settings?key=${encodeURIComponent(accountLifecycleKey)}`;
    const appearanceUrl = `/__fixture/appearance?key=${encodeURIComponent(accountLifecycleKey)}`;
    if (accountLifecycleMode) void fetch(accountLifecycleUrl)
        .then(async (response) => {
            if (!response.ok) throw new Error(`fixture account read returned ${response.status}`);
            setFixtureAccount(await response.json() as FixtureAccountLifecycleState);
            setServerRevision((value) => value + 1);
        });
    if (appearanceMode) void fetch(appearanceUrl)
        .then(async (response) => {
            if (!response.ok) throw new Error(`fixture appearance read returned ${response.status}`);
            const result = await response.json() as { saved: boolean; value: AppearancePreferenceV1 };
            setFixtureAppearance(result.value);
            setFixtureAppearanceSaved(result.saved);
            setServerRevision((value) => value + 1);
        });
    const [fixtureGrokSignIn, setFixtureGrokSignIn] = createSignal<{
        provider: string;
        linked: boolean;
        expires: number | null;
        expired: boolean;
        login: { login_id: string; verification_url: string; user_code: string; status: "pending" | "linked" | "cancelled"; error: null } | null;
    }>({ provider: "xai-grok", linked: false, expires: null, expired: false, login: null });
    let fixtureDeviceAuthority: Promise<FixtureDeviceAuthority> | undefined;
    const deviceAuthority = () => fixtureDeviceAuthority ??= createFixtureDeviceAuthority();
    const proposals = new Map<string, GaugeAppProposal[]>();
    const events = new Map<string, unknown[]>();
    const liveListeners = new Map<string, (frame: GaugeAppAgentLiveFrame) => void>();
    const liveDisconnects = new Map<string, () => void>();
    const liveHistories = new Map<string, GaugeAppAgentLiveFrame[]>();
    const liveTurns = new Map<string, { reject: (error: Error) => void; turnId: string }>();
    const record = (value: unknown) => setCalls((values) => [...values, value]);
    const scope = (): GaugeAppScope => ({ kind: app === "account-settings" ? "person" : app === "administration" ? "tenant" : "provider-tenant", id: scopeId() });
    const commandPages: Record<string, string[]> = allPages && actionablePages && app === "administration" ? {
        organization: domainState
            ? ["organization.display-name.set", "organization.domain.add", "organization.domain.verify", "organization.domain.remove"]
            : ["organization.display-name.set", "organization.domain.verify"],
        "plans-services": ["subscription.service.add"],
        people: ["people.invitation.create"],
        sessions: ["organization-session.revoke"],
        "enterprise-identity": ["enterprise-identity.connection.set"],
        projects: ["project.create"],
        "model-providers": ["organization-provider.api-key.add"],
        "organization-policy": ["organization-policy.set"],
        "project-hosts": ["project-host.add"],
        backups: ["backups.enable"],
        "software-policy": ["software-policy.set"],
        billing: ["billing.contact.set", "billing.payment-method.begin"],
    } : allPages && actionablePages && app === "account-settings" ? {
        account: ["account.profile.set", "account.authenticator.begin-add", "account.recovery-codes.reissue"],
        "provider-connections": ["provider-connection.api-key.add", "provider-connection.subscription.begin"],
        "trusted-devices": ["trusted-device.link.begin"],
        "application-settings": ["application-settings.appearance.set"],
    } : allPages && app === "administration" ? {
        organization: [], "plans-services": [], people: [], sessions: [], "enterprise-identity": [], projects: [],
        "model-providers": [], "organization-policy": [], "project-hosts": [], backups: [], "software-policy": [], billing: [],
    } : allPages && app === "account-settings" ? {
        account: [], "provider-connections": [], "trusted-devices": [],
        "application-settings": ["application-settings.appearance.set"],
    } : app === "administration" && billingUnavailableMode ? {
        billing: [],
    } : app === "administration" && subscriptionLifecycleMode ? {
        "plans-services": ["subscription.plan.change", "subscription.seats.change", "subscription.cancellation.schedule"],
    } : app === "administration" && projectHostMode ? {
        "project-hosts": ["project-host.rename", "project-host.suspend", "project-host.reinstate", "project-host.managed-policy.set", "project-host.retire", "project-home.handoff"],
    } : app === "administration" ? {
        "enterprise-identity": [
            "enterprise-identity.scim-credential.issue",
            "enterprise-identity.connection.set",
            "enterprise-identity.connection.credential.set",
            "enterprise-identity.connection.credential.remove",
            "enterprise-identity.connection.validate",
            "enterprise-identity.test.begin",
            "enterprise-identity.admission-mode.set",
            "enterprise-identity.owner-subject.link",
            "enterprise-identity.enforcement.enable",
            "enterprise-identity.enforcement.disable",
        ],
        people: [],
        backups: ["backups.enable", "backups.disable", "backups.schedule.set", "backups.recovery-holder.add", "backups.recovery-holder.remove", "backups.point.create", "backups.restore", "backups.restore.complete"],
    } : app === "account-settings" && deviceLinkMode ? {
        "trusted-devices": ["trusted-device.rename", "trusted-device.revoke", "trusted-device.link.begin", "trusted-device.link.accept", "trusted-device.link.reject", "trusted-device.link.cancel"],
    } : app === "account-settings" && providerLifecycleMode ? {
        "provider-connections": [
            "provider-connection.api-key.add", "provider-connection.compatible.add", "provider-connection.verify",
            "provider-connection.rename", "provider-connection.revoke", "provider-connection.default-model.set",
            "provider-connection.subscription.begin", "provider-connection.subscription.complete", "managed-inference.plan.change",
        ],
    } : app === "account-settings" && accountErasureMode ? {
        account: ["account.authenticator.begin-add", "account.authenticator.complete-add", "account.erase"],
    } : app === "account-settings" && accountLifecycleMode ? {
        account: [
            "account.profile.set", "account.authenticator.remove", "account.recovery-codes.reissue",
            "account.session.revoke-current", "account.session.revoke", "account.session.revoke-others",
            "account.invitation.accept", "account.invitation.decline", "account.membership.leave",
        ],
    } : app === "account-settings" ? {
        account: ["account.profile.set", "account.authenticator.begin-add", "account.authenticator.complete-add", "account.authenticator.remove", "account.recovery-codes.reissue", "account.membership.leave"],
        "provider-connections": ["provider-connection.api-key.add", "provider-connection.subscription.begin"],
    } : commercialLifecycle ? {
        products: ["commercial-product.create", "commercial-product.read", "commercial-product.revise"],
        clients: ["commercial-client.create", "commercial-client.read", "commercial-client.edit", "commercial-engagements.read-by-client", "commercial-payments.read-by-client", "commercial-client.close"],
        engagements: [
            "commercial-engagement.proposal.create", "commercial-engagement.proposal.save", "commercial-engagement.proposal.send",
            "commercial-engagement.proposal.discard", "commercial-engagement.proposal.revise", "commercial-engagement.proposal.resend",
            "commercial-engagement.proposal.withdraw", "commercial-engagement.proposal-delivery.read", "commercial-engagement.agreement.read", "commercial-engagement.payments.read", "commercial-engagement.placement.link", "commercial-engagement.entitlement.activate",
            "commercial-engagement.entitlement.suspend", "commercial-engagement.entitlement.revoke", "commercial-engagement.invoice.issue",
            "commercial-engagement.close",
        ],
        payments: ["commercial-payments.connect-component.open", "commercial-payments.connect.begin", "commercial-payments.payment.read", "commercial-payments.payment.refund"],
    } : { payments: ["commercial-payments.connect-component.open", "commercial-payments.connect.begin"], products: [] };
    const firstPage = Object.keys(commandPages)[0]!;
    const model = (id: string, idScope: string): unknown => {
        if (id === "account") {
            const lifecycle = accountLifecycleMode ? fixtureAccount() : null;
            const memberships = lifecycle?.membership_ids.map((membershipId) => ({
                id: membershipId,
                display_name: membershipId.startsWith("personal-") ? "Personal" : membershipId.startsWith("invited-") ? "Invited organization" : `Organization ${idScope}`,
                role: membershipId.startsWith("personal-") ? "owner" : "member",
                personal: membershipId.startsWith("personal-"),
                provider_commercial: false,
                can_leave: !membershipId.startsWith("personal-"),
                leave_blocked_reason: null,
            })) ?? [
                { id: `personal-${idScope}`, display_name: "Personal", role: "owner", personal: true, provider_commercial: false, can_leave: false, leave_blocked_reason: null },
                { id: `organization-${idScope}`, display_name: `Organization ${idScope}`, role: "member", personal: false, provider_commercial: false, can_leave: true, leave_blocked_reason: null },
            ];
            const authenticatorIds = lifecycle?.authenticator_ids ?? [`passkey-${idScope}`];
            return {
            profile: { account_id: idScope, display_name: lifecycle?.display_name ?? `Person ${idScope}${serverRevision() ? ` · revision ${serverRevision()}` : ""}` },
            consumer_oidc: { available: true, connection_id: "consumer-google", label: "Google" },
            verified_contacts: [],
            authenticators: [
                ...authenticatorIds.map((authenticatorId, index) => ({
                    id: authenticatorId, kind: "passkey", label: index ? `Backup key ${idScope}` : `Laptop ${idScope}`, created_at: 1,
                    can_remove: authenticatorIds.length > 1,
                    remove_blocked_reason: authenticatorIds.length > 1 ? null : "Add another passkey before removing this one.",
                })),
                ...(lifecycle?.consumer_oidc_linked ? [{
                    id: lifecycle.consumer_oidc_id, kind: "consumer-oidc", connection_id: "consumer-google", linked_at: 1,
                    can_remove: true, remove_blocked_reason: null,
                }] : []),
            ],
            recovery: { batches: lifecycle?.recovery_batches ?? [] },
            sessions: (lifecycle?.session_ids ?? []).map((sessionId) => ({
                id: sessionId, method: sessionId.includes("phone") ? "Phone passkey" : sessionId.includes("browser") ? "Browser sign-in" : "Laptop passkey",
                issued_at_ms: 1_900_000_000_000, last_seen_ms: 1_900_000_100_000, lifetime_secs: 86_400,
                current: sessionId.startsWith("session-current-"),
            })),
            memberships,
            invitations: lifecycle?.invitations ?? [],
            erasure: {
                available: accountErasureMode,
                confirmation: "ERASE MY ACCOUNT",
                blocking_organizations: accountErasureBlocked ? ["Sole-owner organization"] : [],
            },
        };}
        if (id === "provider-connections") return {
            connections: providerLifecycleMode ? fixtureProviderConnections() : [],
            default_model: providerLifecycleMode ? fixtureDefaultModel() : null,
            subscription_sign_ins: { codex: { provider: "openai-codex", linked: false, expires: null, expired: false, login: null }, grok: providerLifecycleMode ? fixtureGrokSignIn() : { provider: "xai-grok", linked: false, expires: null, expired: false, login: null } },
            managed_inference: { plan: null, usage: { runs: 0, input_tokens: 0, output_tokens: 0, total_tokens: 0, included_tokens: 0, overage_tokens: 0, unattributed_runs: 0, unattributed_tokens: 0 }, billing: { customer_linked: false, subscription: null, freshness: "processor-reconciled", processor_mode: "test", verification: "unlinked", configured_plan: { name: "Managed", included_tokens: 0, checkout_available: false }, management: { plan_change: false, seats: false, cancellation: false }, documents: { invoices: [], estimate: null, refreshed_at: null, history_complete: false, freshness: "not-refreshed" } } },
        };
        if (id === "trusted-devices") return {
            devices: fixtureLinkedDevice() ? [{
                id: fixtureLinkedDevice()!.id,
                label: fixtureLinkedDevice()!.label,
                subkey_pubkey: fixtureDeviceLink()?.subkey ?? "fixture-subkey",
                kind: fixtureLinkedDevice()!.kind,
                status: "active",
                enrolled_at: Math.floor(Date.now() / 1_000),
                last_seen_ms: Date.now(),
                current: true,
            }] : [],
            pending_link: fixtureDeviceLink(),
            link_availability: deviceLinkMode ? { available: true } : { available: false, reason: "No recoverable account root is available." },
        };
        if (id === "application-settings") return {
            preferences: {
                appearance: fixtureAppearance(),
            },
            appearance_saved: fixtureAppearanceSaved(),
            ownership: { "attention.rules": "person", appearance: "person" },
            managed: [],
        };
        if (id === "plans-services" && subscriptionLifecycleMode) {
            const standing = subscriptionStanding();
            const active = standing === "active";
            return {
                billing: { id: "billing-fixture", op: "upsert", plan: "GaugeDesk Cloud", seats: 1, managed_inference: { plan: "GaugeDesk Cloud", status: standing, included_tokens: active ? 100_000 : 0 } },
                billing_contact: { id: "billing-contact-fixture", op: "upsert", name: "Morgan Lee", email: "billing@example.test" },
                seats_used: 1,
                managed_usage: {
                    runs: active ? 12 : 0, input_tokens: active ? 18_000 : 0, output_tokens: active ? 4_000 : 0,
                    total_tokens: active ? 22_000 : 0, included_tokens: active ? 100_000 : 0,
                    overage_tokens: 0, unattributed_runs: 0, unattributed_tokens: 0,
                },
                services: [
                    { id: "commercial-operations", status: "not-added", accepted_at_ms: null, removal_effective_at_ms: null },
                    { id: "enterprise-controls", status: "not-added", accepted_at_ms: null, removal_effective_at_ms: null },
                ],
                cloud: {
                    customer_linked: true,
                    subscription: {
                        event_id: active ? "evt_active" : "evt_lapsed", event_created: active ? 2 : 1,
                        subscription_id: active ? "sub_reenrolled" : "sub_ended", customer_id: "cus_fixture", price_id: "price_fixture",
                        subscription_item_id: active ? "si_reenrolled" : "si_ended", quantity: 1, status: standing,
                        storage_bytes: 50_000_000_000, concurrent_agents: 4, retention_secs: 2_592_000,
                        current_period_end: active ? 2_000_000_000 : 1_700_000_000,
                        processor_mode: "test", verified_at: active ? 2 : 1, cancel_at_period_end: false,
                    },
                    processor_mode: "test", verification: "verified",
                    configured_plan: { name: "GaugeDesk Cloud", included_tokens: 100_000, checkout_available: true },
                    management: { plan_change: !active, seats: active, cancellation: active },
                    documents: { invoices: [], estimate: null, refreshed_at: null, history_complete: false, freshness: "not-refreshed" },
                    freshness: "processor-reconciled",
                },
            };
        }
        if (id === "billing" && billingUnavailableMode) return {
            billing: null,
            billing_contact: null,
            seats_used: 0,
            managed_usage: {
                runs: 0, input_tokens: 0, output_tokens: 0, total_tokens: 0,
                included_tokens: 0, overage_tokens: 0, unattributed_runs: 0, unattributed_tokens: 0,
            },
            services: [
                { id: "commercial-operations", status: "not-added", accepted_at_ms: null, removal_effective_at_ms: null },
                { id: "enterprise-controls", status: "not-added", accepted_at_ms: null, removal_effective_at_ms: null },
            ],
            cloud: {
                customer_linked: true,
                subscription: {
                    event_id: "evt_billing_unavailable", event_created: 1,
                    subscription_id: "sub_billing_unavailable", customer_id: "cus_billing_unavailable",
                    price_id: "price_cloud", subscription_item_id: "si_billing_unavailable", quantity: 1,
                    status: "active", storage_bytes: 50_000_000_000, concurrent_agents: 4,
                    retention_secs: 2_592_000, current_period_end: 2_000_000_000,
                    processor_mode: "test", verified_at: 1, cancel_at_period_end: false,
                },
                processor_mode: "test",
                verification: "verified",
                configured_plan: { name: "GaugeDesk Cloud", included_tokens: 100_000, checkout_available: true },
                management: { plan_change: true, seats: true, cancellation: true },
                documents: { invoices: [], estimate: null, refreshed_at: null, history_complete: false, freshness: "not-refreshed" },
                freshness: "processor-reconciled",
            },
        };
        const commercialRevision = () => ({
            ...commercialTestRevision,
            id: `product-a:revision:${commercialProductRevision()}`,
            revision: commercialProductRevision(),
            listing_title: commercialProductTitle(),
            prices: commercialCurrency === null ? commercialTestRevision.prices : commercialTestRevision.prices.map((price) => ({
                ...price, currency: commercialCurrency,
                amount_cents: price.kind === "cost-plus" ? null : 500,
            })),
        });
        const commercialProduct = () => ({
            id: "product-a", current_revision: commercialProductRevision(), commercial: commercialRevision(),
            engagement_counts: {
                open: (commercialEngagementPresent() && ["draft", "sent"].includes(commercialEngagementStage()) ? 1 : 0) + (commercialCreatedEngagement()?.product_id === "product-a" ? 1 : 0),
                active: commercialEngagementPresent() && ["accepted", "active"].includes(commercialEngagementStage()) ? 1 : 0,
                closed: commercialEngagementPresent() && ["withdrawn", "closed"].includes(commercialEngagementStage()) ? 1 : 0,
            },
        });
        const commercialProducts = () => {
            const created = commercialCreatedProduct();
            if (!created) return [commercialProduct()];
            const engagement = commercialCreatedEngagement();
            return [commercialProduct(), {
                ...created,
                engagement_counts: {
                    open: engagement?.product_id === created.id ? 1 : 0,
                    active: 0,
                    closed: 0,
                },
            }];
        };
        const commercialClient = () => ({
            client: { id: "client-a", op: "upsert" as const, display_name: commercialClientName(), billing_reference: commercialClientBillingReference(), status: commercialClientStatus() },
            engagement_counts: {
                ...commercialProduct().engagement_counts,
                open: commercialProduct().engagement_counts.open + (commercialCreatedEngagement()?.client_id === "client-a" && commercialCreatedEngagement()?.product_id !== "product-a" ? 1 : 0),
            },
            participant_references: commercialEngagementTerms().proposal_recipients,
        });
        const commercialEngagement = () => {
            const stage = commercialEngagementStage();
            const product = commercialRevision();
            const terms = commercialEngagementTerms();
            return {
                ...commercialTestEngagement, stage, terms, product_revision: product.revision, proposal_revision: commercialProposalRevision(), product_commercial: product,
                sent_at_ms: stage === "draft" ? null : 1_900_000_000_000,
                agreement: ["accepted", "active", "closed"].includes(stage) ? {
                    product, terms, accepted_by: terms.proposal_recipients[0]!, accepted_at_ms: 1_900_000_100_000,
                } : null,
                placement_ref: commercialPlacement(), entitlement: commercialEntitlement(),
                entitlement_ref: commercialEntitlement() === "inactive" ? null : "entitlement-a",
            };
        };
        if (id === "payments") return {
            ...commercialEmptyModels.payments,
            processor_mode: "test",
            processor: { connected: true, connected_account_ref: `fixture-${idScope}`, charges_ready: true, payouts_ready: true, verified_at: 1, freshness: "processor-verified" },
            ...(commercialCurrency === null ? {} : {
                transactions: [{ event_id: "evt-jpy", event_type: "payment_intent.succeeded", object_id: "pi_jpy", amount_cents: 500, currency: commercialCurrency, status: "succeeded", engagement_id: "engagement-a", client_id: "client-a", payment_intent_id: "pi_jpy", platform_fee_cents: 50, created: 1_900_000_000 }],
                currency_totals: [{ currency: commercialCurrency, gross_cents: 500, platform_fees_cents: 50, refunded_cents: 0, pending_refund_cents: 0 }],
            }),
        };
        if (commercialLifecycle && id === "products") return { products: commercialProducts(), library: { availability: "available", reason: null, home_ref: "home-a", archetypes: [commercialRevision().archetype] } };
        if (commercialLifecycle && id === "clients") return { clients: [commercialClient()] };
        if (commercialLifecycle && id === "engagements") return {
            engagements: [...(commercialEngagementPresent() ? [commercialEngagement()] : []), ...(commercialCreatedEngagement() ? [commercialCreatedEngagement()!] : [])], products: commercialProducts(), clients: [commercialClient()],
            settlement_policy: { take_rate_bps: 1500, metered_floor_cents: 0 },
            metering: { status: "no_edge_deployments", complete: true, metered_cost_cents: 0, reserved_cents: 0, deployments: [], unmatched_deployment_refs: [], basis: "edge authority" },
        };
        if (id === "products") return commercialEmptyModels.products;
        if (id === "enterprise-identity") return {
            ...administrationEmptyModels["enterprise-identity"],
            verified_domains: identityMode === "lifecycle" ? ["example.invalid"] : [],
            browser_test: identityTested() ? {
                id: `test-${idScope}`,
                connection_id: "organization",
                connection_revision: `identity-${idScope}-${serverRevision()}`,
                protocol: "oidc",
                subject: `owner-${idScope}`,
                mapped_roles: [],
                mapped_region: null,
                mapped_tenant: null,
                tested_at_ms: 1_924_819_200_000,
            } : null,
            admission_mode: identityAdmission(),
            current_owner: { is_owner: true, passkey_session: true, subject_linked: identityOwnerLinked() },
            sso: identityConfigured ? {
                id: "organization",
                revision: `identity-${idScope}-${serverRevision()}`,
                protocol: "oidc",
                issuer: "https://login.example.invalid",
                audiences: ["gaugedesk-enterprise"],
                enforce_sso: identityEnforced(),
                claim_mapping: {
                    subject_claim: "sub", email_claim: null, roles_claim: "groups",
                    region_claim: null, tenant_claim: null,
                },
                metadata_configured: false,
                client_secret_configured: identitySecretConfigured(),
            } : null,
            enforcement: {
                required: identityEnforced(),
                ready: identityConfigured && identityMode === "lifecycle" && identityTested() && identityAdmission() !== null && identityOwnerLinked(),
                connection_configured: identityConfigured,
                domain_verified: identityMode === "lifecycle",
                browser_test_current: identityTested(),
                admission_configured: identityAdmission() !== null,
                owner_subject_linked: identityOwnerLinked(),
                owner_recovery_ready: identityMode === "lifecycle",
                second_owner_present: false,
            },
            integration: {
                ...administrationEmptyModels["enterprise-identity"].integration,
                saml: {
                    ...administrationEmptyModels["enterprise-identity"].integration.saml,
                    acs_url: `https://example.invalid/${idScope}/auth/saml/acs`,
                },
                scim: { base_url: `https://example.invalid/${idScope}/scim/v2` },
            },
            scim: {
                credential_configured: false,
                base_url: `https://example.invalid/${idScope}/scim/v2`,
                status: { last_sync_at_ms: null, errors: [] },
            },
        };
        if (id === "people") return administrationEmptyModels.people;
        if (id === "backups") return {
            facility: {
                id: "cloud-backup", op: "upsert", kind: "cloud_backup", owner: "tenant", status: "active",
                display_name: "Backups", config: { schedule_days: 1, retention_days: 30 },
            },
            project_host: { id: `host-${idScope}`, name: `Studio Host ${idScope}`, home_id: `home-${idScope}`, facility_status: "active", home_lifecycle: "active" },
            recipients: [{ id: `holder-${idScope}`, label: `Recovery device ${idScope}`, public_key: "04aa" }],
            points: [
                { handle: `point-${idScope}-2`, created_at: 1_924_819_200, bytes: 2_621_440 },
                { handle: `point-${idScope}-1`, created_at: 1_924_732_800, bytes: 2_359_296 },
            ],
            restore_receivers: [],
        };
        if (id === "project-hosts") return {
            homes: [{
                id: "cloud-home", home_id: `home-${idScope}`, name: `Studio Host ${idScope}`,
                kind: "cloud", endpoint: `https://host-${idScope}.example.invalid`, state: projectHostLifecycle() === "deleted" ? "unreachable" : "indeterminate",
                lifecycle: projectHostLifecycle(), region: "us-east", retention_until: projectHostLifecycle() === "retention" ? 1_924_819_200 : null,
                capacity: { storage_bytes: 10_000_000_000, concurrent_agents: 2 },
                managed_policy: { version: 1, tenant_id: idScope, isolated_workspace_enabled: false, max_attempt_nanos_usd: 0 },
                projects: null, repair_hint: "Connect to the Project Host for a live inventory.",
                execution: {
                    freshness: projectHostLifecycle() === "active" ? "home-admitted" : "host-not-active",
                    selection_policy: "exact_capability_match_no_fallback",
                    profiles: {
                        durable_workflow: { available: true, capabilities: ["chat"], compute_state: "hibernating", metering: { kind: "included" }, reason: null },
                        isolated_workspace: { available: false, capabilities: ["build"], compute_state: "per_attempt", enabled_by_tenant_policy: false, metering: { kind: "usage", reservation_nanos_usd: null, nanos_usd_per_second: null }, reason: "Disabled" },
                        dedicated_compute: { available: false, capabilities: [], compute_state: "unavailable", metering: { kind: "unavailable" }, reason: "Unavailable" },
                    },
                    queue: null, compute: { state: "unavailable", active_attempts: null, wake: "on_demand" }, usage: null, failures: null,
                },
            }],
            managed_enrollment: { available: false, reason: "This organization already has a managed Project Host.", region: "us-east", capacity: { storage_bytes: 10_000_000_000, concurrent_agents: 2 } },
        };
        if (id === "organization" && domainState) return {
            ...administrationEmptyModels.organization,
            domains: [
                { domain: "verified.example", status: "verified", challenge: null },
                {
                    domain: "pending.example", status: "pending",
                    challenge: {
                        record_name: "_gaugewright-challenge.pending.example",
                        record_type: "TXT",
                        value: "gaugewright-domain-verification=fixture-challenge-token",
                    },
                },
            ],
        };
        if (id === "model-providers") return { availability: "unavailable", reason: "not_configured" };
        if (id in administrationEmptyModels) return administrationEmptyModels[id as keyof typeof administrationEmptyModels];
        throw Error(`missing fixture model for ${id}`);
    };
    const response = (result: unknown, status = "applied") => ({ receipt: { status }, result });
    const requireActionAuthority = () => { if (denyActions()) throw Error("action authority unavailable"); };
    const delayed = <T,>(value: T): Promise<T> => !hold() ? Promise.resolve(value) : new Promise((resolve, reject) => {
        setPending((all) => [...all, { resolve: () => resolve(value), reject: () => reject(Error("private retired-context failure")) }]);
    });
    const page = (admitted: GaugeAppSession, id: string): GaugeAppPageModel => ({ app, id, scope: admitted.scope, read_model: gaugeAppPageDefinitions[id as keyof typeof gaugeAppPageDefinitions][1], version: 1, resource_basis: `basis-${admitted.scope.id}-${serverRevision()}`, freshness: "fixture", model: model(id, admitted.scope.id) });
    const proposal = (id: string, commandId = commandPages[firstPage]![0]!, payload: unknown = {}): GaugeAppProposal => ({
        id: `proposal-${id}-${commandId}-${serverRevision()}`,
        app, page_id: firstPage, command_id: commandId, actor: `Person ${id}`,
        expected_basis: `basis-${id}-${serverRevision()}`, payload, status: "proposed",
    } as GaugeAppProposal);
    const accountReviewCommands = new Set(["account.authenticator.remove", "account.session.revoke-current", "account.session.revoke", "account.session.revoke-others"]);
    const applyAccountLifecycle = async (operation: string, payload: unknown) => {
        const lifecycleResponse = await fetch(accountLifecycleUrl, {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({ operation, payload }),
        });
        if (!lifecycleResponse.ok) throw new Error(`fixture account write returned ${lifecycleResponse.status}`);
        setFixtureAccount(await lifecycleResponse.json() as FixtureAccountLifecycleState);
        setServerRevision((value) => value + 1);
    };
    const fixtureDeviceStatus = async (includeAuthorization: boolean): Promise<AccountDeviceLinkStatus> => {
        const link = fixtureDeviceLink();
        if (!link) throw new Error("No device link exists.");
        const authority = await deviceAuthority();
        const terminal = ["enrolled", "rejected", "canceled"].includes(link.phase);
        return {
            link,
            account_root: authority.rootPublic,
            authorization: includeAuthorization && link.phase === "authorized" ? link.authorization ?? null : null,
            completion_challenge: includeAuthorization && link.phase === "authorized" ? link.challenge ?? null : null,
            terminal,
        };
    };
    const updateFixtureProviderConnection = (id: string, update: (connection: ProviderConnectionModel) => ProviderConnectionModel) => {
        setFixtureProviderConnections((connections) => connections.map((connection) => connection.id === id ? update(connection) : connection));
        setServerRevision((value) => value + 1);
    };
    const api = {
        openGaugeApp: async () => ({ id: `session-${scopeId()}`, app, scope: scope(), actor: app === "account-settings" ? scopeId() : "admin", generation: String(generation()), capabilities: ["fixture"],
            pages: Object.entries(commandPages).map(([id, commands]) => ({
                id,
                commands: subscriptionLifecycleMode && id === "plans-services"
                    ? subscriptionStanding() === "lapsed" ? ["subscription.plan.change"] : ["subscription.seats.change", "subscription.cancellation.schedule"]
                    : commands,
                availability: "available", freshness: "live",
            })), commands: [], update_cursor: `fixture-${scopeId()}-${serverRevision()}` }),
        readGaugeAppPage: async (admitted: GaugeAppSession, id: string) => {
            record({ read: id, scope: admitted.scope.id });
            if (denyReads()) throw Error("read denied");
            if (accountLifecycleMode && id === "account") {
                const accountResponse = await fetch(accountLifecycleUrl);
                if (!accountResponse.ok) throw new Error(`fixture account read returned ${accountResponse.status}`);
                setFixtureAccount(await accountResponse.json() as FixtureAccountLifecycleState);
            }
            return page(admitted, id);
        },
        readGaugeAppUpdates: async (admitted: GaugeAppSession, after: string): Promise<GaugeAppUpdateSnapshot> => {
            if (denyUpdates()) throw Error("update authority unavailable");
            const cursor = `fixture-${admitted.scope.id}-${serverRevision()}`;
            if (cursor === after) return { cursor, invalidations: [] };
            record({ updates: admitted.scope.id, after, cursor });
            return { cursor, invalidations: admitted.pages.map((item) => ({ page_id: item.id, resource_basis: `basis-${admitted.scope.id}-${serverRevision()}` })) };
        },
        gaugeAppProposals: async (admitted: GaugeAppSession) => proposals.get(admitted.scope.id) ?? [],
        gaugeAppAgentMessages: async (admitted: GaugeAppSession) => {
            if (!persistentAgent) return { messages: events.get(admitted.scope.id) ?? [] };
            const key = encodeURIComponent(`${persistentRun}:${app}:${admitted.scope.kind}:${admitted.scope.id}`);
            const response = await fetch(`/__fixture/gaugeapp-agent?key=${key}`);
            if (!response.ok) throw new Error(`persistent transcript read returned ${response.status}`);
            return response.json();
        },
        gaugeAppAgentEvents: (
            admitted: GaugeAppSession,
            onFrame: (frame: GaugeAppAgentLiveFrame) => void,
            after?: string,
            onOpen?: () => void,
            onClose?: () => void,
        ) => {
            const id = admitted.scope.id;
            liveListeners.set(id, onFrame);
            const disconnect = () => {
                if (liveListeners.get(id) !== onFrame) return;
                liveListeners.delete(id);
                liveDisconnects.delete(id);
                onClose?.();
            };
            liveDisconnects.set(id, disconnect);
            queueMicrotask(() => {
                onOpen?.();
                const history = liveHistories.get(id) ?? [];
                const offset = after ? history.findIndex((frame) => frame.cursor === after) + 1 : 0;
                for (const frame of history.slice(Math.max(0, offset))) {
                    if (liveListeners.get(id) === onFrame) onFrame(frame);
                }
            });
            return () => {
                if (liveListeners.get(id) === onFrame) liveListeners.delete(id);
                if (liveDisconnects.get(id) === disconnect) liveDisconnects.delete(id);
            };
        },
        stopGaugeAppAgentTurn: async (admitted: GaugeAppSession) => {
            const id = admitted.scope.id;
            record({ stop: id });
            const turn = liveTurns.get(id);
            if (!turn) return false;
            emitLive(id, turn.turnId, { type: "stopped" });
            liveTurns.delete(id);
            turn.reject(new RouteHttpError("POST", "/fixture/agent/messages", 499, "stopped"));
            return true;
        },
        sendGaugeAppAgentMessage: async (admitted: GaugeAppSession, message: string) => {
            const id = admitted.scope.id; record({ send: id });
            if (persistentAgent) {
                const key = encodeURIComponent(`${persistentRun}:${app}:${admitted.scope.kind}:${id}`);
                const response = await fetch(`/__fixture/gaugeapp-agent?key=${key}`, {
                    method: "POST",
                    headers: { "content-type": "application/json" },
                    body: JSON.stringify({ message }),
                });
                if (!response.ok) throw new Error(`persistent transcript write returned ${response.status}`);
                return response.json();
            }
            if (streamingAgent) {
                const turnId = `turn-${id}`;
                return new Promise((_, reject) => {
                    liveHistories.set(id, []);
                    liveTurns.set(id, { reject, turnId });
                    queueMicrotask(() => {
                        emitLive(id, turnId, { type: "started" });
                        emitLive(id, turnId, { type: "text", delta: "Working on this request…" });
                    });
                });
            }
            const item = proposal(id); proposals.set(id, [item]);
            events.set(id, [{ sequence: 1, role: "assistant", text: `Reply for ${id}` }]);
            return delayed({ proposals: [item] });
        },
        eraseGaugeAppAgentTranscript: async (admitted: GaugeAppSession) => {
            record({ erase: admitted.scope.id });
            if (persistentAgent) {
                const key = encodeURIComponent(`${persistentRun}:${app}:${admitted.scope.kind}:${admitted.scope.id}`);
                const response = await fetch(`/__fixture/gaugeapp-agent?key=${key}`, { method: "DELETE" });
                if (!response.ok) throw new Error(`persistent transcript erase returned ${response.status}`);
            }
            events.set(admitted.scope.id, []);
            return { thread_id: `thread-${admitted.scope.id}`, generation: 1 };
        },
        submitGaugeAppCommand: async (request: { scope: GaugeAppScope; command_id: string; payload: unknown }) => {
            record({ command: request.command_id, scope: request.scope.id, payload: request.payload });
            requireActionAuthority();
            const id = request.scope.id;
            if (accountErasureMode && request.command_id === "account.erase") {
                if ((request.payload as { confirmation?: unknown }).confirmation !== "ERASE MY ACCOUNT") {
                    throw new Error("fixture rejected an inexact account-erasure confirmation");
                }
                proposals.set(id, [proposal(id, request.command_id, request.payload)]);
                return response(null, "proposed");
            }
            if (subscriptionLifecycleMode && request.command_id === "subscription.plan.change") {
                proposals.set(id, [proposal(id, request.command_id, request.payload)]);
                return response(null, "proposed");
            }
            if (request.command_id === "application-settings.appearance.set") {
                const appearance = (request.payload as { value: AppearancePreferenceV1 }).value;
                if (appearanceMode) {
                    const persisted = await fetch(appearanceUrl, {
                        method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(appearance),
                    });
                    if (!persisted.ok) throw new Error(`fixture appearance write returned ${persisted.status}`);
                    const result = await persisted.json() as { saved: boolean; value: AppearancePreferenceV1 };
                    setFixtureAppearance(result.value);
                    setFixtureAppearanceSaved(result.saved);
                } else {
                    setFixtureAppearance(appearance);
                    setFixtureAppearanceSaved(true);
                }
                setServerRevision((value) => value + 1);
                return response(null);
            }
            if (reviewNext()) { proposals.set(id, [proposal(id)]); return response(null, "proposed"); }
            if (accountLifecycleMode && request.command_id.startsWith("account.")) {
                if (accountReviewCommands.has(request.command_id)) {
                    proposals.set(id, [proposal(id, request.command_id, request.payload)]);
                    return response(null, "proposed");
                }
                await applyAccountLifecycle(request.command_id, request.payload);
                return response(request.command_id === "account.recovery-codes.reissue" ? { recovery_codes: [`RECOVERY-${id}`] } : null);
            }
            if (request.command_id === "trusted-device.link.begin") {
                const now = Date.now();
                setFixtureDeviceLink({
                    id: "device-link-a",
                    phase: "waiting-for-device",
                    human_code: "ABCD-EF12",
                    qr_payload: "gaugewright://auth/device-link?id=device-link-a&code=ABCD-EF12",
                    created_at_ms: now,
                    expires_at_ms: now + 600_000,
                    device: null,
                    sas: null,
                    completed_at_ms: null,
                });
                setServerRevision((value) => value + 1);
                return response({ pending_link: fixtureDeviceLink() });
            }
            if (request.command_id === "trusted-device.link.accept") {
                const link = fixtureDeviceLink();
                if (!link?.subkey || link.phase !== "awaiting-acceptance") throw new Error("Device link is not ready for acceptance.");
                const prepared = await createFixtureDeviceAuthorization(await deviceAuthority(), link.id, link.subkey);
                setFixtureDeviceLink({ ...link, phase: "authorized", authorization: prepared.authorization, challenge: prepared.challenge });
                setServerRevision((value) => value + 1);
                return response(null);
            }
            if (request.command_id === "trusted-device.link.reject" || request.command_id === "trusted-device.link.cancel") {
                const link = fixtureDeviceLink();
                if (!link) throw new Error("Device link does not exist.");
                setFixtureDeviceLink({ ...link, phase: request.command_id.endsWith("reject") ? "rejected" : "canceled" });
                setServerRevision((value) => value + 1);
                return response(null);
            }
            if (request.command_id === "provider-connection.verify") {
                const connectionId = (request.payload as { id?: string }).id ?? "";
                updateFixtureProviderConnection(connectionId, (connection) => ({ ...connection, verification: "reachable", last_verified_at_ms: Date.now() }));
                return response({ verification: "reachable" });
            }
            if (request.command_id === "provider-connection.rename") {
                const payload = request.payload as { id?: string; label?: string };
                updateFixtureProviderConnection(payload.id ?? "", (connection) => ({ ...connection, name: payload.label?.trim() || connection.name }));
                return response(null);
            }
            if (request.command_id === "provider-connection.default-model.set") {
                const payload = request.payload as { connection_id?: string; model?: string };
                if (payload.connection_id && payload.model) setFixtureDefaultModel({ connection_id: payload.connection_id, model: payload.model });
                setServerRevision((value) => value + 1);
                return response(null);
            }
            if (request.command_id === "provider-connection.revoke") {
                const connectionId = (request.payload as { id?: string }).id ?? "";
                updateFixtureProviderConnection(connectionId, (connection) => ({ ...connection, status: "revoked" }));
                if (fixtureDefaultModel()?.connection_id === connectionId) setFixtureDefaultModel(null);
                return response(null);
            }
            if (request.command_id === "provider-connection.subscription.begin") {
                const provider = (request.payload as { provider?: string }).provider;
                if (provider !== "xai-grok") throw new Error("Fixture supports the Grok browser lifecycle only.");
                const login = { login_id: "grok-login-a", verification_url: "https://accounts.x.ai/device", user_code: "GROK-4821", status: "pending" as const, error: null };
                setFixtureGrokSignIn({ provider, linked: false, expires: null, expired: false, login });
                setServerRevision((value) => value + 1);
                return response({ login });
            }
            if (request.command_id === "provider-connection.subscription.complete") {
                const payload = request.payload as { provider?: string; action?: string };
                if (payload.provider !== "xai-grok") throw new Error("Fixture supports the Grok browser lifecycle only.");
                if (payload.action === "cancel") {
                    setFixtureGrokSignIn({ provider: "xai-grok", linked: false, expires: null, expired: false, login: { ...fixtureGrokSignIn().login!, status: "cancelled" } });
                } else {
                    setFixtureGrokSignIn({ provider: "xai-grok", linked: true, expires: Date.now() + 3_600_000, expired: false, login: { ...fixtureGrokSignIn().login!, status: "linked" } });
                    setFixtureProviderConnections((connections) => connections.some((connection) => connection.id === "xai-grok") ? connections : [...connections, {
                        id: "xai-grok", provider: "xai-grok", name: "Grok", kind: "o-auth", endpoint_class: "provider-hosted", base_url: null,
                        linked: true, status: "active", version: 1, execution_classes: ["private-home"], models: ["grok-4"],
                        linked_at_ms: Date.now(), last_verified_at_ms: Date.now(), verification: "reachable",
                    }]);
                }
                setServerRevision((value) => value + 1);
                return response(null);
            }
            if (request.command_id === "account.authenticator.begin-add") return delayed(response({ ceremony_id: `ceremony-${id}`, public_key: { rp: { name: "Fixture" }, user: { id: "QQ", name: id, displayName: id }, challenge: "QQ", pubKeyCredParams: [{ type: "public-key", alg: -7 }], authenticatorSelection: { residentKey: "required", userVerification: "required" }, timeout: 120000 } }));
            if (request.command_id === "enterprise-identity.test.begin") return delayed(response({
                kind: "enterprise-identity-browser-test-launch",
                protocol: "oidc",
                connection_revision: `identity-${id}-${serverRevision()}`,
                authorize_url: `https://identity.example.invalid/${id}/test`,
            }));
            if (request.command_id === "enterprise-identity.admission-mode.set") {
                const mode = (request.payload as { mode?: "invited-only" | "verified-domain-jit" | "scim" }).mode;
                if (mode) setIdentityAdmission(mode);
            }
            if (request.command_id === "enterprise-identity.owner-subject.link") setIdentityOwnerLinked(true);
            if (request.command_id === "enterprise-identity.enforcement.enable") setIdentityEnforced(true);
            if (request.command_id === "enterprise-identity.enforcement.disable") setIdentityEnforced(false);
            if (request.command_id === "project-host.retire") {
                const phase = (request.payload as { phase?: string }).phase;
                if (phase === "retention") setProjectHostLifecycle("retention");
                if (phase === "erase") setProjectHostLifecycle("deleted");
                setServerRevision((value) => value + 1);
            }
            if (request.command_id === "commercial-product.revise") {
                const revision = (request.payload as { revision?: { listing_title?: string } }).revision;
                if (revision?.listing_title) setCommercialProductTitle(revision.listing_title);
                setCommercialProductRevision((value) => value + 1);
                setServerRevision((value) => value + 1);
            }
            if (request.command_id === "commercial-product.create") {
                const payload = request.payload as { id?: string; revision?: Omit<CommercialProductRevision, "id" | "op" | "product_id" | "revision"> };
                if (payload.id && payload.revision) {
                    setCommercialCreatedProduct({
                        id: payload.id,
                        current_revision: 1,
                        commercial: { ...payload.revision, id: `${payload.id}:revision:1`, op: "upsert", product_id: payload.id, revision: 1 },
                        engagement_counts: { open: 0, active: 0, closed: 0 },
                    });
                }
                setServerRevision((value) => value + 1);
            }
            if (request.command_id === "commercial-product.read") return delayed(response({ id: "product-a" }));
            if (request.command_id === "commercial-client.read") return delayed(response({ client: { id: "client-a" } }));
            if (request.command_id === "commercial-engagements.read-by-client") return delayed(response({
                client_id: "client-a",
                engagements: commercialEngagementPresent() ? [{ id: "engagement-a", stage: commercialEngagementStage() }] : [],
            }));
            if (request.command_id === "commercial-payments.read-by-client") return delayed(response({
                client_id: "client-a",
                transactions: commercialCurrency === null ? [] : [{ object_id: "pi_jpy" }],
                invoices: [],
                refunds: [],
            }));
            if (request.command_id === "commercial-client.edit") {
                const payload = request.payload as { display_name?: string; billing_reference?: string | null };
                if (payload.display_name?.trim()) setCommercialClientName(payload.display_name.trim());
                setCommercialClientBillingReference(payload.billing_reference?.trim() || null);
                setServerRevision((value) => value + 1);
            }
            if (request.command_id === "commercial-client.close") {
                setCommercialClientStatus("closed");
                setServerRevision((value) => value + 1);
            }
            if (request.command_id === "commercial-engagement.proposal.create") {
                const payload = request.payload as { id?: string; client_id?: string; product_id?: string; terms?: CommercialEngagement["terms"] };
                if (payload.id && payload.client_id && payload.product_id && payload.terms) {
                    const createdProduct = commercialCreatedProduct();
                    const product = createdProduct?.id === payload.product_id ? createdProduct.commercial : {
                        ...commercialTestRevision,
                        id: `product-a:revision:${commercialProductRevision()}`,
                        revision: commercialProductRevision(),
                        listing_title: commercialProductTitle(),
                    };
                    setCommercialCreatedEngagement({
                        ...commercialTestEngagement,
                        id: payload.id,
                        client_id: payload.client_id,
                        product_id: payload.product_id,
                        product_revision: product.revision,
                        proposal_revision: 1,
                        terms: {
                            ...payload.terms,
                            seats: payload.terms.seats ?? null,
                            term_months: payload.terms.term_months ?? null,
                            start_at_ms: payload.terms.start_at_ms ?? null,
                        },
                        product_commercial: product,
                    });
                }
                setServerRevision((value) => value + 1);
            }
            if (["commercial-engagement.proposal.save", "commercial-engagement.proposal.revise"].includes(request.command_id)) {
                const terms = (request.payload as { terms?: typeof commercialTestEngagement.terms }).terms;
                if (terms) setCommercialEngagementTerms(terms);
                if (request.command_id.endsWith(".revise")) {
                    setCommercialEngagementStage("draft");
                    setCommercialProposalRevision((value) => value + 1);
                }
                setServerRevision((value) => value + 1);
            }
            if (request.command_id === "commercial-engagement.proposal.send") {
                setCommercialEngagementStage("sent");
                setServerRevision((value) => value + 1);
                return delayed(response({ delivery_links: [{
                    delivery_id: "delivery-engagement-a-1",
                    engagement_id: "engagement-a",
                    proposal_revision: commercialProposalRevision(),
                    recipient: commercialEngagementTerms().proposal_recipients[0],
                    proof: "fixture-send-proof",
                }] }));
            }
            if (request.command_id === "commercial-engagement.proposal.resend") {
                setServerRevision((value) => value + 1);
                return delayed(response({ delivery_links: [{
                    delivery_id: "delivery-engagement-a-1",
                    engagement_id: "engagement-a",
                    proposal_revision: commercialProposalRevision(),
                    recipient: commercialEngagementTerms().proposal_recipients[0],
                    proof: "fixture-resend-proof",
                }] }));
            }
            if (request.command_id === "commercial-engagement.proposal-delivery.read") {
                return delayed(response({
                    engagement_id: "engagement-a",
                    stage: commercialEngagementStage(),
                    sent_at_ms: 1_900_000_000_000,
                    recipients: commercialEngagementTerms().proposal_recipients,
                    deliveries: [{
                        id: "delivery-engagement-a-1",
                        proposal_revision: commercialProposalRevision(),
                        recipient: commercialEngagementTerms().proposal_recipients[0],
                        issued_at_ms: 1_900_000_000_000,
                        accepted: ["accepted", "active", "closed"].includes(commercialEngagementStage()),
                    }],
                }));
            }
            if (request.command_id === "commercial-engagement.agreement.read") {
                const terms = commercialEngagementTerms();
                return delayed(response({
                    engagement_id: "engagement-a",
                    agreement: ["accepted", "active", "closed"].includes(commercialEngagementStage()) ? {
                        product: {
                            ...commercialTestRevision,
                            id: `product-a:revision:${commercialProductRevision()}`,
                            revision: commercialProductRevision(),
                            listing_title: commercialProductTitle(),
                        },
                        terms,
                        accepted_by: terms.proposal_recipients[0],
                        accepted_at_ms: 1_900_000_100_000,
                    } : null,
                }));
            }
            if (request.command_id === "commercial-engagement.payments.read") return delayed(response({
                engagement_id: "engagement-a",
                payment_refs: [],
                transactions: commercialCurrency === null ? [] : [{ object_id: "pi_jpy" }],
                invoices: [],
                refunds: [],
            }));
            if (request.command_id === "commercial-payments.payment.read") return delayed(response({ id: (request.payload as { id?: string }).id }));
            if (request.command_id === "commercial-engagement.proposal.discard") {
                setCommercialEngagementPresent(false);
                setServerRevision((value) => value + 1);
            }
            if (request.command_id === "commercial-engagement.proposal.withdraw") {
                setCommercialEngagementStage("withdrawn");
                setServerRevision((value) => value + 1);
            }
            if (request.command_id === "commercial-engagement.placement.link") {
                setCommercialPlacement((request.payload as { placement_ref?: string }).placement_ref?.trim() || null);
                setServerRevision((value) => value + 1);
            }
            if (request.command_id === "commercial-engagement.entitlement.activate") {
                setCommercialEntitlement("active");
                setCommercialEngagementStage("active");
                setServerRevision((value) => value + 1);
            }
            if (request.command_id === "commercial-engagement.entitlement.suspend") {
                setCommercialEntitlement("suspended");
                setServerRevision((value) => value + 1);
            }
            if (request.command_id === "commercial-engagement.entitlement.revoke") {
                setCommercialEntitlement("revoked");
                setServerRevision((value) => value + 1);
            }
            if (request.command_id === "commercial-engagement.close") {
                setCommercialEngagementStage("closed");
                setServerRevision((value) => value + 1);
            }
            if (request.command_id.startsWith("backups.")) return delayed(response(null));
            const result = request.command_id.includes("recovery")
                ? { recovery_codes: [`RECOVERY-${id}`] }
                : request.command_id.includes("connect-component")
                    ? { client_secret: `STRIPE-${id}`, publishable_key: "pk_test_fixture" }
                    : request.command_id === "enterprise-identity.scim-credential.issue"
                        ? { token: `SCIM-${id}` }
                        : null;
            return delayed(response(result));
        },
        startAccountAuthorization: async (operation: string) => {
            record({ authorizationStart: operation });
            if (!accountErasureMode || operation !== "account.erase") throw new Error("fixture refused fresh authorization");
            return {
                ceremony_id: "account-erasure-authorization-A",
                public_key: {
                    challenge: "Qg",
                    rpId: "localhost",
                    timeout: 120_000,
                    userVerification: "required",
                },
            };
        },
        finishAccountAuthorization: async (ceremonyId: string, credential: Readonly<Record<string, unknown>>) => {
            record({
                authorizationFinish: ceremonyId,
                credential: {
                    id: credential.id,
                    type: credential.type,
                    hasResponse: typeof credential.response === "object" && credential.response !== null,
                },
            });
            if (ceremonyId !== "account-erasure-authorization-A") throw new Error("fixture refused the authorization ceremony");
            return "fresh-account-erasure-proof-A";
        },
        reviewGaugeAppProposal: async (
            admitted: GaugeAppSession,
            proposalId: string,
            decision: "accept" | "reject",
            idempotencyKey: string,
            authorizationProof?: string,
        ) => {
            record({ review: admitted.scope.id, proposal: proposalId, decision, idempotencyKey, authorizationProof });
            requireActionAuthority();
            if (accountErasureMode) {
                const pendingProposal = (proposals.get(admitted.scope.id) ?? []).find((item) => item.id === proposalId);
                if (!pendingProposal || pendingProposal.command_id !== "account.erase") throw new Error("fixture proposal is no longer pending");
                if (decision !== "accept" || authorizationProof !== "fresh-account-erasure-proof-A") {
                    throw new Error("fixture refused account erasure without fresh authorization");
                }
                const attempt = erasureReviewAttempts() + 1;
                setErasureReviewAttempts(attempt);
                if (attempt === 1) throw new Error("response lost after durable account-erasure fence");
                if (attempt === 2) return response(null, "applying");
                if (attempt === 3) throw new Error("account-erasure status transport unavailable");
                proposals.set(admitted.scope.id, []);
                return response({ erasure: "account-erased" }, "applied");
            }
            if (subscriptionLifecycleMode) {
                const pendingProposal = (proposals.get(admitted.scope.id) ?? []).find((item) => item.id === proposalId);
                if (!pendingProposal) throw new Error("fixture proposal is no longer pending");
                proposals.set(admitted.scope.id, []);
                return decision === "accept"
                    ? response({ url: "https://checkout.stripe.example.test/session", destination: "checkout" })
                    : response(null);
            }
            if (accountLifecycleMode) {
                const pendingProposal = (proposals.get(admitted.scope.id) ?? []).find((item) => item.id === proposalId);
                if (!pendingProposal) throw new Error("fixture proposal is no longer pending");
                if (decision === "accept") await applyAccountLifecycle(pendingProposal.command_id, pendingProposal.payload);
                proposals.set(admitted.scope.id, []);
                return response(null);
            }
            return delayed(response({ token: `SCIM-${admitted.scope.id}` }));
        },
        submitAccountProviderSecret: async (request: { scope: GaugeAppScope; command_id?: string; payload?: unknown }, secret: string) => {
            record({ intake: request.scope.id, command: request.command_id, length: secret.length });
            requireActionAuthority();
            if (providerLifecycleMode) {
                const payload = request.payload as { provider?: string; label?: string; base_url?: string; models?: string[] };
                const id = request.command_id === "provider-connection.compatible.add" ? "openai-generic" : payload.provider ?? "provider";
                setFixtureProviderConnections((connections) => [...connections, {
                    id,
                    provider: payload.provider ?? id,
                    name: payload.label?.trim() || payload.provider || "Provider",
                    kind: "api-key",
                    endpoint_class: request.command_id === "provider-connection.compatible.add" ? "openai-compatible" : "provider-hosted",
                    base_url: payload.base_url?.trim() || null,
                    linked: true,
                    status: "active",
                    version: 1,
                    execution_classes: ["local-interactive", "private-home"],
                    models: request.command_id === "provider-connection.compatible.add" ? payload.models ?? [] : ["gpt-5.4", "gpt-5.6-luna"],
                    linked_at_ms: Date.now(),
                    last_verified_at_ms: null,
                    verification: "unverified",
                }]);
                setServerRevision((value) => value + 1);
            }
            return delayed(response(null));
        },
        submitOrganizationSsoCredential: async (request: { scope: GaugeAppScope; command_id: string }, secret?: string) => {
            record({ credential: request.command_id, scope: request.scope.id, length: secret?.length ?? 0 });
            requireActionAuthority();
            const configured = request.command_id === "enterprise-identity.connection.credential.set";
            const nextRevision = serverRevision() + 1;
            setIdentitySecretConfigured(configured);
            setServerRevision(nextRevision);
            return delayed(response({ kind: "enterprise-identity-credential", connection_revision: `identity-${request.scope.id}-${nextRevision}`, client_secret_configured: configured }));
        },
        claimAccountDeviceLink: async (claim: { readonly id?: string; readonly human_code?: string; readonly label: string; readonly kind: "computer" | "phone" | "tablet"; readonly subkey_pubkey: string }) => {
            requireActionAuthority();
            const link = fixtureDeviceLink();
            if (!link || link.phase !== "waiting-for-device" || claim.human_code?.replace(/[^a-z0-9]/gi, "").toUpperCase() !== "ABCDEF12") {
                throw new Error("The device code was not accepted.");
            }
            setFixtureDeviceLink({
                ...link,
                phase: "awaiting-acceptance",
                device: { id: "device-phone", label: claim.label, kind: claim.kind },
                sas: "381947",
                subkey: claim.subkey_pubkey,
            });
            setServerRevision((value) => value + 1);
            return fixtureDeviceStatus(false);
        },
        readAccountDeviceLink: async (id: string) => {
            const link = fixtureDeviceLink();
            if (!link || link.id !== id) throw new Error("Device link was not found.");
            return fixtureDeviceStatus(true);
        },
        completeAccountDeviceLink: async (id: string, completion: { readonly account_key_proof: string; readonly signature: string }) => {
            requireActionAuthority();
            const link = fixtureDeviceLink();
            if (!link?.subkey || !link.challenge || link.id !== id || link.phase !== "authorized") throw new Error("Device link is not authorized.");
            await verifyFixtureDeviceCompletion(await deviceAuthority(), link.subkey, link.challenge, completion);
            const completed = { ...link, phase: "enrolled" as const, completed_at_ms: Date.now(), authorization: undefined, challenge: undefined };
            setFixtureDeviceLink(completed);
            setFixtureLinkedDevice(completed.device);
            setServerRevision((value) => value + 1);
            return fixtureDeviceStatus(false);
        },
        startConsumerOidcLink: async () => {
            requireActionAuthority();
            if (accountLifecycleMode) {
                const linkResponse = await fetch(accountLifecycleUrl, {
                    method: "POST",
                    headers: { "content-type": "application/json" },
                    body: JSON.stringify({ operation: "fixture.consumer-oidc.begin", payload: {} }),
                });
                if (!linkResponse.ok) throw new Error(`fixture consumer link returned ${linkResponse.status}`);
            }
            return `https://accounts.example.invalid/link?state=server-held-${encodeURIComponent(accountLifecycleKey)}`;
        },
        projectHostAccountSettings: async () => {
            if (!projectHostSettingsMode) throw new Error("Current Project Host settings are unavailable.");
            const result = await fetch(projectHostSettingsUrl);
            if (!result.ok) throw new Error(`fixture Project Host settings read returned ${result.status}`);
            return result.json();
        },
        setProjectHostAccountSetting: async (key: string, value: string) => {
            if (!projectHostSettingsMode) throw new Error("Current Project Host settings are unavailable.");
            record({ projectHostSetting: key, value });
            const result = await fetch(projectHostSettingsUrl, {
                method: "POST",
                headers: { "content-type": "application/json" },
                body: JSON.stringify({ key, value }),
            });
            if (!result.ok) throw new Error(`fixture Project Host settings write returned ${result.status}`);
        },
    } as unknown as EnterpriseControlPlane;
    function emitLive(id: string, turnId: string, event: GaugeAppAgentLiveFrame["event"]): void {
        const history = liveHistories.get(id) ?? [];
        const sequence = history.length + 1;
        const frame: GaugeAppAgentLiveFrame = {
            cursor: `${turnId}:${sequence}`,
            thread_id: `thread-${id}`,
            turn_id: turnId,
            sequence,
            event,
        };
        liveHistories.set(id, [...history, frame]);
        liveListeners.get(id)?.(frame);
    }
    const controller = createGaugeAppWorkspace({
        api,
        app,
        enabled,
        active,
        scope: () => { generation(); refreshTick(); return scope(); },
        openExternal: async (url) => { record({ openExternal: url }); return true; },
        onAccountErased: () => {
            record({ accountErased: scopeId(), reviewAttempts: erasureReviewAttempts() });
            setAccountErased(true);
            setEnabled(false);
        },
        onOpenGaugeApp: (destination, page) => record({ openGaugeApp: destination, page }),
        updateIntervalMs: 40,
        updateRetryMs: 40,
    });
    createEffect(() => {
        if (!appearanceMode || !enabled()) {
            resetAppearancePreference();
            return;
        }
        applyAppearancePreference(fixtureAppearance());
    });
    onCleanup(() => resetAppearancePreference());
    const shell = createWorkbenchShellState({
        selection: () => ({ chatSelected: true, fileSelected: true }),
        storagePrefix: "gaugeapp-production-shell-fixture",
    });
    const complete = (failed: boolean) => { const [first, ...rest] = pending(); setPending(rest); if (failed) first?.reject(); else first?.resolve(); };
    const stripeEvent = (event: Event) => setStripe((values) => [...values, (event as CustomEvent<string>).detail]);
    window.addEventListener("fixture-stripe", stripeEvent);
    onCleanup(() => window.removeEventListener("fixture-stripe", stripeEvent));
    const controls = () => <nav aria-label="Fixture timing controls" style="display:flex;flex-wrap:wrap;gap:6px;padding:8px;font-size:12px">
            <button onClick={() => setScopeId((id) => id === "A" ? "B" : "A")}>Switch scope</button>
            <button onClick={() => setEnabled((value) => !value)}>Toggle active</button>
            <button onClick={() => setActive((value) => !value)}>Toggle visible</button>
            <button onClick={() => setGeneration((value) => value + 1)}>New authorization</button>
            <button onClick={() => setRefreshTick((value) => value + 1)}>Refresh fixture</button>
            <button onClick={() => setHold((value) => !value)}>Hold: {hold() ? "on" : "off"}</button>
            <button onClick={() => complete(false)}>Resolve oldest</button><button onClick={() => complete(true)}>Reject oldest</button>
            <button onClick={() => { setDenyReads(true); setRefreshTick((value) => value + 1); }}>Deny reads</button>
            <button onClick={() => setDenyUpdates((value) => !value)}>{denyUpdates() ? "Restore updates" : "Deny updates"}</button>
            <button onClick={() => setDenyActions((value) => !value)}>{denyActions() ? "Restore actions" : "Deny actions"}</button>
            <button onClick={() => liveDisconnects.get(scopeId())?.()}>Drop stream</button>
            <button onClick={() => {
                const turn = liveTurns.get(scopeId());
                if (turn) emitLive(scopeId(), turn.turnId, { type: "text", delta: "Continued after reconnect." });
            }}>Advance stream</button>
            <button onClick={() => setReviewNext(true)}>Review next</button>
            <button onClick={() => { proposals.set(scopeId(), [proposal(scopeId())]); setRefreshTick((value) => value + 1); }}>Seed proposal</button>
            <button onClick={() => setServerRevision((value) => value + 1)}>Server change</button>
            <button onClick={() => { setIdentityTested(true); setRefreshTick((value) => value + 1); }}>Complete sign-in test</button>
            <button onClick={() => { setSubscriptionStanding("active"); setServerRevision((value) => value + 1); setGeneration((value) => value + 1); }}>Complete plan checkout</button>
            <output aria-label="Selected context">{scopeId()} · {enabled() ? "active" : "inactive"} · {generation()}</output>
            <output aria-label="Pending requests">{pending().length}</output>
            <output aria-label="Admission standing">{controller.admitted() ? "admitted" : "not admitted"}</output>
        </nav>;
    return <>
        {mobileSurface
            ? <MobileGaugeAppSurface gaugeApps={{
                active: () => true,
                accountActions: () => [],
                organizationSelector: () => <div />,
                chat: (options) => controller.chat(options),
                content: controller.content,
                menu: controller.menu,
                titles: () => ({ chat: `${app} agent`, content: app === "account-settings" ? "Account Settings" : app === "administration" ? "Administration" : "Commercial Operations", files: "Menu" }),
                close: () => record({ closeGaugeApp: app }),
            }} />
            : actualShell
            ? <WorkbenchShell
                state={shell}
                nav={() => <div />}
                chat={() => controller.chat({ mobile: shell.isMobile(), onCollapse: () => shell.setCollapsed("chat", true) })}
                content={() => controller.content()}
                files={() => controller.menu()}
                titles={{ nav: "Navigate", chat: "Commercial Operations agent", content: "Commercial Operations", files: "Menu" }}
                headings={{ nav: false, chat: false, content: false, files: false }}
                onNewChat={() => undefined}
            />
            : <>
                {controls()}
                <div style="display:grid;grid-template-columns:minmax(0,1fr) 180px;height:calc(100vh - 130px)">
                    <div style="min-width:0;overflow:auto">{controller.content()}</div>{controller.menu()}
                </div>
                <details><summary>Conversation</summary>{controller.chat({ mobile: false, onCollapse: () => {} })}</details>
            </>}
        <details hidden={mobileSurface}><summary>Fixture records</summary><pre data-testid="calls">{JSON.stringify(calls())}</pre><output aria-label="Stripe events">{stripe().join(", ")}</output><output aria-label="Account erasure result">{accountErased() ? "erased" : "present"}</output></details>
    </>;
}
render(
    () => {
        const query = new URLSearchParams(location.search);
        if (query.get("account-entry") === "recovery") return <RecoveryEntryHarness />;
        if (query.get("account-menu") === "signed-out") return <AccountMenuHarness state="signed-out" />;
        if (query.get("account-menu") === "signed-out-failure") return <AccountMenuHarness state="signed-out" fail />;
        if (query.get("account-menu") === "signed-in-failure") return <AccountMenuHarness state="signed-in" fail />;
        return <Harness />;
    },
    document.getElementById("root")!,
);
