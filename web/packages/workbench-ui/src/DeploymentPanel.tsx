/**
 * Deploying a Panel agent's pinned version from its project, and managing what
 * is deployed (`experience/deployments.md`, PANEL-11, PANEL-12).
 *
 * The dialog is ordered by what the owner came to do. Managing a deployment
 * starts with whether it is live, what it has spent, and the code to put on a
 * website. Deploying one starts with where it will appear. The operational
 * settings follow as plain questions — which websites, who can use it, who
 * pays, what it may spend, how long it keeps conversations — in dollars, hours
 * and days. The frozen contract is read back last and folded away: a
 * deployment operates a version, it never redefines it.
 *
 * What is published is unchanged by any of that: `deploymentInput` builds the
 * same request from the same signals, and the pure rules it rests on live in
 * `deployment-origins.ts` and `panel-agent-presentation.ts`.
 */

import { createSignal, For, onCleanup, onMount, Show, type JSX } from "solid-js";
import type {
    PanelPublicProfile,
    AccountTenant,
    PlacementId,
    ProvisionPublicCredentialInput,
    PublicCredentialMetadata,
    PublicDeploymentBindingSummary,
    PublicDeploymentInput,
    PublicDeploymentInspection,
    PublicDeploymentOutcome,
} from "@gaugewright/control-plane-client";
import { startDeploymentMonitor } from "./deployment-monitor";
import { normalizeOrigin, withOrigin, wwwCounterpart } from "./deployment-origins";
import { PanelContractSummary } from "./PanelContractSummary";
import { Option } from "./PanelAgentControls";
import {
    centsFromDollars,
    dollarsFromCents,
    formatAge,
    formatCents,
    formatDuration,
    KEY_PROVIDERS,
    providerName,
} from "./panel-agent-presentation";
import "./panel-agent.css";

export interface DeploymentPanelApi {
    publishDeployment(input: PublicDeploymentInput): Promise<PublicDeploymentOutcome>;
    deploymentManagedTenants?(): Promise<AccountTenant[]>;
    inspectDeployment?(edge: string, deployment: string): Promise<PublicDeploymentInspection>;
    controlDeployment?(
        edge: string,
        deployment: string,
        command: "pause" | "resume" | "revoke",
        expectedRevision: number,
    ): Promise<PublicDeploymentInspection["deployment"]>;
    erasePublicSession?(edge: string, deployment: string, session: string): Promise<void>;
    listPublicCredentials?(edge: string): Promise<PublicCredentialMetadata[]>;
    provisionPublicCredential?(input: ProvisionPublicCredentialInput): Promise<PublicCredentialMetadata>;
    revokePublicCredential?(edge: string, credentialRef: string): Promise<void>;
    importLegacyDeployment?(input: PublicDeploymentInput): Promise<{
        binding_id: string;
        active_release_id: string;
    }>;
    drainCollections?(input: { binding_id: string }): Promise<{
        landed: readonly string[];
        refused: readonly unknown[];
    }>;
    screenQuarantinedItem?(
        project: string,
        item: string,
    ): Promise<{ workspacePath: string | null; parked: boolean }>;
}

export interface DeploymentSelection {
    readonly projectId: string;
    readonly projectName: string;
    readonly placementId: PlacementId;
    readonly archetypeName: string;
    readonly version: number;
    readonly profile: PanelPublicProfile;
    readonly deployments: readonly PublicDeploymentBindingSummary[];
}

function slug(value: string): string {
    return value.toLowerCase().replace(/[^a-z0-9_-]+/g, "-")
        .replace(/^-+|-+$/g, "").slice(0, 64) || "panel-agent";
}

/** A deployment id the placement does not already use. */
function freshSlug(name: string, taken: readonly string[]): string {
    const base = slug(name);
    if (!taken.includes(base)) return base;
    let n = 2;
    while (taken.includes(`${base}-${n}`)) n += 1;
    return `${base}-${n}`;
}

const DEFAULT_LIMITS = { total: 1_000, session: 100, turn: 5, turns: 20, sessions: 100 };

type Lifecycle = PublicDeploymentInspection["deployment"]["lifecycle"];
const LIFECYCLE: Record<Lifecycle, { label: string; tone: string }> = {
    active: { label: "Live", tone: "live" },
    paused: { label: "Paused", tone: "paused" },
    revoked: { label: "Revoked", tone: "revoked" },
};

function CopyBlock(props: { text: string; label: string }): JSX.Element {
    const [copied, setCopied] = createSignal(false);
    return <div class="pa-code">
        <pre aria-label={props.label}>{props.text}</pre>
        <button type="button" class="pa-button" onClick={() => {
            void navigator.clipboard?.writeText(props.text).then(() => {
                setCopied(true);
                setTimeout(() => setCopied(false), 1_600);
            });
        }}>{copied() ? "Copied" : "Copy"}</button>
    </div>;
}

export function DeploymentPanel(props: {
    api: DeploymentPanelApi;
    selection: DeploymentSelection;
    defaultEdgeOrigin: string;
    defaultCredentialRef: string;
    onOpenInbox?: () => void;
    onClose: () => void;
}): JSX.Element {
    const profile = () => props.selection.profile;
    const ceilingHours = () => Math.max(1, Math.floor(profile().retention.idle_ttl_seconds / 3_600));
    const ceilingDays = () => Math.max(1, Math.floor(profile().retention.absolute_ttl_seconds / 86_400));
    const takenIds = () => props.selection.deployments.map((binding) => binding.deploymentId);
    /** The deployment this dialog is managing, or null while it composes a new one. */
    const [binding, setBinding] = createSignal<PublicDeploymentBindingSummary | null>(null);
    const [deploymentId, setDeploymentId] = createSignal(freshSlug(props.selection.archetypeName, takenIds()));
    const [edgeOrigin, setEdgeOrigin] = createSignal(props.defaultEdgeOrigin);
    // The allowlist as the list the edge holds: loaded whole, added to one entry
    // at a time, published whole (`deployment-origins.ts`).
    const [origins, setOrigins] = createSignal<string[]>([]);
    const [originInput, setOriginInput] = createSignal("");
    const [originError, setOriginError] = createSignal("");
    const [fundingMode, setFundingMode] = createSignal<"managed" | "byok">("managed");
    const [managedTenants, setManagedTenants] = createSignal<AccountTenant[]>([]);
    const [managedTenantId, setManagedTenantId] = createSignal("");
    const [managedUnavailable, setManagedUnavailable] = createSignal("");
    const [credentialRef, setCredentialRef] = createSignal(props.defaultCredentialRef);
    // Spend limits are typed in dollars and published in cents; the text is kept
    // as typed so a half-entered amount is not rewritten under the cursor.
    const [spendText, setSpendText] = createSignal({
        total: dollarsFromCents(DEFAULT_LIMITS.total),
        session: dollarsFromCents(DEFAULT_LIMITS.session),
        turn: dollarsFromCents(DEFAULT_LIMITS.turn),
    });
    const [counts, setCounts] = createSignal({ turns: DEFAULT_LIMITS.turns, sessions: DEFAULT_LIMITS.sessions });
    const [idleHours, setIdleHours] = createSignal(ceilingHours());
    const [absoluteDays, setAbsoluteDays] = createSignal(ceilingDays());
    const [endSessions, setEndSessions] = createSignal(false);
    // Not the owner's to set: removing the GaugeWright mark is a paid white-label
    // lever of the hosting entitlement (`experience/embed-surface.md`). A new
    // deployment publishes the mark; a loaded one republishes what it admits.
    const [whiteLabel, setWhiteLabel] = createSignal(false);
    const [audienceMode, setAudienceMode] = createSignal<"anonymous" | "oidc">("anonymous");
    const [oidcIssuer, setOidcIssuer] = createSignal("");
    const [oidcAudience, setOidcAudience] = createSignal("");
    const [busy, setBusy] = createSignal(false);
    const [error, setError] = createSignal("");
    const [outcome, setOutcome] = createSignal<PublicDeploymentOutcome | null>(null);
    const [drainResult, setDrainResult] = createSignal("");
    const [legacyImportRequired, setLegacyImportRequired] = createSignal(false);
    const [legacyConfirmed, setLegacyConfirmed] = createSignal(false);
    const [inspection, setInspection] = createSignal<PublicDeploymentInspection | null>(null);
    const [credentials, setCredentials] = createSignal<PublicCredentialMetadata[]>([]);
    const [addingKey, setAddingKey] = createSignal(false);
    const [providerKey, setProviderKey] = createSignal("");
    // The provider a new key belongs to. The deployment then runs on that
    // provider; the version names none (DR-0272).
    const [keyProvider, setKeyProvider] = createSignal(KEY_PROVIDERS[0]!.value);
    const [credentialLabel, setCredentialLabel] = createSignal("");
    /** The one destructive action awaiting a second click: `revoke`, `session:<id>`, `key:<ref>`. */
    const [confirming, setConfirming] = createSignal<string | null>(null);
    let stopMonitor = () => {};
    const managedFunding = () => fundingMode() === "managed";
    const managing = () => binding() !== null;
    const provider = () => providerName(keyProvider());
    const address = () => `${edgeOrigin().replace(/\/+$/, "")}/d/${deploymentId()}`;
    const embedSnippet = () => `<gw-session host="${address()}" panels="${profile().panels.components
        .map((panel) => panel.replace(/^gw-/, "")).join(",")}"></gw-session>`;
    const spendCents = () => {
        const text = spendText();
        return { total: centsFromDollars(text.total), session: centsFromDollars(text.session), turn: centsFromDollars(text.turn) };
    };
    const retentionError = () => idleHours() > ceilingHours()
        ? `Version ${props.selection.version} allows a conversation to stay resumable for at most ${formatDuration(profile().retention.idle_ttl_seconds)}.`
        : absoluteDays() > ceilingDays()
            ? `Version ${props.selection.version} keeps a conversation for at most ${formatDuration(profile().retention.absolute_ttl_seconds)}.`
            : absoluteDays() * 24 < idleHours()
                ? "A conversation can't be deleted before it stops being resumable."
                : "";

    async function loadCredentials(edge = edgeOrigin()) {
        if (!props.api.listPublicCredentials || !edge.trim()) return;
        const found = await props.api.listPublicCredentials(edge.trim());
        setCredentials(found);
        if (!credentialRef() && found[0]) setCredentialRef(found[0].credential_ref);
    }

    /** Read the live deployment and keep reading it while the dialog is open. */
    async function watch(edge: string, deployment: string) {
        stopMonitor();
        stopMonitor = () => {};
        if (!props.api.inspectDeployment) return null;
        const found = await props.api.inspectDeployment(edge, deployment);
        setInspection(found);
        stopMonitor = startDeploymentMonitor(
            () => props.api.inspectDeployment!(edge, deployment),
            (next) => setInspection(next),
            (reason) => setError(`Live status paused: ${String(reason)}`),
            window,
        );
        return found;
    }

    function composeNew() {
        stopMonitor();
        stopMonitor = () => {};
        setBinding(null);
        setInspection(null);
        setOutcome(null);
        setError("");
        setConfirming(null);
        setDeploymentId(freshSlug(props.selection.archetypeName, takenIds()));
        setEdgeOrigin(props.defaultEdgeOrigin);
        setOrigins([]);
    }

    async function loadDeployment(chosen: PublicDeploymentBindingSummary) {
        stopMonitor();
        stopMonitor = () => {};
        setBinding(chosen);
        setDeploymentId(chosen.deploymentId);
        setEdgeOrigin(chosen.edgeOrigin);
        setOutcome(null);
        setError("");
        setConfirming(null);
        if (!props.api.inspectDeployment || chosen.status !== "active") {
            setInspection(null);
            return;
        }
        setBusy(true);
        try {
            const found = await watch(chosen.edgeOrigin, chosen.deploymentId);
            const config = found!.deployment.config;
            setOrigins([...config.allowed_origins]);
            setSpendText({
                total: dollarsFromCents(config.max_spend_cents ?? DEFAULT_LIMITS.total),
                session: dollarsFromCents(config.max_session_spend_cents ?? DEFAULT_LIMITS.session),
                turn: dollarsFromCents(config.max_turn_spend_cents ?? DEFAULT_LIMITS.turn),
            });
            setCounts({ turns: config.per_visitor_turn_limit, sessions: config.max_concurrent_sessions });
            if (config.retention) {
                setIdleHours(Math.max(1, Math.floor(config.retention.idle_ttl_seconds / 3_600)));
                setAbsoluteDays(Math.max(1, Math.floor(config.retention.absolute_ttl_seconds / 86_400)));
            }
            setWhiteLabel(config.white_label ?? false);
            // Managed funding never names an owner credential and an owner key
            // always does — the invariant the Home enforces at publish. The
            // reference's prefix is versioned, and matching a stale one
            // reopened every managed deployment as key-funded.
            const managed = !config.credential_ref?.trim();
            setFundingMode(managed ? "managed" : "byok");
            if (!managed && config.credential_ref) setCredentialRef(config.credential_ref);
            const audience = config.audience;
            setAudienceMode(audience?.anonymous_allowed === false ? "oidc" : "anonymous");
            setOidcIssuer(audience?.oidc?.issuer ?? "");
            setOidcAudience(audience?.oidc?.audience ?? "");
            await loadCredentials(chosen.edgeOrigin);
        } catch (reason) {
            setError(`Could not read the deployment: ${String(reason)}`);
        } finally {
            setBusy(false);
        }
    }

    onMount(async () => {
        void loadCredentials().catch(() => {});
        if (!props.api.deploymentManagedTenants) {
            setFundingMode("byok");
        } else {
            try {
                const tenants = await props.api.deploymentManagedTenants();
                const eligible = tenants.filter((tenant) => tenant.role === "owner" || tenant.role === "admin");
                setManagedTenants(eligible);
                if (eligible[0]) setManagedTenantId(eligible[0].id);
                else setFundingMode("byok");
            } catch (reason) {
                setManagedUnavailable(`GaugeWright billing is unavailable right now: ${String(reason)}`);
                setFundingMode("byok");
            }
        }
        const existing = props.selection.deployments.find((candidate) => candidate.status === "active")
            ?? props.selection.deployments[0];
        if (existing) await loadDeployment(existing);
    });
    onCleanup(() => stopMonitor());

    function deploymentInput(): PublicDeploymentInput {
        const spend = spendCents();
        return {
            placement_id: props.selection.placementId,
            deployment_id: deploymentId().trim(),
            edge_origin: edgeOrigin().trim(),
            allowed_origins: origins(),
            max_spend_cents: spend.total,
            max_session_spend_cents: spend.session,
            max_turn_spend_cents: spend.turn,
            per_visitor_turn_limit: counts().turns,
            max_concurrent_sessions: counts().sessions,
            funding: managedFunding()
                ? { kind: "managed", tenant_id: managedTenantId() }
                : { kind: "byok", credential_ref: credentialRef().trim() },
            audience: audienceMode() === "anonymous"
                ? { anonymous_allowed: true }
                : { anonymous_allowed: false, oidc: { issuer: oidcIssuer().trim(), audience: oidcAudience().trim() } },
            white_label: whiteLabel(),
            retention_idle_ttl_seconds: idleHours() * 3_600,
            retention_absolute_ttl_seconds: absoluteDays() * 86_400,
            end_sessions: endSessions(),
        };
    }

    /** Why the deployment cannot be published yet, in the owner's terms, or "". */
    function blocker(): string {
        if (!deploymentId().trim()) return "Give the deployment an address.";
        if (!origins().length) return "Add the website it will appear on.";
        const spend = spendCents();
        if (spend.total === null || spend.session === null || spend.turn === null) {
            return "Enter each spending limit as an amount in dollars, such as 10 or 0.05.";
        }
        if (!(counts().turns >= 1) || !(counts().sessions >= 1)) return "Visitor limits must be at least 1.";
        if (retentionError()) return retentionError();
        if (managedFunding() && !managedTenantId()) return "Choose the account that pays for this deployment.";
        if (!managedFunding() && !credentialRef().trim()) return "Choose or add the provider key that pays for this deployment.";
        if (audienceMode() === "oidc" && (!oidcIssuer().trim() || !oidcAudience().trim())) {
            return "Signed-in visitors need both the sign-in provider's address and this site's client ID.";
        }
        return "";
    }

    function addOrigin(input = originInput()) {
        const result = normalizeOrigin(input);
        if ("error" in result) return setOriginError(result.error);
        setOrigins(withOrigin(origins(), result.origin));
        setOriginInput("");
        setOriginError("");
        setError("");
    }

    async function publish() {
        setError("");
        setLegacyImportRequired(false);
        if (blocker()) return setError(blocker());
        setBusy(true);
        try {
            const published = await props.api.publishDeployment(deploymentInput());
            setOutcome(published);
            setBinding({
                id: published.binding_id,
                deploymentId: published.deployment_id,
                edgeOrigin: published.edge_origin,
                activeReleaseId: published.release_id,
                status: "active",
            });
            await watch(published.edge_origin, published.deployment_id).catch((reason) =>
                setError(`Deployed, but its live status could not be read: ${String(reason)}`));
        } catch (reason) {
            const message = String(reason);
            setLegacyImportRequired(message.includes("legacy hosted deployment"));
            setError(message);
        } finally {
            setBusy(false);
        }
    }

    async function importLegacy() {
        if (!props.api.importLegacyDeployment || !legacyConfirmed()) return;
        setBusy(true);
        setError("");
        try {
            const imported = await props.api.importLegacyDeployment(deploymentInput());
            setLegacyImportRequired(false);
            setLegacyConfirmed(false);
            setDrainResult(`Imported without changing hosted release ${imported.active_release_id}. Review the settings, then save when ready.`);
        } catch (reason) {
            setError(String(reason));
        } finally {
            setBusy(false);
        }
    }

    async function drain() {
        const bindingId = outcome()?.binding_id
            ?? binding()?.id
            ?? props.selection.deployments.find((item) => item.deploymentId === deploymentId())?.id;
        if (!bindingId || !props.api.drainCollections) return;
        setBusy(true);
        try {
            const result = await props.api.drainCollections({ binding_id: bindingId });
            if (props.api.screenQuarantinedItem) {
                await Promise.allSettled(result.landed.map((item) =>
                    props.api.screenQuarantinedItem!(props.selection.projectId, item)));
            }
            const landed = result.landed.length;
            setDrainResult(landed
                ? `${landed} result${landed === 1 ? "" : "s"} arrived in the ${props.selection.projectName} Inbox`
                    + (result.refused.length ? `; ${result.refused.length} refused.` : ".")
                : `No new results${result.refused.length ? `; ${result.refused.length} refused.` : "."}`);
        } catch (reason) {
            setDrainResult(String(reason));
        } finally {
            setBusy(false);
        }
    }

    async function control(command: "pause" | "resume" | "revoke") {
        const current = inspection();
        if (!current || !props.api.controlDeployment) return;
        setBusy(true);
        setError("");
        setConfirming(null);
        try {
            const deployment = await props.api.controlDeployment(
                edgeOrigin(), deploymentId(), command, current.deployment.activation_revision,
            );
            setInspection({ ...current, deployment });
        } catch (reason) {
            setError(String(reason));
        } finally {
            setBusy(false);
        }
    }

    async function eraseSession(sessionId: string) {
        if (!props.api.erasePublicSession) return;
        setBusy(true);
        setConfirming(null);
        try {
            await props.api.erasePublicSession(edgeOrigin(), deploymentId(), sessionId);
            setInspection((current) => current && ({
                ...current,
                audience: current.audience.filter((session) => session.session_id !== sessionId),
            }));
        } catch (reason) {
            setError(String(reason));
        } finally {
            setBusy(false);
        }
    }

    async function provisionCredential() {
        if (!props.api.provisionPublicCredential || !providerKey().trim()) return;
        setBusy(true);
        setError("");
        try {
            const created = await props.api.provisionPublicCredential({
                edge_origin: edgeOrigin(),
                provider: keyProvider() === "anthropic" ? "anthropic" : "openai",
                credential_class: KEY_PROVIDERS.find((choice) => choice.value === keyProvider())!.credentialClass,
                api_key: providerKey().trim(),
                label: credentialLabel().trim() || `${props.selection.archetypeName} deployment`,
            });
            setCredentials((current) => [...current.filter((item) => item.credential_ref !== created.credential_ref), created]);
            setCredentialRef(created.credential_ref);
            setProviderKey("");
            setCredentialLabel("");
            setAddingKey(false);
        } catch (reason) {
            setError(String(reason));
        } finally {
            setBusy(false);
        }
    }

    async function revokeCredential(reference: string) {
        if (!props.api.revokePublicCredential) return;
        setBusy(true);
        setError("");
        setConfirming(null);
        try {
            await props.api.revokePublicCredential(edgeOrigin(), reference);
            setCredentials((current) => current.filter((item) => item.credential_ref !== reference));
            if (credentialRef() === reference) setCredentialRef("");
        } catch (reason) {
            setError(String(reason));
        } finally {
            setBusy(false);
        }
    }

    const lifecycle = () => {
        const current = inspection();
        return current ? LIFECYCLE[current.deployment.lifecycle] : null;
    };
    /** Spend against the budget the deployment admitted, not the one being edited. */
    const budget = () => inspection()?.deployment.config.max_spend_cents ?? null;
    const spentShare = () => {
        const current = inspection();
        const total = budget();
        return current && total ? Math.min(1, current.deployment.spent_cents / total) : 0;
    };
    const suggestedOrigin = () => {
        const last = origins()[origins().length - 1];
        const other = last ? wwwCounterpart(last) : null;
        return other && !origins().includes(other) ? other : null;
    };
    const setSpend = (key: "total" | "session" | "turn", value: string) => setSpendText({ ...spendText(), [key]: value });
    const spendField = (key: "total" | "session" | "turn", label: string, note: string) => <label class="pa-field">
        <span>{label}</span>
        <span class="pa-affix"><span>$</span><input class="pa-input" inputmode="decimal" value={spendText()[key]}
            aria-invalid={spendCents()[key] === null} onInput={(event) => setSpend(key, event.currentTarget.value)} /></span>
        <small>{note}</small></label>;
    const countField = (key: "turns" | "sessions", label: string, note: string) => <label class="pa-field">
        <span>{label}</span>
        <input class="pa-input" type="number" min="1" value={counts()[key]}
            onInput={(event) => setCounts({ ...counts(), [key]: event.currentTarget.valueAsNumber })} />
        <small>{note}</small></label>;

    return <div class="modal-overlay" role="presentation" onClick={(event) => {
        if (event.target === event.currentTarget) props.onClose();
    }}><section class="modal pa-dialog pa-root" role="dialog" aria-modal="true" aria-label="Deploy Panel agent">
        <header class="pa-dialog-head">
            <div>
                <span class="pa-dialog-kicker">{managing() ? "Deployment" : "Deploy"}</span>
                <h2>{props.selection.archetypeName}
                    <Show when={lifecycle()}>{(state) => <span class="pa-pill" data-tone={state().tone}>{state().label}</span>}</Show></h2>
                <p>{props.selection.projectName} · version {props.selection.version}</p>
            </div>
            <button type="button" class="pa-dialog-close" aria-label="Close" onClick={props.onClose}>×</button>
        </header>

        <div class="pa-dialog-body">
            <Show when={props.selection.deployments.length}>
                <div class="pa-switcher" role="group" aria-label="Deployments">
                    <For each={props.selection.deployments}>{(candidate) =>
                        <button type="button" aria-pressed={binding()?.id === candidate.id}
                            onClick={() => void loadDeployment(candidate)}>{candidate.deploymentId}</button>}</For>
                    <button type="button" aria-pressed={!managing()} onClick={composeNew}>+ New deployment</button>
                </div>
            </Show>

            <Show when={outcome()}>{(published) => <section class="pa-section">
                <div class="pa-callout success">
                    <strong>{props.selection.archetypeName} is live</strong>
                    <p>Visitors on {origins().join(", ")} can use it now. Paste the code below into your website to show it.</p>
                    <div class="pa-status-line"><a href={published().deployment_url} target="_blank" rel="noreferrer">{published().deployment_url}</a></div>
                </div>
                <CopyBlock label="Embed code" text={published().embed_html} />
            </section>}</Show>

            <Show when={inspection()}>{(current) => <section class="pa-section" data-deployment-status>
                <div class="pa-section-head"><h3>Status</h3></div>
                <div class="pa-status-line">
                    <a href={address()} target="_blank" rel="noreferrer">{address()}</a>
                </div>
                <div class="pa-stats">
                    <div class="pa-stat"><span>Spent</span><strong>{formatCents(current().deployment.spent_cents)}</strong>
                        <small>{budget() === null ? "no total budget" : `of ${formatCents(budget()!)} budget`}</small>
                        <div class="pa-meter" data-tone={spentShare() > 0.8 ? "high" : undefined}><span style={{ width: `${spentShare() * 100}%` }} /></div></div>
                    <div class="pa-stat"><span>Conversations</span><strong>{current().deployment.sessions}</strong><small>since it went live</small></div>
                    <div class="pa-stat"><span>Replies</span><strong>{current().deployment.settled_turns}</strong><small>answered by the agent</small></div>
                </div>
                <div class="pa-row">
                    <Show when={current().deployment.lifecycle === "active"}>
                        <button type="button" class="pa-button" disabled={busy()} onClick={() => void control("pause")}>Pause</button></Show>
                    <Show when={current().deployment.lifecycle === "paused"}>
                        <button type="button" class="pa-button" disabled={busy()} onClick={() => void control("resume")}>Resume</button></Show>
                    <Show when={current().deployment.lifecycle !== "revoked"}>
                        <button type="button" class="pa-button danger" disabled={busy()} onClick={() => setConfirming("revoke")}>Revoke…</button></Show>
                    <span class="pa-hint">{current().deployment.lifecycle === "paused"
                        ? "Paused: visitors can't start or continue conversations."
                        : current().deployment.lifecycle === "revoked" ? "Revoked for good. Its history is kept." : ""}</span>
                </div>
                <Show when={confirming() === "revoke"}>
                    <div class="pa-confirm"><span>Revoking stops every conversation now and for good. It can't be undone; to pause instead, use Pause.</span>
                        <button type="button" class="pa-button" onClick={() => setConfirming(null)}>Keep it</button>
                        <button type="button" class="pa-button danger solid" disabled={busy()} onClick={() => void control("revoke")}>Revoke</button></div>
                </Show>
                <Show when={!outcome()}>
                    <div class="pa-field"><span>Add it to your website</span>
                        <CopyBlock label="Embed code" text={embedSnippet()} /></div>
                </Show>
                <Show when={profile().collection && props.api.drainCollections}>
                    <div class="pa-row">
                        <button type="button" class="pa-button" disabled={busy()} onClick={() => void drain()}>Bring results into the Inbox</button>
                        <Show when={drainResult()}><span class="pa-hint">{drainResult()}</span></Show>
                    </div>
                </Show>
            </section>}</Show>

            <section class="pa-section" data-deployment-websites>
                <div class="pa-section-head">
                    <h3>Websites</h3>
                    <p>It works only on these sites. Add both forms if your site uses them, such as example.com and www.example.com.</p>
                </div>
                <Show when={origins().length} fallback={<p class="pa-empty">No websites yet.</p>}>
                    <ul class="pa-list">
                        <For each={origins()}>{(origin) => <li>
                            <span><strong>{origin}</strong></span>
                            <button type="button" class="pa-quiet danger" aria-label={`Remove ${origin}`}
                                onClick={() => setOrigins(origins().filter((candidate) => candidate !== origin))}>Remove</button>
                        </li>}</For>
                    </ul>
                </Show>
                <div class="pa-row">
                    <input class="pa-input" placeholder="example.com" aria-label="Website address" value={originInput()}
                        aria-invalid={!!originError()}
                        onInput={(event) => { setOriginInput(event.currentTarget.value); setOriginError(""); }}
                        onKeyDown={(event) => { if (event.key === "Enter") { event.preventDefault(); addOrigin(); } }} />
                    <button type="button" class="pa-button" disabled={!originInput().trim()} onClick={() => addOrigin()}>Add website</button>
                </div>
                <Show when={originError()}><p class="pa-error">{originError()}</p></Show>
                <Show when={suggestedOrigin()}>{(other) => <p class="pa-hint">Does your site also answer at {other()}?{" "}
                    <button type="button" class="pa-link" onClick={() => addOrigin(other())}>Add it too</button></p>}</Show>
                <Show when={!managing()}>
                    <label class="pa-field"><span>Address</span>
                        <span class="pa-affix pa-address"><span>{edgeOrigin().replace(/^https?:\/\//, "").replace(/\/+$/, "")}/d/</span>
                            <input class="pa-input" spellcheck={false} value={deploymentId()}
                                onInput={(event) => setDeploymentId(event.currentTarget.value)} /></span>
                        <small>Where the embed loads it from. Visitors don't see this.</small></label>
                </Show>
            </section>

            <section class="pa-section" data-deployment-audience>
                <div class="pa-section-head"><h3>Who can use it</h3></div>
                <div class="pa-options" role="radiogroup" aria-label="Who can use it">
                    <Option type="radio" name="pa-audience" checked={audienceMode() === "anonymous"} onChange={() => setAudienceMode("anonymous")}
                        label="Anyone on those websites" detail="No sign-in. Each visitor gets their own private conversation." />
                    <Option type="radio" name="pa-audience" checked={audienceMode() === "oidc"} onChange={() => setAudienceMode("oidc")}
                        label="Only signed-in visitors" detail="Through your website's own sign-in (OpenID Connect)." />
                </div>
                <Show when={audienceMode() === "oidc"}><div class="pa-fields">
                    <label class="pa-field"><span>Sign-in provider address</span>
                        <input class="pa-input" placeholder="https://accounts.example.com" spellcheck={false} value={oidcIssuer()} onInput={(e) => setOidcIssuer(e.currentTarget.value)} />
                        <small>The OIDC issuer.</small></label>
                    <label class="pa-field"><span>Client ID</span>
                        <input class="pa-input" spellcheck={false} value={oidcAudience()} onInput={(e) => setOidcAudience(e.currentTarget.value)} />
                        <small>The OIDC audience your site's sign-in issues tokens for.</small></label>
                </div></Show>
            </section>

            <section class="pa-section" data-deployment-funding>
                <div class="pa-section-head">
                    <h3>Who pays</h3>
                    <p>Visitors never pay or bring a key. Nothing runs without a way to pay.</p>
                </div>
                <div class="pa-options" role="radiogroup" aria-label="Who pays">
                    <Option type="radio" name="pa-funding" checked={managedFunding()} disabled={!managedTenants().length}
                        title={managedTenants().length ? undefined : "You don't administer a GaugeWright account that can pay for deployments."}
                        onChange={() => setFundingMode("managed")}
                        label="GaugeWright billing" detail="Usage is billed to an account you administer." />
                    <Option type="radio" name="pa-funding" checked={!managedFunding()} onChange={() => setFundingMode("byok")}
                        label="Your own provider key" detail="The key's provider bills you directly for what visitors use, and the deployment runs on that provider." />
                </div>
                <Show when={managedUnavailable()}><p class="pa-hint warn">{managedUnavailable()}</p></Show>
                <Show when={managedFunding()}>
                    <label class="pa-field"><span>Account</span>
                        <select class="pa-input" value={managedTenantId()} onChange={(event) => setManagedTenantId(event.currentTarget.value)}>
                            <For each={managedTenants()}>{(tenant) => <option value={tenant.id}>{tenant.displayName}{tenant.personal ? " (personal)" : ""}</option>}</For>
                        </select>
                        <small>Only accounts you own or administer are listed. You approve the charge when you deploy.</small></label>
                </Show>
                <Show when={!managedFunding()}>
                    <Show when={credentialRef() && !credentials().some((credential) => credential.credential_ref === credentialRef())}>
                        <p class="pa-hint">Paying with the preset key <code>{credentialRef()}</code>.</p>
                    </Show>
                    <Show when={credentials().length} fallback={<p class="pa-hint pa-indent">No provider keys stored yet.</p>}>
                        <div class="pa-options pa-indent" role="radiogroup" aria-label="Provider key">
                            <For each={credentials()}>{(credential) => <>
                                <div class="pa-option-row">
                                    <Option type="radio" name="pa-credential" checked={credentialRef() === credential.credential_ref}
                                        onChange={() => setCredentialRef(credential.credential_ref)}
                                        label={credential.label}
                                        detail={`${providerName(credential.provider)} key, added ${new Date(credential.created_at_unix_ms).toLocaleDateString()}`} />
                                    <Show when={props.api.revokePublicCredential}>
                                        <button type="button" class="pa-quiet danger" onClick={() => setConfirming(`key:${credential.credential_ref}`)}>Remove</button>
                                    </Show>
                                </div>
                                <Show when={confirming() === `key:${credential.credential_ref}`}>
                                    <div class="pa-confirm"><span>Remove “{credential.label}”? Any deployment paying with it stops admitting visitors.</span>
                                        <button type="button" class="pa-button" onClick={() => setConfirming(null)}>Keep it</button>
                                        <button type="button" class="pa-button danger solid" disabled={busy()} onClick={() => void revokeCredential(credential.credential_ref)}>Remove key</button></div>
                                </Show>
                            </>}</For>
                        </div>
                    </Show>
                    <Show when={props.api.provisionPublicCredential}>
                        <Show when={addingKey()} fallback={<div class="pa-row pa-indent">
                            <button type="button" class="pa-button" onClick={() => setAddingKey(true)}>Add a provider key…</button></div>}>
                            <div class="pa-composer pa-indent-box">
                                <div class="pa-fields">
                                    <label class="pa-field"><span>Provider</span>
                                        <select class="pa-input" value={keyProvider()} onChange={(event) => setKeyProvider(event.currentTarget.value)}>
                                            <For each={KEY_PROVIDERS}>{(choice) => <option value={choice.value}>{choice.name}</option>}</For>
                                        </select></label>
                                    <label class="pa-field"><span>Name</span>
                                        <input class="pa-input" placeholder={`${props.selection.archetypeName} deployment`} value={credentialLabel()} onInput={(event) => setCredentialLabel(event.currentTarget.value)} /></label>
                                    <label class="pa-field"><span>{provider()} API key</span>
                                        <input class="pa-input" type="password" autocomplete="off" value={providerKey()} onInput={(event) => setProviderKey(event.currentTarget.value)} /></label>
                                </div>
                                <p class="pa-hint">Sent once to GaugeWright's hosting, which stores it encrypted. This computer keeps no copy, and the key is never shown again.</p>
                                <div class="pa-row">
                                    <button type="button" class="pa-button primary" disabled={busy() || !providerKey().trim()} onClick={() => void provisionCredential()}>Save key</button>
                                    <button type="button" class="pa-button" onClick={() => { setAddingKey(false); setProviderKey(""); }}>Cancel</button>
                                </div>
                            </div>
                        </Show>
                    </Show>
                </Show>
            </section>

            <section class="pa-section" data-deployment-limits>
                <div class="pa-section-head">
                    <h3>Spending limits</h3>
                    <p>Visitors are turned away once any limit is reached.</p>
                </div>
                <div class="pa-fields">
                    {spendField("total", "Total budget", "For this deployment, ever.")}
                    {spendField("session", "Per conversation", "Most one visitor's conversation may cost.")}
                    {spendField("turn", "Per reply", "Most a single reply may cost.")}
                </div>
                <div class="pa-fields">
                    {countField("turns", "Replies per visitor", "Messages the agent answers for one visitor.")}
                    {countField("sessions", "Conversations at once", "Visitors served at the same time.")}
                </div>
            </section>

            <section class="pa-section" data-deployment-history>
                <div class="pa-section-head">
                    <h3>Conversation history</h3>
                    <p>Version {props.selection.version} allows up to {formatDuration(profile().retention.idle_ttl_seconds)} and {formatDuration(profile().retention.absolute_ttl_seconds)}.</p>
                </div>
                <div class="pa-fields">
                    <label class="pa-field"><span>Resumable for</span>
                        <span class="pa-affix"><input class="pa-input" type="number" min="1" max={ceilingHours()} value={idleHours()}
                            aria-invalid={idleHours() > ceilingHours()} onInput={(event) => setIdleHours(event.currentTarget.valueAsNumber)} /><span>hours</span></span>
                        <small>after the visitor's last message</small></label>
                    <label class="pa-field"><span>Deleted after</span>
                        <span class="pa-affix"><input class="pa-input" type="number" min="1" max={ceilingDays()} value={absoluteDays()}
                            aria-invalid={absoluteDays() > ceilingDays()} onInput={(event) => setAbsoluteDays(event.currentTarget.valueAsNumber)} /><span>days</span></span>
                        <small>from when it started</small></label>
                </div>
                <Show when={retentionError()}><p class="pa-error">{retentionError()}</p></Show>
            </section>

            <section class="pa-section" data-deployment-update>
                <Show when={managing()}>
                    <Option type="checkbox" checked={endSessions()} onChange={setEndSessions}
                        label="End conversations on the previous version"
                        detail="Otherwise, conversations under way finish on the version they started with." />
                </Show>
                <Show when={!managing()}>
                    <details class="pa-advanced"><summary>Advanced</summary><div>
                        <label class="pa-field"><span>Hosting service</span>
                            <input class="pa-input" spellcheck={false} value={edgeOrigin()} onInput={(e) => setEdgeOrigin(e.currentTarget.value)} />
                            <small>The public host that serves the deployment.</small></label>
                    </div></details>
                </Show>
            </section>

            <Show when={inspection()?.audience.length}>
                <section class="pa-section" data-deployment-visitors>
                    <div class="pa-section-head">
                        <h3>Visitors</h3>
                        <p>Each visitor's conversation is private to them. Erasing one deletes it for good.</p>
                    </div>
                    <ul class="pa-list">
                        <For each={inspection()!.audience}>{(session) => <li>
                            <span><strong>{session.principal_mode === "authenticated" ? (session.audience_id ?? "Signed-in visitor") : "Anonymous visitor"}</strong>
                                <small>{session.origin.replace(/^https:\/\//, "")} · started {formatAge(session.created_at_unix_ms, Date.now())} · {session.settled_turns} repl{session.settled_turns === 1 ? "y" : "ies"}</small></span>
                            <Show when={confirming() === `session:${session.session_id}`} fallback={
                                <button type="button" class="pa-quiet danger" disabled={busy()} onClick={() => setConfirming(`session:${session.session_id}`)}>Erase…</button>}>
                                <div class="pa-row">
                                    <button type="button" class="pa-button" onClick={() => setConfirming(null)}>Keep</button>
                                    <button type="button" class="pa-button danger solid" disabled={busy()} onClick={() => void eraseSession(session.session_id)}>Erase</button>
                                </div>
                            </Show>
                        </li>}</For>
                    </ul>
                </section>
            </Show>

            <Show when={legacyImportRequired() && props.api.importLegacyDeployment}>
                <section class="pa-section"><div class="pa-callout warn">
                    <strong>This deployment was made before project bindings</strong>
                    <p>Importing binds its existing release and conversations to this placement and {props.selection.projectName}. It doesn't change what is live; save afterwards to update it.</p>
                    <label class="pa-row"><input type="checkbox" checked={legacyConfirmed()} onChange={(event) => setLegacyConfirmed(event.currentTarget.checked)} />
                        <span class="pa-hint">This is the source Panel agent and the project that should receive it.</span></label>
                    <div class="pa-row"><button type="button" class="pa-button" disabled={!legacyConfirmed() || busy()} onClick={() => void importLegacy()}>Import existing deployment</button></div>
                </div></section>
            </Show>
            <Show when={drainResult() && !inspection()}><p class="pa-hint">{drainResult()}</p></Show>

            <details class="pa-section pa-advanced" data-deployment-contract>
                <summary>What visitors get · version {props.selection.version}</summary>
                <div>
                    <PanelContractSummary profile={profile()} />
                    <p class="pa-hint">Fixed by version {props.selection.version}. To change any of it, edit the Panel agent, try it, publish a new version, and upgrade this placement.</p>
                </div>
            </details>
        </div>

        <footer class="pa-dialog-foot">
            <Show when={error()} fallback={<span class="pa-hint">{managing()
                ? "Changes apply to new conversations once saved."
                : `Deploys version ${props.selection.version} to the websites above.`}</span>}>
                <p class="pa-error" role="alert">{error()}</p>
            </Show>
            <div>
                <Show when={props.onOpenInbox}><button type="button" class="pa-button" onClick={props.onOpenInbox}>Open Inbox</button></Show>
                <button type="button" class="pa-button" onClick={props.onClose}>{outcome() ? "Done" : "Cancel"}</button>
                <button type="button" class="pa-button primary" disabled={busy()} onClick={() => void publish()}>
                    {busy() ? (managing() ? "Saving…" : "Deploying…") : managing() ? "Save changes" : "Deploy"}</button>
            </div>
        </footer>
    </section></div>;
}
