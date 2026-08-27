import { createSignal, For, onCleanup, onMount, Show, type JSX } from "solid-js";
import { Dynamic } from "solid-js/web";
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
    const [deploymentId, setDeploymentId] = createSignal(slug(props.selection.archetypeName));
    const [edgeOrigin, setEdgeOrigin] = createSignal(props.defaultEdgeOrigin);
    const [allowedOrigin, setAllowedOrigin] = createSignal(
        typeof window === "undefined" ? "https://example.com" : window.location.origin,
    );
    const [fundingMode, setFundingMode] = createSignal<"managed" | "byok">("managed");
    const [managedTenants, setManagedTenants] = createSignal<AccountTenant[]>([]);
    const [managedTenantId, setManagedTenantId] = createSignal("");
    const [credentialRef, setCredentialRef] = createSignal(props.defaultCredentialRef);
    const [limits, setLimits] = createSignal({ total: 1_000, session: 100, turn: 5, turns: 20, sessions: 100 });
    const [idleHours, setIdleHours] = createSignal(ceilingHours());
    const [absoluteDays, setAbsoluteDays] = createSignal(ceilingDays());
    const [endSessions, setEndSessions] = createSignal(false);
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
    const [providerKey, setProviderKey] = createSignal("");
    const [credentialLabel, setCredentialLabel] = createSignal("");
    let stopMonitor = () => {};
    const managedFunding = () => fundingMode() === "managed";
    const collectionLabel = () => {
        const collection = profile().collection;
        return collection ? `${collection.schema_ref} → project Inbox` : "Off";
    };
    const retentionError = () => idleHours() > ceilingHours()
        ? "Idle retention exceeds the frozen version ceiling."
        : absoluteDays() > ceilingDays()
            ? "Absolute retention exceeds the frozen version ceiling."
            : absoluteDays() * 24 < idleHours()
                ? "Absolute retention must be at least the idle window."
                : "";

    async function loadCredentials(edge = edgeOrigin()) {
        if (!props.api.listPublicCredentials || !edge.trim()) return;
        const found = await props.api.listPublicCredentials(edge.trim());
        setCredentials(found);
        if (!credentialRef() && found[0]) setCredentialRef(found[0].credential_ref);
    }

    async function loadDeployment(binding: PublicDeploymentBindingSummary) {
        stopMonitor();
        stopMonitor = () => {};
        setDeploymentId(binding.deploymentId);
        setEdgeOrigin(binding.edgeOrigin);
        setOutcome(null);
        setError("");
        if (!props.api.inspectDeployment || binding.status !== "active") {
            setInspection(null);
            return;
        }
        setBusy(true);
        try {
            const found = await props.api.inspectDeployment(binding.edgeOrigin, binding.deploymentId);
            const config = found.deployment.config;
            setInspection(found);
            setAllowedOrigin(config.allowed_origins[0] ?? "");
            setLimits({
                total: config.max_spend_cents ?? 1_000,
                session: config.max_session_spend_cents ?? 100,
                turn: config.max_turn_spend_cents ?? 5,
                turns: config.per_visitor_turn_limit,
                sessions: config.max_concurrent_sessions,
            });
            if (config.retention) {
                setIdleHours(Math.max(1, Math.floor(config.retention.idle_ttl_seconds / 3_600)));
                setAbsoluteDays(Math.max(1, Math.floor(config.retention.absolute_ttl_seconds / 86_400)));
            }
            setWhiteLabel(config.white_label ?? false);
            const managed = config.funding_ref?.startsWith("managed:") ?? false;
            setFundingMode(managed ? "managed" : "byok");
            if (!managed && config.credential_ref) setCredentialRef(config.credential_ref);
            const audience = config.audience;
            setAudienceMode(audience?.anonymous_allowed === false ? "oidc" : "anonymous");
            setOidcIssuer(audience?.oidc?.issuer ?? "");
            setOidcAudience(audience?.oidc?.audience ?? "");
            await loadCredentials(binding.edgeOrigin);
            if (props.api.inspectDeployment) {
                stopMonitor = startDeploymentMonitor(
                    () => props.api.inspectDeployment!(binding.edgeOrigin, binding.deploymentId),
                    (next) => setInspection(next),
                    (reason) => setError(`Deployment monitoring paused: ${String(reason)}`),
                    window,
                );
            }
        } catch (reason) {
            setError(`Could not inspect deployment: ${String(reason)}`);
        } finally {
            setBusy(false);
        }
    }

    onMount(async () => {
        if (!props.api.deploymentManagedTenants) {
            setFundingMode("byok");
            return;
        }
        try {
            const tenants = await props.api.deploymentManagedTenants();
            const eligible = tenants.filter((tenant) => tenant.role === "owner" || tenant.role === "admin");
            setManagedTenants(eligible);
            if (eligible[0]) setManagedTenantId(eligible[0].id);
            else setFundingMode("byok");
        } catch (reason) {
            setError(`Managed funding is unavailable: ${String(reason)}`);
            setFundingMode("byok");
        }
        const existing = props.selection.deployments.find((binding) => binding.status === "active")
            ?? props.selection.deployments[0];
        if (existing) await loadDeployment(existing);
    });
    onCleanup(() => stopMonitor());

    function deploymentInput(): PublicDeploymentInput {
        const value = limits();
        return {
            placement_id: props.selection.placementId,
            deployment_id: deploymentId().trim(),
            edge_origin: edgeOrigin().trim(),
            allowed_origins: [allowedOrigin().trim()],
            max_spend_cents: value.total,
            max_session_spend_cents: value.session,
            max_turn_spend_cents: value.turn,
            per_visitor_turn_limit: value.turns,
            max_concurrent_sessions: value.sessions,
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

    async function publish() {
        setError("");
        setLegacyImportRequired(false);
        if (retentionError()) return setError(retentionError());
        if (managedFunding() && !managedTenantId()) {
            return setError("Choose an account that will fund this deployment.");
        }
        if (!managedFunding() && !credentialRef().trim()) {
            return setError("Choose an exact provider credential for BYOK funding.");
        }
        if (audienceMode() === "oidc" && (!oidcIssuer().trim() || !oidcAudience().trim())) {
            return setError("OIDC issuer and audience are required.");
        }
        setBusy(true);
        try {
            setOutcome(await props.api.publishDeployment(deploymentInput()));
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
            setDrainResult(`Imported without changing hosted release ${imported.active_release_id}. Review and publish when ready.`);
        } catch (reason) {
            setError(String(reason));
        } finally {
            setBusy(false);
        }
    }

    async function drain() {
        const binding = outcome()?.binding_id
            ?? props.selection.deployments.find((item) => item.deploymentId === deploymentId())?.id;
        if (!binding || !props.api.drainCollections) return;
        setBusy(true);
        try {
            const result = await props.api.drainCollections({ binding_id: binding });
            if (props.api.screenQuarantinedItem) {
                await Promise.allSettled(result.landed.map((item) =>
                    props.api.screenQuarantinedItem!(props.selection.projectId, item)));
            }
            setDrainResult(`${result.landed.length} item(s) entered ${props.selection.projectName} Inbox`
                + (result.refused.length ? `; ${result.refused.length} refused.` : "."));
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
                provider: profile().provider.provider === "anthropic" ? "anthropic" : "openai",
                credential_class: profile().provider.credential_class,
                api_key: providerKey().trim(),
                label: credentialLabel().trim() || `${props.selection.archetypeName} deployment`,
            });
            setCredentials((current) => [...current.filter((item) => item.credential_ref !== created.credential_ref), created]);
            setCredentialRef(created.credential_ref);
            setProviderKey("");
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

    const numeric = (
        label: string,
        value: () => number,
        update: (next: number) => void,
        max?: () => number,
    ) => <label class="settings-field"><span class="settings-label">{label}</span><input
        class="settings-input" type="number" min="1" max={max?.()} value={value()}
        onInput={(event) => update(event.currentTarget.valueAsNumber)} /></label>;

    return <div class="modal-overlay" role="presentation" onClick={(event) => {
        if (event.target === event.currentTarget) props.onClose();
    }}><section class="modal embed-monitor" role="dialog" aria-modal="true" aria-label="Deploy Panel agent">
        <header class="modal-head"><div><strong>Deploy {props.selection.archetypeName}</strong>
            <div class="muted">{props.selection.projectName} · Panel agent v{props.selection.version}</div></div>
            <button type="button" class="icon-button" aria-label="Close" onClick={props.onClose}>×</button></header>

        <section class="admin-section"><h3>Frozen public contract</h3>
            <p class="settings-hint">This comes from the pinned Panel-agent version. Deployment operates it; it does not redefine it.</p>
            <div class="member-list">
                <div class="member-row"><span>Panels</span><span class="member-id">{profile().panels.components.join(", ")}</span></div>
                <div class="member-row"><span>Abilities</span><span class="member-id">{profile().public_abilities.join(", ") || "Chat only"}</span></div>
                <div class="member-row"><span>Provider</span><span class="member-id">{profile().provider.provider} · {profile().provider.model}</span></div>
                <div class="member-row"><span>Audience inputs</span><span class="member-id">{profile().audience_inputs.join(", ")}</span></div>
                <div class="member-row"><span>Initial content</span><span class="member-id">{profile().initial_workspace.length} file(s)</span></div>
                <div class="member-row"><span>Collection</span><span class="member-id">{collectionLabel()}</span></div>
            </div><p class="settings-hint warn">To change this contract, edit the Agent, Preview it, and publish a new version.</p>
        </section>

        <Show when={props.selection.deployments.length}><section class="admin-section"><h3>Project deployments</h3>
            <div class="member-list"><For each={props.selection.deployments}>{(deployment) =>
                <button type="button" class="member-row" onClick={() => void loadDeployment(deployment)}><span>{deployment.deploymentId}</span><span class="member-id">{deployment.status} · {deployment.activeReleaseId ?? "no active release"}</span></button>
            }</For></div></section></Show>

        <section class="admin-section"><h3>Operational settings</h3><div class="settings-form">
            <div class="deployment-field-grid">
                <label class="settings-field"><span class="settings-label">Deployment ID</span><input class="settings-input" value={deploymentId()} onInput={(e) => setDeploymentId(e.currentTarget.value)} /></label>
                <label class="settings-field"><span class="settings-label">Edge origin</span><input class="settings-input" value={edgeOrigin()} onInput={(e) => setEdgeOrigin(e.currentTarget.value)} /></label>
            </div>
            <label class="settings-field"><span class="settings-label">Allowed website origin</span><input class="settings-input" value={allowedOrigin()} onInput={(e) => setAllowedOrigin(e.currentTarget.value)} /></label>
            <fieldset class="deployment-fieldset"><legend>Who pays for public turns?</legend>
                <label class="settings-checkbox"><input type="radio" checked={managedFunding()} disabled={!managedTenants().length} onChange={() => setFundingMode("managed")} /> GaugeWright managed inference</label>
                <Show when={managedFunding()}><label class="settings-field"><span class="settings-label">Funding account</span><select class="settings-input" value={managedTenantId()} onChange={(event) => setManagedTenantId(event.currentTarget.value)}>
                    <For each={managedTenants()}>{(tenant) => <option value={tenant.id}>{tenant.displayName}{tenant.personal ? " (Personal)" : ""}</option>}</For>
                </select><span class="settings-hint">Only accounts where you are an owner or admin are shown. Authorization is obtained at publish time.</span></label></Show>
                <label class="settings-checkbox"><input type="radio" checked={!managedFunding()} onChange={() => setFundingMode("byok")} /> Bring your own provider key</label>
                <Show when={!managedFunding()}><div class="settings-form"><label class="settings-field"><span class="settings-label">Exact credential</span><select class="settings-input" value={credentialRef()} onChange={(event) => setCredentialRef(event.currentTarget.value)}>
                    <option value="">Choose a credential…</option><For each={credentials()}>{(credential) => <option value={credential.credential_ref}>{credential.label} · {credential.provider}</option>}</For>
                </select></label><Show when={credentials().length && props.api.revokePublicCredential}><div class="member-list"><For each={credentials()}>{(credential) => <div class="member-row"><span>{credential.label}<small class="member-id">{credential.provider}</small></span><button type="button" disabled={busy()} onClick={() => void revokeCredential(credential.credential_ref)}>Revoke</button></div>}</For></div></Show><Show when={props.api.provisionPublicCredential}><div class="deployment-field-grid">
                    <label class="settings-field"><span class="settings-label">Credential label</span><input class="settings-input" value={credentialLabel()} onInput={(event) => setCredentialLabel(event.currentTarget.value)} /></label>
                    <label class="settings-field"><span class="settings-label">Provider API key</span><input class="settings-input" type="password" value={providerKey()} onInput={(event) => setProviderKey(event.currentTarget.value)} /></label>
                </div><button type="button" disabled={busy() || !providerKey().trim()} onClick={() => void provisionCredential()}>Store credential</button></Show></div></Show>
            </fieldset>
            <fieldset class="deployment-fieldset"><legend>Audience admission</legend>
                <label class="settings-checkbox"><input type="radio" checked={audienceMode() === "anonymous"} onChange={() => setAudienceMode("anonymous")} /> Anonymous visitors</label>
                <label class="settings-checkbox"><input type="radio" checked={audienceMode() === "oidc"} onChange={() => setAudienceMode("oidc")} /> Signed-in OIDC audience</label>
                <Show when={audienceMode() === "oidc"}><div class="deployment-field-grid">
                    <label class="settings-field"><span class="settings-label">OIDC issuer</span><input class="settings-input" value={oidcIssuer()} onInput={(e) => setOidcIssuer(e.currentTarget.value)} /></label>
                    <label class="settings-field"><span class="settings-label">OIDC audience</span><input class="settings-input" value={oidcAudience()} onInput={(e) => setOidcAudience(e.currentTarget.value)} /></label>
                </div></Show></fieldset>
            <div class="deployment-field-grid">
                {numeric("Total spend (cents)", () => limits().total, (total) => setLimits({ ...limits(), total }))}
                {numeric("Session spend (cents)", () => limits().session, (session) => setLimits({ ...limits(), session }))}
                {numeric("Turn spend (cents)", () => limits().turn, (turn) => setLimits({ ...limits(), turn }))}
                {numeric("Turns per visitor", () => limits().turns, (turns) => setLimits({ ...limits(), turns }))}
                {numeric("Concurrent sessions", () => limits().sessions, (sessions) => setLimits({ ...limits(), sessions }))}
                {numeric("Idle retention (hours)", idleHours, setIdleHours, ceilingHours)}
                {numeric("Absolute retention (days)", absoluteDays, setAbsoluteDays, ceilingDays)}
            </div>
            <label class="settings-checkbox"><input type="checkbox" checked={whiteLabel()} disabled={profile().panels.attribution !== "white_label_eligible"} onChange={(e) => setWhiteLabel(e.currentTarget.checked)} /> Use eligible white-label branding</label>
            <label class="settings-checkbox"><input type="checkbox" checked={endSessions()} onChange={(e) => setEndSessions(e.currentTarget.checked)} /> End sessions still using the previous version</label>
            <Show when={retentionError()}><p class="error">{retentionError()}</p></Show>
        </div></section>

        <Show when={error()}><p class="error">{error()}</p></Show>
        <Show when={legacyImportRequired() && props.api.importLegacyDeployment}><section class="admin-section">
            <h3>Confirm legacy deployment ownership</h3>
            <p class="settings-hint warn">This hosted deployment predates local project bindings. Import will bind its existing release and sessions to this Panel placement and {props.selection.projectName}; it will not update the hosted deployment.</p>
            <label class="settings-checkbox"><input type="checkbox" checked={legacyConfirmed()} onChange={(event) => setLegacyConfirmed(event.currentTarget.checked)} /> I confirm this is the source Panel agent and receiving project.</label>
            <button type="button" disabled={!legacyConfirmed() || busy()} onClick={() => void importLegacy()}>Import existing deployment</button>
        </section></Show>
        <Show when={drainResult()}><p class="settings-hint">{drainResult()}</p></Show>
        <div class="deployment-actions"><button type="button" onClick={props.onClose}>Cancel</button>
            <button type="button" class="primary" disabled={busy()} onClick={() => void publish()}>{busy() ? "Publishing…" : "Publish deployment"}</button>
            <Show when={props.onOpenInbox}><button type="button" onClick={props.onOpenInbox}>Open Inbox</button></Show></div>

        <Show when={inspection()}>{(current) => <section class="admin-section"><h3>Live deployment</h3>
            <div class="member-list"><div class="member-row"><span>Status</span><span class="member-id">{current().deployment.lifecycle}</span></div>
                <div class="member-row"><span>Release</span><span class="member-id">{current().deployment.active_release_id}</span></div>
                <div class="member-row"><span>Usage</span><span class="member-id">{current().deployment.settled_turns} turns · {current().deployment.spent_cents}¢ · {current().deployment.sessions} sessions</span></div></div>
            <div class="deployment-actions"><Show when={current().deployment.lifecycle === "active"}><button type="button" disabled={busy()} onClick={() => void control("pause")}>Pause</button></Show>
                <Show when={current().deployment.lifecycle === "paused"}><button type="button" disabled={busy()} onClick={() => void control("resume")}>Resume</button></Show>
                <button type="button" class="danger" disabled={busy() || current().deployment.lifecycle === "revoked"} onClick={() => void control("revoke")}>Revoke</button></div>
            <Show when={current().audience.length}><h4>Visitor sessions</h4><div class="member-list"><For each={current().audience}>{(session) => <div class="member-row"><span>{session.session_id}</span><button type="button" disabled={busy()} onClick={() => void eraseSession(session.session_id)}>Erase</button></div>}</For></div></Show>
            <p><a href={`${edgeOrigin()}/d/${deploymentId()}`} target="_blank" rel="noreferrer">Open public deployment</a></p>
            <pre class="embed-snippet">{`<gw-session host="${edgeOrigin()}/d/${deploymentId()}" panels="${profile().panels.components.map((panel) => panel.replace(/^gw-/, "")).join(",")}"></gw-session>`}</pre>
            <Show when={profile().collection && props.api.drainCollections}><button type="button" disabled={busy()} onClick={() => void drain()}>Drain into Inbox</button></Show>
        </section>}</Show>

        <Show when={outcome()}>{(published) => <section class="admin-section"><h3>Published</h3>
            <p><a href={published().deployment_url} target="_blank" rel="noreferrer">{published().deployment_url}</a></p>
            <pre class="embed-snippet">{published().embed_html}</pre>
            <Show when={profile().collection && props.api.drainCollections}><button type="button" disabled={busy()} onClick={() => void drain()}>Drain into Inbox</button></Show>
            <div class="deployment-preview"><Dynamic component="gw-session" ref={(element: HTMLElement) => {
                element.setAttribute("host", `${published().edge_origin}/d/${published().deployment_id}`);
                element.setAttribute("panels", profile().panels.components.map((panel) => panel.replace(/^gw-/, "")).join(","));
            }}>
                <For each={profile().panels.components}>{(panel) => <Dynamic component={panel} />}</For>
            </Dynamic></div>
        </section>}</Show>
    </section></div>;
}
