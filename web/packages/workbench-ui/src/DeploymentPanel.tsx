import { createSignal, For, Show, type JSX } from "solid-js";
import { Dynamic } from "solid-js/web";
import type {
    PanelPublicProfile,
    PlacementId,
    PublicDeploymentBindingSummary,
    PublicDeploymentInput,
    PublicDeploymentOutcome,
} from "@gaugewright/control-plane-client";

export interface DeploymentPanelApi {
    publishDeployment(input: PublicDeploymentInput): Promise<PublicDeploymentOutcome>;
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
    defaultFundingRef: string;
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
    const [fundingRef, setFundingRef] = createSignal(props.defaultFundingRef);
    const [credentialRef, setCredentialRef] = createSignal(props.defaultCredentialRef);
    const [limits, setLimits] = createSignal({ total: 1_000, session: 100, turn: 5, turns: 20, sessions: 100 });
    const [idleHours, setIdleHours] = createSignal(ceilingHours());
    const [absoluteDays, setAbsoluteDays] = createSignal(ceilingDays());
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
    const managedFunding = () => fundingRef().startsWith("managed:");
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
            funding_ref: fundingRef().trim(),
            credential_ref: managedFunding() ? "" : credentialRef().trim(),
            audience: audienceMode() === "anonymous"
                ? { anonymous_allowed: true }
                : { anonymous_allowed: false, oidc: { issuer: oidcIssuer().trim(), audience: oidcAudience().trim() } },
            white_label: whiteLabel(),
            retention_idle_ttl_seconds: idleHours() * 3_600,
            retention_absolute_ttl_seconds: absoluteDays() * 86_400,
        };
    }

    async function publish() {
        setError("");
        setLegacyImportRequired(false);
        if (retentionError()) return setError(retentionError());
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
        const published = outcome();
        if (!published || !props.api.drainCollections) return;
        setBusy(true);
        try {
            const result = await props.api.drainCollections({ binding_id: published.binding_id });
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
                <div class="member-row"><span>{deployment.deploymentId}</span><span class="member-id">{deployment.status} · {deployment.activeReleaseId ?? "no active release"}</span></div>
            }</For></div></section></Show>

        <section class="admin-section"><h3>Operational settings</h3><div class="settings-form">
            <div class="deployment-field-grid">
                <label class="settings-field"><span class="settings-label">Deployment ID</span><input class="settings-input" value={deploymentId()} onInput={(e) => setDeploymentId(e.currentTarget.value)} /></label>
                <label class="settings-field"><span class="settings-label">Edge origin</span><input class="settings-input" value={edgeOrigin()} onInput={(e) => setEdgeOrigin(e.currentTarget.value)} /></label>
            </div>
            <label class="settings-field"><span class="settings-label">Allowed website origin</span><input class="settings-input" value={allowedOrigin()} onInput={(e) => setAllowedOrigin(e.currentTarget.value)} /></label>
            <div class="deployment-field-grid">
                <label class="settings-field"><span class="settings-label">Funding reference</span><input class="settings-input" value={fundingRef()} onInput={(e) => setFundingRef(e.currentTarget.value)} /></label>
                <label class="settings-field"><span class="settings-label">Exact credential</span><input class="settings-input" disabled={managedFunding()} value={credentialRef()} onInput={(e) => setCredentialRef(e.currentTarget.value)} placeholder={managedFunding() ? "Managed by plan" : profile().provider.credential_class} /></label>
            </div>
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

        <Show when={outcome()}>{(published) => <section class="admin-section"><h3>Published</h3>
            <p><a href={published().deployment_url} target="_blank" rel="noreferrer">{published().deployment_url}</a></p>
            <pre class="embed-snippet">{published().embed_html}</pre>
            <Show when={profile().collection && props.api.drainCollections}><button type="button" disabled={busy()} onClick={() => void drain()}>Drain into Inbox</button></Show>
            <div class="deployment-preview"><Dynamic component="gw-session" host={`${published().edge_origin}/d/${published().deployment_id}`} panels={profile().panels.components.map((panel) => panel.replace(/^gw-/, "")).join(",")} /></div>
        </section>}</Show>
    </section></div>;
}
