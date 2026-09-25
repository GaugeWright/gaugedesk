/**
 * A Panel agent's Preview (ADR 0143 §3, PANEL-3, PANEL-12): the real
 * public-session release of the Workshop draft or a placement's pinned version,
 * run disposably. It lives inside the opened Panel agent, mounted but idle
 * until the owner starts it, because starting spends real funding. Unmounting
 * revokes a running session.
 */

import { createSignal, For, onCleanup, onMount, Show, type JSX } from "solid-js";
import { Dynamic } from "solid-js/web";
import type {
    AccountTenant,
    ArchetypeNode,
    PanelPreviewInput,
    PanelPreviewOutcome,
    PlacementId,
    ProjectNode,
    PublicCredentialMetadata,
} from "@gaugewright/control-plane-client";

export interface PanelAgentPreviewApi {
    startPanelPreview(input: PanelPreviewInput): Promise<PanelPreviewOutcome>;
    stopPanelPreview(previewId: string): Promise<void>;
    deploymentManagedTenants?(): Promise<AccountTenant[]>;
    listPublicCredentials?(edge: string): Promise<PublicCredentialMetadata[]>;
}

export function PanelAgentPreview(props: {
    api: PanelAgentPreviewApi;
    agent: ArchetypeNode;
    project?: ProjectNode;
    placementId?: PlacementId;
    defaultEdgeOrigin: string;
    defaultCredentialRef: string;
}): JSX.Element {
    const profile = () => props.agent.panelProfile;
    const [fundingMode, setFundingMode] = createSignal<"managed" | "byok">("managed");
    const [managedTenants, setManagedTenants] = createSignal<AccountTenant[]>([]);
    const [managedTenantId, setManagedTenantId] = createSignal("");
    const [credentials, setCredentials] = createSignal<PublicCredentialMetadata[]>([]);
    const [credentialRef, setCredentialRef] = createSignal("");
    const [preview, setPreview] = createSignal<PanelPreviewOutcome | null>(null);
    const [busy, setBusy] = createSignal(false);
    const [error, setError] = createSignal("");
    let stopped = false;

    onMount(async () => {
        const [tenants, foundCredentials] = await Promise.allSettled([
            props.api.deploymentManagedTenants?.() ?? Promise.resolve([]),
            props.api.listPublicCredentials?.(props.defaultEdgeOrigin) ?? Promise.resolve([]),
        ]);
        if (tenants.status === "fulfilled") {
            const eligible = tenants.value.filter((tenant) =>
                tenant.role === "owner" || tenant.role === "admin");
            setManagedTenants(eligible);
            if (eligible[0]) setManagedTenantId(eligible[0].id);
            else setFundingMode("byok");
        } else {
            setFundingMode("byok");
        }
        if (foundCredentials.status === "fulfilled") {
            setCredentials(foundCredentials.value);
            const preferred = foundCredentials.value.find((credential) =>
                credential.credential_ref === props.defaultCredentialRef);
            setCredentialRef(preferred?.credential_ref
                ?? foundCredentials.value[0]?.credential_ref
                ?? "");
        }
    });

    async function start() {
        setError("");
        if (!profile()) return setError("This Panel agent has no public profile.");
        if (fundingMode() === "managed" && !managedTenantId()) {
            return setError("Choose an account that will fund Preview turns.");
        }
        if (fundingMode() === "byok" && !credentialRef()) {
            return setError("Choose an exact provider credential for Preview.");
        }
        setBusy(true);
        try {
            const outcome = await props.api.startPanelPreview({
                agent_id: props.agent.id,
                placement_id: props.placementId,
                edge_origin: props.defaultEdgeOrigin,
                allowed_origin: window.location.origin,
                funding: fundingMode() === "managed"
                    ? { kind: "managed", tenant_id: managedTenantId() }
                    : { kind: "byok", credential_ref: credentialRef() },
            });
            stopped = false;
            setPreview(outcome);
        } catch (reason) {
            setError(String(reason));
        } finally {
            setBusy(false);
        }
    }

    async function end() {
        const active = preview();
        if (!active || stopped) return;
        setBusy(true);
        try {
            await props.api.stopPanelPreview(active.preview_id);
            stopped = true;
            setPreview(null);
        } catch (reason) {
            setError(`Could not revoke Preview: ${String(reason)}`);
        } finally {
            setBusy(false);
        }
    }

    onCleanup(() => {
        const active = preview();
        if (active && !stopped) void props.api.stopPanelPreview(active.preview_id);
    });

    return <section class="admin-section panel-agent-preview" data-panel-preview aria-label={`Preview ${props.agent.name}`}>
        <h3>Preview</h3>
        <div class="muted">Disposable public session · {props.project ? `${props.project.name} pinned placement` : "Workshop draft"}</div>
        <div class="settings-hint warn">Preview runs the real public-session release. Its workspace and output expire, never enter Personal or a project Inbox, and admit no production collection recipient.</div>
        <Show when={profile()} fallback={<p class="error">This Panel agent has no public profile.</p>}>
            <Show when={!preview()}><div class="settings-form"><h4>Preview funding</h4>
                <p class="settings-hint">Preview uses the frozen provider path and a small one-hour, one-session spend envelope. Nothing runs until you start it.</p>
                <label class="settings-checkbox"><input type="radio" checked={fundingMode() === "managed"} disabled={!managedTenants().length} onChange={() => setFundingMode("managed")} /> GaugeWright managed inference</label>
                <Show when={fundingMode() === "managed"}><label class="settings-field"><span class="settings-label">Funding account</span><select class="settings-input" value={managedTenantId()} onChange={(event) => setManagedTenantId(event.currentTarget.value)}>
                    <For each={managedTenants()}>{(tenant) => <option value={tenant.id}>{tenant.displayName}{tenant.personal ? " (Personal)" : ""}</option>}</For>
                </select></label></Show>
                <label class="settings-checkbox"><input type="radio" checked={fundingMode() === "byok"} onChange={() => setFundingMode("byok")} /> Bring your own provider key</label>
                <Show when={fundingMode() === "byok"}><label class="settings-field"><span class="settings-label">Exact credential</span><select class="settings-input" value={credentialRef()} onChange={(event) => setCredentialRef(event.currentTarget.value)}>
                    <option value="">Choose a credential…</option><For each={credentials()}>{(credential) => <option value={credential.credential_ref}>{credential.label} · {credential.provider}</option>}</For>
                </select></label></Show>
                <div class="deployment-actions"><button type="button" class="primary" disabled={busy()} onClick={() => void start()}>{busy() ? "Starting Preview…" : "Start real Preview"}</button></div>
            </div></Show>
            <Show when={preview()}>{(active) => <div class="settings-form"><h4>Disposable session</h4>
                <p class="settings-hint">Release {active().release_id} · expires {new Date(active().expires_at_unix_ms).toLocaleTimeString()}</p>
                <div class="deployment-preview"><Dynamic component="gw-session" ref={(element: HTMLElement) => {
                    element.setAttribute("host", active().deployment_url);
                    element.setAttribute("panels", active().panels.map((panel) => panel.replace(/^gw-/, "")).join(","));
                }}>
                    <For each={active().panels}>{(panel) => <Dynamic component={panel} />}</For>
                </Dynamic></div>
                <div class="deployment-actions"><button type="button" disabled={busy()} onClick={() => void end()}>End Preview</button></div>
            </div>}</Show>
        </Show>
        <Show when={error()}><p class="error">{error()}</p></Show>
    </section>;
}
