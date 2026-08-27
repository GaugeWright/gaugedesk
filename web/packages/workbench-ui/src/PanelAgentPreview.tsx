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
    onClose: () => void;
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

    async function close() {
        const active = preview();
        if (active && !stopped) {
            setBusy(true);
            try {
                await props.api.stopPanelPreview(active.preview_id);
                stopped = true;
            } catch (reason) {
                setError(`Could not revoke Preview: ${String(reason)}`);
                setBusy(false);
                return;
            }
        }
        props.onClose();
    }

    onCleanup(() => {
        const active = preview();
        if (active && !stopped) void props.api.stopPanelPreview(active.preview_id);
    });

    return <div class="modal-overlay" role="presentation" onClick={(event) => {
        if (event.target === event.currentTarget) void close();
    }}><section class="modal embed-monitor" role="dialog" aria-modal="true" aria-label={`Preview ${props.agent.name}`}>
        <header class="modal-head"><div><strong>{props.agent.name} · Preview</strong>
            <div class="muted">Disposable public session · {props.project ? `${props.project.name} pinned placement` : "Library draft"}</div></div>
            <button type="button" class="icon-button" aria-label="Close" disabled={busy()} onClick={() => void close()}>×</button></header>
        <div class="settings-hint warn">Preview runs the real public-session release. Its workspace and output expire, never enter Personal or a project Inbox, and admit no production collection recipient.</div>
        <Show when={profile()} fallback={<p class="error">This Panel agent has no public profile.</p>}>
            {(contract) => <>
                <section class="admin-section"><h3>Contract under test</h3><div class="member-list">
                    <div class="member-row"><span>Panels</span><span class="member-id">{contract().panels.components.join(", ")}</span></div>
                    <div class="member-row"><span>Abilities</span><span class="member-id">{contract().public_abilities.join(", ") || "Chat only"}</span></div>
                    <div class="member-row"><span>Inputs</span><span class="member-id">{contract().audience_inputs.join(", ")}</span></div>
                    <div class="member-row"><span>Provider</span><span class="member-id">{contract().provider.provider} · {contract().provider.model}</span></div>
                    <div class="member-row"><span>Collection</span><span class="member-id">{contract().collection?.schema_ref ? `${contract().collection?.schema_ref} (test output only)` : "Off"}</span></div>
                </div></section>
                <Show when={!preview()}><section class="admin-section"><h3>Preview funding</h3>
                    <p class="settings-hint">Preview uses the frozen provider path and a small one-hour, one-session spend envelope.</p>
                    <label class="settings-checkbox"><input type="radio" checked={fundingMode() === "managed"} disabled={!managedTenants().length} onChange={() => setFundingMode("managed")} /> GaugeWright managed inference</label>
                    <Show when={fundingMode() === "managed"}><label class="settings-field"><span class="settings-label">Funding account</span><select class="settings-input" value={managedTenantId()} onChange={(event) => setManagedTenantId(event.currentTarget.value)}>
                        <For each={managedTenants()}>{(tenant) => <option value={tenant.id}>{tenant.displayName}{tenant.personal ? " (Personal)" : ""}</option>}</For>
                    </select></label></Show>
                    <label class="settings-checkbox"><input type="radio" checked={fundingMode() === "byok"} onChange={() => setFundingMode("byok")} /> Bring your own provider key</label>
                    <Show when={fundingMode() === "byok"}><label class="settings-field"><span class="settings-label">Exact credential</span><select class="settings-input" value={credentialRef()} onChange={(event) => setCredentialRef(event.currentTarget.value)}>
                        <option value="">Choose a credential…</option><For each={credentials()}>{(credential) => <option value={credential.credential_ref}>{credential.label} · {credential.provider}</option>}</For>
                    </select></label></Show>
                    <button type="button" class="primary" disabled={busy()} onClick={() => void start()}>{busy() ? "Starting Preview…" : "Start real Preview"}</button>
                </section></Show>
                <Show when={preview()}>{(active) => <section class="admin-section"><h3>Disposable session</h3>
                    <p class="settings-hint">Release {active().release_id} · expires {new Date(active().expires_at_unix_ms).toLocaleTimeString()}</p>
                    <div class="deployment-preview"><Dynamic component="gw-session" ref={(element: HTMLElement) => {
                        element.setAttribute("host", active().deployment_url);
                        element.setAttribute("panels", active().panels.map((panel) => panel.replace(/^gw-/, "")).join(","));
                    }}>
                        <For each={active().panels}>{(panel) => <Dynamic component={panel} />}</For>
                    </Dynamic></div>
                </section>}</Show>
            </>}
        </Show>
        <Show when={error()}><p class="error">{error()}</p></Show>
        <div class="deployment-actions"><button type="button" disabled={busy()} onClick={() => void close()}>{preview() ? "End Preview" : "Close"}</button></div>
    </section></div>;
}
