import { createMemo, createSignal, For, Show, type JSX } from "solid-js";
import { parseProjectHostsPage, type GaugeAppCommandResult, type GaugeAppPageModel, type ProjectHost } from "@gaugewright/control-plane-client";
import { hostBytes, hostKind, hostStanding, nanoUsdInput, parseNanoUsd, retiredHost } from "./project-host-presentation";

export function ProjectHostsPage(props: {
    page: GaugeAppPageModel;
    commands: readonly string[];
    onSubmit: (command: string, payload: Readonly<Record<string, unknown>>) => Promise<GaugeAppCommandResult>;
}): JSX.Element {
    const model = createMemo(() => parseProjectHostsPage(props.page).model);
    const [selectedId, setSelectedId] = createSignal("");
    const selected = createMemo(() => model().homes.find((host) => host.id === selectedId()));
    const managed = createMemo(() => { const host = selected(); return host?.kind === "cloud" ? host : undefined; });
    const [mode, setMode] = createSignal<"add" | "rename" | "policy" | "retire" | "handoff" | null>(null);
    const [movingProjectId, setMovingProjectId] = createSignal("");
    const [name, setName] = createSignal("");
    const [enabled, setEnabled] = createSignal(false);
    const [cap, setCap] = createSignal("0");
    const [retireConfirmation, setRetireConfirmation] = createSignal("");
    const [busy, setBusy] = createSignal(false);
    const [error, setError] = createSignal("");
    const can = (operation: string) => props.commands.includes(operation);
    const choose = (host: ProjectHost) => { setSelectedId(host.id); setMode(null); setError(""); };
    const close = () => { setMode(null); setError(""); };
    const beginAdd = () => { setName("Managed Project Host"); setMode("add"); setError(""); };
    const beginRename = () => { setName(selected()?.name ?? ""); setMode("rename"); setError(""); };
    const beginPolicy = () => {
        const host = managed(); if (!host) return;
        setEnabled(host.managed_policy.isolated_workspace_enabled);
        setCap(nanoUsdInput(host.managed_policy.max_attempt_nanos_usd));
        setMode("policy"); setError("");
    };
    const beginRetire = () => { setRetireConfirmation(""); setMode("retire"); setError(""); };
    // Projects this Home could hand to the selected one. A host that reports no
    // inventory is not offering an empty one — it has not been connected, so it
    // contributes nothing here rather than appearing to hold nothing.
    const movable = createMemo(() => {
        const target = selected();
        if (!target) return [];
        return model().homes
            .filter((host) => host.home_id !== target.home_id && host.projects !== null)
            .flatMap((host) => host.projects!.map((project) => ({ ...project, from: host })));
    });
    const beginHandoff = () => { setMovingProjectId(movable()[0]?.id ?? ""); setMode("handoff"); setError(""); };
    const submit = async (command: string, payload: Readonly<Record<string, unknown>>) => {
        if (busy()) return;
        setBusy(true); setError("");
        try { await props.onSubmit(command, payload); setMode(null); }
        catch (reason) { setError(reason instanceof Error ? reason.message : String(reason)); }
        finally { setBusy(false); }
    };
    const save = (event: SubmitEvent) => {
        event.preventDefault();
        const host = selected();
        if (mode() === "add") void submit("project-host.add", { kind: "managed", name: name().trim() });
        else if (mode() === "rename" && host) void submit("project-host.rename", { id: host.id, name: name().trim() });
        else if (mode() === "policy" && host) {
            const amount = parseNanoUsd(cap());
            if (amount !== null) void submit("project-host.managed-policy.set", { id: host.id, isolated_workspace_enabled: enabled(), max_attempt_nanos_usd: amount });
        }
        else if (mode() === "handoff" && host) {
            const project = movable().find((candidate) => candidate.id === movingProjectId());
            // The Home the page believed it was moving from travels with the
            // request, so a move that happened while this form was open is
            // refused rather than silently retargeted.
            if (project) void submit("project-home.handoff", { project_id: project.id, expected_current_home_id: project.from.home_id, target_home_id: host.home_id });
        }
        else if (mode() === "retire" && host?.kind === "cloud") {
            void submit("project-host.retire", {
                id: host.id,
                phase: host.lifecycle === "retention" ? "erase" : "retention",
            });
        }
    };
    const policyValid = () => parseNanoUsd(cap()) !== null && (!enabled() || parseNanoUsd(cap())! > 0);
    return <>
        <section class="gaugeapp-panel gaugeapp-hosts">
            <header class="gaugeapp-host-section-head"><h2>{model().homes.length} Project Host{model().homes.length === 1 ? "" : "s"}</h2>
                <Show when={can("project-host.add")}><button type="button" class="primary" disabled={busy() || !model().managed_enrollment.available} onClick={beginAdd}>Add managed host</button></Show>
            </header>
            <Show when={model().homes.length} fallback={<p class="gaugeapp-empty">No Project Hosts have been added to this organization.</p>}>
                <div class="gaugeapp-host-list"><For each={model().homes}>{(host) => <div class="gaugeapp-host-row" data-host-id={host.id}>
                    <button type="button" class="gaugeapp-host-name" onClick={() => choose(host)}><strong>{host.name}</strong><span>{hostKind(host)}{host.kind === "cloud" && host.region ? ` · ${host.region}` : ""}</span></button>
                    <span class="gaugeapp-host-standing">{hostStanding(host)}</span>
                    <button type="button" onClick={() => choose(host)}>View</button>
                </div>}</For></div>
            </Show>
            <Show when={!model().managed_enrollment.available && !model().homes.some((host) => host.kind === "cloud")}><p class="gaugeapp-host-note">{model().managed_enrollment.reason}</p></Show>
        </section>

        <Show when={selected()}>{(host) => <section class="gaugeapp-panel gaugeapp-host-detail">
            <header class="gaugeapp-host-section-head"><div><span class="gaugeapp-eyebrow">{hostKind(host())}</span><h2>{host().name}</h2></div><button type="button" onClick={() => { setSelectedId(""); close(); }}>Close</button></header>
            <div class="gaugeapp-host-actions">
                <Show when={!retiredHost(host()) && can("project-host.rename")}><button type="button" disabled={busy()} onClick={beginRename}>Rename</button></Show>
                <Show when={managed() && !retiredHost(host()) && can("project-host.managed-policy.set")}><button type="button" disabled={busy()} onClick={beginPolicy}>Compute policy</button></Show>
                <Show when={managed() && host().lifecycle === "active" && can("project-host.suspend")}><button type="button" class="danger" disabled={busy()} onClick={() => void submit("project-host.suspend", { id: host().id })}>Suspend</button></Show>
                <Show when={managed() && ["suspended", "retention"].includes(host().lifecycle) && can("project-host.reinstate")}><button type="button" class="primary" disabled={busy()} onClick={() => void submit("project-host.reinstate", { id: host().id })}>Reinstate</button></Show>
                <Show when={!retiredHost(host()) && can("project-home.handoff")}><button type="button" disabled={busy() || movable().length === 0} title={movable().length === 0 ? "No other Project Host is reporting a project inventory to move from." : undefined} onClick={beginHandoff}>Move a project here</button></Show>
                <Show when={managed() && ["active", "suspended", "retention"].includes(host().lifecycle) && can("project-host.retire")}><button type="button" class="danger" disabled={busy()} onClick={beginRetire}>{host().lifecycle === "retention" ? "Erase permanently" : "Retire"}</button></Show>
            </div>
            <dl class="gaugeapp-host-facts">
                <div><dt>Service</dt><dd>{hostStanding(host())}</dd></div>
                <div><dt>Project inventory</dt><dd>{host().projects === null ? "Not connected" : `${host().projects!.length} projects`}</dd></div>
                <Show when={managed()}>{(managedHost) => <>
                    <div><dt>Location</dt><dd>{managedHost().region ?? "Not reported by service"}</dd></div>
                    <div><dt>Plan capacity</dt><dd>{hostBytes(managedHost().capacity.storage_bytes)} storage · {managedHost().capacity.concurrent_agents} concurrent agents</dd></div>
                    <Show when={managedHost().retention_until !== null}><div><dt>Retained until</dt><dd>{new Date(managedHost().retention_until! * 1000).toLocaleString()}</dd></div></Show>
                    <div><dt>Included workflows</dt><dd>{managedHost().execution.profiles.durable_workflow.available ? "Available" : "Unavailable"}</dd></div>
                    <div><dt>Isolated workspace</dt><dd>{managedHost().managed_policy.isolated_workspace_enabled ? `Enabled · USD ${nanoUsdInput(managedHost().managed_policy.max_attempt_nanos_usd)} per-attempt cap` : "Disabled"}</dd></div>
                    <div><dt>Running / queued</dt><dd>{managedHost().execution.compute.active_attempts === null || managedHost().execution.queue === null ? "Unavailable" : `${managedHost().execution.compute.active_attempts} / ${managedHost().execution.queue!.total}`}</dd></div>
                    <div><dt>Compute charged</dt><dd>{managedHost().execution.usage === null ? "Unavailable" : `USD ${nanoUsdInput(managedHost().execution.usage!.charged_nanos_usd)}`}</dd></div>
                </>}</Show>
            </dl>
            <Show when={host().projects === null}><p class="gaugeapp-host-note">Project names and access come from a connection admitted by this host. Adding a host does not grant project access.</p></Show>
            {/* ADR 0171 asks for a truthful unavailable state rather than a
                server-made recovery key, so the page says why the recovery
                export is not here instead of offering a control that could
                only fail. */}
            <p class="gaugeapp-host-note">Recovery export is unavailable: it seals the cut to a recovery holder whose private key stays in a trusted device's key store, and this organization has no such holder enrolled.</p>
            <Show when={host().projects !== null && host().projects!.length > 0}><ul class="gaugeapp-host-projects"><For each={host().projects!}>{(project) => <li>{project.name || project.id}</li>}</For></ul></Show>
            <details class="gaugeapp-host-diagnostics"><summary>Connection details</summary><dl class="gaugeapp-host-facts"><div><dt>Home identity</dt><dd><code>{host().home_id}</code></dd></div><div><dt>Endpoint</dt><dd>{host().endpoint || "This computer"}</dd></div></dl></details>
        </section>}</Show>

        <Show when={mode() === "add" || ((mode() === "rename" || mode() === "policy" || mode() === "retire" || mode() === "handoff") && selected())}>
            <form class="gaugeapp-panel gaugeapp-host-editor" onSubmit={save}>
                <h2>{mode() === "add" ? "Add managed Project Host" : mode() === "rename" ? "Rename Project Host" : mode() === "policy" ? "Compute policy" : mode() === "handoff" ? `Move a project to ${selected()?.name}` : managed()?.lifecycle === "retention" ? "Erase Project Host" : "Retire Project Host"}</h2>
                <Show when={mode() === "handoff"}>
                    <label><span>Project</span><select value={movingProjectId()} onChange={(event) => setMovingProjectId(event.currentTarget.value)}><For each={movable()}>{(project) => <option value={project.id}>{project.name || project.id} — currently on {project.from.name}</option>}</For></select></label>
                    <p class="gaugeapp-host-note">The project moves between the two Project Hosts directly. Its content does not pass through this page, and the move completes only once the receiving host holds everything.</p>
                </Show>
                <Show when={mode() !== "policy" && mode() !== "retire" && mode() !== "handoff"}><label><span>Name</span><input value={name()} maxLength={120} required onInput={(event) => setName(event.currentTarget.value)} /></label></Show>
                <Show when={mode() === "add"}><dl class="gaugeapp-host-facts"><div><dt>Service location</dt><dd>{model().managed_enrollment.region}</dd></div><div><dt>Plan capacity</dt><dd>{model().managed_enrollment.capacity ? `${hostBytes(model().managed_enrollment.capacity!.storage_bytes)} · ${model().managed_enrollment.capacity!.concurrent_agents} concurrent agents` : "Unavailable"}</dd></div></dl><p class="gaugeapp-host-note">Uses this organization's current hosting plan. Your plan is not changed.</p></Show>
                <Show when={mode() === "policy"}>
                    <label class="gaugeapp-host-toggle"><input type="checkbox" checked={enabled()} onChange={(event) => setEnabled(event.currentTarget.checked)} /><span>Allow metered Isolated workspace compute</span></label>
                    <label><span>Maximum reservation per attempt (USD)</span><input inputmode="decimal" value={cap()} onInput={(event) => setCap(event.currentTarget.value)} required /></label>
                    <p class="gaugeapp-host-note">Retries require a new reservation. Included workflows are unaffected.</p>
                    <Show when={managed()?.execution.profiles.isolated_workspace.metering.nanos_usd_per_second != null}><p class="gaugeapp-host-note">Current rate: USD {nanoUsdInput(managed()!.execution.profiles.isolated_workspace.metering.nanos_usd_per_second!)} / second.</p></Show>
                </Show>
                <Show when={mode() === "retire"}>
                    <Show when={managed()?.lifecycle === "retention"} fallback={<p class="gaugeapp-host-note">Retirement stops new work and begins the plan's retention period. You can reinstate the host while its data is retained.</p>}>
                        <p class="gaugeapp-host-note">Permanent erasure deletes this Project Host and cannot be undone. Export or recover anything you need before continuing.</p>
                    </Show>
                    <label><span>Type {managed()?.name} to confirm</span><input value={retireConfirmation()} autocomplete="off" onInput={(event) => setRetireConfirmation(event.currentTarget.value)} /></label>
                </Show>
                <div class="gaugeapp-host-actions"><button type="button" disabled={busy()} onClick={close}>Cancel</button><button type="submit" classList={{ primary: mode() !== "retire", danger: mode() === "retire" }} disabled={busy() || (mode() === "policy" ? !policyValid() : mode() === "retire" ? retireConfirmation().trim() !== managed()?.name.trim() : mode() === "handoff" ? !movingProjectId() : !name().trim())}>{busy() ? "Preparing…" : mode() === "add" ? "Add host" : mode() === "handoff" ? "Move project" : mode() === "retire" ? managed()?.lifecycle === "retention" ? "Erase permanently" : "Begin retention" : "Save"}</button></div>
            </form>
        </Show>
        <Show when={error()}><p class="gaugeapp-host-error" role="alert">{error()}</p></Show>
    </>;
}
