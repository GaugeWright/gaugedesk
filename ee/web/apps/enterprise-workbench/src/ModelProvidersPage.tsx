import { createEffect, createMemo, createSignal, For, onCleanup, Show, type JSX } from "solid-js";
import { modelProvidersUnavailableReason, newIdempotencyKey, parseModelProvidersPage, type GaugeAppCommandResult, type GaugeAppPageModel, type GaugeAppSession } from "@gaugewright/control-plane-client";
import type { EnterpriseControlPlane } from "@gaugewright/enterprise-client";
import { createGaugeAppResource } from "@gaugewright/workbench-ui";
import { moneyInput, moneyLabel, parseMoneyCap, parseTokenCap, providerRequest, subjectLabel, terminalConnection, type ProviderCommand, type ProviderConnection, type ProviderGrant, type ProviderPolicy, type Providers } from "./model-provider-presentation";

interface Props {
    page: GaugeAppPageModel;
    session: GaugeAppSession;
    commands: readonly string[];
    api: EnterpriseControlPlane;
    onSubmit: (command: string, payload: Readonly<Record<string, unknown>>) => Promise<GaugeAppCommandResult>;
    onRefresh: () => Promise<void>;
}
export function ModelProvidersPage(props: Props): JSX.Element {
    const [retrying, setRetrying] = createSignal(false);
    const model = createMemo(() => parseModelProvidersPage(props.page).model);
    const available = createMemo(() => { const value = model(); return value.availability === "available" ? value : undefined; });
    const unavailable = () => { const value = model(); return value.availability === "unavailable" ? modelProvidersUnavailableReason(value.reason) : ""; };
    const retry = async () => { setRetrying(true); try { await props.onRefresh(); } catch { /* The unavailable state remains visible. */ } finally { setRetrying(false); } };
    return <Show when={available()} fallback={<section class="gaugeapp-panel"><p class="gaugeapp-empty">{unavailable()}</p><div class="gaugeapp-host-actions"><button type="button" disabled={retrying()} onClick={() => void retry()}>Retry</button></div></section>}>{(value) => <ProviderManager {...props} model={value()} />}</Show>;
}

function PolicyFields(props: { choices: ProviderPolicy; value: ProviderPolicy; onChange: (value: ProviderPolicy) => void }): JSX.Element {
    const toggleModel = (id: string, enabled: boolean) => props.onChange({ ...props.value, models: enabled ? [...props.value.models, id] : props.value.models.filter((v) => v !== id) });
    const toggleClass = (id: ProviderPolicy["execution_classes"][number], enabled: boolean) => props.onChange({ ...props.value, execution_classes: enabled ? [...props.value.execution_classes, id] : props.value.execution_classes.filter((v) => v !== id) });
    return <>
        <fieldset class="gaugeapp-org-provider-models"><legend>Approved models</legend><For each={props.choices.models}>{(id) => <label title={id}><input type="checkbox" checked={props.value.models.includes(id)} onChange={(event) => toggleModel(id, event.currentTarget.checked)} /><span>{id}</span></label>}</For></fieldset>
        <fieldset class="gaugeapp-org-provider-models"><legend>Execution</legend><For each={props.choices.execution_classes}>{(id) => <label><input type="checkbox" checked={props.value.execution_classes.includes(id)} onChange={(event) => toggleClass(id, event.currentTarget.checked)} /><span>{id === "private_broker" ? "Private broker" : "Public direct"}</span></label>}</For></fieldset>
    </>;
}
function ProviderManager(props: Props & { model: Providers }): JSX.Element {
    const [selectedId, setSelectedId] = createSignal("");
    const selected = createMemo(() => props.model.connections.find((row) => row.id === selectedId()));
    const [mode, setMode] = createSignal<"add" | "rename" | "models" | "grant" | "caps" | "secret" | null>(null);
    const [grantId, setGrantId] = createSignal("");
    const grant = createMemo(() => props.model.grants.find((row) => row.id === grantId()));
    const [name, setName] = createSignal("");
    const [providerIndex, setProviderIndex] = createSignal(0);
    const options = createMemo(() => props.model.setup.providers.filter((p) => p.authentication === "api_key"));
    const option = () => options()[providerIndex()];
    const [policy, setPolicy] = createSignal<ProviderPolicy>({ models: [], execution_classes: [] });
    const [grantKind, setGrantKind] = createSignal<"member" | "project">("member");
    const [member, setMember] = createSignal("");
    const [project, setProject] = createSignal("");
    const [tokens, setTokens] = createSignal("");
    const [spend, setSpend] = createSignal("");
    const [currency, setCurrency] = createSignal("USD");
    const [versionId, setVersionId] = createSignal("");
    const [busy, setBusy] = createSignal(false);
    const [error, setError] = createSignal("");
    const [notice, setNotice] = createSignal("");
    const [expandedGrants, setExpandedGrants] = createSignal<readonly string[]>([]);
    let secretInput: HTMLInputElement | undefined;
    let upload: AbortController | undefined;
    let epoch = 0;
    let draftBasis = "";
    const can = (suffix: string) => props.commands.includes(`organization-provider.${suffix}`);
    // The check is admitted by `organization-provider.verify`. Until every
    // operated authority advertises it, a session that admits key setup at all
    // still offers the check, because the alternative is a sealed candidate
    // with no way forward and no explanation. Drop the second clause once
    // gaugewright-cloud's COMMAND_IDS carries `organization-provider.verify`.
    const canVerify = () => can("verify") || can("intake.cancel");
    const clearSecret = () => { if (secretInput) secretInput.value = ""; upload?.abort(); upload = undefined; };
    const close = () => { epoch++; clearSecret(); setMode(null); setBusy(false); setError(""); };
    onCleanup(() => { epoch++; clearSecret(); });
    const identity = createMemo(() => `${props.session.id}:${props.session.generation}:${props.session.actor}:${props.model.binding.authority}:${props.model.binding.organization}:${props.model.binding.environment}`);
    createEffect(() => { identity(); close(); setSelectedId(""); setGrantId(""); setNotice(""); setExpandedGrants([]); });
    createEffect(() => { props.page.resource_basis; close(); });
    createEffect(() => { props.commands.join("|"); close(); });
    const [members] = createGaugeAppResource(() => props.session.pages.some((p) => p.id === "people" && p.availability === "available") ? { identity: identity(), session: props.session } : false,
        (request) => request.identity,
        async ({ session }) => {
            const page = await props.api.readGaugeAppPage(session, "people");
            return page.model.members
                .filter((row) => row.status === "active" && Boolean(row.authority))
                .map((row) => ({ id: row.authority, label: row.email || row.authority }));
        });
    const knownMembers = () => members.error ? [] : members() ?? [];
    const [projects] = createGaugeAppResource(() => props.session.pages.some((p) => p.id === "projects" && p.availability === "available") ? { identity: identity(), session: props.session } : false,
        (request) => request.identity,
        async ({ session }) => {
            const page = await props.api.readGaugeAppPage(session, "projects");
            return page.model.projects
                .filter((row) => !row.is_personal && Boolean(row.id) && Boolean(row.authority) && Boolean(row.home.id))
                .map((row) => ({ id: row.id, label: row.name || row.id, authority: row.authority, home: row.home.id }));
        });
    const knownProjects = () => projects.error ? [] : projects() ?? [];
    const labelSubject = (row: ProviderGrant) => {
        const subject = row.subject;
        return subject.kind === "member"
            ? knownMembers().find((member) => member.id === subject.id)?.label ?? subjectLabel(subject)
            : knownProjects().find((project) => project.id === subject.id && project.authority === subject.authority)?.label ?? subjectLabel(subject);
    };
    const begin = (value: NonNullable<ReturnType<typeof mode>>) => { close(); draftBasis = props.page.resource_basis; setNotice(""); setMode(value); };
    const choose = (row: ProviderConnection) => { close(); setSelectedId(row.id); setNotice(""); };
    const chooseProvider = (index: number) => { setProviderIndex(index); setPolicy(options()[index]?.policy ?? { models: [], execution_classes: [] }); };
    const beginAdd = () => { begin("add"); setName(""); chooseProvider(0); };
    const beginCaps = (row: ProviderGrant) => { begin("caps"); setGrantId(row.id); setTokens(row.caps.tokens ?? ""); setSpend(row.caps.money ? moneyInput(row.caps.money.micros) : ""); setCurrency(row.caps.money?.currency ?? "USD"); };
    const beginGrant = () => {
        const connection = selected(); if (!connection) return;
        begin("grant"); setGrantKind("member"); setMember(""); setProject(""); setTokens(""); setSpend(""); setCurrency("USD");
        setPolicy({ models: connection.policy.models, execution_classes: ["private_broker"] });
    };
    const choices = (): ProviderPolicy => {
        const row = selected();
        if (mode() === "add") return option()?.policy ?? { models: [], execution_classes: [] };
        if (!row) return { models: [], execution_classes: [] };
        if (mode() === "grant") return { models: row.policy.models, execution_classes: row.policy.execution_classes.filter((v) => v === "private_broker") };
        return props.model.setup.providers.find((p) => p.provider === row.provider && p.endpoint === row.endpoint && p.authentication === row.authentication)?.policy ?? row.policy;
    };
    const submit = async (command: ProviderCommand, args: Readonly<Record<string, unknown>>) => {
        if (busy()) return;
        if (mode() && draftBasis !== props.page.resource_basis) { close(); setError("This page changed. Open the editor again."); return; }
        const current = epoch; setBusy(true); setError(""); setNotice("");
        try {
            await props.onSubmit(command, providerRequest(props.model, command, args, newIdempotencyKey()));
            if (current === epoch) { setMode(null); setNotice("Change prepared below. Accept it to apply."); }
        } catch { if (current === epoch) setError("The change could not be prepared. Refresh and try again."); }
        finally { if (current === epoch) setBusy(false); }
    };
    const uploadSecret = async () => {
        const connection = selected(); if (!connection || busy() || !secretInput?.value) return;
        const controller = new AbortController(); upload = controller; const current = epoch;
        let pending: ReturnType<EnterpriseControlPlane["submitOrganizationProviderSecret"]>;
        setBusy(true); setError("");
        try {
            // The explicit DOM field is the only key draft. No signal, command,
            // proposal, local storage or transcript receives its contents.
            pending = props.api.submitOrganizationProviderSecret({ binding: props.model.binding, connection: connection.id, version: versionId() }, secretInput.value, controller.signal);
            secretInput.value = "";
            await pending;
            if (controller.signal.aborted || current !== epoch) return;
            setMode(null); await props.onRefresh();
            if (current === epoch) setNotice("Key stored. Verification is still required before activation.");
        } catch { if (current === epoch && !controller.signal.aborted) setError("The key was not confirmed. Refresh to check setup status before trying again."); }
        finally { if (current === epoch) { clearSecret(); setBusy(false); } }
    };
    const verifyCandidate = async (connection: ProviderConnection, version: ProviderConnection["versions"][number]) => {
        if (busy()) return;
        const current = epoch; setBusy(true); setError(""); setNotice("");
        try {
            const result = await props.api.verifyOrganizationProviderCandidate({ binding: props.model.binding, connection: connection.id, version: version.id });
            if (current !== epoch) return;
            const checked = result.availability === "available" ? result.connections.find((row) => row.id === connection.id)?.versions.find((candidate) => candidate.id === version.id) : undefined;
            setNotice(checked?.phase === "verified" ? "Model catalog check passed. Review and activate the key when ready." : "The provider refused model catalog access. Replace the key or update its provider permissions.");
            await props.onRefresh();
        } catch { if (current === epoch) setError("The key could not be checked. It remains inactive; refresh and try again."); }
        finally { if (current === epoch) setBusy(false); }
    };
    const save = (event: SubmitEvent) => {
        event.preventDefault(); const row = selected();
        try {
            if (mode() === "secret") { void uploadSecret(); return; }
            if (mode() === "add") { const p = option(); if (p) void submit("organization-provider.api-key.add", { name: name().trim(), provider: p.provider, endpoint: p.endpoint, policy: policy(), reconnects: null }); }
            else if (mode() === "rename" && row) void submit("organization-provider.rename", { connection: row.id, name: name().trim() });
            else if (mode() === "models" && row) void submit("organization-provider.model.approve", { connection: row.id, policy: policy() });
            else if (mode() === "caps" && grant()) void submit("organization-provider.grant.cap.set", { grant: grant()!.id, caps: { tokens: parseTokenCap(tokens()), money: parseMoneyCap(spend(), currency()) } });
            else if (mode() === "grant" && row) {
                const subject = grantKind() === "member"
                    ? knownMembers().find((candidate) => candidate.id === member())
                    : knownProjects().find((candidate) => candidate.id === project());
                if (subject) void submit("organization-provider.grant.create", { connection: row.id, subject: grantKind() === "member" ? { kind: "member", id: subject.id } : { kind: "project", authority: "authority" in subject ? subject.authority : "", id: subject.id }, policy: policy(), audiences: ["member"], caps: { tokens: parseTokenCap(tokens()), money: parseMoneyCap(spend(), currency()) } });
            }
        } catch (cause) { setError(cause instanceof Error ? cause.message : "Check the form values."); }
    };
    const candidates = () => selected()?.versions.filter((v) => ["awaiting_secret", "sealed", "verified"].includes(v.phase)) ?? [];
    const defaultModels = () => props.model.connections.filter((row) => row.status === "active" && !row.erasure_requested).flatMap((row) => row.policy.models.map((model) => ({ connection: row.id, model, label: `${row.name} · ${model}` })));
    const defaultValue = () => { const value = props.model.default_model; return value ? JSON.stringify([value.connection, value.model]) : ""; };
    const validPolicy = () => policy().models.length > 0 && policy().execution_classes.length > 0;
    const refresh = async () => {
        close(); const current = epoch; setBusy(true); setNotice("");
        try { await props.onRefresh(); }
        catch { if (current === epoch) setError("The service could not be refreshed. Try again when it reconnects."); }
        finally { if (current === epoch) setBusy(false); }
    };
    return <div class="gaugeapp-org-providers">
        <section class="gaugeapp-panel">
            <header class="gaugeapp-host-section-head"><h2>Connections</h2><div class="gaugeapp-host-actions"><button type="button" disabled={busy()} onClick={() => void refresh()}>Refresh</button><Show when={can("api-key.add")}><button type="button" class="primary" disabled={busy() || !props.model.setup.api_key_intake || !options().length} onClick={beginAdd}>Add connection</button></Show></div></header>
            <For each={props.model.connections} fallback={<p class="gaugeapp-host-note">No organization connections.</p>}>{(row) => <div class="gaugeapp-org-provider-row" data-provider-id={row.id}>
                <button type="button" class="gaugeapp-org-provider-name" onClick={() => choose(row)}><strong>{row.name}</strong><small>{row.provider}</small></button>
                <span class="gaugeapp-org-provider-status">{row.status}</span><button type="button" onClick={() => choose(row)}>View</button>
            </div>}</For>
            <Show when={!props.model.setup.api_key_intake && can("api-key.add")}><p class="gaugeapp-host-note">Key setup is unavailable until the organization's credential service is configured.</p></Show>
            <label class="gaugeapp-org-provider-default"><span>Organization default</span><select aria-label="Organization default model" value={defaultValue()} disabled={busy() || !can("default-model.set")} onChange={(event) => {
                const value = event.currentTarget.value; const choice = defaultModels().find((row) => JSON.stringify([row.connection, row.model]) === value);
                if (!value || choice) void submit("organization-provider.default-model.set", { selection: choice ? { connection: choice.connection, model: choice.model } : null });
                event.currentTarget.value = defaultValue();
            }}><option value="">No organization default</option><Show when={props.model.default_model && !props.model.default_model.available}><option value={defaultValue()}>Unavailable · {props.model.default_model?.model}</option></Show><For each={defaultModels()}>{(choice) => <option value={JSON.stringify([choice.connection, choice.model])}>{choice.label}</option>}</For></select></label>
        </section>
        <Show when={selected()}>{(row) => <section class="gaugeapp-panel gaugeapp-org-provider-detail">
            <header class="gaugeapp-host-section-head"><h2>{row().name}</h2><button type="button" onClick={() => { close(); setSelectedId(""); }}>Close</button></header>
            <div class="gaugeapp-host-actions">
                <Show when={!terminalConnection(row()) && can("rename")}><button type="button" disabled={busy()} onClick={() => { begin("rename"); setName(row().name); }}>Rename</button></Show>
                <Show when={!terminalConnection(row()) && can("model.approve")}><button type="button" disabled={busy()} onClick={() => { begin("models"); setPolicy(row().policy); }}>Models</button></Show>
                <Show when={row().status === "active" && can("suspend")}><button type="button" disabled={busy()} onClick={() => void submit("organization-provider.suspend", { connection: row().id })}>Suspend</button></Show>
                <Show when={row().status === "suspended" && can("resume")}><button type="button" disabled={busy()} onClick={() => void submit("organization-provider.resume", { connection: row().id })}>Resume</button></Show>
                <Show when={!terminalConnection(row()) && !candidates().length && row().authentication === "api_key" && can("rotate")}><button type="button" disabled={busy() || !props.model.setup.api_key_intake} onClick={() => void submit("organization-provider.rotate", { connection: row().id })}>Replace key</button></Show>
                <Show when={!terminalConnection(row()) && can("revoke")}><button type="button" class="danger" disabled={busy()} onClick={() => void submit("organization-provider.revoke", { connection: row().id })}>Revoke</button></Show>
                <Show when={!row().erasure_requested && can("erase")}><button type="button" class="danger" disabled={busy()} onClick={() => void submit("organization-provider.erase", { connection: row().id })}>Erase credentials</button></Show>
            </div>
            <p class="gaugeapp-host-note">{row().policy.models.join(" · ") || "No approved models"}</p>
            <Show when={row().overrun_pending}><p role="alert" class="gaugeapp-host-note">A usage bound was exceeded. Capped execution is unavailable until the service resolves it.</p></Show>
            <For each={candidates()}>{(version) => <div class="gaugeapp-org-provider-candidate"><div><strong>Key setup</strong><span>{version.phase === "awaiting_secret" ? "API key needed" : version.phase === "sealed" ? "Stored · verification pending" : version.verification ? "Model catalog check passed · ready to activate" : "Check details unavailable · replace this candidate"}</span><Show when={version.verification}><small>Inference access and billing have not been tested.</small></Show></div><div class="gaugeapp-host-actions">
                <Show when={version.phase === "awaiting_secret" && props.model.setup.api_key_intake && can("intake.cancel")}><button type="button" class="primary" disabled={busy()} onClick={() => { begin("secret"); setVersionId(version.id); }}>Enter key</button></Show>
                <Show when={version.phase === "sealed" && props.model.setup.providers.some((option) => option.provider === row().provider && option.endpoint === row().endpoint && option.authentication === row().authentication && option.verification_check === "model_catalog_read") && canVerify()}><button type="button" class="primary" disabled={busy()} onClick={() => void verifyCandidate(row(), version)}>Check key</button></Show>
                <Show when={version.phase === "verified" && version.verification && can("version.activate")}><button type="button" class="primary" disabled={busy()} onClick={() => void submit("organization-provider.version.activate", { connection: row().id, version: version.id })}>Activate</button></Show>
                <Show when={can("intake.cancel")}><button type="button" disabled={busy()} onClick={() => void submit("organization-provider.intake.cancel", { connection: row().id, version: version.id })}>Cancel setup</button></Show>
            </div></div>}</For>
            <details class="gaugeapp-host-diagnostics"><summary>Connection details</summary><dl class="gaugeapp-host-facts"><div><dt>Endpoint</dt><dd>{row().endpoint}</dd></div><div><dt>Connection</dt><dd>{row().id}</dd></div><div><dt>Current key version</dt><dd>{row().current_version ?? "None"}</dd></div><div><dt>Execution</dt><dd>{row().policy.execution_classes.map((v) => v === "private_broker" ? "Private broker" : "Public direct").join(" · ")}</dd></div></dl></details>
        </section>}</Show>
        <section class="gaugeapp-panel">
            <header class="gaugeapp-host-section-head"><h2>Access & monthly caps</h2><Show when={selected()?.status === "active" && selected()?.policy.execution_classes.includes("private_broker") && can("grant.create")}><button type="button" disabled={busy() || (!knownMembers().length && !knownProjects().length)} onClick={beginGrant}>Grant access</button></Show></header>
            <p class="gaugeapp-host-note">{props.model.period.year}-{String(props.model.period.month).padStart(2, "0")} UTC · All applicable caps apply together.</p>
            <For each={props.model.grants.filter((g) => !selected() || g.connection === selectedId())} fallback={<p class="gaugeapp-host-note">{selected() ? "No access grants for this connection." : "No access grants. Select a connection to grant access to a member or project."}</p>}>{(row) => <div class="gaugeapp-org-provider-grant" data-grant-id={row.id}>
                <div class="gaugeapp-org-provider-grant-title"><strong>{labelSubject(row)}</strong><span>{props.model.connections.find((c) => c.id === row.connection)?.name} · {row.status}</span></div>
                <span class="gaugeapp-org-provider-limit">{row.caps.money ? moneyLabel(row.caps.money) : "No spend cap"}<small>{row.caps.tokens === null ? "No token cap" : `${row.caps.tokens} tokens`}</small></span>
                <Show when={row.status !== "revoked" && can("grant.cap.set")}><button type="button" disabled={busy()} onClick={() => beginCaps(row)}>Edit caps</button></Show>
                <details class="gaugeapp-org-provider-usage" open={expandedGrants().includes(row.id)} onToggle={(event) => { const open = event.currentTarget.open; setExpandedGrants((ids) => open ? ids.includes(row.id) ? ids : [...ids, row.id] : ids.filter((id) => id !== row.id)); }}><summary>Usage & access</summary>
                    <dl class="gaugeapp-host-facts"><For each={[["Measured", row.usage.measured], ["Reserved", row.usage.reserved], ["Accounted at bound", row.usage.accounted_at_bound]] as const}>{([label, total]) => <div><dt>{label}</dt><dd>{total.tokens} tokens{total.money.map((m) => ` · ${moneyLabel(m)}`).join("")}{total.unknown_money ? " · Cost unknown" : ""}</dd></div>}</For><div><dt>Unknown outcomes</dt><dd>{row.usage.unknown_outcomes}</dd></div><div><dt>Models</dt><dd>{row.policy.models.join(" · ")}</dd></div><div><dt>Audiences</dt><dd>{row.audiences.join(" · ")}</dd></div></dl>
                    <div class="gaugeapp-host-actions"><Show when={row.status === "active" && can("grant.suspend")}><button type="button" disabled={busy()} onClick={() => void submit("organization-provider.grant.suspend", { grant: row.id })}>Suspend</button></Show><Show when={row.status === "suspended" && can("grant.resume")}><button type="button" disabled={busy()} onClick={() => void submit("organization-provider.grant.resume", { grant: row.id })}>Resume</button></Show><Show when={row.status !== "revoked" && can("grant.revoke")}><button type="button" class="danger" disabled={busy()} onClick={() => void submit("organization-provider.grant.revoke", { grant: row.id })}>Revoke</button></Show></div>
                </details>
            </div>}</For>
            <Show when={members.error}><p class="gaugeapp-host-note">Member directory unavailable. Existing grants remain visible.</p></Show>
            <Show when={projects.error}><p class="gaugeapp-host-note">Project directory unavailable. Existing grants remain visible.</p></Show>
        </section>
        <Show when={mode()}><form class="gaugeapp-panel gaugeapp-org-provider-editor" onSubmit={save} ref={(element) => queueMicrotask(() => { if (element.isConnected) element.scrollIntoView({ block: "nearest" }); })}>
            <h2>{({ add: "Add connection", rename: "Rename connection", models: "Approved models", grant: "Grant access", caps: "Monthly usage caps", secret: "Enter API key" } as const)[mode()!]}</h2>
            <Show when={mode() === "caps" && grant()}><p class="gaugeapp-host-note">{labelSubject(grant()!)}</p></Show>
            <Show when={mode() === "add" || mode() === "rename"}><label><span>Name</span><input value={name()} maxLength={120} required onInput={(event) => setName(event.currentTarget.value)} /></label></Show>
            <Show when={mode() === "add"}><label><span>Provider</span><select aria-label="Provider" value={providerIndex()} onChange={(event) => chooseProvider(Number(event.currentTarget.value))}><For each={options()}>{(p, index) => <option value={index()}>{p.provider} · {new URL(p.endpoint).host}</option>}</For></select></label></Show>
            <Show when={mode() === "grant"}>
                <label><span>Grant to</span><select aria-label="Grant to" value={grantKind()} onChange={(event) => { setGrantKind(event.currentTarget.value as "member" | "project"); setMember(""); setProject(""); }}><option value="member">Member</option><option value="project">Project</option></select></label>
                <Show when={grantKind() === "member"} fallback={<label><span>Project</span><select aria-label="Project" required value={project()} onChange={(event) => setProject(event.currentTarget.value)}><option value="">Choose project</option><For each={knownProjects()}>{(row) => <option value={row.id}>{row.label}</option>}</For></select></label>}><label><span>Member</span><select aria-label="Member" required value={member()} onChange={(event) => setMember(event.currentTarget.value)}><option value="">Choose member</option><For each={knownMembers()}>{(row) => <option value={row.id}>{row.label}</option>}</For></select></label></Show>
            </Show>
            <Show when={mode() === "add" || mode() === "models" || mode() === "grant"}><PolicyFields choices={choices()} value={policy()} onChange={setPolicy} /></Show>
            <Show when={mode() === "caps" || mode() === "grant"}>
                <label><span>Token cap / month</span><input inputmode="numeric" value={tokens()} placeholder="No token cap" onInput={(event) => setTokens(event.currentTarget.value)} /></label>
                <label><span>Spend cap / month</span><input inputmode="decimal" value={spend()} placeholder="No spend cap" onInput={(event) => setSpend(event.currentTarget.value)} /></label>
                <label><span>Currency</span><input value={currency()} maxLength={3} onInput={(event) => setCurrency(event.currentTarget.value.toUpperCase())} /></label>
                <p class="gaugeapp-host-note">Leave a cap blank for no limit on that dimension. Zero permits no allowance. Changes keep this month's usage and reservations.</p>
            </Show>
            <Show when={mode() === "secret"}><label><span>API key</span><input ref={secretInput} type="password" required autocomplete="off" spellcheck={false} name="organization-provider-key" /></label><p class="gaugeapp-host-note">Sent directly to your organization's credential service. Never added to chat or change history.</p></Show>
            <div class="gaugeapp-host-actions"><button type="button" onClick={close}>{busy() && mode() === "secret" ? "Close" : "Cancel"}</button><button type="submit" class="primary" disabled={busy() || ((mode() === "add" || mode() === "rename") && !name().trim()) || ((mode() === "add" || mode() === "models" || mode() === "grant") && !validPolicy()) || (mode() === "grant" && (grantKind() === "member" ? !member() : !project()))}>{busy() ? "Working…" : mode() === "secret" ? "Store key" : "Save"}</button></div>
        </form></Show>
        <Show when={notice()}><p class="gaugeapp-host-note" role="status">{notice()}</p></Show><Show when={error()}><p class="gaugeapp-host-error" role="alert">{error()}</p></Show>
    </div>;
}
