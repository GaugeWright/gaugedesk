import { render } from "solid-js/web";
import { createSignal, For, Show } from "solid-js";
import { ModelProvidersPage } from "../../apps/enterprise-workbench/src/ModelProvidersPage";
import { summarizeGaugeAppChange } from "../../apps/enterprise-workbench/src/gaugeapp-review";
import { MODEL_PROVIDER_REVIEW_COMMANDS, type Providers } from "../../apps/enterprise-workbench/src/model-provider-presentation";
import fixture from "../../../../crates/app/src/model_provider_management/projection/page.fixture.json";
import "../../../../web/packages/workbench-ui/src/styles.css";
import "../../apps/enterprise-workbench/src/administration-gaugeapp.css";
import type { EnterpriseControlPlane } from "@gaugewright/enterprise-client";
import { parseModelProvidersModel, type GaugeAppCommandResult, type GaugeAppPageModel, type GaugeAppProposal, type GaugeAppSession, type OrganizationProviderCandidate } from "@gaugewright/control-plane-client";

// Synthetic authority replies are confined to this component test fixture.
function Harness() {
    const parsed = parseModelProvidersModel(fixture);
    if (parsed.availability !== "available") throw Error("Expected available fixture");
    const connection = parsed.connections[0]!;
    const initial: Providers = {
        ...parsed,
        setup: { api_key_intake: true, providers: [{ provider: connection.provider, endpoint: connection.endpoint, authentication: "api_key", verification_check: "model_catalog_read", policy: connection.policy }] },
        connections: [{ ...connection, name: "Research team", versions: [...connection.versions, { id: "candidate-a", phase: "awaiting_secret", material: "unobserved", expires_at: "1999999999", verification: null }] }],
        grants: [{ ...parsed.grants[0]!, subject: { kind: "member", id: "person-a" } }, { ...parsed.grants[0]!, id: "project-grant", subject: { kind: "project", authority: "project-home", id: "Research project" }, caps: { tokens: "1000000", money: { currency: "USD", micros: "200000000" } } }],
    };
    const commands = Object.keys(MODEL_PROVIDER_REVIEW_COMMANDS);
    const [model, setModel] = createSignal(initial);
    const [allowed, setAllowed] = createSignal(commands);
    const [basis, setBasis] = createSignal("basis-a");
    const [proposal, setProposal] = createSignal<GaugeAppProposal>();
    const [calls, setCalls] = createSignal<unknown[]>([]);
    const [holdUpload, setHoldUpload] = createSignal(false);
    const [holdDirectory, setHoldDirectory] = createSignal(false);
    const [uploadStatus, setUploadStatus] = createSignal("");
    let sealed = false;
    let verified = false;
    const page = (): GaugeAppPageModel => ({ app: "administration", id: "model-providers", scope: { kind: "tenant", id: model().binding.organization }, read_model: "OrganizationModelProvidersPageV1", version: 1, freshness: "Component fixture", resource_basis: basis(), model: model() });
    const session = (): GaugeAppSession => ({ id: model().binding.organization, generation: "1", app: "administration", scope: page().scope, actor: "test-admin", capabilities: [], pages: [{ id: "people", availability: "available" }, { id: "projects", availability: "available" }] as never, commands: [], update_cursor: "0" });
    const api = {
        readGaugeAppPage: async (_session: GaugeAppSession, pageId: string) => {
            if (holdDirectory()) await new Promise(() => {});
            return pageId === "projects"
                ? { scope: page().scope, model: { projects: [{ id: "project-a", name: "Research project", authority: "project-authority", home: { id: "home-a" }, is_personal: false }, { id: "personal", name: "Personal", authority: "person-a", home: { id: "home-a" }, is_personal: true }] } }
                : { scope: page().scope, model: { members: [{ authority: "person-a", status: "active", email: "researcher@example.invalid" }] } };
        },
        submitOrganizationProviderSecret: async (candidate: OrganizationProviderCandidate, secret: string, signal: AbortSignal) => {
            setCalls((calls) => [...calls, { candidate, secretLength: secret.length }]);
            if (holdUpload()) await new Promise((_, reject) => signal.addEventListener("abort", () => { setUploadStatus("Upload aborted"); reject(Error("Aborted")); }, { once: true }));
            setUploadStatus("Upload completed");
            sealed = true;
        },
        verifyOrganizationProviderCandidate: async (candidate: OrganizationProviderCandidate) => {
            setCalls((calls) => [...calls, { verification: candidate }]);
            verified = true;
            return { ...model(), connections: model().connections.map((row) => row.id !== candidate.connection ? row : ({ ...row, versions: row.versions.map((version) => version.id !== candidate.version ? version : ({ ...version, phase: "verified", material: "held", verification: { check: "model_catalog_read", observed_at: "3" } })) })) };
        },
    } as unknown as EnterpriseControlPlane;
    const submit = async (command_id: string, payload: Readonly<Record<string, unknown>>): Promise<GaugeAppCommandResult> => {
        setCalls((calls) => [...calls, { command_id, payload }]);
        setProposal({ id: "proposal-a", app: "administration", page_id: "model-providers", command_id, payload, expected_basis: basis(), status: "proposed" } as GaugeAppProposal);
        return { receipt: { status: "proposed" } } as never;
    };
    const changeServer = () => { setBasis((value) => `${value}-next`); setModel((value) => ({ ...value, management_revision: (BigInt(value.management_revision) + 1n).toString() })); };
    const refresh = async () => {
        if (sealed) setModel((value) => ({ ...value, connections: value.connections.map((row) => ({ ...row, versions: row.versions.map((version) => version.id === "candidate-a" ? verified ? { ...version, phase: "verified", material: "held", verification: { check: "model_catalog_read", observed_at: "3" } } : { ...version, phase: "sealed", material: "held" } : version) })) }));
        changeServer();
    };
    return <>
        <nav aria-label="Test controls" style="padding:8px;display:flex;gap:6px;flex-wrap:wrap;font-size:12px">
            <button onClick={() => { setModel((value) => ({ ...value, binding: { ...value.binding, organization: "another-organization" } })); setProposal(undefined); }}>Switch organization</button>
            <button onClick={changeServer}>Change server revision</button>
            <button onClick={() => setAllowed([])}>Remove management role</button>
            <button onClick={() => setHoldUpload(true)}>Hold upload</button>
            <button onClick={() => setHoldDirectory(true)}>Hold directory</button>
            <button onClick={() => setModel((value) => ({ ...value, connections: [], grants: [], default_model: null }))}>Empty fixture</button>
            <button onClick={() => setModel((value) => ({ ...value, connections: value.connections.map((row) => ({ ...row, versions: row.versions.map((version) => version.id === "candidate-a" ? { ...version, phase: "verified", material: "held", verification: { check: "model_catalog_read", observed_at: "3" } } : version) })) }))}>Verify candidate</button>
            <button onClick={() => setModel((value) => ({ ...value, connections: value.connections.map((row) => ({ ...row, versions: row.versions.map((version) => version.id === "candidate-a" ? { ...version, phase: "verified", material: "held", verification: null } : version) })) }))}>Legacy candidate</button>
            <button onClick={() => setModel((value) => ({ ...value, connections: value.connections.map((row) => ({ ...row, status: "suspended" })), grants: value.grants.map((row) => ({ ...row, status: "suspended" })) }))}>Suspend fixture</button>
            <button onClick={() => setModel((value) => ({ ...value, connections: value.connections.map((row) => ({ ...row, versions: row.versions.filter((v) => v.id !== "candidate-a") })) }))}>Remove candidate</button>
        </nav>
        <main class="gaugeapp-content" style="height:calc(100vh - 62px)">
            <article class="gaugeapp-page"><header class="gaugeapp-page-head"><div><span class="gaugeapp-eyebrow">Administration</span><h1>Model Providers</h1></div></header><ModelProvidersPage page={page()} session={session()} commands={allowed()} api={api} onSubmit={submit} onRefresh={refresh} /></article>
            <Show when={proposal()}>{(p) => { const summary = () => summarizeGaugeAppChange(p(), page()); return <section class="gaugeapp-proposals"><h2>{summary().title}</h2><Show when={summary().unavailable} fallback={<dl class="gaugeapp-host-facts"><For each={summary().fields}>{(field) => <div><dt>{field.label}</dt><dd>{field.before ? `${field.before} → ` : ""}{field.value}</dd></div>}</For></dl>}><p>{summary().unavailable}</p></Show><p>{summary().note}</p><button onClick={() => setProposal(undefined)}>Discard test proposal</button></section>; }}</Show>
            <output aria-label="Upload status">{uploadStatus()}</output><details><summary>Test command records</summary><pre data-testid="calls">{JSON.stringify(calls())}</pre></details>
        </main>
    </>;
}
render(() => <Harness />, document.getElementById("root")!);
