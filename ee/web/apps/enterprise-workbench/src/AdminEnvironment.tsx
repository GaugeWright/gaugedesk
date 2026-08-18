/**
 * The Admin Environment is the desktop workbench over a different Session.
 * Admin records are virtual Workspace files. `.environment/manifest.json`
 * binds their plain JSON paths to constrained Views in the shared viewer.
 */
import {
    createEffect,
    createMemo,
    createResource,
    createSignal,
    For,
    Show,
    type JSX,
} from "solid-js";
import {
    engagementId,
    newIdempotencyKey,
    type ManagementEnvironmentChange,
    type EngagementId,
    type HumanTask,
} from "@gaugewright/control-plane-client";
import type {
    AdminHomeProjection,
    ArchetypeApprovalPolicy,
    Billing,
    Member,
    MemberGrant,
    OrgSettings,
    PlacementPolicy,
    SecurityPolicy,
    Session as ClientSession,
    SoftwarePolicy,
    SsoConnection,
} from "@gaugewright/enterprise-client";
import { EnterpriseControlPlane } from "@gaugewright/enterprise-client";
import {
    ChatPaneHeader,
    ChatPanel,
    ContentViewer,
    createWorkbenchShellState,
    emptyTranscript,
    localTurnActivity,
    SessionProvider,
    TaskBar,
    WorkbenchShell,
    Workspace,
    type EnvironmentComplexView,
    type EnvironmentViewRegistry,
    type Session as WorkbenchSession,
    type Transcript,
} from "@gaugewright/workbench-ui";
import { SsoWizard } from "./SsoWizard";
import {
    ADMIN_HELP_INDEX,
    ADMIN_MANIFEST,
    ADMIN_STATIC_FILES,
    ADMIN_VIEW_SOURCES,
    adminFileIsEditable,
    type AdminConfigPath,
    type AdminWorkspacePath,
} from "./admin-agent-files";
import "./admin-environment.css";

type AdminConfigDocument = { readonly path: AdminConfigPath; readonly value: unknown };
type AdminDocument =
    | AdminConfigDocument
    | { readonly path: Exclude<AdminWorkspacePath, AdminConfigPath>; readonly raw: string };
type AttentionItem = { readonly id: string; readonly path: AdminConfigPath; readonly title: string };
type ResourcePolicy = { readonly rules: readonly unknown[] };
type AutomationProjection = {
    readonly automations?: readonly {
        readonly id: string;
        readonly project_id: string;
        readonly placement_id: string;
        readonly title: string;
        readonly source_handle: string;
        readonly source_version: number;
        readonly trigger_ref: string;
        readonly task_ref: string;
        readonly status: "enabled" | "disabled" | "deleted";
    }[];
    readonly runs?: readonly {
        readonly id: string;
        readonly automation_id: string;
        readonly runtime_command_id: string;
        readonly phase: string;
        readonly evidence_ref?: string | null;
        readonly error_code?: string | null;
    }[];
};
type DeploymentProjection = {
    readonly deployments?: readonly {
        readonly binding: {
            readonly deployment_id: string;
            readonly tenant_id: string;
            readonly placement_id: string;
        };
        readonly name: string;
        readonly endpoint: string;
        readonly created_at: number;
        readonly package_version: number;
        readonly package_ref: string;
        readonly status: "active" | "paused" | "revoked";
        readonly initial_config: {
            readonly auth_mode: "anonymous" | "provider";
            readonly allowed_origins: readonly string[];
            readonly max_spend_cents: number;
            readonly per_visitor_quota: number;
            readonly panels: readonly string[];
            readonly white_label: boolean;
        };
    }[];
};

const ADMIN_ENGAGEMENT = engagementId("admin:organization");
const ROLES = ["owner", "admin", "member", "viewer", "billing"];
const isRecord = (value: unknown): value is Record<string, unknown> =>
    typeof value === "object" && value !== null && !Array.isArray(value);
const ADMIN_SCHEMAS: EnvironmentViewRegistry["schemas"] = {
    "gw://schemas/administration/overview/v1": isRecord,
    "gw://schemas/administration/organization/v1": (value) => value === null || isRecord(value),
    "gw://schemas/administration/access/v1": isRecord,
    "gw://schemas/administration/identity/v1": isRecord,
    "gw://schemas/administration/policy/v1": isRecord,
    "gw://schemas/administration/software-policy/v1": isRecord,
    "gw://schemas/administration/clients/v1": isRecord,
    "gw://schemas/administration/machines/v1": isRecord,
    "gw://schemas/administration/backups/v1": isRecord,
    "gw://schemas/administration/deployments/v1": isRecord,
    "gw://schemas/administration/automations/v1": isRecord,
    "gw://schemas/administration/audit/v1": isRecord,
    "gw://schemas/administration/billing/v1": isRecord,
};

interface AdminMutations {
    command(path: AdminConfigPath, commandId: string, payload: unknown): Promise<unknown>;
    setOrg(value: OrgSettings): Promise<unknown>;
    domainChallenge(domain: string): Promise<{ readonly record_name: string; readonly record_type: "TXT"; readonly value: string }>;
    verifyDomain(domain: string): Promise<unknown>;
    invite(value: { authority: string; email?: string; role: string }): Promise<unknown>;
    setRole(id: string, role: string): Promise<unknown>;
    deactivate(id: string): Promise<unknown>;
    grant(authority: string, projectId: string): Promise<unknown>;
    revokeGrant(authority: string, projectId: string): Promise<unknown>;
    setSso(value: SsoConnection): Promise<unknown>;
    rotateScim(): Promise<unknown>;
    setSecurity(value: SecurityPolicy): Promise<unknown>;
    setPlacement(value: PlacementPolicy): Promise<unknown>;
    setApproval(value: ArchetypeApprovalPolicy): Promise<unknown>;
    setSoftware(value: SoftwarePolicy): Promise<unknown>;
    setBilling(value: Billing): Promise<unknown>;
}

export function AdminEnvironment(props: { api: EnterpriseControlPlane; onReturnToWork: () => void }): JSX.Element {
    const [refreshKey, setRefreshKey] = createSignal(0);
    const refresh = () => setRefreshKey((value) => value + 1);
    const [fileRevision, setFileRevision] = createSignal(0);
    const [status, setStatus] = createSignal("");
    const [wizardOpen, setWizardOpen] = createSignal(false);
    const [oneTimeSecret, setOneTimeSecret] = createSignal("");
    const [selectedFile, setSelectedFile] = createSignal<AdminWorkspacePath | null>("overview.json");
    // Audit documents refresh after mutations. Keep the user's filters at the
    // Environment level so a refreshed constrained View cannot silently reset
    // them while the person is typing or exporting.
    const [auditActor, setAuditActor] = createSignal("");
    const [auditAction, setAuditAction] = createSignal("");

    const [environmentSession, { refetch: refetchEnvironment }] = createResource(
        refreshKey,
        () => props.api.openAdministration(),
    );
    const [environmentChanges, { refetch: refetchChanges }] = createResource(
        environmentSession,
        (session) => props.api.administrationChanges(session),
    );
    const [agentHistory] = createResource(
        environmentSession,
        (session) => props.api.administrationAgentMessages(session),
    );
    const pendingChanges = () => (environmentChanges() ?? []).filter((change) => change.status === "proposed");
    const [environmentDocuments, { refetch: refetchDocuments }] = createResource(
        environmentSession,
        async (session) => new Map(await Promise.all(session.documents.map(async (grant) => {
            const document = await props.api.readAdministrationDocument(session, grant.id);
            return [grant.path, document.content] as const;
        }))),
    );
    const content = <T,>(path: AdminConfigPath): T | undefined => environmentDocuments()?.get(path) as T | undefined;
    const org = () => content<OrgSettings | null>("organization.json");
    const homes = () => content<{ homes: AdminHomeProjection[] }>("machines.json")?.homes;
    const sso = () => content<{ sso: SsoConnection | null }>("identity.json")?.sso;
    const policy = () => content<{ resource: ResourcePolicy; security: SecurityPolicy | null; placement: PlacementPolicy; archetype_approval: ArchetypeApprovalPolicy }>("policy.json");
    const resourcePolicy = () => policy()?.resource;
    const security = () => policy()?.security;
    const placement = () => policy()?.placement;
    const approval = () => policy()?.archetype_approval;
    const software = () => content<SoftwarePolicy>("software-policy.json");
    const fullAdmin = () => environmentSession()?.documents.some((document) => document.id === "administration.organization") === true;
    const billingAdmin = () => environmentSession()?.documents.some((document) => document.id === "administration.billing") === true;
    const softwareAdmin = () => environmentSession()?.documents.some((document) => document.id === "administration.software-policy") === true;
    const commandsFor = (path: AdminConfigPath): readonly string[] =>
        environmentSession()?.documents.find((document) => document.path === path)?.commands ?? [];

    const configDocuments = createMemo<AdminConfigDocument[]>(() =>
        (environmentSession()?.documents ?? []).flatMap((grant) => {
            const value = environmentDocuments()?.get(grant.path);
            return value === undefined ? [] : [{ path: grant.path as AdminConfigPath, value }];
        }),
    );

    const documents = createMemo<AdminDocument[]>(() => [
        ...configDocuments(),
        ...ADMIN_STATIC_FILES.map((file) => ({ path: file.path, raw: file.content })),
    ]);

    // The virtual Workspace is a projection over independently loading admin
    // resources. Give Workspace/ContentViewer their own revision whenever that
    // projection changes; do not couple it to the API refetch trigger.
    createEffect(() => {
        documents();
        setFileRevision((value) => value + 1);
    });

    createEffect(() => {
        const files = configDocuments();
        if (!files.length) return;
        const selected = selectedFile();
        if (!selected || (!selected.startsWith(".environment/") && !files.some((file) => file.path === selected))) {
            setSelectedFile(files[0]!.path);
        }
    });

    const shell = createWorkbenchShellState({
        storagePrefix: "ui.admin",
        selection: () => ({ chatSelected: true, fileSelected: selectedFile() !== null }),
    });

    const selectFile = (path: string | null) => {
        setSelectedFile(path as AdminWorkspacePath | null);
        if (path) shell.openPane("content", { chatSelected: true, fileSelected: true });
    };

    const act = async (verb: string, command: () => Promise<unknown>) => {
        setStatus(`${verb}…`);
        try {
            const result = await command() as { readonly status?: string } | undefined;
            setStatus(result?.status === "proposed" ? `${verb} proposed — review it below` : `${verb} ✓`);
            refresh();
        } catch (error) {
            setStatus(`Could not ${verb.toLowerCase()}: ${messageOf(error)}`);
        }
    };

    const proposeCommand = async (path: AdminConfigPath, commandId: string, payload: unknown, client: "browser" | "agent" = "browser") => {
        const session = environmentSession();
        if (!session) throw new Error("Administration session is not admitted");
        const document = session.documents.find((candidate) => candidate.path === path);
        if (!document) throw new Error(`${path} is not admitted in this Administration session`);
        const receipt = await props.api.submitAdministrationCommand({
            session_id: session.id,
            environment: session.environment,
            scope: session.scope,
            document_id: document.id,
            command_id: commandId,
            base_revision: document.revision,
            payload,
            client,
        }, newIdempotencyKey());
        await refetchChanges();
        setStatus(receipt.status === "proposed" ? "Change proposed — review it below" : `Change ${receipt.status}`);
        return receipt;
    };

    const policyPayload = (overrides: Partial<{ resource: ResourcePolicy; security: SecurityPolicy; placement: PlacementPolicy; archetype_approval: ArchetypeApprovalPolicy }> = {}) => ({
        resource: overrides.resource ?? resourcePolicy() ?? { rules: [] },
        security: overrides.security ?? security() ?? { require_mfa: false, session_lifetime_secs: 0, idle_timeout_secs: 0, residency_region: null, audit_retention_min_days: 365, allow_auto_upgrade: false },
        placement: overrides.placement ?? placement() ?? { require_attested: false, allowed_operators: [] },
        archetype_approval: overrides.archetype_approval ?? approval() ?? { require_approval: false },
    });

    const mutations: AdminMutations = {
        command: (path, commandId, payload) => proposeCommand(path, commandId, payload),
        setOrg: (value) => proposeCommand("organization.json", "organization.update", value),
        domainChallenge: (domain) => {
            const session = environmentSession();
            if (!session) throw new Error("Administration session is not admitted");
            return props.api.administrationDomainChallenge(session, domain);
        },
        verifyDomain: (domain) => proposeCommand("organization.json", "domain.verify", { domain }),
        invite: (value) => proposeCommand("access.json", "member.invite", value),
        setRole: (id, role) => proposeCommand("access.json", "member.role.set", { id, role }),
        deactivate: (id) => proposeCommand("access.json", "member.deactivate", { id }),
        grant: (authority, project_id) => proposeCommand("access.json", "grant.add", { authority, project_id }),
        revokeGrant: (authority, project_id) => proposeCommand("access.json", "grant.revoke", { authority, project_id }),
        setSso: (value) => proposeCommand("identity.json", "sso.configure", value),
        rotateScim: () => proposeCommand("identity.json", "scim-token.rotate", {}),
        setSecurity: (value) => proposeCommand("policy.json", "policy.update", policyPayload({ security: value })),
        setPlacement: (value) => proposeCommand("policy.json", "policy.update", policyPayload({ placement: value })),
        setApproval: (value) => proposeCommand("policy.json", "policy.update", policyPayload({ archetype_approval: value })),
        setSoftware: (value) => proposeCommand("software-policy.json", "software-policy.update", value),
        // `billing.update` replaces the whole `billing.json` document, and that
        // document nests the writable record under `billing` beside its derived
        // `seats_used`/`managed_usage`. The form composes the same payload a
        // literal Edit of the document would send; the derived keys are the
        // command's to ignore, not this control's to invent.
        setBilling: (value) => proposeCommand("billing.json", "billing.update", { billing: value }),
    };

    const reviewChange = async (change: ManagementEnvironmentChange, decision: "accept" | "reject") => {
        const session = environmentSession();
        if (!session) throw new Error("Administration session is not admitted");
        setStatus(`${decision === "accept" ? "Applying" : "Rejecting"} change…`);
        try {
            const result = await props.api.reviewAdministrationChange(session, change.id, decision, newIdempotencyKey());
            const token = (result.result as { readonly token?: unknown } | null)?.token;
            if (typeof token === "string") setOneTimeSecret(token);
            const url = (result.result as { readonly url?: unknown } | null)?.url;
            if (typeof url === "string") {
                window.location.assign(url);
                return;
            }
            setStatus(result.receipt.status === "applied" ? "Change applied ✓" : "Change rejected");
            refresh();
            await Promise.all([refetchEnvironment(), refetchDocuments(), refetchChanges()]);
        } catch (error) {
            setStatus(`Could not review change: ${messageOf(error)}`);
            await refetchChanges();
        }
    };

    const applyRawDocument = async (path: string, raw: string) => {
        const value = JSON.parse(raw) as Record<string, unknown>;
        const session = environmentSession();
        if (!session) throw new Error("Administration session is not admitted");
        const document = session.documents.find((candidate) => candidate.path === path);
        if (!document) throw new Error("This projection is read-only or not admitted");
        await props.api.proposeAdministrationDocumentChange({ session, documentId: document.id, baseRevision: document.revision, content: value, client: "edit" }, newIdempotencyKey());
        await refetchChanges();
        setStatus("Document change proposed — review it below");
    };

    const [transcript, setTranscript] = createSignal<Transcript>({
        ...emptyTranscript,
        lines: [{
            seq: 0,
            tier: "admitted",
            kind: "assistant",
            text: "I can explain the admitted Administration documents and prepare reviewable typed proposals. I cannot approve my own changes or infer missing control or compliance evidence.",
        }],
    });
    createEffect(() => {
        const history = agentHistory();
        if (!history?.length) return;
        setTranscript({
            openText: null,
            lines: history.map((message) => ({
                seq: message.sequence,
                tier: "admitted" as const,
                kind: message.role,
                text: message.text,
            })),
        });
    });
    const appendLine = (kind: "user" | "assistant", text: string) =>
        setTranscript((current) => ({
            openText: null,
            lines: [...current.lines, { seq: current.lines.length, tier: "admitted", kind, text }],
        }));
    const [agentBusy, setAgentBusy] = createSignal(false);
    const answer = async (text: string) => {
        setAgentBusy(true);
        appendLine("user", text);
        try {
            const session = environmentSession();
            if (!session) throw new Error("Administration session is not admitted");
            const turn = await props.api.sendAdministrationAgentMessage(session, text);
            for (const proposal of turn.proposals) {
                await props.api.submitAdministrationCommand({
                    session_id: session.id,
                    environment: session.environment,
                    scope: session.scope,
                    document_id: proposal.document_id,
                    command_id: proposal.command_id,
                    base_revision: proposal.base_revision,
                    payload: proposal.payload,
                    client: "agent",
                }, newIdempotencyKey());
                const document = session.documents.find((candidate) => candidate.id === proposal.document_id);
                if (document) selectFile(document.path);
            }
            await refetchChanges();
            appendLine("assistant", turn.message);
            if (turn.proposals.length > 0) {
                setStatus(`${turn.proposals.length} agent proposal${turn.proposals.length === 1 ? "" : "s"} ready for human review`);
            }
        } catch (error) {
            appendLine("assistant", `I could not complete that governed agent turn: ${messageOf(error)}`);
            throw error;
        } finally {
            setAgentBusy(false);
        }
    };

    const adminSession: WorkbenchSession = {
        api: {
            getTree: async () => documents().map((document) => ({ path: document.path, isDir: false })),
            getFile: async (_id, path) => {
                const document = documents().find((candidate) => candidate.path === path);
                // The selected path exists before the independent admin reads have
                // all settled. Serve an empty projection for that brief window;
                // fileRevision refetches the same path as each admitted record lands.
                if (!document) return "{}\n";
                if ("raw" in document) return document.raw;
                return `${JSON.stringify(document.value, null, 2)}\n`;
            },
            putFile: async (_id, path, content) => applyRawDocument(path, content),
        },
        engagementId: () => ADMIN_ENGAGEMENT,
        worktreeRev: fileRevision,
        selectedFile,
        selectFile,
        diff: () => "",
        mergePhase: () => null,
        mergeConflicted: () => false,
        chatKind: () => "work",
        methodName: () => "Administration",
        transcript,
        busy: agentBusy,
        turnActivity: localTurnActivity(agentBusy, transcript),
        composerCapabilities: () => ({
            queue: true,
            steer: false,
            stop: false,
            // `stage` became `hold` when holding stopped being a server verb and
            // became the client act of not submitting (ADR 0137 §2). Same offer to
            // the reader: a queued instruction can be kept out of the running order.
            hold: true,
            // Administration chats have one line. There is no fork tree here to
            // branch into, so the composer must not offer to mint one.
            fork: false,
            attachments: [],
        }),
        // Same-origin HTTP to the Administration Environment: no separately
        // observable transport state, so a command is always issuable and its
        // failure is reported as the turn's.
        canCommand: () => true,
        merge: () => undefined,
        onContentSaved: refresh,
        send: answer,
        canEditFile: adminFileIsEditable,
        readOnlyFileReason: () => "This Administration file is read-only. Use its rendered controls or ask the agent to prepare a declared typed proposal.",
    };

    let composerInput: HTMLTextAreaElement | undefined;
    const attention = createMemo<AttentionItem[]>(() => {
        if (!fullAdmin()) return [];
        const items: AttentionItem[] = [];
        if (!org()) items.push({ id: "setup:organization", path: "organization.json", title: "Organization profile has not been admitted" });
        else if (!org()!.verified_domains.length) items.push({ id: "setup:domain", path: "identity.json", title: "No organization domain is verified" });
        if (!sso()) items.push({ id: "setup:sso", path: "identity.json", title: "No SSO connection is configured" });
        if (!security()) items.push({ id: "setup:security", path: "policy.json", title: "Security policy is using system defaults" });
        if (softwareAdmin() && !software()?.minimum_version && !software()?.minimum_protocol && !software()?.allowed_channels.length) {
            items.push({ id: "setup:software", path: "software-policy.json", title: "Client software admission is not configured" });
        }
        for (const change of pendingChanges()) {
            const path = environmentSession()?.documents.find((document) => document.id === change.document_id)?.path as AdminConfigPath | undefined;
            if (path) items.push({ id: `change:${change.id}`, path, title: `Review ${change.command_id}` });
        }
        return items;
    });

    const viewFrame = (kind: string, body: JSX.Element): JSX.Element => (
        <div class="filebody markdown-body" data-admin-dashboard={kind} data-environment-file-view={`${kind}.json`}>
            <Show when={status()}><p class="status">{status()}</p></Show>
            <For each={pendingChanges().filter((change) => change.document_id === `administration.${kind}`)}>{(change) => (
                <section class="environment-change-review" data-environment-change={change.id}>
                    <strong>Review proposed {change.command_id}</strong>
                    <p>This change has not been applied. Its base is <code>{change.base_revision}</code>.</p>
                    <button type="button" onClick={() => void reviewChange(change, "accept")}>apply change</button>
                    <button type="button" onClick={() => void reviewChange(change, "reject")}>reject</button>
                </section>
            )}</For>
            <Show when={kind === "identity" && oneTimeSecret()}>
                <section class="environment-one-time-secret">
                    <strong>SCIM token — copy it now</strong>
                    <code>{oneTimeSecret()}</code>
                    <p>It will not be shown again or written into an Environment document.</p>
                </section>
            </Show>
            {body}
        </div>
    );
    const components: Readonly<Record<string, EnvironmentComplexView>> = {
        AdminOverview: ({ document }) => viewFrame("overview", <OverviewFile value={document as any} onSelect={selectFile} />),
        AdminOrganization: ({ document }) => viewFrame("organization", <OrganizationFile value={document as OrgSettings | null} mutations={mutations} onAct={act} />),
        AdminAccess: ({ document }) => viewFrame("access", <AccessFile value={document as { members: Member[]; sessions: any[]; grants: MemberGrant[] }} mutations={mutations} onAct={act} />),
        AdminIdentity: ({ document }) => viewFrame("identity", <IdentityFile value={document as { sso: SsoConnection | null }} mutations={mutations} onOpenSso={() => setWizardOpen(true)} onStatus={setStatus} />),
        AdminPolicy: ({ document }) => viewFrame("policy", <PolicyFile value={document as { resource: ResourcePolicy; security: SecurityPolicy | null; placement: PlacementPolicy; archetype_approval: ArchetypeApprovalPolicy }} mutations={mutations} onAct={act} />),
        AdminSoftwarePolicy: ({ document }) => viewFrame("software-policy", <SoftwarePolicyFile value={document as SoftwarePolicy} mutations={mutations} onAct={act} />),
        AdminClients: ({ document }) => viewFrame("clients", <ClientsFile value={document as { sessions: ClientSession[] }} />),
        AdminMachines: ({ document }) => viewFrame("machines", <MachinesFile value={document as { homes: AdminHomeProjection[] }} commands={commandsFor("machines.json")} mutations={mutations} onAct={act} />),
        AdminBackups: ({ document }) => viewFrame("backups", <BackupsFile value={document as BackupProjection} commands={commandsFor("backups.json")} mutations={mutations} onAct={act} />),
        AdminDeployments: ({ document }) => viewFrame("deployments", <DeploymentsFile value={document as DeploymentProjection} commands={commandsFor("deployments.json")} mutations={mutations} onAct={act} />),
        AdminAutomations: ({ document }) => viewFrame("automations", <AutomationsFile value={document as AutomationProjection} commands={commandsFor("automations.json")} mutations={mutations} onAct={act} />),
        AdminAudit: ({ document }) => viewFrame("audit", <AuditFile
            value={document as { integrity: any; entries: any[] }}
            actorFilter={auditActor()}
            actionFilter={auditAction()}
            onActorFilter={setAuditActor}
            onActionFilter={setAuditAction}
            onExport={async (format, filters) => {
                setStatus(`Exporting audit as ${format.toUpperCase()}…`);
                try {
                    const exported = await props.api.exportAdministrationAudit(format, filters);
                    const url = URL.createObjectURL(new Blob([exported.body], { type: exported.contentType }));
                    const link = window.document.createElement("a");
                    link.href = url;
                    link.download = exported.filename;
                    link.click();
                    window.setTimeout(() => URL.revokeObjectURL(url), 0);
                    setStatus(`Audit exported as ${format.toUpperCase()}`);
                } catch (error) {
                    setStatus(messageOf(error));
                    throw error;
                }
            }}
        />),
        AdminBilling: ({ document }) => viewFrame("billing", <BillingFile value={document as any} commands={commandsFor("billing.json")} mutations={mutations} onAct={act} />),
    };
    const environmentView: EnvironmentViewRegistry = {
        manifest: ADMIN_MANIFEST,
        views: ADMIN_VIEW_SOURCES,
        schemas: ADMIN_SCHEMAS,
        components,
    };

    return (
        <>
            <WorkbenchShell
                state={shell}
                titles={{ nav: "Administration" }}
                taskBar={() => (
                    <TaskBar
                        api={{
                            getTasks: async (): Promise<HumanTask[]> => attention().map((item) => ({
                                id: `admin:${item.id}`,
                                title: item.title,
                                agent: "Admin",
                                kind: "answer",
                            })),
                            // Administration attention items are virtual Environment
                            // tasks, not tracker work items. They deliberately expose
                            // no assignment roster or assignment command.
                            getRoster: async () => [],
                            assignWorkItem: async () => null,
                        }}
                        selected={selectedFile() ? (`admin:${selectedFile()}` as EngagementId) : null}
                        refreshKey={`${refreshKey()}:${attention().map((item) => item.path).join(",")}`}
                        onSelect={(id) => {
                            const item = attention().find((candidate) => `admin:${candidate.id}` === String(id));
                            if (item) selectFile(item.path);
                        }}
                    />
                )}
                nav={() => (
                    <AdminNavigator
                        documents={configDocuments()}
                        selected={selectedFile()}
                        homes={homes()}
                        onSelect={selectFile}
                    />
                )}
                navFooter={() => (
                    <div class="admin-nav-footer">
                        <span class="network-bar-dot" />
                        <span>{fullAdmin() ? "Admin authority admitted" : billingAdmin() ? "Billing authority admitted" : "Admin unavailable"}</span>
                        <button
                            type="button"
                            data-admin-return
                            title="Return to ordinary work"
                            onClick={props.onReturnToWork}
                        >
                            Back to work
                        </button>
                    </div>
                )}
                chat={() => (
                    <>
                        <ChatPaneHeader
                            title="Admin agent"
                            context={org()?.display_name || "Organization"}
                            contextKind="work"
                            kind="work"
                            // The admin agent runs no turns of its own, so its gem has no
                            // live tone: an unavailable admin is a permission outcome, not
                            // an errored turn, and it stays in the written label.
                            statusLabel={fullAdmin() || billingAdmin() ? "Ready" : "Unavailable"}
                            mobile={shell.isMobile()}
                            onCollapse={() => shell.setCollapsed("chat", true)}
                        />
                        <ChatPanel
                            session={adminSession}
                            bare
                            composerPlaceholder="task the admin agent…"
                            composerInputRef={(element) => (composerInput = element)}
                        />
                    </>
                )}
                content={() => (
                    <>
                        <h2>Content</h2>
                        <SessionProvider value={adminSession}>
                            <ContentViewer environmentView={environmentView} refreshKey={fileRevision} />
                        </SessionProvider>
                    </>
                )}
                files={() => (
                    <>
                        <h2>Files</h2>
                        <SessionProvider value={adminSession}><Workspace /></SessionProvider>
                    </>
                )}
                onNewChat={() => {
                    shell.openPane("chat", { chatSelected: true, fileSelected: selectedFile() !== null });
                    queueMicrotask(() => composerInput?.focus());
                }}
            />
            <Show when={wizardOpen()}>
                <SsoWizard api={props.api} onProposeSso={mutations.setSso} onProposeScim={mutations.rotateScim} onClose={() => { setWizardOpen(false); refresh(); }} />
            </Show>
        </>
    );
}

function AdminNavigator(props: {
    documents: AdminConfigDocument[];
    selected: AdminWorkspacePath | null;
    homes: AdminHomeProjection[] | undefined;
    onSelect: (path: string) => void;
}): JSX.Element {
    const labels: Record<AdminConfigPath, string> = {
        "overview.json": "Overview",
        "organization.json": "Organization",
        "access.json": "People & access",
        "identity.json": "Identity",
        "policy.json": "Policy",
        "software-policy.json": "Software",
        "clients.json": "Clients",
        "machines.json": "Machines",
        "backups.json": "Backups",
        "deployments.json": "Deployments",
        "automations.json": "Automations",
        "audit.json": "Audit",
        "billing.json": "Billing",
    };
    return (
        <div class="admin-navigator" data-admin-navigator>
            <nav aria-label="Administration files">
                <For each={props.documents} fallback={<p class="status">This authority has no admitted admin files.</p>}>
                    {(document) => (
                        <button
                            type="button"
                            classList={{ active: props.selected === document.path }}
                            onClick={() => props.onSelect(document.path)}
                        >
                            {labels[document.path]}
                        </button>
                    )}
                </For>
                <button
                    type="button"
                    data-admin-help-index
                    classList={{ active: props.selected === ADMIN_HELP_INDEX }}
                    onClick={() => props.onSelect(ADMIN_HELP_INDEX)}
                >
                    Help &amp; docs
                </button>
            </nav>
            <Show when={props.documents.some((document) => document.path === "machines.json")}>
                <div class="admin-home-tree">
                    <span>Machines</span>
                    <For each={props.homes} fallback={<p>No admitted Home projection</p>}>
                        {(home) => (
                            <button type="button" onClick={() => props.onSelect("machines.json")}>
                                <b classList={{ caveat: home.state !== "live" }} />
                                <code>{home.id}</code>
                                <small>{home.state}</small>
                            </button>
                        )}
                    </For>
                </div>
            </Show>
        </div>
    );
}

function OverviewFile(props: { value: any; onSelect: (path: string) => void }): JSX.Element {
    const caveated = () => (props.value.homes ?? []).filter((home: AdminHomeProjection) => home.state !== "live").length;
    return <><h1>{props.value.organization?.display_name || "Organization administration"}</h1><p>Derived from the selected canonical administration document. No aggregate compliance score is inferred.</p><Definition label="Members" value={String(props.value.member_count ?? 0)} /><Definition label="Machines" value={`${(props.value.homes ?? []).length - caveated()} live / ${(props.value.homes ?? []).length} registered`} /><Definition label="Projects" value={String(props.value.live_project_count ?? 0)} /><Definition label="Placements" value={String(props.value.live_placement_count ?? 0)} /><h3>Configuration</h3>{(["organization", "access", "identity", "policy", "software-policy", "clients", "machines", "backups", "deployments", "automations", "audit", "billing"] as const).map((name) => <button class="tree-action" type="button" onClick={() => props.onSelect(`${name}.json`)}>{name}</button>)}</>;
}

function OrganizationFile(props: { value: OrgSettings | null; mutations: AdminMutations; onAct: (verb: string, command: () => Promise<unknown>) => Promise<void> }): JSX.Element {
    const [name, setName] = createSignal(""); const [region, setRegion] = createSignal("");
    const [kind, setKind] = createSignal<"client" | "consultant" | null>(null);
    const [domain, setDomain] = createSignal("");
    const [challenge, setChallenge] = createSignal<{ readonly record_name: string; readonly record_type: "TXT"; readonly value: string } | null>(null);
    const loadChallenge = async () => setChallenge(await props.mutations.domainChallenge(domain()));
    return <><h1>Organization</h1><div class="settings-form"><label class="settings-field"><span class="settings-label">Display name</span><input class="settings-input" value={name() || props.value?.display_name || ""} onInput={(event) => setName(event.currentTarget.value)} /></label><label class="settings-field"><span class="settings-label">Business mode</span><select class="settings-input" value={kind() ?? props.value?.kind ?? "client"} onChange={(event) => setKind(event.currentTarget.value as "client" | "consultant")}><option value="client">Uses expert services</option><option value="consultant">Provides expert services through Vend</option></select></label><p class="muted">Provider mode admits Vend for tenant owners and administrators. Changing it remains a reviewed tenant-governance action.</p><Definition label="Verified domains" value={props.value?.verified_domains.join(", ") || "None verified"} /><p class="muted">Verified domains change only through DNS-backed domain verification.</p><label class="settings-field"><span class="settings-label">Domain to verify</span><input class="settings-input" value={domain()} onInput={(event) => { setDomain(event.currentTarget.value); setChallenge(null); }} placeholder="example.com" /></label><div class="bar"><button type="button" onClick={() => props.onAct("Load DNS challenge", loadChallenge)}>show DNS challenge</button><button type="button" disabled={!domain().trim()} onClick={() => props.onAct("Propose domain verification", () => props.mutations.verifyDomain(domain()))}>propose verification</button></div><Show when={challenge()}>{(value) => <div class="resource-row"><span class="resource-kind">{value().record_type}</span><code class="resource-title">{value().record_name}</code><code>{value().value}</code></div>}</Show><label class="settings-field"><span class="settings-label">Default residency region</span><input class="settings-input" value={region() || props.value?.default_region || ""} onInput={(event) => setRegion(event.currentTarget.value)} /></label></div><button type="button" onClick={() => props.onAct("Propose organization change", () => props.mutations.setOrg({ display_name: name() || props.value?.display_name || "", verified_domains: props.value?.verified_domains ?? [], default_region: region() || props.value?.default_region || null, kind: kind() ?? props.value?.kind ?? "client" }))}>propose</button></>;
}

function AccessFile(props: { value: { members: Member[]; sessions: any[]; grants: MemberGrant[] }; mutations: AdminMutations; onAct: (verb: string, command: () => Promise<unknown>) => Promise<void> }): JSX.Element {
    const [invite, setInvite] = createSignal(""); const [role, setRole] = createSignal("member"); const [grantAuthority, setGrantAuthority] = createSignal(""); const [project, setProject] = createSignal("");
    return <><h1>People &amp; access</h1><h3>Members</h3><For each={props.value.members}>{(member) => <div class="resource-row" data-member={member.id}><span class="resource-title">{member.email || member.authority}</span><select value={member.role} disabled={member.managed_by_scim} onChange={(event) => props.onAct("Propose role change", () => props.mutations.setRole(member.id, event.currentTarget.value))}><For each={ROLES}>{(item) => <option value={item}>{item}</option>}</For></select><span class="resource-availability">{member.status}</span><button type="button" onClick={() => props.onAct("Propose deactivation", () => props.mutations.deactivate(member.id))}>deactivate</button></div>}</For><div class="bar" data-admin-invite><input data-admin-invite-authority value={invite()} onInput={(event) => setInvite(event.currentTarget.value)} placeholder="authority or email" /><select value={role()} onChange={(event) => setRole(event.currentTarget.value)}><For each={ROLES}>{(item) => <option value={item}>{item}</option>}</For></select><button type="button" onClick={() => props.onAct("Propose member invitation", () => props.mutations.invite({ authority: invite(), email: invite(), role: role() }))}>propose invite</button></div><h3>Project grants</h3><For each={props.value.grants}>{(grant) => <div class="resource-row"><code class="resource-title">{grant.authority} → {grant.project_id}</code><button type="button" onClick={() => props.onAct("Propose grant revocation", () => props.mutations.revokeGrant(grant.authority, grant.project_id))}>revoke</button></div>}</For><div class="bar"><input value={grantAuthority()} onInput={(event) => setGrantAuthority(event.currentTarget.value)} placeholder="member authority" /><input value={project()} onInput={(event) => setProject(event.currentTarget.value)} placeholder="project id" /><button type="button" onClick={() => props.onAct("Propose project access", () => props.mutations.grant(grantAuthority(), project()))}>propose grant</button></div><h3 data-sessions>Active sessions</h3><For each={props.value.sessions}>{(session) => <Definition label={session.authority} value={`idle ${Math.round(session.idle_ms / 1000)}s`} />}</For></>;
}

function IdentityFile(props: { value: { sso: SsoConnection | null }; mutations: AdminMutations; onOpenSso: () => void; onStatus: (status: string) => void }): JSX.Element {
    return <><h1>Identity</h1><Definition label="Single sign-on" value={props.value.sso ? `${props.value.sso.protocol.toUpperCase()} · ${props.value.sso.enforce_sso ? "enforced" : "optional"}` : "Not configured"} /><button data-admin-sso-wizard type="button" onClick={props.onOpenSso}>set up SSO</button><h3>Provisioning</h3><p>SCIM credentials are shown once and never enter this file.</p><button type="button" onClick={async () => { try { await props.mutations.rotateScim(); props.onStatus("SCIM token rotation proposed — review it above"); } catch (error) { props.onStatus(messageOf(error)); } }}>propose SCIM token rotation</button></>;
}

function PolicyFile(props: { value: { resource: ResourcePolicy; security: SecurityPolicy | null; placement: PlacementPolicy; archetype_approval: ArchetypeApprovalPolicy }; mutations: AdminMutations; onAct: (verb: string, command: () => Promise<unknown>) => Promise<void> }): JSX.Element {
    const [mfa, setMfa] = createSignal<boolean | null>(null); const [attested, setAttested] = createSignal<boolean | null>(null); const [approval, setApproval] = createSignal<boolean | null>(null);
    return <><h1>Policy</h1><div class="settings-form"><label class="settings-checkbox"><input type="checkbox" checked={mfa() ?? props.value.security?.require_mfa ?? false} onChange={(event) => setMfa(event.currentTarget.checked)} />Require MFA</label><button type="button" onClick={() => props.onAct("Propose security policy", () => props.mutations.setSecurity({ ...(props.value.security ?? { require_mfa: false, session_lifetime_secs: 0, idle_timeout_secs: 0, residency_region: null, audit_retention_min_days: 365, allow_auto_upgrade: false }), require_mfa: mfa() ?? props.value.security?.require_mfa ?? false }))}>propose security policy</button><label class="settings-checkbox"><input type="checkbox" checked={attested() ?? props.value.placement?.require_attested ?? false} onChange={(event) => setAttested(event.currentTarget.checked)} />Require attested placement</label><button type="button" onClick={() => props.onAct("Propose placement policy", () => props.mutations.setPlacement({ ...(props.value.placement ?? { allowed_operators: [] }), require_attested: attested() ?? props.value.placement?.require_attested ?? false }))}>propose placement policy</button><label class="settings-checkbox"><input type="checkbox" checked={approval() ?? props.value.archetype_approval?.require_approval ?? false} onChange={(event) => setApproval(event.currentTarget.checked)} />Require archetype approval</label><button type="button" onClick={() => props.onAct("Propose archetype policy", () => props.mutations.setApproval({ require_approval: approval() ?? props.value.archetype_approval?.require_approval ?? false }))}>propose archetype policy</button></div></>;
}

function SoftwarePolicyFile(props: { value: SoftwarePolicy; mutations: AdminMutations; onAct: (verb: string, command: () => Promise<unknown>) => Promise<void> }): JSX.Element {
    const current = () => props.value ?? { minimum_version: "", minimum_protocol: 0, allowed_channels: [], grace_until_unix_ms: null };
    const [version, setVersion] = createSignal<string | null>(null);
    const [protocol, setProtocol] = createSignal<string | null>(null);
    const [channels, setChannels] = createSignal<string[] | null>(null);
    const [grace, setGrace] = createSignal<string | null>(null);
    const selectedChannels = () => channels() ?? [...current().allowed_channels];
    const toggleChannel = (channel: string, checked: boolean) => setChannels(
        checked
            ? [...new Set([...selectedChannels(), channel])]
            : selectedChannels().filter((candidate) => candidate !== channel),
    );
    const save = () => {
        const graceText = grace() ?? dateTimeInput(current().grace_until_unix_ms);
        const parsedGrace = graceText ? Date.parse(graceText) : Number.NaN;
        return props.mutations.setSoftware({
            minimum_version: version() ?? current().minimum_version,
            minimum_protocol: Number(protocol() ?? current().minimum_protocol) || 0,
            allowed_channels: selectedChannels() as SoftwarePolicy["allowed_channels"],
            grace_until_unix_ms: Number.isFinite(parsedGrace) ? parsedGrace : null,
        });
    };
    return <><h1>Client software admission</h1><p>These are compatibility controls over reported builds. They do not attest a device or binary.</p><div class="settings-form"><label class="settings-field"><span class="settings-label">Minimum GaugeDesk version</span><input class="settings-input" data-software-minimum-version value={version() ?? current().minimum_version} placeholder="0.4.3" onInput={(event) => setVersion(event.currentTarget.value)} /></label><label class="settings-field"><span class="settings-label">Minimum client protocol</span><input class="settings-input" data-software-minimum-protocol type="number" min="0" value={protocol() ?? String(current().minimum_protocol)} onInput={(event) => setProtocol(event.currentTarget.value)} /></label><span class="settings-label">Allowed release channels</span><For each={(["stable", "beta", "dev"] as const)}>{(channel) => <label class="settings-checkbox"><input type="checkbox" checked={selectedChannels().includes(channel)} onChange={(event) => toggleChannel(channel, event.currentTarget.checked)} />{channel}</label>}</For><label class="settings-field"><span class="settings-label">Grace until</span><input class="settings-input" data-software-grace type="datetime-local" value={grace() ?? dateTimeInput(current().grace_until_unix_ms)} onInput={(event) => setGrace(event.currentTarget.value)} /></label><button data-software-save type="button" onClick={() => props.onAct("Save software policy", save)}>save software policy</button></div></>;
}

function ClientsFile(props: { value: { sessions: ClientSession[] } }): JSX.Element {
    return <><h1>Client sessions</h1><p>Build details are reported compatibility evidence, not device attestation.</p><For each={props.value.sessions} fallback={<p class="status">No active enterprise client sessions have been reported.</p>}>{(session) => <div class="resource-row" data-client-session={session.authority}><span class="resource-kind">{session.software_status}</span><strong class="resource-title">{session.authority}</strong><code>{session.client.platform || "unknown"} · {session.client.version || "unknown version"} · protocol {session.client.protocol ?? "unknown"} · {session.client.channel || "unknown channel"}</code><span class="resource-availability">idle {Math.round(session.idle_ms / 1000)}s</span><small>{session.software_reason}</small></div>}</For></>;
}

function dateTimeInput(value: number | null | undefined): string {
    if (!value) return "";
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? "" : date.toISOString().slice(0, 16);
}

function MachinesFile(props: { value: { homes: AdminHomeProjection[] }; commands: readonly string[]; mutations: AdminMutations; onAct: (verb: string, command: () => Promise<unknown>) => Promise<void> }): JSX.Element {
    const [homeId, setHomeId] = createSignal(""); const [endpoint, setEndpoint] = createSignal(""); const [name, setName] = createSignal("");
    const [region, setRegion] = createSignal("eastus"); const [exportId, setExportId] = createSignal("");
    const admitted = (command: string) => props.commands.includes(command);
    const managed = () => props.value.homes.find((home) => home.kind === "cloud");
    return <><h1>Machines</h1><p>Self-managed and GaugeWright-managed machines share one surface. Live inventory remains target-admitted; registration metadata is not project authority.</p><For each={props.value.homes} fallback={<p class="status">No Machine management projection is admitted.</p>}>{(home) => <section><h3>{home.id} · {home.lifecycle ?? home.state}</h3><code>{home.endpoint}</code><Show when={home.kind === "registered" && admitted("machine.revoke")}><button type="button" onClick={() => props.onAct("Propose machine removal", () => props.mutations.command("machines.json", "machine.revoke", { id: home.id }))}>remove</button></Show><Show when={home.kind === "cloud"}><div class="bar"><Show when={home.lifecycle === "active" && admitted("machine.managed.suspend")}><button type="button" onClick={() => props.onAct("Propose managed machine suspension", () => props.mutations.command("machines.json", "machine.managed.suspend", {}))}>suspend</button></Show><Show when={(home.lifecycle === "suspended" || home.lifecycle === "retention") && admitted("machine.managed.reinstate")}><button type="button" onClick={() => props.onAct("Propose managed machine reinstatement", () => props.mutations.command("machines.json", "machine.managed.reinstate", {}))}>reinstate</button></Show><Show when={home.lifecycle !== "retention" && home.lifecycle !== "deleted" && admitted("machine.managed.retention")}><button type="button" onClick={() => props.onAct("Propose managed machine retention", () => props.mutations.command("machines.json", "machine.managed.retention", {}))}>begin retention</button></Show><Show when={home.lifecycle === "retention" && admitted("machine.managed.erase")}><button type="button" onClick={() => props.onAct("Propose managed machine erasure", () => props.mutations.command("machines.json", "machine.managed.erase", { confirm: true }))}>erase permanently</button></Show></div><Show when={home.execution}>{(execution) => <MachineExecution value={execution()} commands={props.commands} mutations={props.mutations} onAct={props.onAct} />}</Show></Show><Show when={home.state === "live"} fallback={<p class="status">Inventory withheld: {home.repair_hint || home.state}</p>}><For each={home.projects} fallback={<p class="status">No projects reported.</p>}>{(project) => <div class="resource-row"><span class="resource-title">{project.name}</span><code>{project.id}</code><span class="resource-availability">{project.placements.length} placements</span></div>}</For></Show></section>}</For><Show when={!managed() && admitted("machine.managed.provision")}><h3>Add a managed machine</h3><div class="settings-form"><input value={region()} onInput={(event) => setRegion(event.currentTarget.value)} placeholder="region" /><button type="button" disabled={!region().trim()} onClick={() => props.onAct("Propose managed machine provisioning", () => props.mutations.command("machines.json", "machine.managed.provision", { region: region() }))}>propose managed machine</button></div></Show><Show when={managed() && admitted("machine.managed.export")}><h3>Export managed machine</h3><div class="settings-form"><input value={exportId()} onInput={(event) => setExportId(event.currentTarget.value)} placeholder="export id" /><button type="button" disabled={!exportId().trim()} onClick={() => props.onAct("Propose managed machine export", () => props.mutations.command("machines.json", "machine.managed.export", { export_id: exportId() }))}>propose export</button></div></Show><Show when={admitted("machine.register")}><h3>Connect a self-managed machine</h3><div class="settings-form"><input value={name()} onInput={(event) => setName(event.currentTarget.value)} placeholder="machine name" /><input value={homeId()} onInput={(event) => setHomeId(event.currentTarget.value)} placeholder="Home identity" /><input value={endpoint()} onInput={(event) => setEndpoint(event.currentTarget.value)} placeholder="https://machine.example" /><button type="button" disabled={!homeId().trim() || !endpoint().trim()} onClick={() => props.onAct("Propose machine registration", () => props.mutations.command("machines.json", "machine.register", { home_id: homeId(), endpoint: endpoint(), display_name: name() }))}>propose registration</button></div></Show></>;
}

function MachineExecution(props: { value: NonNullable<AdminHomeProjection["execution"]>; commands: readonly string[]; mutations: AdminMutations; onAct: (verb: string, command: () => Promise<unknown>) => Promise<void> }): JSX.Element {
    const profiles = () => Object.entries(props.value.profiles);
    const money = (nanos: number) => `$${(nanos / 1_000_000_000).toFixed(6)}`;
    const isolated = () => props.value.profiles.isolated_workspace;
    const [enabled, setEnabled] = createSignal(isolated().enabled_by_tenant_policy === true);
    const [attemptLimit, setAttemptLimit] = createSignal(
        isolated().metering.reservation_nanos_usd
            ? String(isolated().metering.reservation_nanos_usd! / 1_000_000_000)
            : "",
    );
    const savePolicy = () => props.mutations.command("machines.json", "machine.managed.execution-policy", {
        isolated_workspace_enabled: enabled(),
        max_attempt_nanos_usd: Math.round(Number(attemptLimit()) * 1_000_000_000),
    });
    return <section class="machine-execution" data-machine-execution>
        <h3>Execution</h3>
        <p class="muted">Capabilities select one exact profile. There is no automatic escalation or Dedicated fallback.</p>
        <div class="bar">
            <Definition label="Compute" value={`${props.value.compute.state} · ${props.value.compute.active_attempts} active`} />
            <Definition label="Queue" value={`${props.value.queue.total} commands`} />
            <Definition label="Charged" value={money(props.value.usage.charged_nanos_usd)} />
        </div>
        <For each={profiles()}>{([name, profile]) => <div class="resource-row" data-execution-profile={name}>
            <span class="resource-kind">{profile.available ? "available" : "unavailable"}</span>
            <strong class="resource-title">{name.replaceAll("_", " ")}</strong>
            <code>{profile.capabilities.join(", ") || "no capabilities"}</code>
            <small>{profile.reason ?? `${profile.compute_state} · ${profile.metering.kind}`}</small>
        </div>}</For>
        <Show when={props.commands.includes("machine.managed.execution-policy")}>
            <h3>Isolated workspace policy</h3>
            <div class="settings-form">
                <label class="settings-checkbox"><input type="checkbox" checked={enabled()} onChange={(event) => setEnabled(event.currentTarget.checked)} />enable separately metered workspace compute</label>
                <label class="settings-field"><span class="settings-label">Maximum spend per attempt (USD)</span><input class="settings-input" type="number" min="0.000001" step="0.000001" value={attemptLimit()} onInput={(event) => setAttemptLimit(event.currentTarget.value)} /></label>
                <button type="button" disabled={enabled() && !(Number(attemptLimit()) > 0)} onClick={() => props.onAct("Propose execution policy", savePolicy)}>propose execution policy</button>
            </div>
        </Show>
        <Show when={props.value.failures.length > 0}>
            <h3>Needs attention</h3>
            <For each={props.value.failures}>{(failure) => <div class="resource-row">
                <span class="resource-kind">{failure.phase}</span>
                <strong class="resource-title">{failure.command_id}</strong>
                <code>{failure.profile} · attempt {failure.attempt}</code>
            </div>}</For>
        </Show>
    </section>;
}

type BackupProjection = {
    readonly facility?: { readonly status?: string; readonly config?: { readonly schedule_days?: number; readonly retention_days?: number } } | null;
    readonly recipients?: readonly { readonly id: string; readonly label?: string; readonly public_key: string }[];
    readonly points?: readonly { readonly handle: string; readonly created_at: number; readonly bytes: number }[];
    readonly restore_receivers?: readonly { readonly id: string; readonly point_handle: string; readonly public_key: string }[];
    readonly machine_lifecycle?: "active" | "suspended" | "retention" | "erased" | null;
};

function BackupsFile(props: { value: BackupProjection; commands: readonly string[]; mutations: AdminMutations; onAct: (verb: string, command: () => Promise<unknown>) => Promise<void> }): JSX.Element {
    const [schedule, setSchedule] = createSignal(String(props.value.facility?.config?.schedule_days ?? 1)); const [retention, setRetention] = createSignal(String(props.value.facility?.config?.retention_days ?? 30));
    const [recipientId, setRecipientId] = createSignal(""); const [recipientLabel, setRecipientLabel] = createSignal(""); const [recipientKey, setRecipientKey] = createSignal("");
    const [restorePoint, setRestorePoint] = createSignal(""); const [receiverId, setReceiverId] = createSignal(""); const [receiverWrap, setReceiverWrap] = createSignal("");
    const config = () => ({ schedule_days: Number(schedule()), retention_days: Number(retention()) });
    const selectReceiver = (id: string, point: string) => { setReceiverId(id); setRestorePoint(point); };
    const completeRestore = () => props.mutations.command("backups.json", "backup.restore.complete", {
        point_handle: restorePoint(),
        receiver_id: receiverId(),
        receiver_wrap: JSON.parse(receiverWrap()),
    });
    return <><h1>Backups</h1><Definition label="State" value={props.value.facility?.status ?? "Not enabled"} /><Definition label="Machine" value={props.value.machine_lifecycle ?? "Not provisioned"} /><Definition label="Restore points" value={String(props.value.points?.length ?? 0)} /><Show when={props.value.facility?.status === "active" && props.commands.includes("backup.point.create")}><button type="button" onClick={() => props.onAct("Propose restore point", () => props.mutations.command("backups.json", "backup.point.create", {}))}>propose restore point</button></Show><h3>Restore points</h3><For each={props.value.points ?? []} fallback={<p class="status">No sealed restore points.</p>}>{(point) => <div class="resource-row"><strong class="resource-title">{point.handle}</strong><small>{point.bytes} encrypted bytes</small><Show when={props.value.machine_lifecycle === "erased" && props.commands.includes("backup.restore.begin")}><button type="button" onClick={() => props.onAct("Propose restore receiver", () => props.mutations.command("backups.json", "backup.restore.begin", { point_handle: point.handle }))}>begin restore</button></Show></div>}</For><Show when={props.value.machine_lifecycle === "erased"}><h3>Pending restore receivers</h3><p class="muted">A retained tenant recovery holder unwraps the selected point locally and re-wraps it to this one-time public receiver. GaugeWright never receives the holder's private key or plaintext point key.</p><For each={props.value.restore_receivers ?? []} fallback={<p class="status">Accept a begin-restore proposal to mint a receiver.</p>}>{(receiver) => <div class="resource-row"><strong class="resource-title">{receiver.point_handle}</strong><code>{receiver.id}</code><code>{receiver.public_key}</code><button type="button" onClick={() => selectReceiver(receiver.id, receiver.point_handle)}>use receiver</button></div>}</For><div class="settings-form"><input value={restorePoint()} onInput={(event) => setRestorePoint(event.currentTarget.value)} placeholder="restore point handle" /><input value={receiverId()} onInput={(event) => setReceiverId(event.currentTarget.value)} placeholder="receiver id" /><textarea value={receiverWrap()} onInput={(event) => setReceiverWrap(event.currentTarget.value)} placeholder="receiver wrap JSON from the recovery holder" /><Show when={props.commands.includes("backup.restore.complete")}><button type="button" disabled={!restorePoint() || !receiverId() || !receiverWrap()} onClick={() => props.onAct("Propose restore completion", completeRestore)}>propose completion</button></Show></div></Show><h3>Tenant-held recipients</h3><For each={props.value.recipients ?? []} fallback={<p class="status">Add a public recovery recipient before enabling backups.</p>}>{(recipient) => <div class="resource-row"><span class="resource-title">{recipient.label || recipient.id}</span><code>{recipient.id}</code><button type="button" onClick={() => props.onAct("Propose recipient removal", () => props.mutations.command("backups.json", "backup.recipient.remove", { id: recipient.id }))}>remove</button></div>}</For><div class="settings-form"><input value={recipientId()} onInput={(event) => setRecipientId(event.currentTarget.value)} placeholder="recipient id" /><input value={recipientLabel()} onInput={(event) => setRecipientLabel(event.currentTarget.value)} placeholder="label" /><input value={recipientKey()} onInput={(event) => setRecipientKey(event.currentTarget.value)} placeholder="public recovery key" /><button type="button" disabled={!recipientId() || !recipientKey()} onClick={() => props.onAct("Propose recipient", () => props.mutations.command("backups.json", "backup.recipient.add", { id: recipientId(), label: recipientLabel(), public_key: recipientKey() }))}>propose recipient</button></div><h3>Schedule</h3><div class="settings-form"><input type="number" value={schedule()} onInput={(event) => setSchedule(event.currentTarget.value)} /><input type="number" value={retention()} onInput={(event) => setRetention(event.currentTarget.value)} /><button type="button" onClick={() => props.onAct("Propose backup configuration", () => props.mutations.command("backups.json", props.value.facility ? "backup.configure" : "backup.enable", config()))}>{props.value.facility ? "propose configuration" : "propose enable"}</button><Show when={props.value.facility}><button type="button" onClick={() => props.onAct("Propose backup suspension", () => props.mutations.command("backups.json", "backup.disable", {}))}>propose disable</button></Show></div></>;
}

function AutomationsFile(props: { value: AutomationProjection; commands: readonly string[]; mutations: AdminMutations; onAct: (verb: string, command: () => Promise<unknown>) => Promise<void> }): JSX.Element {
    const [id, setId] = createSignal("");
    const [title, setTitle] = createSignal("");
    const [project, setProject] = createSignal("");
    const [placement, setPlacement] = createSignal("");
    const [source, setSource] = createSignal("");
    const [version, setVersion] = createSignal("1");
    const [trigger, setTrigger] = createSignal("");
    const [task, setTask] = createSignal("");
    const [enabled, setEnabled] = createSignal(true);
    const admitted = (command: string) => props.commands.includes(command);
    const canCreate = () => [id(), title(), project(), placement(), source(), trigger(), task()].every((value) => value.trim().length > 0) && Number(version()) > 0;
    const create = () => props.mutations.command("automations.json", "automation.create", {
        id: id().trim(),
        project_id: project().trim(),
        placement_id: placement().trim(),
        title: title().trim(),
        source_handle: source().trim(),
        source_version: Number(version()),
        trigger_ref: trigger().trim(),
        task_ref: task().trim(),
        enabled: enabled(),
    });
    return <><h1>Automations</h1><p>Each automation is a Home-owned reference to one project, one active placement, and one versioned WhippleScript source. Trigger and task bodies stay with WhippleScript; this projection carries references and admitted run evidence only.</p><For each={props.value.automations ?? []} fallback={<p class="status">No Whip automations are registered in this Machine.</p>}>{(automation) => <section class="resource-row" data-automation={automation.id}><span class="resource-kind">{automation.status}</span><strong class="resource-title">{automation.title}</strong><code>{automation.project_id} · {automation.placement_id}</code><small>{automation.source_handle}@{automation.source_version} · {automation.trigger_ref} · {automation.task_ref}</small><div class="bar"><Show when={automation.status === "enabled" && admitted("automation.disable")}><button type="button" onClick={() => props.onAct("Propose automation disable", () => props.mutations.command("automations.json", "automation.disable", { id: automation.id }))}>disable</button></Show><Show when={automation.status === "disabled" && admitted("automation.enable")}><button type="button" onClick={() => props.onAct("Propose automation enable", () => props.mutations.command("automations.json", "automation.enable", { id: automation.id }))}>enable</button></Show><Show when={automation.status !== "deleted" && admitted("automation.delete")}><button type="button" onClick={() => props.onAct("Propose automation deletion", () => props.mutations.command("automations.json", "automation.delete", { id: automation.id }))}>delete</button></Show></div></section>}</For><h3>Run evidence</h3><For each={props.value.runs ?? []} fallback={<p class="status">No admitted automation runs have been recorded.</p>}>{(run) => <div class="resource-row" data-automation-run={run.id}><span class="resource-kind">{run.phase}</span><strong class="resource-title">{run.automation_id}</strong><code>{run.runtime_command_id}</code><small>{run.evidence_ref || run.error_code || "No evidence reference reported"}</small></div>}</For><Show when={admitted("automation.create")}><h3>Register a Whip automation</h3><div class="settings-form"><input value={id()} onInput={(event) => setId(event.currentTarget.value)} placeholder="automation id" /><input value={title()} onInput={(event) => setTitle(event.currentTarget.value)} placeholder="title" /><input value={project()} onInput={(event) => setProject(event.currentTarget.value)} placeholder="project id" /><input value={placement()} onInput={(event) => setPlacement(event.currentTarget.value)} placeholder="placement id" /><input value={source()} onInput={(event) => setSource(event.currentTarget.value)} placeholder="Whip source handle" /><input type="number" min="1" value={version()} onInput={(event) => setVersion(event.currentTarget.value)} placeholder="source version" /><input value={trigger()} onInput={(event) => setTrigger(event.currentTarget.value)} placeholder="trigger reference" /><input value={task()} onInput={(event) => setTask(event.currentTarget.value)} placeholder="task reference" /><label class="settings-checkbox"><input type="checkbox" checked={enabled()} onChange={(event) => setEnabled(event.currentTarget.checked)} />enable after review</label><button type="button" disabled={!canCreate()} onClick={() => props.onAct("Propose Whip automation", create)}>propose automation</button></div></Show></>;
}

function DeploymentsFile(props: { value: DeploymentProjection; commands: readonly string[]; mutations: AdminMutations; onAct: (verb: string, command: () => Promise<unknown>) => Promise<void> }): JSX.Element {
    const [name, setName] = createSignal("");
    const [placement, setPlacement] = createSignal("");
    const [origin, setOrigin] = createSignal("");
    const [budget, setBudget] = createSignal("25");
    const [quota, setQuota] = createSignal("20");
    const [authMode, setAuthMode] = createSignal<"anonymous" | "provider">("anonymous");
    const [viewer, setViewer] = createSignal(true);
    const [files, setFiles] = createSignal(false);
    const [chats, setChats] = createSignal(false);
    const [whiteLabel, setWhiteLabel] = createSignal(false);
    const admitted = () => props.commands.includes("deployment.create");
    const budgetCents = () => Math.round(Number(budget()) * 100);
    const canCreate = () => name().trim().length > 0 && placement().trim().length > 0 && origin().trim().length > 0 && budgetCents() > 0 && Number(quota()) > 0;
    const panels = () => ["chat", ...(viewer() ? ["viewer"] : []), ...(files() ? ["files"] : []), ...(chats() ? ["chats"] : [])];
    const create = () => props.mutations.command("deployments.json", "deployment.create", {
        request_id: crypto.randomUUID(),
        name: name().trim(),
        placement_id: placement().trim(),
        funding: "managed_plan",
        config: {
            auth_mode: authMode(),
            allowed_origins: [origin().trim()],
            max_spend_cents: budgetCents(),
            per_visitor_quota: Number(quota()),
            panels: panels(),
            white_label: whiteLabel(),
        },
    });
    return <><h1>Deployments</h1><p>Technical public-agent deployments are exact bindings to a placement in this tenant's admitted Machine. Vend owns offers and client entitlement; this file owns runtime exposure, audience policy, and funding limits.</p><For each={props.value.deployments ?? []} fallback={<p class="status">No technical deployments are admitted in this Machine.</p>}>{(deployment) => <section class="resource-row" data-deployment={deployment.binding.deployment_id}><span class="resource-kind">{deployment.status ?? "active"} · v{deployment.package_version}</span><strong class="resource-title">{deployment.name}</strong><code>{deployment.binding.placement_id}</code><a href={deployment.endpoint} target="_blank" rel="noreferrer">{deployment.endpoint}</a><small>{deployment.initial_config.auth_mode} · {deployment.initial_config.panels.join(", ")} · ${(deployment.initial_config.max_spend_cents / 100).toFixed(2)} cap · {deployment.initial_config.per_visitor_quota} turns per visitor</small><div class="bar"><Show when={(deployment.status ?? "active") === "active" && props.commands.includes("deployment.pause")}><button type="button" onClick={() => props.onAct("Propose deployment pause", () => props.mutations.command("deployments.json", "deployment.pause", { deployment_id: deployment.binding.deployment_id }))}>pause</button></Show><Show when={deployment.status === "paused" && props.commands.includes("deployment.resume")}><button type="button" onClick={() => props.onAct("Propose deployment resume", () => props.mutations.command("deployments.json", "deployment.resume", { deployment_id: deployment.binding.deployment_id }))}>resume</button></Show><Show when={deployment.status !== "revoked" && props.commands.includes("deployment.redeploy")}><button type="button" onClick={() => props.onAct("Propose deployment refresh", () => props.mutations.command("deployments.json", "deployment.redeploy", { deployment_id: deployment.binding.deployment_id }))}>redeploy latest</button></Show><Show when={deployment.status !== "revoked" && props.commands.includes("deployment.revoke")}><button type="button" onClick={() => props.onAct("Propose deployment revocation", () => props.mutations.command("deployments.json", "deployment.revoke", { deployment_id: deployment.binding.deployment_id }))}>revoke</button></Show></div><Show when={deployment.status !== "revoked" && props.commands.includes("deployment.configure")}><DeploymentConfiguration deployment={deployment} mutations={props.mutations} onAct={props.onAct} /></Show></section>}</For><Show when={admitted()}><h3>Create a technical deployment</h3><div class="settings-form"><label class="settings-field"><span class="settings-label">Name</span><input class="settings-input" value={name()} onInput={(event) => setName(event.currentTarget.value)} placeholder="Documentation assistant" /></label><label class="settings-field"><span class="settings-label">Placement</span><input class="settings-input" value={placement()} onInput={(event) => setPlacement(event.currentTarget.value)} placeholder="placement id" /></label><label class="settings-field"><span class="settings-label">Allowed origin</span><input class="settings-input" value={origin()} onInput={(event) => setOrigin(event.currentTarget.value)} placeholder="https://docs.example.com" /></label><label class="settings-field"><span class="settings-label">Authentication</span><select class="settings-input" value={authMode()} onChange={(event) => setAuthMode(event.currentTarget.value as "anonymous" | "provider")}><option value="anonymous">Anonymous audiences</option><option value="provider">Provider identities required</option></select></label><label class="settings-field"><span class="settings-label">Spend cap (USD)</span><input class="settings-input" type="number" min="0.01" step="0.01" value={budget()} onInput={(event) => setBudget(event.currentTarget.value)} /></label><label class="settings-field"><span class="settings-label">Turns per visitor</span><input class="settings-input" type="number" min="1" step="1" value={quota()} onInput={(event) => setQuota(event.currentTarget.value)} /></label><label class="settings-checkbox"><input type="checkbox" checked={viewer()} onChange={(event) => setViewer(event.currentTarget.checked)} />viewer panel</label><label class="settings-checkbox"><input type="checkbox" checked={files()} onChange={(event) => setFiles(event.currentTarget.checked)} />files panel</label><label class="settings-checkbox"><input type="checkbox" checked={chats()} onChange={(event) => setChats(event.currentTarget.checked)} />chat history panel</label><label class="settings-checkbox"><input type="checkbox" checked={whiteLabel()} onChange={(event) => setWhiteLabel(event.currentTarget.checked)} />white label</label><button type="button" disabled={!canCreate()} onClick={() => props.onAct("Propose technical deployment", create)}>propose deployment</button></div><p class="muted">Creation always enters human review. The deployment does not exist until the proposal is accepted.</p></Show></>;
}

function DeploymentConfiguration(props: { deployment: NonNullable<DeploymentProjection["deployments"]>[number]; mutations: AdminMutations; onAct: (verb: string, command: () => Promise<unknown>) => Promise<void> }): JSX.Element {
    const current = props.deployment.initial_config;
    const [origins, setOrigins] = createSignal(current.allowed_origins.join(", "));
    const [budget, setBudget] = createSignal(String(current.max_spend_cents / 100));
    const [quota, setQuota] = createSignal(String(current.per_visitor_quota));
    const [authMode, setAuthMode] = createSignal<"anonymous" | "provider">(current.auth_mode);
    const [viewer, setViewer] = createSignal(current.panels.includes("viewer"));
    const [files, setFiles] = createSignal(current.panels.includes("files"));
    const [chats, setChats] = createSignal(current.panels.includes("chats"));
    const [whiteLabel, setWhiteLabel] = createSignal(current.white_label);
    const configure = () => props.mutations.command("deployments.json", "deployment.configure", {
        deployment_id: props.deployment.binding.deployment_id,
        config: {
            auth_mode: authMode(),
            allowed_origins: origins().split(",").map((origin) => origin.trim()).filter(Boolean),
            max_spend_cents: Math.round(Number(budget()) * 100),
            per_visitor_quota: Number(quota()),
            panels: ["chat", ...(viewer() ? ["viewer"] : []), ...(files() ? ["files"] : []), ...(chats() ? ["chats"] : [])],
            white_label: whiteLabel(),
        },
    });
    return <details><summary>Audience configuration</summary><div class="settings-form"><label class="settings-field"><span class="settings-label">Allowed origins</span><input class="settings-input" value={origins()} onInput={(event) => setOrigins(event.currentTarget.value)} /></label><label class="settings-field"><span class="settings-label">Authentication</span><select class="settings-input" value={authMode()} onChange={(event) => setAuthMode(event.currentTarget.value as "anonymous" | "provider")}><option value="anonymous">Anonymous audiences</option><option value="provider">Provider identities required</option></select></label><label class="settings-field"><span class="settings-label">Spend cap (USD)</span><input class="settings-input" type="number" min="0.01" step="0.01" value={budget()} onInput={(event) => setBudget(event.currentTarget.value)} /></label><label class="settings-field"><span class="settings-label">Turns per visitor</span><input class="settings-input" type="number" min="1" step="1" value={quota()} onInput={(event) => setQuota(event.currentTarget.value)} /></label><label class="settings-checkbox"><input type="checkbox" checked={viewer()} onChange={(event) => setViewer(event.currentTarget.checked)} />viewer panel</label><label class="settings-checkbox"><input type="checkbox" checked={files()} onChange={(event) => setFiles(event.currentTarget.checked)} />files panel</label><label class="settings-checkbox"><input type="checkbox" checked={chats()} onChange={(event) => setChats(event.currentTarget.checked)} />chat history panel</label><label class="settings-checkbox"><input type="checkbox" checked={whiteLabel()} onChange={(event) => setWhiteLabel(event.currentTarget.checked)} />white label</label><button type="button" onClick={() => props.onAct("Propose deployment configuration", configure)}>propose configuration</button></div></details>;
}

function AuditFile(props: {
    value: { integrity: any; entries: any[] };
    actorFilter: string;
    actionFilter: string;
    onActorFilter: (value: string) => void;
    onActionFilter: (value: string) => void;
    onExport: (format: "csv" | "json", filters: { readonly actor?: string; readonly action?: string }) => Promise<void>;
}): JSX.Element {
    const visibleEntries = () => [...(props.value.entries ?? [])]
        .filter((entry) => !props.actorFilter.trim() || entry.actor === props.actorFilter.trim())
        .filter((entry) => !props.actionFilter.trim() || entry.action === props.actionFilter.trim())
        .reverse();
    const filters = () => ({ actor: props.actorFilter.trim() || undefined, action: props.actionFilter.trim() || undefined });
    return <><h1>Audit</h1><Definition label="Integrity" value={props.value.integrity ? `${props.value.integrity.ok ? "verified" : "failed"} · ${props.value.integrity.entries} entries` : "Unknown"} /><div class="settings-form" data-audit-controls><label class="settings-field"><span class="settings-label">Actor</span><input class="settings-input" data-audit-actor value={props.actorFilter} onInput={(event) => props.onActorFilter(event.currentTarget.value)} /></label><label class="settings-field"><span class="settings-label">Action</span><input class="settings-input" data-audit-action value={props.actionFilter} onInput={(event) => props.onActionFilter(event.currentTarget.value)} /></label><div class="bar"><button type="button" data-audit-export="csv" onClick={() => void props.onExport("csv", filters())}>export CSV</button><button type="button" data-audit-export="json" onClick={() => void props.onExport("json", filters())}>export JSON</button></div></div><div data-audit-list><For each={visibleEntries()}>{(entry) => <div class="resource-row"><code class="resource-kind">{entry.actor}</code><span class="resource-title">{entry.action}</span><code>{entry.target}</code></div>}</For></div></>;
}

function BillingFile(props: { value: any; commands: readonly string[]; mutations: AdminMutations; onAct: (verb: string, command: () => Promise<unknown>) => Promise<void> }): JSX.Element {
    const [plan, setPlan] = createSignal(""); const [seats, setSeats] = createSignal(""); const record = () => props.value?.billing;
    const subscription = () => props.value?.cloud?.subscription;
    return <><h1>Billing</h1><Definition label="Plan" value={record()?.plan || "Not configured"} /><Definition label="Seats" value={record() ? `${props.value.seats_used} / ${record().seats}` : "Unknown"} /><Definition label="Cloud subscription" value={subscription()?.status || (props.value?.cloud?.customer_linked ? "Customer linked" : "Not subscribed")} /><div class="bar"><Show when={props.commands.includes("billing.subscription.checkout")}><button type="button" onClick={() => props.onAct("Propose subscription checkout", () => props.mutations.command("billing.json", "billing.subscription.checkout", { quantity: Math.max(1, Number(seats() || record()?.seats || 1)) }))}>start subscription checkout</button></Show><Show when={props.commands.includes("billing.portal") && props.value?.cloud?.customer_linked}><button type="button" onClick={() => props.onAct("Propose billing portal session", () => props.mutations.command("billing.json", "billing.portal", {}))}>open billing portal</button></Show></div><div class="settings-form"><label class="settings-field"><span class="settings-label">Plan</span><input class="settings-input" value={plan() || record()?.plan || ""} onInput={(event) => setPlan(event.currentTarget.value)} /></label><label class="settings-field"><span class="settings-label">Seats</span><input class="settings-input" type="number" value={seats() || String(record()?.seats ?? 0)} onInput={(event) => setSeats(event.currentTarget.value)} /></label></div><button type="button" onClick={() => props.onAct("Propose billing change", () => props.mutations.setBilling({ plan: plan() || record()?.plan || "", seats: Number(seats() || record()?.seats || 0), managed_inference: record()?.managed_inference ?? null }))}>propose</button></>;
}

function Definition(props: { label: string; value: string }): JSX.Element {
    return <div class="resource-row"><span class="resource-kind">{props.label}</span><strong class="resource-title">{props.value}</strong></div>;
}

function messageOf(error: unknown): string {
    return error instanceof Error ? error.message : String(error);
}
