import { createEffect, createMemo, createResource, createSignal, For, onCleanup, Show, type JSX } from "solid-js";
import { Portal } from "solid-js/web";
import { App, openExternal, type WorkbenchGaugeApps } from "@gaugewright/workbench-web";
import { createGaugeAppResource, gaugeAppMenuIdentity } from "@gaugewright/workbench-ui";
import { availablePopoverHeight } from "./popover-fit";
import {
    type GaugeAppKind,
    type GaugeAppScope,
    parseAccountGaugeAppPage,
    parseAppearancePreference,
} from "@gaugewright/control-plane-client";
import {
    EnterpriseControlPlane,
    setBearer,
    type CommercialProposalAccess,
    type PlacementPolicy,
} from "@gaugewright/enterprise-client";
import { createGaugeAppWorkspace, type GaugeAppWorkspaceController, type OrganizationInvitationAccess } from "./AdministrationGaugeApp";
import { parseDeviceLinkInvitation, type DeviceLinkInvitation } from "./account-device-link";
import { ProposalChat, ProposalContent, ProposalMenu } from "./CommercialProposal";
import { applyAppearancePreference, resetAppearancePreference } from "./appearance-preference";

const APP_LABELS: Readonly<Record<GaugeAppKind, string>> = {
    "account-settings": "Account Settings",
    administration: "Administration",
    "commercial-operations": "Commercial Operations",
};

const PAGE_LABELS: Readonly<Record<string, string>> = {
    account: "Account Settings",
    "provider-connections": "Provider Connections",
    "trusted-devices": "Trusted Devices",
    "application-settings": "Application Settings",
    organization: "Organization",
    "plans-services": "Plans & services",
    people: "People",
    sessions: "Sessions",
    "enterprise-identity": "Enterprise Identity",
    projects: "Projects",
    "model-providers": "Model Providers",
    "organization-policy": "Organization Policy",
    "project-hosts": "Project Hosts",
    backups: "Backups",
    "software-policy": "Software policy",
    billing: "Billing",
    products: "Products",
    clients: "Clients",
    engagements: "Engagements",
    payments: "Payments",
};

interface Membership {
    readonly id: string;
    readonly display_name: string;
    readonly role: string;
    readonly personal: boolean;
    readonly provider_commercial: boolean;
}

function record(value: unknown): Record<string, unknown> | null {
    return typeof value === "object" && value !== null && !Array.isArray(value)
        ? value as Record<string, unknown>
        : null;
}

function initialGaugeApp(): GaugeAppKind | null {
    const requested = new URLSearchParams(window.location.search).get("gaugeapp");
    return requested === "account-settings" || requested === "administration" || requested === "commercial-operations"
        ? requested
        : null;
}

function consumeCommercialProposalLink(): CommercialProposalAccess | null {
    const url = new URL(window.location.href);
    const fragment = new URLSearchParams(url.hash.replace(/^#/, ""));
    const access = {
        tenant_id: url.searchParams.get("proposal_tenant") ?? "",
        engagement_id: url.searchParams.get("proposal") ?? "",
        delivery_id: url.searchParams.get("delivery") ?? "",
        proof: fragment.get("proposal_proof") ?? "",
    };
    if (!access.tenant_id || !access.engagement_id || !access.delivery_id || !access.proof) return null;
    url.searchParams.delete("proposal_tenant");
    url.searchParams.delete("proposal");
    url.searchParams.delete("delivery");
    fragment.delete("proposal_proof");
    url.hash = fragment.toString();
    window.history.replaceState(window.history.state, "", `${url.pathname}${url.search}${url.hash}`);
    return access;
}

const initialCommercialProposal = consumeCommercialProposalLink();

function consumeOrganizationInvitationLink(): OrganizationInvitationAccess | null {
    const url = new URL(window.location.href);
    const fragment = new URLSearchParams(url.hash.replace(/^#/, ""));
    const access = {
        tenant_id: url.searchParams.get("organization_invitation_tenant") ?? "",
        invitation_id: url.searchParams.get("organization_invitation") ?? "",
        proof: fragment.get("organization_invitation_proof") ?? "",
    };
    if (!access.tenant_id || !access.invitation_id || !access.proof) return null;
    url.searchParams.delete("organization_invitation_tenant");
    url.searchParams.delete("organization_invitation");
    fragment.delete("organization_invitation_proof");
    url.hash = fragment.toString();
    window.history.replaceState(window.history.state, "", `${url.pathname}${url.search}${url.hash}`);
    return access;
}

const initialOrganizationInvitation = consumeOrganizationInvitationLink();

function clearDeviceLinkLocation(): void {
    const url = new URL(window.location.href);
    url.searchParams.delete("device_link_id");
    url.searchParams.delete("device_link_code");
    window.history.replaceState(window.history.state, "", `${url.pathname}${url.search}${url.hash}`);
}

function writeManagementLocation(app: GaugeAppKind | null, page?: string, tenant?: string | null): void {
    const url = new URL(window.location.href);
    if (app) url.searchParams.set("gaugeapp", app);
    else url.searchParams.delete("gaugeapp");
    if (page) url.searchParams.set("page", page);
    else url.searchParams.delete("page");
    if (tenant) url.searchParams.set("tenant", tenant);
    else url.searchParams.delete("tenant");
    url.searchParams.delete("environment");
    window.history.replaceState(window.history.state, "", `${url.pathname}${url.search}${url.hash}`);
}

function OrganizationSelector(props: {
    memberships: readonly Membership[];
    selected: string | null;
    administration?: GaugeAppWorkspaceController;
    commercial?: GaugeAppWorkspaceController;
    onSelect: (id: string) => void;
    onCreate: (displayName: string) => Promise<void>;
    onOpen: (app: GaugeAppKind, page: string) => void;
    onWork: () => void;
}): JSX.Element {
    const [open, setOpen] = createSignal(false);
    const [creating, setCreating] = createSignal(false);
    const [organizationName, setOrganizationName] = createSignal("");
    const [createError, setCreateError] = createSignal("");
    const [submitting, setSubmitting] = createSignal(false);
    const [menuHeight, setMenuHeight] = createSignal(0);
    const [menuPosition, setMenuPosition] = createSignal({ left: 8, bottom: 0 });
    let anchor!: HTMLDivElement;
    createEffect(() => {
        if (!open()) return;
        const pane = anchor.closest(".panel-body");
        const fit = () => {
            const rect = anchor.getBoundingClientRect();
            setMenuHeight(availablePopoverHeight(rect.top, pane?.getBoundingClientRect().top ?? 0));
            const width = Math.min(292, Math.max(0, window.innerWidth - 24));
            setMenuPosition({
                left: Math.max(8, Math.min(rect.left, window.innerWidth - width - 8)),
                bottom: window.innerHeight - rect.top + 5,
            });
        };
        fit();
        const observer = new ResizeObserver(fit);
        observer.observe(anchor);
        if (pane) observer.observe(pane);
        window.addEventListener("resize", fit);
        document.addEventListener("scroll", fit, true);
        onCleanup(() => {
            observer.disconnect();
            window.removeEventListener("resize", fit);
            document.removeEventListener("scroll", fit, true);
        });
    });
    const selected = () => props.memberships.find((membership) => membership.id === props.selected);
    const icon = (membership: Membership) => membership.personal ? "◇" : membership.provider_commercial ? "¤" : "▦";
    const pageButtons = (controller: GaugeAppWorkspaceController | undefined, app: GaugeAppKind) =>
        <Show when={controller?.session()}>{(session) => <div class="organization-menu-branch">
            <span>{APP_LABELS[app]}</span>
            <For each={session().pages}>{(page) => <button type="button" onClick={() => {
                setOpen(false);
                props.onOpen(app, page.id);
            }}>{PAGE_LABELS[page.id] ?? page.id}</button>}</For>
        </div>}</Show>;
    const cancelCreate = () => {
        setCreating(false);
        setOrganizationName("");
        setCreateError("");
    };
    const submitCreate = async (event: SubmitEvent) => {
        event.preventDefault();
        const displayName = organizationName().trim();
        if (!displayName || submitting()) return;
        setSubmitting(true);
        setCreateError("");
        try {
            await props.onCreate(displayName);
            cancelCreate();
            setOpen(false);
        } catch (error) {
            setCreateError(error instanceof Error ? error.message : String(error));
        } finally {
            setSubmitting(false);
        }
    };
    return <div class="organization-anchor" ref={anchor}>
        <button type="button" class="organization-trigger" aria-haspopup="menu" aria-expanded={open()} onClick={() => setOpen((value) => !value)}>
            <span class="organization-mark" aria-hidden="true">{selected() ? icon(selected()!) : "◇"}</span>
            <span><small>Organization</small><strong>{selected()?.display_name ?? "Choose organization"}</strong></span>
            <span aria-hidden="true">⌃</span>
        </button>
        <Show when={open()}>
            <Portal>
            <div class="popover-catcher" onClick={() => setOpen(false)} />
            <div class="organization-popover" role="menu" style={{
                "max-height": `${menuHeight()}px`, left: `${menuPosition().left}px`, bottom: `${menuPosition().bottom}px`,
            }}>
                <button type="button" class="organization-work" onClick={() => { setOpen(false); props.onWork(); }}>Work</button>
                <div class="organization-menu-choices">
                    <For each={props.memberships}>{(membership) => <button
                        type="button"
                        classList={{ active: membership.id === props.selected }}
                        onClick={() => props.onSelect(membership.id)}
                    >
                        <span class="organization-mark" aria-hidden="true">{icon(membership)}</span>
                        <span><strong>{membership.display_name}</strong><small>{membership.personal ? "Personal" : membership.role}</small></span>
                    </button>}</For>
                </div>
                <Show when={!creating()} fallback={<form class="organization-create" onSubmit={(event) => void submitCreate(event)}>
                    <label for="organization-create-name">Organization name</label>
                    <input id="organization-create-name" value={organizationName()} onInput={(event) => setOrganizationName(event.currentTarget.value)} autofocus />
                    <Show when={createError()}><p role="alert">{createError()}</p></Show>
                    <div>
                        <button type="submit" disabled={!organizationName().trim() || submitting()}>{submitting() ? "Creating…" : "Create"}</button>
                        <button type="button" onClick={cancelCreate} disabled={submitting()}>Cancel</button>
                    </div>
                </form>}>
                    <button type="button" class="organization-create-trigger" onClick={() => setCreating(true)}>New organization</button>
                </Show>
                {pageButtons(props.administration, "administration")}
                {pageButtons(props.commercial, "commercial-operations")}
            </div>
            </Portal>
        </Show>
    </div>;
}

/** The one GaugeDesk composition. GaugeApps replace pane contents in-place;
 * ordinary work and its chat remain mounted underneath and return unchanged. */
export function EnterpriseWorkbench(): JSX.Element {
    const query = new URLSearchParams(window.location.search);
    const [activeApp, setActiveApp] = createSignal<GaugeAppKind | null>(initialGaugeApp());
    const [deviceLinkInvitation, setDeviceLinkInvitation] = createSignal<DeviceLinkInvitation | null>(
        parseDeviceLinkInvitation(window.location.href),
    );
    const [organizationInvitation, setOrganizationInvitation] = createSignal<OrganizationInvitationAccess | null>(initialOrganizationInvitation);
    const [proposalAccess, setProposalAccess] = createSignal<CommercialProposalAccess | null>(initialCommercialProposal);
    const [tenant, setTenant] = createSignal<string | null>(query.get("tenant"));
    const [projectRequest, setProjectRequest] = createSignal<{ readonly id: string; readonly name: string } | null>(null);
    const api = new EnterpriseControlPlane(undefined, { tenant });
    const [proposalResponse, { refetch: refetchProposal }] = createResource(proposalAccess, (access) =>
        api.previewCommercialProposal(access));
    const proposal = createMemo(() => proposalResponse()?.proposal);
    const [proposalAccepting, setProposalAccepting] = createSignal(false);
    const [proposalAcceptError, setProposalAcceptError] = createSignal("");
    const acceptProposal = async () => {
        const access = proposalAccess();
        if (!access) return;
        setProposalAccepting(true);
        setProposalAcceptError("");
        try {
            await api.acceptCommercialProposal(access);
            await refetchProposal();
        } catch (error) {
            setProposalAcceptError(error instanceof Error ? error.message : String(error));
        } finally {
            setProposalAccepting(false);
        }
    };

    const account = createGaugeAppWorkspace({
        api,
        app: "account-settings",
        enabled: () => true,
        active: () => activeApp() === "account-settings",
        scope: () => undefined,
        openExternal,
        onPageChange: (page) => {
            if (activeApp() === "account-settings") writeManagementLocation("account-settings", page, tenant());
        },
        onAccountErased: () => {
            setBearer(null);
            setTenant(null);
            setActiveApp(null);
            setProposalAccess(null);
            writeManagementLocation(null);
        },
        deviceLinkInvitation,
        onDeviceLinkClaimed: () => {
            setDeviceLinkInvitation(null);
            clearDeviceLinkLocation();
        },
        organizationInvitation,
        onOrganizationInvitationResponded: () => setOrganizationInvitation(null),
    });
    const appearanceGrant = createMemo(() => {
        const session = account.session();
        return session?.pages.some((page) => page.id === "application-settings") ? session : undefined;
    });
    const [accountAppearancePage] = createGaugeAppResource(appearanceGrant,
        (session) => JSON.stringify([session.actor, session.id, session.generation, session.update_cursor]),
        (session) => api.readGaugeAppPage(session, "application-settings"));
    let appearanceSession = "";
    createEffect(() => {
        const admitted = account.session();
        const key = admitted ? JSON.stringify([admitted.actor, admitted.id, admitted.generation]) : "";
        if (key !== appearanceSession) {
            appearanceSession = key;
            resetAppearancePreference();
        }
        if (!admitted) return;
        const current = account.page()?.id === "application-settings"
            ? account.page()
            : accountAppearancePage();
        if (!current) return;
        const parsed = parseAccountGaugeAppPage(current);
        if (parsed.id === "application-settings") {
            applyAppearancePreference(parseAppearancePreference(parsed.model.preferences.appearance, "application-settings.appearance"));
        }
    });
    const [accountIndex, { refetch: refetchAccountIndex }] = createGaugeAppResource(account.session,
        (session) => JSON.stringify([session.actor, session.id, session.generation]),
        (session) => api.readGaugeAppPage(session, "account"));
    const memberships = createMemo<readonly Membership[]>(() => {
        const model = record(accountIndex()?.model);
        const values = Array.isArray(model?.memberships) ? model.memberships : [];
        return values.flatMap((value) => {
            const membership = record(value);
            return membership && typeof membership.id === "string"
                ? [{
                    id: membership.id,
                    display_name: typeof membership.display_name === "string" ? membership.display_name : membership.id,
                    role: typeof membership.role === "string" ? membership.role : "member",
                    personal: membership.personal === true,
                    provider_commercial: membership.provider_commercial === true,
                }]
                : [];
        });
    });
    createEffect(() => {
        if (tenant() || memberships().length === 0) return;
        const first = memberships().find((membership) => membership.personal) ?? memberships()[0];
        setTenant(first?.id ?? null);
    });

    const tenantScope = createMemo<GaugeAppScope | undefined>(() => tenant()
        ? { kind: "tenant", id: tenant()! }
        : undefined);
    const providerScope = createMemo<GaugeAppScope | undefined>(() => tenant()
        ? { kind: "provider-tenant", id: tenant()! }
        : undefined);
    let commercial: GaugeAppWorkspaceController;
    const administration = createGaugeAppWorkspace({
        api,
        app: "administration",
        enabled: () => Boolean(tenant()),
        active: () => activeApp() === "administration",
        scope: tenantScope,
        onPageChange: (page) => {
            if (activeApp() === "administration") writeManagementLocation("administration", page, tenant());
        },
        onOrganizationDeleted: () => {
            const personal = memberships().find((membership) => membership.personal);
            const nextTenant = personal?.id ?? null;
            setTenant(nextTenant);
            setActiveApp(null);
            setProposalAccess(null);
            writeManagementLocation(null, undefined, nextTenant);
            void refetchAccountIndex();
            setProjectRequest(null);
        },
        onOpenProject: setProjectRequest,
        onOpenGaugeApp: (app, page) => openGaugeApp(app, page),
        onTenantServicesChanged: async () => {
            await refetchAccountIndex();
            await commercial.refresh().catch(() => undefined);
        },
    });
    commercial = createGaugeAppWorkspace({
        api,
        app: "commercial-operations",
        // Attempt exact-scope admission and let the server decide. A cached
        // membership label or organization kind is never a capability gate.
        enabled: () => Boolean(tenant()),
        active: () => activeApp() === "commercial-operations",
        scope: providerScope,
        onPageChange: (page) => {
            if (activeApp() === "commercial-operations") writeManagementLocation("commercial-operations", page, tenant());
        },
    });

    const controller = (app: GaugeAppKind | null): GaugeAppWorkspaceController | undefined => {
        if (app === "account-settings") return account;
        if (app === "administration") return administration;
        if (app === "commercial-operations") return commercial;
        return undefined;
    };
    const activeController = createMemo(() => controller(activeApp()));
    const closeGaugeApp = () => {
        setActiveApp(null);
        writeManagementLocation(null, undefined, tenant());
    };
    const closeSurface = () => {
        setProposalAccess(null);
        setProposalAcceptError("");
        closeGaugeApp();
    };
    const openGaugeApp = (app: GaugeAppKind, page: string): void => {
        const target = controller(app);
        if (!target?.session()?.pages.some((candidate) => candidate.id === page)) return;
        setProposalAccess(null);
        // Set the navigation request before activating the App. Its initial
        // selection effect reads this URL synchronously when activeApp changes.
        writeManagementLocation(app, page, tenant());
        target.openPage(page);
        setActiveApp(app);
    };
    if (typeof window !== "undefined") {
        const onDeviceLink = (event: Event) => {
            const value = (event as CustomEvent).detail;
            if (typeof value !== "string") return;
            const invitation = parseDeviceLinkInvitation(value);
            if (invitation) setDeviceLinkInvitation(invitation);
        };
        window.addEventListener("gw-deep-link", onDeviceLink);
        onCleanup(() => window.removeEventListener("gw-deep-link", onDeviceLink));
    }
    createEffect(() => {
        if (!deviceLinkInvitation() || !account.session()) return;
        openGaugeApp("account-settings", "trusted-devices");
    });
    createEffect(() => {
        const app = activeApp();
        if (!app) return;
        const target = controller(app);
        if (target?.session()) {
            const requested = new URLSearchParams(window.location.search).get("page");
            const next = requested && target.session()?.pages.some((page) => page.id === requested)
                ? requested
                : target.session()?.pages[0]?.id;
            if (next) {
                target.openPage(next);
                if (next !== requested) writeManagementLocation(app, next, tenant());
            }
            return;
        }
        if (!target || target.session.error) closeGaugeApp();
    });

    const [governance] = createGaugeAppResource(() => ({ tenant: tenant() }),
        ({ tenant }) => tenant ?? "", () => api.placementGovernance());
    const orgManaged = () => governance()?.managed !== false;
    const placementPolicy = (): PlacementPolicy | undefined => {
        const value = governance();
        return value?.managed === true ? value.policy : undefined;
    };

    const gaugeApps: WorkbenchGaugeApps = {
        active: () => Boolean(proposalAccess() || activeController()?.session()),
        accountIdentity: () => gaugeAppMenuIdentity(
            account.session.error ? undefined : account.session(), accountIndex(),
        ),
        accountActions: () => (account.session()?.pages ?? []).map((page) => ({
            id: page.id,
            label: PAGE_LABELS[page.id] ?? page.id,
            open: () => openGaugeApp("account-settings", page.id),
        })),
        organizationSelector: () => <OrganizationSelector
            memberships={memberships()}
            selected={tenant()}
            administration={administration.admitted() ? administration : undefined}
            commercial={commercial.admitted() ? commercial : undefined}
            onSelect={(id) => {
                setTenant(id);
                closeGaugeApp();
                writeManagementLocation(null, undefined, id);
            }}
            onCreate={async (displayName) => {
                const created = await api.createOrganization(displayName);
                await refetchAccountIndex();
                setTenant(created.id);
                closeGaugeApp();
                writeManagementLocation(null, undefined, created.id);
            }}
            onOpen={openGaugeApp}
            onWork={closeSurface}
        />,
        chat: (controls) => proposalAccess()
            ? <ProposalChat preview={proposal()} onClose={closeSurface} />
            : activeController()?.chat(controls) ?? <p>Management conversation unavailable.</p>,
        content: () => proposalAccess()
            ? <ProposalContent preview={proposal()} loading={proposalResponse.loading} error={proposalResponse.error} accepting={proposalAccepting()} actionError={proposalAcceptError()} onAccept={() => void acceptProposal()} />
            : activeController()?.content() ?? <p>Management page unavailable.</p>,
        menu: () => proposalAccess()
            ? <ProposalMenu preview={proposal()} />
            : activeController()?.menu() ?? <nav aria-label="Management pages" />,
        titles: () => proposalAccess() ? {
            chat: "Proposal",
            content: "Commercial proposal",
            files: "Details",
        } : ({
            chat: `${APP_LABELS[activeApp() ?? "account-settings"]} agent`,
            content: APP_LABELS[activeApp() ?? "account-settings"],
            files: "Menu",
        }),
        onNewChat: () => undefined,
        projectRequest,
        clearProjectRequest: () => setProjectRequest(null),
        get projectShareCandidates() {
            return tenant()
                ? () => api.projectShareCandidates(tenant()!)
                : undefined;
        },
        get openOrganizationPeople() {
            return administration.session()?.pages.some((page) => page.id === "people")
                ? () => openGaugeApp("administration", "people")
                : undefined;
        },
        close: closeSurface,
        onNativeAccountSessionChanged: async (linked) => {
            if (!linked) closeSurface();
            // The boolean is only a wake-up signal. Session, page grants,
            // identity, memberships, and chat all come back through the local
            // control plane's sealed account-authority proxy.
            await account.refresh().catch(() => undefined);
            await refetchAccountIndex().catch(() => undefined);
        },
        onMobileAccountToken: async (token) => {
            setBearer(token);
            if (!token) {
                closeSurface();
                return;
            }
            // The native handoff is the first moment this WebView owns an
            // account bearer. Re-admit from each owning server rather than
            // treating the OS-vault token or an earlier failed resource as
            // management state.
            await account.refresh();
            await refetchAccountIndex();
            if (tenant()) {
                await Promise.all([
                    administration.refresh().catch(() => undefined),
                    commercial.refresh().catch(() => undefined),
                ]);
            }
        },
    };

    return <App
        onTenantContextChange={(requested) => {
            if (requested && requested !== tenant()) setTenant(requested);
        }}
        placementPolicy={orgManaged() ? placementPolicy : undefined}
        gaugeApps={gaugeApps}
    />;
}
