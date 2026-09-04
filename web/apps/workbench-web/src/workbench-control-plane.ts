import * as accountClient from "@gaugewright/control-plane-client";
import * as federationClient from "@gaugewright/control-plane-client";
import * as workbenchClient from "@gaugewright/control-plane-client";
import type {
    AccessPhase,
    AgentKind,
    ArchetypeId,
    AuditEvent,
    Engagement,
    EngagementId,
    ExportState,
    FileEntry,
    HumanTask,
    MergeAction,
    MergeState,
    PlacementId,
    PanelPublicProfile,
    PanelPreviewInput,
    PanelPreviewOutcome,
    CollectionRecipient,
    PublicDeploymentInput,
    PublicDeploymentInspection,
    PublicDeploymentOutcome,
    PublicCredentialMetadata,
    ProvisionPublicCredentialInput,
    ProjectId,
    ResourceView,
    RosterPerson,
    ResourceExportAction,
    ResourceReviewAction,
    ReviewState,
    RunCommand,
    RunState,
    ScopeId,
    SearchHit,
    StreamEvent,
    WorkstreamId,
    WorkstreamNode,
    WorkTargetId,
    WorkTargetNode,
    Workspace,
    WorkspaceChange,
    WorkspaceDelta,
    ProjectionCarriage,
    ProjectHome,
    AccountHome,
    HomeId,
    OpaqueHomeRoute,
    CreatedHomeInvitation,
    TunnelRoute,
    StopTurnResult,
} from "@gaugewright/control-plane-client";
import {
    browserTunnelSocket,
    HomePool,
    openTunnel,
    tunnelAvailable,
    tunnelRouteJson,
    UnroutedHomeError,
} from "@gaugewright/control-plane-client";
import {
    browserRouteEventStream,
    browserRouteJson,
    browserRouteRequest,
    controlPlaneBase,
    isSecureControlPlaneEndpoint,
    RemoteControlPlane,
    type RouteEventStream,
    type RouteJson,
    type RouteRequest,
} from "@gaugewright/control-plane-client";
import type { ControlPlane } from "@gaugewright/control-plane-client";

export { controlPlaneBase };

export type HomeBootstrapState =
    | { readonly kind: "direct" }
    | { readonly kind: "connected"; readonly home: AccountHome }
    | {
          readonly kind: "none";
          readonly homes: AccountHome[];
          readonly routes: OpaqueHomeRoute[];
      };

/** A Console-safe pointer: the owning workspace and a count, never review data. */
export interface TenantReviewNotification {
    readonly tenant: string;
    readonly count: number;
    /** Homes that could not be checked after target admission. */
    readonly unavailableHomes: number;
}

/** A member-visible, non-secret projection used only to decide whether the
 * signed desktop updater may offer its stable release lane. */
export interface SoftwareUpdatePolicy {
    readonly allowedChannels: readonly string[];
}

class NoSelectedHomeError extends Error {}

/** The single-Home rollout can expose its private Home origin before a
 * tenant-owned Home is provisioned. That is an onboarding state, not an
 * authorization failure: return the ordinary setup surface instead of showing
 * the raw Home response. */
function isUnprovisionedHomeError(error: unknown): boolean {
    const message = error instanceof Error ? error.message : String(error ?? "");
    return /POST \/home\/admissions: 403 Home has no active owner/.test(message);
}

/** App-owned control-plane edge for the open workbench shell. */
export class WorkbenchControlPlane implements ControlPlane {
    private bearer: string | null = null;
    private homeAdmission: string | null = null;
    private readonly route: RouteJson;
    private readonly request: RouteRequest;
    private readonly events: RouteEventStream;
    private readonly splitHomes: boolean;
    private readonly workTransport: workbenchClient.WorkbenchTransport;
    private homeTransport: Promise<workbenchClient.WorkbenchTransport> | null = null;
    /** Several Homes at once, resolved per project (DESK-3). There is no
     * selected Home here: whichever project is open decides which Home serves,
     * and a Home that fails degrades only the projects routed to it. */
    private pool: HomePool<workbenchClient.WorkbenchTransport> | null = null;
    private currentProject: ProjectId | null = null;

    constructor(
        private readonly base = controlPlaneBase(),
        options: { readonly splitHomes?: boolean } = {},
    ) {
        this.splitHomes = options.splitHomes ?? import.meta.env?.VITE_HOME_SPLIT === "true";
        const auth = {
            bearer: () => this.bearer,
            // In split mode this is the Hub transport. A Home credential must
            // never leak onto account-plane requests: besides crossing the
            // authority boundary, the edge uses that header to select Home.
            homeAdmission: () => (this.splitHomes ? null : this.homeAdmission),
        };
        this.route = browserRouteJson(this.base, auth);
        this.request = browserRouteRequest(this.base, auth);
        this.events = browserRouteEventStream(this.base, auth);
        this.workTransport = this.splitHomes
            ? {
                  base: "",
                  json: async (...args) => (await this.requireHomeTransport()).json(...args),
                  request: async (...args) => {
                      const request = (await this.requireHomeTransport()).request;
                      if (!request) throw new Error("Home raw transport unavailable");
                      return request(...args);
                  },
                  events: (path, onMessage, onOpen) => {
                      let closed = false;
                      let stop = () => {};
                      void this.requireHomeTransport()
                          .then((transport) => {
                              if (!closed && transport.events) {
                                  stop = transport.events(path, onMessage, onOpen);
                              }
                          })
                          .catch(() => {});
                      return () => {
                          closed = true;
                          stop();
                      };
                  },
              }
            : {
                  base: this.base,
                  json: this.route,
                  request: this.request,
                  events: this.events,
              };
    }

    setBearer(token: string | null): void {
        if (this.bearer !== token) {
            this.homeAdmission = null;
            this.homeTransport = null;
            void this.pool?.closeAll().catch(() => undefined);
            this.pool = null;
        }
        this.bearer = token;
    }

    /**
     * The signed-in subject, read from the bearer's own claims (DESK-5g).
     *
     * It namespaces the root-key pin, nothing more: signing out as one person
     * and in as another must not compare keys across them (ADR 0132 §5). No
     * signature check is needed or wanted here — a forged subject would only
     * pin under a namespace that grants nothing, while verifying would need a
     * key this page has no way to hold.
     */
    private subject(): string {
        const token = this.bearer;
        if (!token) return "";
        const claims = token.split(".")[1];
        if (!claims) return "";
        try {
            const decoded = JSON.parse(atob(claims.replace(/-/g, "+").replace(/_/g, "/"))) as {
                sub?: unknown;
            };
            return typeof decoded.sub === "string" ? decoded.sub : "";
        } catch {
            return "";
        }
    }

    /**
     * Project→Home routes across both channels (DESK-5g, ADR 0133 §3): the
     * root-signed record where it verifies against the pinned root, the hub's
     * table for endpoints otherwise. Every route read in this client goes
     * through here, so provenance and pinning cannot diverge between call sites.
     */
    private async homeRoutes(): Promise<OpaqueHomeRoute[]> {
        const resolved = await accountClient.resolveHomeRoutes({
            json: this.route,
            subject: this.subject(),
            // Said once, at warning level: a browser that cannot use the signed
            // record falls back to endpoint-only reachability, which is correct
            // and indistinguishable from having no signed routes at all. Every
            // relay-only Home is unreachable in that state, so it must not be
            // silent (ADR 0131 §3).
            onDegraded: (reason) => {
                console.warn("[account] no signed Home routes: %s", reason);
            },
            onRootKeyConflict: (error) => {
                // Surfaced, never silently adopted: this is the substitution the
                // pin exists to catch (ADR 0132 §2). Reachability is unaffected
                // — the endpoints still work — so it is reported rather than
                // thrown at a caller who was only opening a project.
                console.error("[account] %s", error.message);
            },
        });
        return resolved.routes;
    }

    setHomeAdmission(token: string | null): void {
        this.homeAdmission = token;
    }

    async admitHome(): Promise<string> {
        const result = (await this.route("POST", "/home/admissions")) as {
            home?: unknown;
            admission?: unknown;
        };
        if (typeof result.home !== "string" || typeof result.admission !== "string") {
            throw new Error("Home admission response is malformed");
        }
        this.homeAdmission = result.admission;
        return result.home;
    }

    private routeJson(): RouteJson {
        return this.route;
    }

    private workbenchTransport(): workbenchClient.WorkbenchTransport {
        return this.workTransport;
    }

    private async runtimeAccountJson(): Promise<RouteJson> {
        return this.splitHomes ? (await this.requireHomeTransport()).json : this.route;
    }

    /** Open a project, so subsequent work resolves to *its* Home. Passing null
     * returns to whatever the account last selected. */
    setCurrentProject(project: ProjectId | null): void {
        if (this.currentProject === project) return;
        this.currentProject = project;
        // Only the per-project path is invalidated; other Homes in the pool keep
        // their connections, which is the point of holding several.
        this.homeTransport = null;
    }

    /** Resolve the transport for the work in hand.
     *
     * Every work call in this client funnels through here, so per-project
     * resolution lands in one place rather than in each caller. A project with a
     * granted route is served by its own Home through the pool; anything else
     * falls back to the account's selected Home, which is what accounts whose
     * Homes have not yet authored routes still rely on (DESK-5a). */
    private requireHomeTransport(): Promise<workbenchClient.WorkbenchTransport> {
        if (!this.splitHomes) return Promise.resolve(this.workTransport);
        const project = this.currentProject;
        if (project) {
            this.homeTransport ??= this.connectRoutedProject(project).catch((error) => {
                // A project with no granted route is not an error: it predates
                // authorship, so the selected Home still serves it.
                if (String(error).includes("no granted Home route")) {
                    this.homeTransport = null;
                    return this.connectSelectedHome();
                }
                throw error;
            });
            return this.homeTransport;
        }
        this.homeTransport ??= this.connectSelectedHome();
        return this.homeTransport;
    }

    /** Connect the exact Home a project is routed to, reusing a live connection
     * when the pool already holds one. */
    private async connectRoutedProject(
        project: ProjectId,
    ): Promise<workbenchClient.WorkbenchTransport> {
        const pool = await this.homePool();
        const route = pool.routeFor(project);
        // A relay-only route is not dialable without a tunnel module. That is
        // an absence of a usable route, not a broken connection, so it reads as
        // one and the account's selected Home serves instead.
        if (!route.endpoint && !(route.relay && tunnelAvailable())) {
            throw new Error(`no granted Home route for project ${project}`);
        }
        const connection = await pool.connectProject(project);
        return connection.api;
    }

    /** The account's project→Home routes, as a live pool. Built once and
     * refreshed whenever the account directory is re-read. */
    private async homePool(): Promise<HomePool<workbenchClient.WorkbenchTransport>> {
        if (this.pool) return this.pool;
        const routes = await this.homeRoutes();
        // The live carrier per relay-only Home. A tunnel is not reclaimed by
        // being forgotten: the Home stays spliced to a client that has gone and
        // never re-parks, so the *next* attempt to reach it waits for a splice
        // that cannot happen. The pool tells us when a Home is done with.
        const tunnels = new Map<HomeId, TunnelRoute>();
        this.pool = new HomePool<workbenchClient.WorkbenchTransport>(
            routes,
            () => this.bearer,
            {
                // A Home with no endpoint is reachable only through the relay.
                // Serve it over the tunnel when this build registered a module;
                // otherwise fall through, so a build without one behaves exactly
                // as it did rather than failing in a new way (DESK-7).
                routeJson: (endpoint, auth, route) => {
                    const relay = route.relay;
                    if (route.endpoint || !relay || !tunnelAvailable()) {
                        return browserRouteJson(endpoint, auth);
                    }
                    const carried = tunnelRouteJson({
                        open: async () => {
                            const { tunnel, handshake } = await openTunnel(relay);
                            const url = `${relay.endpoint}/v1/relay/${relay.handle}`;
                            return { tunnel, socket: await browserTunnelSocket(url, handshake) };
                        },
                    });
                    // A re-admission after a rotation builds a new carrier for a
                    // Home that already has one. Hang the old one up here rather
                    // than waiting for a `closeRoute` that will name only the
                    // survivor.
                    tunnels.get(route.homeId)?.close();
                    tunnels.set(route.homeId, carried);
                    return carried;
                },
                closeRoute: async (homeId) => {
                    tunnels.get(homeId)?.close();
                    tunnels.delete(homeId);
                },
                client: (context) => {
                    const auth = {
                        bearer: context.bearer,
                        homeAdmission: context.homeAdmission,
                    };
                    // The tunnel carries JSON calls and nothing else: raw
                    // fetches and the SSE stream are still browser-native, and a
                    // Home with no endpoint gives them no origin to aim at.
                    // Omitting them makes callers say so — `workTransport`
                    // raises "Home raw transport unavailable" and the event
                    // subscription simply does not start — rather than firing
                    // relative requests at desk's own origin, where they would
                    // come back as this page's HTML.
                    if (!context.endpoint) {
                        return { base: "", json: context.routeJson };
                    }
                    return {
                        base: context.endpoint,
                        json: context.routeJson,
                        request: browserRouteRequest(context.endpoint, auth),
                        events: browserRouteEventStream(context.endpoint, auth),
                    };
                },
                // A Home rotates its locator on a schedule, which invalidates
                // outstanding ones the moment it lands. Re-reading once turns
                // that into a reconnect instead of an unreachable Home.
                refreshRoutes: () => this.homeRoutes(),
            },
        );
        return this.pool;
    }

    /** The Home that answers work not scoped to a project — the chat list, the
     * workspace, the account's own view of itself. */
    private async connectSelectedHome(): Promise<workbenchClient.WorkbenchTransport> {
        const state = await accountClient.accountHomes(this.route);
        const selected = state.homes.find((home) => home.id === state.selectedHome);
        if (!selected) throw new NoSelectedHomeError("No reachable Home is selected");
        // No address to dial (ADR 0134 §3). Its reachability lives in the
        // root-signed record, which the pool already reads and verifies — and
        // going through the pool rather than around it means the project work on
        // this Home shares the one tunnel and the one admission (§4).
        //
        // Note what is *not* read here: the locator on the account Home record.
        // Anyone holding the person's session can write that table, so its pin
        // proves nothing (ADR 0131 §3).
        if (!selected.endpoint) {
            const pool = await this.homePool();
            return (await pool.connectHome(selected.id)).api;
        }
        let admission: string | null = null;
        const auth = {
            bearer: () => this.bearer,
            homeAdmission: () => admission,
        };
        const json = browserRouteJson(selected.endpoint, auth);
        const result = (await json("POST", "/home/admissions")) as {
            home?: unknown;
            admission?: unknown;
        };
        if (result.home !== selected.id || typeof result.admission !== "string") {
            throw new Error(`Selected Home identity mismatch: expected ${selected.id}`);
        }
        admission = result.admission;
        this.homeAdmission = admission;
        return {
            base: selected.endpoint,
            json,
            request: browserRouteRequest(selected.endpoint, auth),
            events: browserRouteEventStream(selected.endpoint, auth),
        };
    }

    async bootstrapHome(): Promise<HomeBootstrapState> {
        if (!this.splitHomes) return { kind: "direct" };
        try {
            await this.requireHomeTransport();
            const state = await accountClient.accountHomes(this.route);
            const home = state.homes.find((item) => item.id === state.selectedHome);
            if (!home) throw new NoSelectedHomeError("No reachable Home is selected");
            return { kind: "connected", home };
        } catch (error) {
            // A selected Home that has published no route belongs with the other
            // "no Home is serving you yet" states, not with connection failures
            // (ADR 0134 §5): the surface below lists the account's Homes and
            // routes, which is exactly what someone in that position needs.
            if (
                !(error instanceof NoSelectedHomeError)
                && !(error instanceof UnroutedHomeError)
                && !isUnprovisionedHomeError(error)
            ) {
                throw error;
            }
            this.homeTransport = null;
            const [state, routes] = await Promise.all([
                accountClient.accountHomes(this.route),
                this.homeRoutes(),
            ]);
            return { kind: "none", homes: state.homes, routes };
        }
    }

    async connectHome(endpoint: string): Promise<HomeBootstrapState> {
        const normalized = endpoint.trim().replace(/\/+$/, "");
        if (!isSecureControlPlaneEndpoint(normalized)) {
            throw new Error("Use an HTTPS Home endpoint (HTTP is allowed only on this computer)");
        }
        const home = new RemoteControlPlane(normalized, { bearer: () => this.bearer });
        const id = (await home.admitHome()) as HomeId;
        await accountClient.accountRegisterHome(
            this.route,
            { id, kind: "registered", endpoint: normalized },
            true,
        );
        this.homeTransport = null;
        return this.bootstrapHome();
    }

    async selectHome(id: HomeId): Promise<HomeBootstrapState> {
        await accountClient.accountSelectHome(this.route, id);
        this.homeTransport = null;
        return this.bootstrapHome();
    }

    /** Resolve a Console workspace to its tenant-owned Cloud Home before project
     * work mounts. The membership-gated Hub route is authoritative; a local
     * resume hint can never select another tenant's Home. */
    async selectTenantWorkspace(tenant: string): Promise<void> {
        if (!this.splitHomes) return;
        const home = await this.getCloudHome(tenant);
        if (home.status !== "active") {
            throw new Error("This workspace's Cloud Home is not active yet.");
        }
        await accountClient.accountRegisterHome(this.route, {
            id: home.homeId,
            kind: "cloud",
            endpoint: home.endpoint,
        }, true);
        this.homeAdmission = null;
        this.homeTransport = null;
    }

    tenantHosts(tenant: string): Promise<accountClient.TenantHost[]> {
        return accountClient.tenantHosts(this.route, tenant);
    }

    tenantFacilities(tenant: string): Promise<accountClient.AccountFacility[]> {
        return accountClient.tenantFacilities(this.route, tenant);
    }

    /** Read each currently accessible tenant Home through a short-lived target
     * admission and return only a pending-review count for its workspace. This
     * never selects/registers a Home in the account directory. */
    async reviewNotifications(
        tenants: readonly accountClient.AccountTenant[],
    ): Promise<TenantReviewNotification[]> {
        return Promise.all(tenants.map(async (tenant) => {
            const [hosts, facilities] = await Promise.allSettled([
                this.tenantHosts(tenant.id),
                this.tenantFacilities(tenant.id),
            ]);
            let unavailableHomes = hosts.status === "rejected" ? 1 : 0;
            const targets: Array<{ homeId: string; endpoint: string }> =
                hosts.status === "fulfilled"
                    ? hosts.value.map((host) => ({ homeId: host.homeId, endpoint: host.endpoint }))
                    : [];
            const cloudFacilityHeld = facilities.status === "fulfilled"
                && facilities.value.some((facility) =>
                    facility.owner === "tenant"
                    && facility.kind === "hosted_home_node"
                    && facility.status === "active",
                );
            // A missing Cloud Home is an ordinary facility projection, not an
            // exceptional route probe. Retain the direct-read fallback only
            // when the independently deployed facility endpoint is unavailable.
            if (cloudFacilityHeld || facilities.status === "rejected") {
                try {
                    const cloudHome = await this.getCloudHome(tenant.id);
                    if (cloudHome.status === "active") {
                        targets.push({ homeId: cloudHome.homeId, endpoint: cloudHome.endpoint });
                    }
                } catch (error) {
                    if (!String(error).includes(": 404")) unavailableHomes += 1;
                }
            }
            const seen = new Set<string>();
            const uniqueTargets = targets.filter((target) => {
                const key = `${target.homeId}\n${target.endpoint}`;
                if (seen.has(key)) return false;
                seen.add(key);
                return true;
            });
            const counts = await Promise.all(uniqueTargets.map(async (target) => {
                const home = new RemoteControlPlane(target.endpoint, { bearer: () => this.bearer });
                try {
                    if (await home.admitHome() !== target.homeId) {
                        unavailableHomes += 1;
                        return 0;
                    }
                    return await home.reviewNotificationCount();
                } catch {
                    unavailableHomes += 1;
                    return 0;
                } finally {
                    await home.revokeHomeAdmission().catch(() => {});
                }
            }));
            return { tenant: tenant.id, count: counts.reduce((total, count) => total + count, 0), unavailableHomes };
        }));
    }

    /** Operational host evidence is browser-collected after Home admission and
     * deliberately stays out of the Hub's tenant directory. */
    async tenantHostOverviews(tenant: string): Promise<accountClient.TenantHostOverview[]> {
        const hosts = await this.tenantHosts(tenant);
        return Promise.all(hosts.map(async (host) => {
            const home = new RemoteControlPlane(host.endpoint, { bearer: () => this.bearer });
            try {
                const admitted = await home.admitHome();
                if (admitted !== host.homeId) {
                    return { ...host, reachability: "identity-mismatch", projects: [] };
                }
                const workspace = await home.getWorkspace();
                return {
                    ...host,
                    reachability: "online",
                    projects: workspace.projects.map((project) => ({ id: project.id, name: project.name })),
                };
            } catch {
                return { ...host, reachability: "offline", projects: [] };
            } finally {
                await home.revokeHomeAdmission().catch(() => {});
            }
        }));
    }

    /** Select one tenant-owned registered Home after freshly verifying the
     * directory pointer. Work is then mounted through the normal adapter. */
    async selectTenantHost(tenant: string, hostId: string): Promise<void> {
        const host = (await this.tenantHosts(tenant)).find((item) => item.id === hostId);
        if (!host) throw new Error("This computer is no longer registered for the workspace.");
        const home = new RemoteControlPlane(host.endpoint, { bearer: () => this.bearer });
        try {
            const admitted = await home.admitHome();
            if (admitted !== host.homeId) {
                throw new Error("This computer no longer identifies as its registered Home.");
            }
        } finally {
            await home.revokeHomeAdmission().catch(() => {});
        }
        await accountClient.accountRegisterHome(this.route, {
            id: host.homeId,
            kind: "registered",
            endpoint: host.endpoint,
        }, true);
        this.homeAdmission = null;
        this.homeTransport = null;
    }

    getCloudHome(tenant: string): Promise<accountClient.CloudHomeProjection> {
        return accountClient.getCloudHome(this.route, tenant);
    }
    queueBackgroundCommand(
        chat: EngagementId,
        prompt: string,
        runAt?: number,
    ): Promise<accountClient.BackgroundCommand> {
        return accountClient.queueBackgroundCommand(this.workbenchTransport(), chat, prompt, runAt);
    }

    listBackgroundCommands(chat: EngagementId): Promise<accountClient.BackgroundCommand[]> {
        return accountClient.listBackgroundCommands(this.workbenchTransport(), chat);
    }

    cancelBackgroundCommand(id: string): Promise<accountClient.BackgroundCommand> {
        return accountClient.cancelBackgroundCommand(this.workbenchTransport(), id);
    }

    async acceptHomeInvitation(invite: string): Promise<HomeBootstrapState> {
        if (!this.splitHomes) throw new Error("Home invitations require hosted Home routing");
        const accepted = await accountClient.acceptHomeInvitation(invite, {
            bearer: () => this.bearer,
        });
        const home: AccountHome = {
            id: accepted.homeId,
            kind: "registered",
            endpoint: accepted.endpoint,
        };
        await accountClient.accountRegisterHome(this.route, home, true);
        await accountClient.accountPublishHomeRoute(this.route, {
            project: accepted.project,
            homeId: accepted.homeId,
            endpoint: accepted.endpoint,
        });
        this.homeAdmission = accepted.admission;
        this.homeTransport = Promise.resolve(
            accountClient.acceptedHomeTransport(accepted, () => this.bearer),
        );
        return { kind: "connected", home };
    }

    async createHomeInvitation(
        authority: string,
        project: ProjectId,
        role: "member" | "viewer" = "member",
    ): Promise<CreatedHomeInvitation> {
        const state = await accountClient.accountHomes(this.route);
        const selected = state.homes.find((home) => home.id === state.selectedHome);
        if (!selected) throw new NoSelectedHomeError("No reachable Home is selected");
        const transport = await this.requireHomeTransport();
        return accountClient.createHomeInvitation(transport.json, {
            authority: authority.trim(),
            project,
            endpoint: selected.endpoint,
            role,
        });
    }

    getRun(scope: ScopeId): Promise<RunState> {
        return workbenchClient.getRun(this.workbenchTransport(), scope);
    }

    listEngagements(): Promise<EngagementId[]> {
        return workbenchClient.listEngagements(this.workbenchTransport());
    }

    getWorkspace(): Promise<Workspace> {
        return workbenchClient.getWorkspace(this.workbenchTransport());
    }

    getWorkspaceCarriage(): Promise<ProjectionCarriage<Workspace>> {
        return workbenchClient.getWorkspaceCarriage(this.workbenchTransport());
    }

    getWorkspaceDeltaCarriage(
        change: WorkspaceChange,
    ): Promise<ProjectionCarriage<WorkspaceDelta>> {
        return workbenchClient.getWorkspaceDeltaCarriage(
            this.workbenchTransport(),
            change,
        );
    }

    getTasks(): Promise<HumanTask[]> {
        return workbenchClient.getTasks(this.workbenchTransport());
    }

    getRoster(): Promise<RosterPerson[]> {
        return workbenchClient.getRoster(this.workbenchTransport());
    }

    assignWorkItem(boundary: string, item: string, to: string | null): Promise<string | null> {
        return workbenchClient.assignWorkItem(this.workbenchTransport(), boundary, item, to);
    }

    async softwareUpdatePolicy(): Promise<SoftwareUpdatePolicy | null> {
        try {
            const value = await this.workbenchTransport().json("GET", "/admin/software-policy") as {
                software_policy?: { allowed_channels?: unknown };
            };
            const channels = value.software_policy?.allowed_channels;
            return {
                allowedChannels: Array.isArray(channels)
                    ? channels.filter((channel): channel is string => typeof channel === "string")
                    : [],
            };
        } catch (error) {
            // The open/solo control plane intentionally has no Administration
            // route; that is an unmanaged installation, not an updater failure.
            if (String(error).includes(" 404")) return null;
            throw error;
        }
    }

    search(query: string): Promise<SearchHit[]> {
        return workbenchClient.search(this.workbenchTransport(), query);
    }

    createArchetype(name: string, kind: AgentKind = "work"): Promise<ArchetypeId> {
        return workbenchClient.createArchetype(this.workbenchTransport(), name, kind);
    }

    copyAgentAsPanel(id: ArchetypeId, name?: string): Promise<ArchetypeId> {
        return workbenchClient.copyAgentAsPanel(this.workbenchTransport(), id, name);
    }

    getPanelProfile(id: ArchetypeId): Promise<PanelPublicProfile> {
        return workbenchClient.getPanelProfile(this.workbenchTransport(), id);
    }

    setPanelProfile(id: ArchetypeId, profile: PanelPublicProfile): Promise<PanelPublicProfile> {
        return workbenchClient.setPanelProfile(this.workbenchTransport(), id, profile);
    }

    renameArchetype(id: ArchetypeId, name: string): Promise<void> {
        return workbenchClient.renameArchetype(this.workbenchTransport(), id, name);
    }

    getArchetypeConfig(id: ArchetypeId): Promise<string> {
        return workbenchClient.getArchetypeConfig(this.workbenchTransport(), id);
    }

    setArchetypeConfig(id: ArchetypeId, config: string): Promise<void> {
        return workbenchClient.setArchetypeConfig(this.workbenchTransport(), id, config);
    }

    getArchetypeAbilities(id: ArchetypeId): Promise<workbenchClient.AgentAbility[]> {
        return workbenchClient.getArchetypeAbilities(this.workbenchTransport(), id);
    }

    setArchetypeAbilities(
        id: ArchetypeId,
        abilities: workbenchClient.AgentAbility[],
    ): Promise<void> {
        return workbenchClient.setArchetypeAbilities(
            this.workbenchTransport(),
            id,
            abilities,
        );
    }

    getPlacementAbilities(id: PlacementId): Promise<workbenchClient.AgentAbility[]> {
        return workbenchClient.getPlacementAbilities(this.workbenchTransport(), id);
    }

    deleteArchetype(id: ArchetypeId): Promise<void> {
        return workbenchClient.deleteArchetype(this.workbenchTransport(), id);
    }

    forkArchetype(id: ArchetypeId, name?: string): Promise<ArchetypeId> {
        return workbenchClient.forkArchetype(this.workbenchTransport(), id, name);
    }

    pullFromSource(id: ArchetypeId): Promise<void> {
        return workbenchClient.pullFromSource(this.workbenchTransport(), id);
    }

    publishArchetype(id: ArchetypeId, autoUpgrade?: boolean): Promise<{ version: number; autoUpgraded: number }> {
        return workbenchClient.publishArchetype(this.workbenchTransport(), id, autoUpgrade);
    }

    upgradePlacement(placementId: PlacementId): Promise<number> {
        return workbenchClient.upgradePlacement(this.workbenchTransport(), placementId);
    }

    acceptPlacement(placementId: PlacementId): Promise<void> {
        return workbenchClient.acceptPlacement(this.workbenchTransport(), placementId);
    }

    getPlacementDistribution(placementId: PlacementId): Promise<workbenchClient.PlacementDistributionStatus> {
        return workbenchClient.getPlacementDistribution(this.workbenchTransport(), placementId);
    }

    setPlacementDistribution(
        placementId: PlacementId,
        input: {
            profile: workbenchClient.DistributionProfile;
            recipient_authority?: string;
            recipient_display_name?: string;
            lease_seconds?: number;
            max_runs?: number;
        },
    ): Promise<workbenchClient.PlacementDistributionStatus> {
        return workbenchClient.setPlacementDistribution(this.workbenchTransport(), placementId, input);
    }

    revokePlacementDistribution(placementId: PlacementId): Promise<workbenchClient.PlacementDistributionStatus> {
        return workbenchClient.revokePlacementDistribution(this.workbenchTransport(), placementId);
    }

    renewPlacementDistribution(placementId: PlacementId): Promise<workbenchClient.PlacementDistributionStatus> {
        return workbenchClient.renewPlacementDistribution(this.workbenchTransport(), placementId);
    }

    getPlacementDistributionAudit(placementId: PlacementId): Promise<{
        events: readonly { action: string; at: number; uses: number; detail: string }[];
    }> {
        return workbenchClient.getPlacementDistributionAudit(this.workbenchTransport(), placementId);
    }

    getPlacementConfig(placementId: PlacementId): Promise<{ config: string; notes: string }> {
        return workbenchClient.getPlacementConfig(this.workbenchTransport(), placementId);
    }

    setPlacementConfig(placementId: PlacementId, config: string, notes: string): Promise<void> {
        return workbenchClient.setPlacementConfig(this.workbenchTransport(), placementId, config, notes);
    }

    forkChat(id: EngagementId, destination?: workbenchClient.ForkDestination): Promise<EngagementId> {
        return workbenchClient.forkChat(this.workbenchTransport(), id, destination);
    }

    forkChatAt(id: EngagementId, entryId: number, destination?: workbenchClient.ForkDestination): Promise<EngagementId> {
        return workbenchClient.forkChatAt(this.workbenchTransport(), id, entryId, destination);
    }

    revertChat(id: EngagementId): Promise<void> {
        return workbenchClient.revertChat(this.workbenchTransport(), id);
    }

    createProject(name: string): Promise<ProjectId> {
        return workbenchClient.createProject(this.workbenchTransport(), name);
    }

    attachTarget(
        projectId: ProjectId,
        name: string,
        kind: "external-vcs" | "external-folder",
        path: string,
    ): Promise<WorkTargetNode> {
        return workbenchClient.attachTarget(this.workbenchTransport(), projectId, name, kind, path);
    }

    renameProject(id: ProjectId, name: string): Promise<void> {
        return workbenchClient.renameProject(this.workbenchTransport(), id, name);
    }

    setProjectNetworkIsolated(id: ProjectId, isolated: boolean): Promise<void> {
        return workbenchClient.setProjectNetworkIsolated(this.workbenchTransport(), id, isolated);
    }

    deleteProject(id: ProjectId): Promise<void> {
        return workbenchClient.deleteProject(this.workbenchTransport(), id);
    }

    projectHome(id: ProjectId): Promise<ProjectHome> {
        return workbenchClient.projectHome(this.workbenchTransport(), id);
    }

    forkTree(): Promise<import("@gaugewright/control-plane-client").ForkNode[]> {
        return accountClient.forkTree(this.routeJson());
    }

    placeArchetype(
        pid: ProjectId,
        archetypeId: ArchetypeId,
        recipient?: CollectionRecipient,
    ): Promise<PlacementId> {
        return workbenchClient.placeArchetype(this.workbenchTransport(), pid, archetypeId, recipient);
    }

    async publishDeployment(input: PublicDeploymentInput): Promise<PublicDeploymentOutcome> {
        let admitted = input;
        if (
            this.splitHomes
            && input.funding.kind === "managed"
            && !input.funding.entitlement
        ) {
            const publicKey = await workbenchClient.publicPublisherKey(this.workbenchTransport());
            const entitlement = await accountClient.mintManagedEntitlement(
                this.route,
                input.funding.tenant_id,
                publicKey,
            );
            admitted = { ...input, funding: { ...input.funding, entitlement } };
        }
        return workbenchClient.publishDeployment(this.workbenchTransport(), admitted);
    }

    async startPanelPreview(input: PanelPreviewInput): Promise<PanelPreviewOutcome> {
        let admitted = input;
        if (
            this.splitHomes
            && input.funding.kind === "managed"
            && !input.funding.entitlement
        ) {
            const publicKey = await workbenchClient.publicPublisherKey(this.workbenchTransport());
            const entitlement = await accountClient.mintManagedEntitlement(
                this.route,
                input.funding.tenant_id,
                publicKey,
            );
            admitted = { ...input, funding: { ...input.funding, entitlement } };
        }
        return workbenchClient.startPanelPreview(this.workbenchTransport(), admitted);
    }

    stopPanelPreview(previewId: string): Promise<void> {
        return workbenchClient.stopPanelPreview(this.workbenchTransport(), previewId);
    }

    /** Owner/admin tenants eligible to be selected as managed deployment
     * funding authority. Desktop reads them through its sealed Hub-session
     * proxy; hosted GaugeDesk already runs in the browser-authenticated Hub
     * plane. */
    deploymentManagedTenants(): Promise<accountClient.AccountTenant[]> {
        return this.splitHomes
            ? accountClient.accountTenants(this.route)
            : accountClient.hubSessionTenants(this.route);
    }

    importLegacyDeployment(input: PublicDeploymentInput) {
        return workbenchClient.importLegacyDeployment(this.workbenchTransport(), input);
    }

    // The collection surfaces (ADR 0109 §5–§7, GATE-8): which keyrings exist, how
    // one is minted, and the drain that ends this surface at the project's
    // quarantine rather than in a workspace.
    listCollectionRecipients() {
        return workbenchClient.listCollectionRecipients(this.workbenchTransport());
    }

    ensureCollectionRecipient(recipientId: string) {
        return workbenchClient.ensureCollectionRecipient(this.workbenchTransport(), recipientId);
    }

    drainCollections(input: {
        binding_id: string;
    }) {
        return workbenchClient.drainCollections(this.workbenchTransport(), input);
    }

    inspectDeployment(edge: string, deployment: string): Promise<PublicDeploymentInspection> {
        return workbenchClient.inspectDeployment(this.workbenchTransport(), edge, deployment);
    }

    controlDeployment(
        edge: string,
        deployment: string,
        command: "pause" | "resume" | "revoke",
        expectedRevision: number,
    ): Promise<PublicDeploymentInspection["deployment"]> {
        return workbenchClient.controlDeployment(
            this.workbenchTransport(),
            edge,
            deployment,
            command,
            expectedRevision,
        );
    }

    erasePublicSession(edge: string, deployment: string, session: string): Promise<void> {
        return workbenchClient.erasePublicSession(
            this.workbenchTransport(),
            edge,
            deployment,
            session,
        );
    }

    listPublicCredentials(edge: string): Promise<PublicCredentialMetadata[]> {
        return workbenchClient.listPublicCredentials(this.workbenchTransport(), edge);
    }

    provisionPublicCredential(
        input: ProvisionPublicCredentialInput,
    ): Promise<PublicCredentialMetadata> {
        return workbenchClient.provisionPublicCredential(this.workbenchTransport(), input);
    }

    revokePublicCredential(edge: string, credentialRef: string): Promise<void> {
        return workbenchClient.revokePublicCredential(
            this.workbenchTransport(),
            edge,
            credentialRef,
        );
    }

    removePlacement(pid: ProjectId, placementId: PlacementId): Promise<void> {
        return workbenchClient.removePlacement(this.workbenchTransport(), pid, placementId);
    }

    createChatUnderArchetype(archetypeId: ArchetypeId, title: string): Promise<EngagementId> {
        return workbenchClient.createChatUnderArchetype(this.workbenchTransport(), archetypeId, title);
    }

    useArchetype(archetypeId: ArchetypeId, title: string): Promise<EngagementId> {
        return workbenchClient.useArchetype(this.workbenchTransport(), archetypeId, title);
    }

    createChatUnderPlacement(pid: ProjectId, placementId: PlacementId, title: string, targetIds: readonly WorkTargetId[]): Promise<EngagementId> {
        return workbenchClient.createChatUnderPlacement(this.workbenchTransport(), pid, placementId, title, targetIds);
    }

    async reviseChatTargets(id: EngagementId, targets: readonly { targetId: WorkTargetId; participation: "read-only" | "writable" }[]): Promise<void> {
        await workbenchClient.reviseChatTargets(this.workbenchTransport(), id, targets);
    }

    renameChat(id: EngagementId, title: string): Promise<void> {
        return workbenchClient.renameChat(this.workbenchTransport(), id, title);
    }

    deleteChat(id: EngagementId): Promise<void> {
        return workbenchClient.deleteChat(this.workbenchTransport(), id);
    }

    engagementDiff(id: EngagementId): Promise<string> {
        return workbenchClient.engagementDiff(this.workbenchTransport(), id);
    }

    submitRunCommand(scope: ScopeId, command: RunCommand): Promise<RunState> {
        return workbenchClient.submitRunCommand(this.workbenchTransport(), scope, command);
    }

    createEngagement(id?: EngagementId): Promise<Engagement> {
        return workbenchClient.createEngagement(this.workbenchTransport(), id);
    }

    runTask(
        id: EngagementId,
        prompt: string,
        images: { data: string; mimeType: string }[] = [],
        composedId?: string,
    ): Promise<unknown> {
        return workbenchClient.runTask(this.workbenchTransport(), id, prompt, images, composedId);
    }

    stopTurn(id: EngagementId): Promise<StopTurnResult> {
        return workbenchClient.stopTurn(this.workbenchTransport(), id);
    }

    syncFromMain(id: EngagementId): Promise<{ synced: boolean; conflict: boolean }> {
        return workbenchClient.syncFromMain(this.workbenchTransport(), id);
    }

    createWorkstream(placementId: PlacementId, name: string): Promise<WorkstreamNode> {
        return workbenchClient.createWorkstream(this.workbenchTransport(), placementId, name);
    }

    listWorkstreams(placementId: PlacementId): Promise<WorkstreamNode[]> {
        return workbenchClient.listWorkstreams(this.workbenchTransport(), placementId);
    }

    joinWorkstream(ws: WorkstreamId, chat: EngagementId): Promise<void> {
        return workbenchClient.joinWorkstream(this.workbenchTransport(), ws, chat);
    }

    leaveWorkstream(ws: WorkstreamId, chat: EngagementId): Promise<void> {
        return workbenchClient.leaveWorkstream(this.workbenchTransport(), ws, chat);
    }

    archiveWorkstream(ws: WorkstreamId): Promise<void> {
        return workbenchClient.archiveWorkstream(this.workbenchTransport(), ws);
    }

    async promoteWorkstream(ws: WorkstreamId): Promise<void> {
        await workbenchClient.promoteWorkstream(this.workbenchTransport(), ws);
    }

    async settleWorkstreamTarget(
        ws: WorkstreamId,
        target: WorkTargetId,
        act: "apply" | "publish" | "release",
        promotionManifestRef?: string,
    ): Promise<void> {
        await workbenchClient.settleWorkstreamTarget(this.workbenchTransport(), ws, target, act, promotionManifestRef);
    }

    async settleChatTargets(chat: EngagementId, members: readonly { target_id: WorkTargetId; act: "apply" | "publish" | "release" }[]): Promise<void> {
        await workbenchClient.settleChatTargets(this.workbenchTransport(), chat, members);
    }

    async getTargetSettlement(declarationId: string): Promise<void> {
        await workbenchClient.getTargetSettlement(this.workbenchTransport(), declarationId);
    }

    async queryTargetSettlementMember(declarationId: string, memberId: string): Promise<void> {
        await workbenchClient.queryTargetSettlementMember(this.workbenchTransport(), declarationId, memberId);
    }

    async retryTargetSettlementMember(declarationId: string, memberId: string): Promise<void> {
        await workbenchClient.retryTargetSettlementMember(this.workbenchTransport(), declarationId, memberId);
    }

    async supersedeTargetSettlementMember(declarationId: string, memberId: string, laterDeclarationId: string, laterMemberId: string): Promise<void> {
        await workbenchClient.supersedeTargetSettlementMember(this.workbenchTransport(), declarationId, memberId, laterDeclarationId, laterMemberId);
    }

    async compensateTargetSettlement(declarationId: string, receiptRefs: readonly string[], reconciliationComplete: boolean): Promise<void> {
        await workbenchClient.compensateTargetSettlement(this.workbenchTransport(), declarationId, receiptRefs, reconciliationComplete);
    }

    async abandonTargetSettlement(declarationId: string, reason: string): Promise<void> {
        await workbenchClient.abandonTargetSettlement(this.workbenchTransport(), declarationId, reason);
    }

    async cancelTargetSettlement(declarationId: string, reason: string): Promise<void> {
        await workbenchClient.cancelTargetSettlement(this.workbenchTransport(), declarationId, reason);
    }

    getMerge(id: EngagementId): Promise<MergeState> {
        return workbenchClient.getMerge(this.workbenchTransport(), id);
    }

    getMergeCarriage(id: EngagementId): Promise<ProjectionCarriage<MergeState>> {
        return workbenchClient.getMergeCarriage(this.workbenchTransport(), id);
    }

    mergeCommand(id: EngagementId, action: MergeAction): Promise<MergeState> {
        return workbenchClient.mergeCommand(this.workbenchTransport(), id, action);
    }

    subscribe(id: EngagementId, onEvent: (ev: StreamEvent) => void, onOpen?: () => void): () => void {
        return workbenchClient.subscribe(this.workbenchTransport(), id, onEvent, onOpen);
    }

    subscribeWorkspace(onChange: (change: WorkspaceChange) => void): () => void {
        return workbenchClient.subscribeWorkspace(this.workbenchTransport(), onChange);
    }

    getResourceReview(id: EngagementId, resource: string): Promise<ReviewState> {
        return workbenchClient.getResourceReview(this.workbenchTransport(), id, resource);
    }

    resourceReviewCommand(
        id: EngagementId,
        resource: string,
        action: ResourceReviewAction,
    ): Promise<ReviewState> {
        return workbenchClient.resourceReviewCommand(this.workbenchTransport(), id, resource, action);
    }

    getResourceExport(id: EngagementId, resource: string): Promise<ExportState> {
        return workbenchClient.getResourceExport(this.workbenchTransport(), id, resource);
    }

    resourceExportCommand(
        id: EngagementId,
        resource: string,
        action: ResourceExportAction,
    ): Promise<ExportState> {
        return workbenchClient.resourceExportCommand(this.workbenchTransport(), id, resource, action);
    }

    getAudit(scope: ScopeId): Promise<AuditEvent[]> {
        return workbenchClient.getAudit(this.workbenchTransport(), scope);
    }

    getChatGovernanceAudit(id: EngagementId): Promise<unknown[]> {
        return workbenchClient.getChatGovernanceAudit(this.workbenchTransport(), id);
    }

    getTargetActs(target: WorkTargetId): Promise<unknown[]> {
        return workbenchClient.getTargetActs(this.workbenchTransport(), target);
    }

    publishTarget(chat: EngagementId): Promise<void> {
        return workbenchClient.publishTarget(this.workbenchTransport(), chat);
    }

    getResources(id: EngagementId): Promise<ResourceView[]> {
        return workbenchClient.getResources(this.workbenchTransport(), id);
    }

    getResourceContent(id: EngagementId, resource: string, path?: string): Promise<string> {
        return workbenchClient.getResourceContent(this.workbenchTransport(), id, resource, path);
    }

    getResourceAccess(id: EngagementId, resource: string): Promise<AccessPhase> {
        return workbenchClient.getResourceAccess(this.workbenchTransport(), id, resource);
    }

    requestResourceAccess(
        id: EngagementId,
        resource: string,
    ): Promise<AccessPhase> {
        return workbenchClient.requestResourceAccess(
            this.workbenchTransport(),
            id,
            resource,
        );
    }

    approveResourceAccess(
        id: EngagementId,
        resource: string,
    ): Promise<AccessPhase> {
        return workbenchClient.approveResourceAccess(
            this.workbenchTransport(),
            id,
            resource,
        );
    }

    revokeResourceAccess(id: EngagementId, resource: string): Promise<AccessPhase> {
        return workbenchClient.revokeResourceAccess(this.workbenchTransport(), id, resource);
    }

    proposeResourceReview(
        id: EngagementId,
        resource: string,
    ): Promise<{ scope: string; state: ReviewState }> {
        return workbenchClient.proposeResourceReview(this.workbenchTransport(), id, resource);
    }

    proposeResourceExport(
        id: EngagementId,
        resource: string,
    ): Promise<{ scope: string; state: ExportState }> {
        return workbenchClient.proposeResourceExport(this.workbenchTransport(), id, resource);
    }

    exportResourceToDisk(
        id: EngagementId,
        resource: string,
        dest: string,
        path?: string,
    ): Promise<{ exported: string[]; dest: string }> {
        return workbenchClient.exportResourceToDisk(
            this.workbenchTransport(),
            id,
            resource,
            dest,
            path,
        );
    }

    tombstoneResource(id: EngagementId, resource: string): Promise<void> {
        return workbenchClient.tombstoneResource(this.workbenchTransport(), id, resource);
    }

    getTranscript(id: EngagementId): Promise<StreamEvent[]> {
        return workbenchClient.getTranscript(this.workbenchTransport(), id);
    }

    getContextUsage(id: EngagementId): Promise<workbenchClient.ChatContextUsage | null> {
        return workbenchClient.getContextUsage(this.workbenchTransport(), id);
    }

    getTree(id: EngagementId): Promise<FileEntry[]> {
        return workbenchClient.getTree(this.workbenchTransport(), id);
    }

    getFile(id: EngagementId, path: string): Promise<string> {
        return workbenchClient.getFile(this.workbenchTransport(), id, path);
    }

    // The review surface's three reads/commands (ADR 0110 §7). Project-scoped, not
    // engagement-scoped: quarantine belongs to a project and reaches no chat's
    // worktree, which is the whole protection (ADR 0110 §1).
    listQuarantine(project: string) {
        return workbenchClient.listQuarantine(this.workbenchTransport(), project);
    }

    readQuarantinedItem(project: string, item: string): Promise<string> {
        return workbenchClient.readQuarantinedItem(this.workbenchTransport(), project, item);
    }

    screenQuarantinedItem(project: string, item: string) {
        return workbenchClient.screenQuarantinedItem(
            this.workbenchTransport(),
            project,
            item,
        );
    }

    reviewQuarantinedItem(
        project: string,
        item: string,
        verdict: "keep" | "flag",
    ): Promise<{ workspacePath: string | null }> {
        return workbenchClient.reviewQuarantinedItem(
            this.workbenchTransport(),
            project,
            item,
            verdict,
        );
    }

    getFileWithCut(
        id: EngagementId,
        path: string,
    ): Promise<{ content: string; cut: string | null }> {
        return workbenchClient.getFileWithCut(this.workbenchTransport(), id, path);
    }

    putFile(id: EngagementId, path: string, content: string): Promise<void> {
        return workbenchClient.putFile(this.workbenchTransport(), id, path, content);
    }

    saveFile(
        id: EngagementId,
        path: string,
        content: string,
        base: workbenchClient.SaveBase,
        resolutions?: workbenchClient.RegionResolution[],
    ): Promise<workbenchClient.SaveFileResult> {
        return workbenchClient.saveFile(
            this.workbenchTransport(),
            id,
            path,
            content,
            base,
            resolutions,
        );
    }

    previewMerge(
        id: EngagementId,
        path: string,
        draft: string,
        baseCut: string,
    ): Promise<workbenchClient.MergePreviewResult> {
        return workbenchClient.previewMerge(this.workbenchTransport(), id, path, draft, baseCut);
    }

    getConfig(id: EngagementId): Promise<string> {
        return workbenchClient.getConfig(this.workbenchTransport(), id);
    }

    putConfig(id: EngagementId, raw: string): Promise<void> {
        return workbenchClient.putConfig(this.workbenchTransport(), id, raw);
    }

    ingestContext(id: EngagementId, path: string, targetId?: WorkTargetId): Promise<number> {
        return workbenchClient.ingestContext(this.workbenchTransport(), id, path, targetId);
    }

    ingestContextUpload(id: EngagementId, files: workbenchClient.UploadContextFile[], targetId?: WorkTargetId): Promise<number> {
        return workbenchClient.ingestContextUpload(this.workbenchTransport(), id, files, targetId);
    }

    openPairing(device: string, bridgeGrant: string | null): Promise<{ pairingId: string; bridgeGrant: string }> {
        return workbenchClient.openPairing(this.workbenchTransport(), device, bridgeGrant);
    }

    acceptBoundary(boundaryId: string, participant: string): Promise<void> {
        return workbenchClient.acceptBoundary(this.workbenchTransport(), boundaryId, participant);
    }

    pairingStatus(boundaryId: string): Promise<unknown> {
        return workbenchClient.pairingStatus(this.workbenchTransport(), boundaryId);
    }

    mintPairingTicket(): Promise<federationClient.PairingTicket> {
        return federationClient.mintPairingTicket(this.routeJson());
    }

    pair(ticket: federationClient.PairingTicket): Promise<federationClient.FederationPeer> {
        return federationClient.pair(this.routeJson(), ticket);
    }

    listPeers(): Promise<federationClient.FederationPeer[]> {
        return federationClient.listPeers(this.routeJson());
    }

    revokePeer(authority: string): Promise<void> {
        return federationClient.revokePeer(this.routeJson(), authority);
    }

    handoffAbort(project: ProjectId): Promise<federationClient.HandoffStatus> {
        return federationClient.handoffAbort(this.routeJson(), project);
    }

    handoffStatus(project: ProjectId): Promise<federationClient.HandoffStatus> {
        return federationClient.handoffStatus(this.routeJson(), project);
    }

    handoffRelocate(project: ProjectId, peer: string): Promise<federationClient.HandoffStatus> {
        return federationClient.handoffRelocate(this.routeJson(), project, peer);
    }

    placeRun(
        peer: string,
        project: ProjectId,
        archetype: string,
        dataHandle: string,
        prompt: string,
        targetChat?: string,
    ): Promise<federationClient.PlacedRun> {
        return federationClient.placeRun(
            this.routeJson(),
            peer,
            project,
            archetype,
            dataHandle,
            prompt,
            targetChat,
        );
    }

    runQueue(): Promise<federationClient.QueuedRun[]> {
        return federationClient.runQueue(this.routeJson());
    }

    allowRuns(project: ProjectId, operator: string, allow = true): Promise<void> {
        return federationClient.allowRuns(this.routeJson(), project, operator, allow);
    }

    denyRun(correlation: string): Promise<void> {
        return federationClient.denyRun(this.routeJson(), correlation);
    }

    admitRunOnce(correlation: string): Promise<void> {
        return federationClient.admitRunOnce(this.routeJson(), correlation);
    }

    runResult(correlation: string): Promise<federationClient.RunResult> {
        return federationClient.runResult(this.routeJson(), correlation);
    }

    invite(project: ProjectId): Promise<federationClient.EngagementInvite> {
        return federationClient.invite(this.routeJson(), project);
    }

    inviteAccept(invite: string): Promise<federationClient.InviteAcceptResult> {
        return federationClient.inviteAccept(this.routeJson(), invite);
    }

    inviteStatus(inviteId: string): Promise<federationClient.InviteStatus> {
        return federationClient.inviteStatus(this.routeJson(), inviteId);
    }

    handoffIncoming(): Promise<federationClient.IncomingHandoff[]> {
        return federationClient.handoffIncoming(this.routeJson());
    }

    handoffAccept(project: string, source: string): Promise<federationClient.HandoffStatus> {
        return federationClient.handoffAccept(this.routeJson(), project, source);
    }

    handoffDecline(project: string, source: string): Promise<void> {
        return federationClient.handoffDecline(this.routeJson(), project, source);
    }

    handoffAcceptAll(): Promise<string[]> {
        return federationClient.handoffAcceptAll(this.routeJson());
    }

    handoffPreauth(peer: string, allow = true): Promise<void> {
        return federationClient.handoffPreauth(this.routeJson(), peer, allow);
    }

    handoffParticipants(project: ProjectId): Promise<federationClient.Participant[]> {
        return federationClient.handoffParticipants(this.routeJson(), project);
    }

    handoffRevoke(project: ProjectId, authority: string, owns: string): Promise<void> {
        return federationClient.handoffRevoke(this.routeJson(), project, authority, owns);
    }

    handoffConnectData(project: ProjectId, handle: string, label?: string): Promise<void> {
        return federationClient.handoffConnectData(this.routeJson(), project, handle, label);
    }

    handoffData(project: ProjectId): Promise<federationClient.ConnectedData[]> {
        return federationClient.handoffData(this.routeJson(), project);
    }

    // Account-level facilities + the tenant switcher (ADR 0077 §7/§9) — the hosted
    // Console reads these; on the desktop the tenant list is empty (org-free solo).
    accountFacilities(): Promise<accountClient.AccountFacility[]> {
        return accountClient.accountFacilities(this.routeJson());
    }

    accountAttachFacility(input: accountClient.AttachFacilityInput): Promise<accountClient.AccountFacility> {
        return accountClient.accountAttachFacility(this.routeJson(), input);
    }

    accountDetachFacility(id: string): Promise<void> {
        return accountClient.accountDetachFacility(this.routeJson(), id);
    }

    accountPublishLibrarySync(): Promise<void> {
        return accountClient.accountPublishLibrarySync(this.routeJson());
    }

    accountPullLibrarySync(): Promise<accountClient.LibrarySyncPullResult> {
        return accountClient.accountPullLibrarySync(this.routeJson());
    }

    accountTenants(): Promise<accountClient.AccountTenant[]> {
        return accountClient.accountTenants(this.routeJson());
    }

    accountSignInMethod(): Promise<accountClient.AccountSignInMethod> {
        return accountClient.accountSignInMethod(this.routeJson());
    }

    accountInvitations(): Promise<accountClient.AccountInvitation[]> {
        return accountClient.accountInvitations(this.routeJson());
    }

    acceptAccountInvitation(tenantId: string): Promise<accountClient.AccountTenant> {
        return accountClient.acceptAccountInvitation(this.routeJson(), tenantId);
    }

    createOrganization(displayName: string): Promise<accountClient.AccountTenant> {
        return accountClient.createOrganization(this.routeJson(), displayName);
    }

    deleteOrganization(tenantId: string): Promise<void> {
        return accountClient.deleteOrganization(this.routeJson(), tenantId);
    }

    accountDevices(): Promise<accountClient.AccountDevice[]> {
        return accountClient.accountDevices(this.routeJson());
    }

    accountRevokeDevice(id: string): Promise<void> {
        return accountClient.accountRevokeDevice(this.routeJson(), id);
    }

    enrollHost(): Promise<accountClient.EnrollmentTicket> {
        return accountClient.enrollHost(this.routeJson());
    }

    mintMachineControllerInvitation(
        endpoint: string,
    ): Promise<accountClient.MachineControllerInvitation> {
        return accountClient.mintMachineControllerInvitation(this.routeJson(), endpoint);
    }

    listMachineControllerRequests(): Promise<accountClient.MachineControllerRequest[]> {
        return accountClient.listMachineControllerRequests(this.routeJson());
    }

    approveMachineController(requestId: string): Promise<void> {
        return accountClient.approveMachineController(this.routeJson(), requestId);
    }

    rejectMachineController(requestId: string): Promise<void> {
        return accountClient.rejectMachineController(this.routeJson(), requestId);
    }

    listMachineControllers(): Promise<accountClient.MachineController[]> {
        return accountClient.listMachineControllers(this.routeJson());
    }

    revokeMachineController(controllerId: string): Promise<void> {
        return accountClient.revokeMachineController(this.routeJson(), controllerId);
    }

    enrollHostStatus(session: string): Promise<accountClient.EnrollmentStatus> {
        return accountClient.enrollHostStatus(this.routeJson(), session);
    }

    enrollAuthorize(session: string): Promise<void> {
        return accountClient.enrollAuthorize(this.routeJson(), session);
    }

    enrollJoin(ticket: accountClient.EnrollmentTicket): Promise<string> {
        return accountClient.enrollJoin(this.routeJson(), ticket);
    }

    enrollJoinStatus(session: string): Promise<accountClient.EnrollmentStatus> {
        return accountClient.enrollJoinStatus(this.routeJson(), session);
    }

    accountSettings(): Promise<Record<string, string>> {
        return accountClient.accountSettings(this.routeJson());
    }

    accountSetSetting(key: string, value: string): Promise<void> {
        return accountClient.accountSetSetting(this.routeJson(), key, value);
    }

    accountCredentials(): Promise<accountClient.LinkedProvider[]> {
        return this.runtimeAccountJson().then((json) => accountClient.accountCredentials(json));
    }

    accountLinkCredential(provider: string, token: string, baseUrl?: string): Promise<void> {
        return this.runtimeAccountJson().then((json) =>
            accountClient.accountLinkCredential(json, provider, token, baseUrl),
        );
    }

    accountUnlinkCredential(provider: string): Promise<void> {
        return this.runtimeAccountJson().then((json) =>
            accountClient.accountUnlinkCredential(json, provider),
        );
    }

    accountManagedInference(): Promise<accountClient.ManagedInferenceBilling> {
        return accountClient.accountManagedInference(this.routeJson());
    }

    accountSetManagedInference(plan: accountClient.ManagedInferencePlan): Promise<void> {
        return accountClient.accountSetManagedInference(this.routeJson(), plan).then(async () => {
            if (this.splitHomes) {
                const json = await this.runtimeAccountJson();
                await accountClient.accountSetManagedInference(json, plan);
            }
        });
    }

    projectCredentials(project: string): Promise<accountClient.LinkedProvider[]> {
        return this.runtimeAccountJson().then((json) =>
            accountClient.projectCredentials(json, project),
        );
    }

    linkProjectCredential(
        project: string,
        provider: string,
        token: string,
        baseUrl?: string,
    ): Promise<void> {
        return this.runtimeAccountJson().then((json) =>
            accountClient.linkProjectCredential(json, project, provider, token, baseUrl),
        );
    }

    unlinkProjectCredential(project: string, provider: string): Promise<void> {
        return this.runtimeAccountJson().then((json) =>
            accountClient.unlinkProjectCredential(json, project, provider),
        );
    }

    codexStatus(): Promise<accountClient.CodexStatus> {
        return this.runtimeAccountJson().then((json) => accountClient.codexStatus(json));
    }

    onboardingStatus(): Promise<{ credentialRequired: boolean }> {
        return this.runtimeAccountJson().then((json) => accountClient.onboardingStatus(json));
    }

    defaultModel(): Promise<{ provider: string | null; model: string | null }> {
        return this.runtimeAccountJson().then((json) => accountClient.defaultModel(json));
    }

    codexLoginStart(): Promise<accountClient.CodexLoginStart> {
        return this.runtimeAccountJson().then((json) => accountClient.codexLoginStart(json));
    }

    codexLoginCancel(): Promise<void> {
        return this.runtimeAccountJson().then((json) => accountClient.codexLoginCancel(json));
    }

    xaiGrokStatus(): Promise<accountClient.XaiGrokStatus> {
        return this.runtimeAccountJson().then((json) => accountClient.xaiGrokStatus(json));
    }

    xaiGrokLoginStart(): Promise<accountClient.XaiGrokLoginStart> {
        return this.runtimeAccountJson().then((json) => accountClient.xaiGrokLoginStart(json));
    }

    xaiGrokLoginCancel(): Promise<void> {
        return this.runtimeAccountJson().then((json) => accountClient.xaiGrokLoginCancel(json));
    }

    // Desktop → Hub account sign-in (ADR 0123, LOGIN-2): the local control
    // plane custodies the session; the client sees only the login URL, the
    // one-time code, and non-secret status.
    hubSessionStatus(): Promise<accountClient.HubSessionStatus> {
        return this.runtimeAccountJson().then((json) => accountClient.hubSessionStatus(json));
    }

    hubSessionStart(): Promise<{ url: string; webReturn: boolean }> {
        return this.runtimeAccountJson().then((json) => accountClient.hubSessionStart(json));
    }

    hubSessionCallback(code: string): Promise<accountClient.HubSessionStatus> {
        return this.runtimeAccountJson().then((json) =>
            accountClient.hubSessionCallback(json, code),
        );
    }

    hubSessionSignOut(): Promise<void> {
        return this.runtimeAccountJson().then((json) => accountClient.hubSessionSignOut(json));
    }

    hubSessionReach(): Promise<accountClient.HubSessionReach> {
        return this.runtimeAccountJson().then((json) => accountClient.hubSessionReach(json));
    }
}
