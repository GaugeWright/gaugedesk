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
    openReconnectingEventStream,
    reconnectingRouteEventStream,
    RemoteControlPlane,
    RouteHttpError,
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
          /** The Home the account selected, when it named one that is not
           * serving. Carried because "no Home is serving you" covers three
           * different people — nobody has registered a Home, several are
           * registered and none is chosen, or the chosen one is not reachable —
           * and a surface that cannot tell them apart can only address the
           * first. Null when no Home is selected at all. */
          readonly selectedHome: HomeId | null;
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

/** How long "Finding your Home…" waits on the selected Home before saying it is
 * not responding. A Home that accepts the connection and never answers would
 * otherwise hold that screen, which has no other way off it, forever. */
export const HOME_DIAL_TIMEOUT_MS = 20_000;

export class HomeDialTimeoutError extends Error {
    constructor() {
        super("The Home did not answer in time");
        this.name = "HomeDialTimeoutError";
    }
}

function withinHomeDialTimeout<T>(pending: Promise<T>, ms: number): Promise<T> {
    let timer: ReturnType<typeof setTimeout> | undefined;
    const timeout = new Promise<never>((_, reject) => {
        timer = setTimeout(() => reject(new HomeDialTimeoutError()), ms);
    });
    return Promise.race([pending, timeout]).finally(() => clearTimeout(timer));
}

/** Whether dialing a Home failed because nothing answered: the connection
 * could not be made (`fetch` rejects with a TypeError), or a gateway in front of
 * the Home said it is down. A refusal from a Home that did answer is not this. */
function isHomeUnreachable(error: unknown): boolean {
    if (error instanceof TypeError || error instanceof HomeDialTimeoutError) return true;
    return error instanceof RouteHttpError && [502, 503, 504].includes(error.status);
}

/** A Home restart invalidates its memory-only admissions. This exact refusal is
 * emitted by the admission middleware before a work route can run, so it is
 * safe to obtain a fresh admission and retry the same operation once. Other
 * 401s are account-authentication failures and must not be hidden by reconnects. */
function isExpiredHomeAdmission(error: unknown): boolean {
    return error instanceof RouteHttpError
        && error.status === 401
        && /target Home admission required/.test(error.message);
}

async function isExpiredHomeAdmissionResponse(response: Response): Promise<boolean> {
    if (response.status !== 401 || !response.headers.get("content-type")?.startsWith("application/json")) {
        return false;
    }
    const length = Number(response.headers.get("content-length"));
    // A missing, invalid, or oversized body is not the admission middleware's
    // small closed response and must not be read or reinterpreted here.
    if (!Number.isSafeInteger(length) || length < 1 || length > 256) return false;
    try {
        const body = await response.clone().json() as { error?: unknown };
        return body.error === "target Home admission required";
    } catch {
        return false;
    }
}

/** App-owned control-plane edge for the open workbench shell. */
export class WorkbenchControlPlane implements ControlPlane {
    private bearer: string | null = null;
    private credentialGeneration = 0;
    private homeAdmission: string | null = null;
    private readonly route: RouteJson;
    private readonly request: RouteRequest;
    private readonly events: RouteEventStream;
    private readonly splitHomes: boolean;
    private readonly nativeShell: boolean;
    private nativeRemote = false;
    private readonly homeDialTimeoutMs: number;
    private readonly workTransport: workbenchClient.WorkbenchTransport;
    private readonly localWorkTransport: workbenchClient.WorkbenchTransport;
    private homeTransport: Promise<workbenchClient.WorkbenchTransport> | null = null;
    private selectedDirectJson: RouteJson | null = null;
    /** Several Homes at once, resolved per project (DESK-3). There is no
     * selected Home here: whichever project is open decides which Home serves,
     * and a Home that fails degrades only the projects routed to it. */
    private pool: HomePool<workbenchClient.WorkbenchTransport> | null = null;
    private currentProject: ProjectId | null = null;
    private readonly restartWorkStreams = new Set<() => void>();

    constructor(
        private readonly base = controlPlaneBase(),
        options: { readonly splitHomes?: boolean; readonly homeDialTimeoutMs?: number } = {},
    ) {
        this.splitHomes = options.splitHomes ?? import.meta.env?.VITE_HOME_SPLIT === "true";
        this.nativeShell = typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
        this.homeDialTimeoutMs = options.homeDialTimeoutMs ?? HOME_DIAL_TIMEOUT_MS;
        const auth = {
            bearer: () => this.bearer,
            // In split mode this is the Hub transport. A Home credential must
            // never leak onto account-plane requests: besides crossing the
            // authority boundary, the edge uses that header to select Home.
            homeAdmission: () => (this.splitHomes ? null : this.homeAdmission),
        };
        this.route = browserRouteJson(this.base, auth);
        this.request = browserRouteRequest(this.base, auth);
        const eventSource = browserRouteEventStream(this.base, auth);
        this.events = reconnectingRouteEventStream(() => eventSource, {
            beforeReconnect: async (reason) => {
                if (
                    !this.splitHomes
                    && reason?.status === 401
                    && reason.detail === "target Home admission required"
                ) {
                    this.homeAdmission = null;
                    await this.admitHome();
                }
            },
        });
        this.localWorkTransport = {
            base: this.base,
            json: this.route,
            request: this.request,
            events: this.events,
        };
        this.workTransport = this.splitHomes || this.nativeShell
            ? {
                  base: "",
                  json: (...args) => this.withHomeAdmissionRetry((transport) => transport.json(...args)),
                  request: (...args) => this.withHomeRequestAdmissionRetry(...args),
                  events: (path, onMessage, onOpen, onClose) => {
                      const subscription = openReconnectingEventStream(
                          async () => (await this.requireHomeTransport()).events,
                          path,
                          onMessage,
                          onOpen,
                          onClose,
                          {
                              beforeReconnect: async (reason) => {
                                  if (
                                      reason?.status === 401
                                      && reason.detail === "target Home admission required"
                                  ) {
                                      await this.invalidateHomeTransport(this.currentProject);
                                  }
                              },
                          },
                      );
                      this.restartWorkStreams.add(subscription.reconnect);
                      return () => {
                          this.restartWorkStreams.delete(subscription.reconnect);
                          subscription.close();
                      };
                  },
              }
            : this.localWorkTransport;
    }

    /** Retry only the pre-effect expired-admission refusal, once, and only while
     * the same project remains selected. The pool has already marked a routed
     * connection non-live through its authorization callback; clearing this
     * cached transport makes the next resolution disconnect it and re-admit.
     * A selected endpoint outside the pool is likewise re-admitted. */
    private async withHomeAdmissionRetry<T>(
        operation: (transport: workbenchClient.WorkbenchTransport) => Promise<T>,
    ): Promise<T> {
        const project = this.currentProject;
        try {
            return await operation(await this.requireHomeTransport());
        } catch (error) {
            if (!isExpiredHomeAdmission(error) || this.currentProject !== project) throw error;
            await this.invalidateHomeTransport(project);
            return operation(await this.requireHomeTransport());
        }
    }

    private async withHomeRequestAdmissionRetry(...args: Parameters<RouteRequest>): Promise<Response> {
        const project = this.currentProject;
        const request = async () => {
            const transport = await this.requireHomeTransport();
            if (!transport.request) throw new Error("Home raw transport unavailable");
            return transport.request(...args);
        };
        const response = await request();
        if (this.currentProject !== project || !(await isExpiredHomeAdmissionResponse(response))) {
            return response;
        }
        await this.invalidateHomeTransport(project);
        return request();
    }

    private async invalidateHomeTransport(project: ProjectId | null): Promise<void> {
        if (project) await this.pool?.invalidateProject(project);
        this.homeTransport = null;
    }

    /** The shell proves local Home standing separately from Hub sign-in. A
     * selected visitor uses its own Home over the sealed desktop broker. */
    setNativeRemote(remote: boolean): boolean {
        if (!this.nativeShell || this.nativeRemote === remote) return false;
        this.nativeRemote = remote;
        this.credentialGeneration++;
        this.homeAdmission = null;
        this.homeTransport = null;
        this.selectedDirectJson = null;
        void this.pool?.closeAll().catch(() => undefined);
        this.pool = null;
        for (const reconnect of this.restartWorkStreams) reconnect();
        return true;
    }

    async closeAccountConnections(): Promise<void> {
        this.credentialGeneration++;
        this.homeTransport = null;
        const selected = this.selectedDirectJson;
        this.selectedDirectJson = null;
        const pool = this.pool;
        this.pool = null;
        await Promise.allSettled([
            selected?.("DELETE", "/home/admissions"),
            pool?.closeAll(),
        ]);
    }

    private usesRemoteHome(): boolean {
        return this.splitHomes || this.nativeRemote;
    }

    setBearer(token: string | null): void {
        if (this.bearer !== token) {
            this.credentialGeneration++;
            this.homeAdmission = null;
            this.homeTransport = null;
            void this.pool?.closeAll().catch(() => undefined);
            this.pool = null;
        }
        this.bearer = token;
    }

    /** Explicit original-Home routing for retained saves. This is available to
     * qualified callers; it does not replace the editor's legacy save method or
     * enable the Home's optional native submission/supervisor composition. */
    async openNativeFileSaveSession(home: string, journal: workbenchClient.NativeSaveJournal)
        : Promise<workbenchClient.NativeFileSaveSession> {
        if (!home.trim()) throw new Error("An original Home is required for native file saves");
        const generation = this.credentialGeneration;
        const connections = new Map<string, Promise<workbenchClient.NativeSaveHome>>();
        return workbenchClient.openNativeFileSaveSession(home, journal,
            (originalHome) => {
                let pending = connections.get(originalHome);
                if (!pending) {
                    pending = this.connectNativeFileHome(originalHome);
                    connections.set(originalHome, pending);
                    const attempt = pending;
                    void pending.catch(() => {
                        if (connections.get(originalHome) === attempt) connections.delete(originalHome);
                    });
                }
                return pending;
            },
            () => generation === this.credentialGeneration);
    }

    private async connectNativeFileHome(home: string): Promise<workbenchClient.NativeSaveHome> {
        if (!this.usesRemoteHome()) {
            // A retained binding must not follow a later admission header to
            // another Home at the same local or reverse-proxy origin.
            const bearer = this.bearer;
            const admission = this.homeAdmission;
            return { home, transport: { base: this.base, json: browserRouteJson(this.base, {
                bearer: () => bearer, homeAdmission: () => admission,
            }) } };
        }
        const pool = await this.homePool();
        try {
            const connection = await pool.connectHome(home as HomeId);
            if (connection.homeId !== home) throw new Error("Native save Home identity mismatch");
            return { home, transport: connection.api };
        } catch (error) {
            if (!(error instanceof UnroutedHomeError)) throw error;
        }
        // Registered Homes may have an endpoint before publishing project
        // routes. Resolve this exact id; the account's selected Home is unused.
        const state = this.nativeRemote
            ? await accountClient.hubSessionReach(this.route)
            : await accountClient.accountHomes(this.route);
        const original = state.homes.find((candidate) => candidate.id === home);
        if (!original?.endpoint) throw new UnroutedHomeError(`No route reaches original Home ${home}`);
        const bearer = this.nativeRemote ? null : this.bearer;
        let admission: string | null = null;
        const endpoint = this.nativeRemote ? this.nativeHomeBase(original.id) : original.endpoint;
        const json = browserRouteJson(endpoint, {
            bearer: () => bearer, homeAdmission: () => admission,
        });
        const admitted = await json("POST", "/home/admissions") as { home?: unknown; admission?: unknown };
        if (admitted.home !== home || typeof admitted.admission !== "string" || !admitted.admission) {
            if (typeof admitted.admission === "string" && admitted.admission) {
                admission = admitted.admission;
                await json("DELETE", "/home/admissions").catch(() => undefined);
            }
            throw new Error(`Native save Home identity mismatch: expected ${home}`);
        }
        admission = admitted.admission;
        return { home, transport: { base: endpoint, json } };
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
        if (this.nativeRemote) return (await accountClient.hubSessionReach(this.route)).routes;
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
        return this.nativeRemote
            ? (...args) => this.requireHomeTransport().then((transport) => transport.json(...args))
            : this.route;
    }

    private workbenchTransport(): workbenchClient.WorkbenchTransport {
        return this.workTransport;
    }

    private async runtimeAccountJson(): Promise<RouteJson> {
        return this.usesRemoteHome() ? (await this.requireHomeTransport()).json : this.route;
    }

    private async desktopSessionJson(): Promise<RouteJson> {
        return this.nativeShell ? this.route : this.runtimeAccountJson();
    }

    /** Open a project, so subsequent work resolves to *its* Home. Passing null
     * returns to whatever the account last selected. */
    setCurrentProject(project: ProjectId | null): void {
        if (this.currentProject === project) return;
        this.currentProject = project;
        // Only the per-project path is invalidated; other Homes in the pool keep
        // their connections, which is the point of holding several.
        this.homeTransport = null;
        for (const reconnect of this.restartWorkStreams) reconnect();
    }

    /** Resolve the transport for the work in hand.
     *
     * Every work call in this client funnels through here, so per-project
     * resolution lands in one place rather than in each caller. A project with a
     * granted route is served by its own Home through the pool; anything else
     * falls back to the account's selected Home, which is what accounts whose
     * Homes have not yet authored routes still rely on (DESK-5a). */
    private requireHomeTransport(): Promise<workbenchClient.WorkbenchTransport> {
        if (!this.usesRemoteHome()) return Promise.resolve(this.localWorkTransport);
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
        let route: OpaqueHomeRoute;
        try {
            route = pool.routeFor(project);
        } catch (error) {
            // A project may have been created after this browser built its Home
            // pool. Re-read the account projection once before treating it as a
            // legacy unrouted project; otherwise a newly created project opens
            // against the previously selected Home and can display another
            // project's workspace.
            if (!String(error).includes("no granted Home route")) throw error;
            pool.replaceRoutes(await this.homeRoutes());
            route = pool.routeFor(project);
        }
        // A relay-only route is not dialable without a tunnel module. That is
        // an absence of a usable route, not a broken connection, so it reads as
        // one and the account's selected Home serves instead.
        if (!route.endpoint && !(route.relay && (this.nativeRemote || tunnelAvailable()))) {
            throw new Error(`no granted Home route for project ${project}`);
        }
        const connection = await pool.connectProject(project);
        return connection.api;
    }

    /** The account's project→Home routes, as a live pool. Built once and
     * refreshed whenever the account directory is re-read. */
    private async homePool(): Promise<HomePool<workbenchClient.WorkbenchTransport>> {
        if (this.pool) return this.pool;
        // Routes resolved under one credential are never used under another.
        // One change is not a change of person, though: a page that started
        // with no bearer at all receiving its first one. After a reload that
        // happens every time — discovery begins on the cookie at once and the
        // first `/auth/refresh` lands in the middle of it — and refusing it
        // showed "We couldn't load your Homes" on every hosted load
        // (2026-09-24). That one transition resolves again; a bearer replaced
        // by another still refuses, because work begun for one account must
        // never be admitted under the next.
        let routes: OpaqueHomeRoute[] | undefined;
        for (let attempt = 0; attempt < 2 && routes === undefined; attempt += 1) {
            const generation = this.credentialGeneration;
            const rehydrating = this.bearer === null;
            const resolved = await this.homeRoutes();
            if (generation === this.credentialGeneration) routes = resolved;
            else if (!rehydrating || this.credentialGeneration !== generation + 1) break;
        }
        if (routes === undefined) {
            throw new Error("Account session changed while resolving Home routes");
        }
        if (this.pool) return this.pool;
        // The live carrier per relay-only Home. A tunnel is not reclaimed by
        // being forgotten: the Home stays spliced to a client that has gone and
        // never re-parks, so the *next* attempt to reach it waits for a splice
        // that cannot happen. The pool tells us when a Home is done with.
        const tunnels = new Map<HomeId, TunnelRoute>();
        this.pool = new HomePool<workbenchClient.WorkbenchTransport>(
            routes,
            () => this.nativeRemote ? "selected desktop session" : this.bearer,
            {
                // A Home with no endpoint is reachable only through the relay.
                // Serve it over the tunnel when this build registered a module;
                // otherwise fall through, so a build without one behaves exactly
                // as it did rather than failing in a new way (DESK-7).
                routeJson: (endpoint, auth, route) => {
                    if (this.nativeRemote) {
                        return browserRouteJson(endpoint, { homeAdmission: auth.homeAdmission });
                    }
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
                        // The same credentials the direct route carries. Without
                        // them a carried revocation is refused, and a Home that
                        // gates its work routes admits a caller it then refuses.
                        bearer: auth.bearer,
                        homeAdmission: auth.homeAdmission,
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
                    if (this.nativeRemote) {
                        const admission = { homeAdmission: context.homeAdmission };
                        return {
                            base: context.endpoint,
                            json: context.routeJson,
                            request: browserRouteRequest(context.endpoint, admission),
                            events: browserRouteEventStream(context.endpoint, admission),
                        };
                    }
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
                ...(this.nativeRemote ? {
                    resolveEndpoint: async (route: OpaqueHomeRoute) => this.nativeHomeBase(route.homeId),
                } : {}),
            },
        );
        return this.pool;
    }

    private nativeHomeBase(home: HomeId): string {
        return `${this.base.replace(/\/+$/, "")}/account/hub-session/home/${encodeURIComponent(home)}`;
    }

    /** The Home that answers work not scoped to a project — the chat list, the
     * workspace, the account's own view of itself. */
    private async connectSelectedHome(): Promise<workbenchClient.WorkbenchTransport> {
        if (this.nativeRemote) {
            const generation = this.credentialGeneration;
            const reach = await accountClient.hubSessionReach(this.route);
            const selected = reach.homes.find((home) => home.id === reach.selectedHome);
            if (!selected) throw new NoSelectedHomeError("No reachable Home is selected");
            if (reach.routes.some((route) => route.homeId === selected.id && (route.endpoint || route.relay))) {
                return (await (await this.homePool()).connectHome(selected.id)).api;
            }
            if (!selected.endpoint) throw new UnroutedHomeError(`No direct endpoint reaches Home ${selected.id}`);
            const endpoint = this.nativeHomeBase(selected.id);
            let admission: string | null = null;
            const auth = { homeAdmission: () => admission };
            const json = browserRouteJson(endpoint, auth);
            const result = await json("POST", "/home/admissions") as {
                home?: unknown; admission?: unknown;
            };
            if (result.home !== selected.id || typeof result.admission !== "string") {
                throw new Error(`Selected Home identity mismatch: expected ${selected.id}`);
            }
            admission = result.admission;
            if (generation !== this.credentialGeneration || !this.nativeRemote) {
                await json("DELETE", "/home/admissions").catch(() => undefined);
                throw new Error("Account selection changed during Home admission");
            }
            this.selectedDirectJson = json;
            return {
                base: endpoint,
                json,
                request: browserRouteRequest(endpoint, auth),
                events: browserRouteEventStream(endpoint, auth),
            };
        }
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
        if (!this.usesRemoteHome()) return { kind: "direct" };
        try {
            await withinHomeDialTimeout(this.requireHomeTransport(), this.homeDialTimeoutMs);
            const state = this.nativeRemote
                ? await accountClient.hubSessionReach(this.route)
                : await accountClient.accountHomes(this.route);
            const home = state.homes.find((item) => item.id === state.selectedHome);
            if (!home) throw new NoSelectedHomeError("No reachable Home is selected");
            return { kind: "connected", home };
        } catch (error) {
            // `requireHomeTransport` keeps the connection attempt, rejected or
            // not. A failed one must not outlive this call, or every Retry would
            // read back the same rejection without dialing anything.
            this.homeTransport = null;
            // A selected Home that has published no route belongs with the other
            // "no Home is serving you yet" states, not with connection failures
            // (ADR 0134 §5): the surface below lists the account's Homes and
            // routes, which is exactly what someone in that position needs.
            if (
                !(error instanceof NoSelectedHomeError)
                && !(error instanceof UnroutedHomeError)
                && !isUnprovisionedHomeError(error)
            ) {
                // So does a Home that did not answer while the account did: an
                // asleep laptop is "that Home is not responding", with the
                // account's other Homes beside it — not "we couldn't load your
                // Homes", which blamed the account service and offered only a
                // Retry of the same Home. Authentication and identity refusals
                // are not outages and still fail as themselves.
                if (isHomeUnreachable(error)) {
                    const none = await this.noHomeServing().catch(() => null);
                    if (none?.selectedHome) return none;
                }
                throw error;
            }
            return this.noHomeServing();
        }
    }

    private async noHomeServing(): Promise<HomeBootstrapState & { kind: "none" }> {
        if (this.nativeRemote) {
            const reach = await accountClient.hubSessionReach(this.route);
            return { kind: "none", homes: reach.homes, routes: reach.routes,
                selectedHome: reach.selectedHome };
        }
        const [state, routes] = await Promise.all([
            accountClient.accountHomes(this.route),
            this.homeRoutes(),
        ]);
        return {
            kind: "none",
            homes: state.homes,
            routes,
            selectedHome: state.selectedHome,
        };
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

    private async projectTrackerTransport(project: ProjectId): Promise<workbenchClient.WorkbenchTransport> {
        if (!this.usesRemoteHome()) return this.localWorkTransport;
        try {
            return await this.connectRoutedProject(project);
        } catch (error) {
            // Older projects may predate route authorship; their selected Home
            // still admits the exact requested project at the product boundary.
            if (String(error).includes("no granted Home route")) return this.connectSelectedHome();
            throw error;
        }
    }

    async listProjectTrackers(project: ProjectId) {
        return workbenchClient.listProjectTrackers(await this.projectTrackerTransport(project), project);
    }

    async subscribeProjectTrackerChanges(project: ProjectId, onChange: () => void) {
        return workbenchClient.subscribeProjectTrackerChanges(await this.projectTrackerTransport(project), project, onChange);
    }

    /** Any project's tracker changed on this Home — for the personal queue. */
    subscribeAnyProjectTrackerChanges(onChange: (project: string) => void): () => void {
        return workbenchClient.subscribeAnyProjectTrackerChanges(this.workbenchTransport(), onChange);
    }

    async readProjectTrackerBacklog(project: ProjectId, queue: string) {
        return workbenchClient.readProjectTrackerBacklog(await this.projectTrackerTransport(project), project, queue);
    }

    async readProjectTrackerTasks(project: ProjectId, queue: string) {
        return workbenchClient.readProjectTrackerTasks(await this.projectTrackerTransport(project), project, queue);
    }

    /** Start, or find, this Home owner's run of a shipped tutorial (WHIP-5). */
    startShippedTutorial(name: string) {
        return workbenchClient.startShippedTutorial(this.workbenchTransport(), name);
    }

    getShippedTutorial(name: string) {
        return workbenchClient.getShippedTutorial(this.workbenchTransport(), name);
    }

    async completeProjectTrackerIssue(project: ProjectId, queue: string, item: string, intent: workbenchClient.TrackerCompletionIntent) {
        return workbenchClient.completeProjectTrackerIssue(await this.projectTrackerTransport(project), project, queue, item, intent);
    }
    async controlProjectTrackerIssue(project: ProjectId, queue: string, item: string, intent: workbenchClient.TrackerControlIntent) {
        return workbenchClient.controlProjectTrackerIssue(await this.projectTrackerTransport(project), project, queue, item, intent);
    }

    getTasks(): Promise<HumanTask[]> {
        return workbenchClient.getTasks(this.workbenchTransport());
    }

    getRoster(): Promise<RosterPerson[]> {
        return workbenchClient.getRoster(this.workbenchTransport());
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
        let admitted = { ...input, dictation_entitlement: await this.dictationEntitlement() };
        if (
            this.usesRemoteHome()
            && input.funding.kind === "managed"
            && !input.funding.entitlement
        ) {
            const publicKey = await workbenchClient.publicPublisherKey(this.workbenchTransport());
            const entitlement = await accountClient.mintManagedEntitlement(
                this.route,
                input.funding.tenant_id,
                publicKey,
            );
            admitted = { ...admitted, funding: { ...input.funding, entitlement } };
        }
        return workbenchClient.publishDeployment(this.workbenchTransport(), admitted);
    }

    async transcribeAudio(audio: Blob, signal: AbortSignal): Promise<string> {
        const response = await this.request("/account/dictation/transcribe", {
            method: "POST",
            headers: { "content-type": "audio/wav" },
            body: audio,
            signal,
        });
        const result = (await response.json()) as { text?: unknown; error?: unknown };
        if (!response.ok) throw new Error(typeof result.error === "string" ? result.error : "Transcription failed.");
        if (typeof result.text !== "string") throw new Error("Transcription response was malformed.");
        return result.text;
    }

    async startPanelPreview(input: PanelPreviewInput): Promise<PanelPreviewOutcome> {
        let admitted = { ...input, dictation_entitlement: await this.dictationEntitlement() };
        if (
            this.usesRemoteHome()
            && input.funding.kind === "managed"
            && !input.funding.entitlement
        ) {
            const publicKey = await workbenchClient.publicPublisherKey(this.workbenchTransport());
            const entitlement = await accountClient.mintManagedEntitlement(
                this.route,
                input.funding.tenant_id,
                publicKey,
            );
            admitted = { ...admitted, funding: { ...input.funding, entitlement } };
        }
        return workbenchClient.startPanelPreview(this.workbenchTransport(), admitted);
    }

    private async dictationEntitlement(): Promise<string | undefined> {
        const publicKey = await workbenchClient.publicPublisherKey(this.workbenchTransport());
        try {
            const claim = await this.route("POST", "/account/dictation/entitlement", { publisher_key: publicKey });
            return JSON.stringify(claim);
        } catch (error) {
            if (error instanceof RouteHttpError && (error.status === 401 || error.status === 402)) return undefined;
            throw error;
        }
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

    organizeChat(id: EngagementId, change: { archived?: boolean; pinned?: boolean }): Promise<void> {
        return workbenchClient.organizeChat(this.workbenchTransport(), id, change);
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

    async compensateTargetSettlement(declarationId: string, receiptLinks: readonly workbenchClient.CompensationReceiptLink[]): Promise<void> {
        await workbenchClient.compensateTargetSettlement(this.workbenchTransport(), declarationId, receiptLinks);
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

    subscribeWorkspace(onChange: (change: WorkspaceChange) => void, onOpen?: () => void): () => void {
        return workbenchClient.subscribeWorkspace(this.workbenchTransport(), onChange, onOpen);
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

    getModelContext(id: EngagementId): Promise<workbenchClient.LiveModelContext> {
        return workbenchClient.getModelContext(this.workbenchTransport(), id);
    }

    getContextUsage(id: EngagementId): Promise<workbenchClient.ChatContextUsage | null> {
        return workbenchClient.getContextUsage(this.workbenchTransport(), id);
    }

    getTree(id: EngagementId): Promise<FileEntry[]> {
        return workbenchClient.getTree(this.workbenchTransport(), id);
    }

    manageFile(id: EngagementId, command: workbenchClient.FileManagerCommand): Promise<void> {
        return workbenchClient.manageFile(this.workbenchTransport(), id, command);
    }

    getFile(id: EngagementId, path: string): Promise<string> {
        return workbenchClient.getFile(this.workbenchTransport(), id, path);
    }

    // The review surface's three reads/commands (ADR 0110 §7). Project-scoped, not
    // engagement-scoped: quarantine belongs to a project and reaches no chat's
    // worktree, which is the whole protection (ADR 0110 §1).
    listWhips(project: string) {
        return workbenchClient.projectWhips(this.workbenchTransport(), project);
    }
    /** WHIP-3's Run control: what this chat's `.whip` file would launch. */
    describeChatWhip(id: EngagementId, path: string) {
        return workbenchClient.describeChatWhip(this.workbenchTransport(), id, path);
    }
    runChatWhip(id: EngagementId, run: { path: string; cut: string; inputs: Record<string, unknown>; requestId: string }) {
        return workbenchClient.runChatWhip(this.workbenchTransport(), id, run);
    }
    listChatWhipRuns(id: EngagementId, path?: string) {
        return workbenchClient.listChatWhipRuns(this.workbenchTransport(), id, path);
    }
    stopChatWhip(id: EngagementId, stop: { path: string; launchedBy: string; requestId: string; key: string }) {
        return workbenchClient.stopChatWhip(this.workbenchTransport(), id, stop);
    }
    listWhipCosts(project: string) {
        return workbenchClient.projectWhipCosts(this.workbenchTransport(), project);
    }
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

    getFileBytes(
        id: EngagementId,
        path: string,
    ): Promise<{ bytes: Uint8Array; cut: string | null }> {
        return workbenchClient.getFileBytes(this.workbenchTransport(), id, path);
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

    streamContextUpload(id: EngagementId, file: { name: string; body: Blob }, targetId?: WorkTargetId): Promise<number> {
        return workbenchClient.streamContextUpload(this.workbenchTransport(), id, file, targetId);
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
        return this.nativeRemote
            ? accountClient.hubSessionTenants(this.route)
            : accountClient.accountTenants(this.routeJson());
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

    projectOrganizationModelOptions(
        project: string,
    ): Promise<accountClient.ProjectOrganizationModelOptions> {
        // Organization connection discovery belongs to the account/organization
        // plane. The returned project/Home identity is checked again by the
        // strict reader; no credential or project payload crosses this route.
        return accountClient.projectOrganizationModelOptions(this.routeJson(), project);
    }

    projectOrganizationModelSelection(
        project: string,
    ): Promise<accountClient.ProjectOrganizationModelSelection | null> {
        return this.runtimeAccountJson().then((json) =>
            accountClient.projectOrganizationModelSelection(json, project),
        );
    }

    selectProjectOrganizationModel(
        project: string,
        input: {
            readonly binding: accountClient.OrganizationModelAuthorityBinding;
            readonly connection: string;
            readonly model: string;
            readonly privateBroker: string;
            readonly admitPrivatePlaintext: true;
        },
    ): Promise<accountClient.ProjectOrganizationModelSelection> {
        return this.runtimeAccountJson().then((json) =>
            accountClient.selectProjectOrganizationModel(json, project, input),
        );
    }

    clearProjectOrganizationModelSelection(project: string): Promise<void> {
        return this.runtimeAccountJson().then((json) =>
            accountClient.clearProjectOrganizationModelSelection(json, project),
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
        return this.desktopSessionJson().then((json) => accountClient.hubSessionStatus(json));
    }

    hubSessionClaimHome(person: string): Promise<accountClient.HubSessionStatus> {
        return this.desktopSessionJson().then((json) => accountClient.hubSessionClaimHome(json, person));
    }

    hubSessionAccounts(): Promise<accountClient.HubSessionAccounts> {
        return this.desktopSessionJson().then((json) => accountClient.hubSessionAccounts(json));
    }

    hubSessionSelect(person: string): Promise<accountClient.HubSessionStatus> {
        return this.desktopSessionJson().then((json) => accountClient.hubSessionSelect(json, person));
    }

    hubSessionSelectLocal(): Promise<accountClient.HubSessionStatus> {
        return accountClient.hubSessionSelectLocal(this.route);
    }

    hubSessionStart(provider?: string): Promise<{ url: string; webReturn: boolean }> {
        return this.desktopSessionJson().then((json) => accountClient.hubSessionStart(json, provider));
    }

    hubSessionCallback(code: string): Promise<accountClient.HubSessionStatus> {
        return this.desktopSessionJson().then((json) => accountClient.hubSessionCallback(json, code));
    }

    hubSessionSignOut(): Promise<void> {
        return this.desktopSessionJson().then((json) => accountClient.hubSessionSignOut(json));
    }

    hubSessionReach(): Promise<accountClient.HubSessionReach> {
        return this.desktopSessionJson().then((json) => accountClient.hubSessionReach(json));
    }
}
