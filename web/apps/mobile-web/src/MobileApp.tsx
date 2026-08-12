/**
 * The mobile **flow client** (`mobile-client.md`; MOB-029): the one place that
 * composes the committed D-MOBILE islands into the device's actual user journey —
 * **pair → navigate → send (offline + online)** — over the *real* control plane.
 * It is the surface the mobile e2e (`web/e2e/features/mobile.feature`) drives.
 *
 * It owns no truth of its own: every decision is a committed pure reducer.
 *   - Pairing is the {@link PairingFlow} island over the {@link reducePairing}
 *     machine, fed by the real `POST /pairing-requests` → owner `POST
 *     /boundaries/:id/accept` → `GET /pairing-status/:id` handshake (MOB-027). In
 *     the single-authority loopback dev/e2e shell the owner *is* this process, so
 *     that harness drives the accept itself. The native shell presents its
 *     keystore-derived device id and waits for the Machine owner to approve.
 *   - Once paired it mints the held {@link BridgeGrant} the boundary pinned and
 *     feeds the {@link ConnectionState} machine (MOB-018); the relay toggle moves
 *     the device between `active` and `offline` exactly as a dropped relay would.
 *   - Navigation is the {@link Carousel} island (MOB-014) over the pure carousel
 *     reducer (MOB-009); the chat stop is the {@link MobileChat} composer (MOB-020)
 *     whose send gate and the {@link ConnectionBanner} (MOB-028) read one
 *     connection fold, so a degraded link refuses a standing command in both places.
 *
 * It is reached at `?mobile=1` (or `#mobile`) so it composes with — rather than
 * replaces — the desktop workbench, and so the e2e can address it directly without
 * a native toolchain (the projection-client web build, ADR 0020 / `MOBILE-PROJECTION-1`).
 */

import {
    createEffect,
    createMemo,
    createResource,
    createSignal,
    For,
    onCleanup,
    type JSX,
    Show,
} from "solid-js";
import {
    cancel as cancelBarcodeScan,
    checkPermissions as checkCameraPermissions,
    Format as BarcodeFormat,
    openAppSettings,
    requestPermissions as requestCameraPermissions,
    scan,
} from "@tauri-apps/plugin-barcode-scanner";
import {
    bridgeGrantId,
    clientRequestId,
    decodeSubject,
    type BridgeGrant,
    type EngagementId,
    type LocalState,
    type ProjectionCarriage,
    type ProjectId,
    type ProjectNode,
    type Workspace,
    publicKey,
    refreshMobileAccountToken,
    scopeId,
} from "@gaugewright/control-plane-client";
import {
    applySelection,
    Carousel,
    ChatApprovalCard,
    type ChatApprovalState,
    ChatPanel,
    ConnectionBanner,
    type ConnectionState,
    createSessionComposerController,
    emptyTranscript,
    FacetBrowser,
    fromSnapshot,
    initialCarousel,
    initialConnection,
    initialPairing,
    PairingFlow,
    parsePairingStatus,
    parseTicket,
    type PairingState,
    QueueSheet,
    reduceCarousel,
    reduceChatApproval,
    reduceConnection,
    reducePairing,
    reduceTranscript,
    tapGesture,
    TopBar,
    type Transcript,
    type CarouselState,
    type PaneKind,
} from "@gaugewright/workbench-ui";
import { createMobileSession } from "./mobile-session";
import { MobileControlPlane } from "./mobile-control-plane";
import {
    accountTokenExpiresWithin,
    loadMobileHomeRoutes,
    MobileHomePool,
    MobileRouteCache,
    type MobileHomeConnection,
    type MobileHomeConnectionState,
} from "./mobile-home-pool";
import {
    MobileHomeCache,
    projectScopedWorkspace,
    type MobileTargetReference,
} from "./mobile-home-cache";
import {
    beginMobileAccountLogin,
    clearMachineEndpoint,
    closeMobileRelayRoute,
    loadMobileRuntime,
    machineCredentialIsRejected,
    MOBILE_ACCOUNT_BASE,
    onMobileAuthCallback,
    onMobileTargetReference,
    redeemMobileAccountHandoff,
    resolveMobileRouteEndpoint,
    saveMachineEndpoint,
    onMachineInvitation,
    parseMachineInvitationLink,
    type MobileRuntime,
    type MachineCredential,
    type MachineControllerInvitation,
} from "./mobile-runtime";
import "./mobile-scanner.css";

/** Whether the harness is addressed — `?mobile=1` or `#mobile`. The desktop app
 *  delegates here on that flag so the two shells share one entry point. */
export function isMobileHarness(): boolean {
    if (typeof window === "undefined") return false;
    const p = new URLSearchParams(window.location.search);
    return p.get("mobile") === "1" || window.location.hash.replace(/^#/, "") === "mobile";
}

export function MobileApp(): JSX.Element {
    const [runtime, runtimeActions] = createResource(() => loadMobileRuntime());
    const [accessMode, setAccessMode] = createSignal<"account" | "direct" | null>(null);
    const [accountToken, setAccountToken] = createSignal<string | null>(null);
    const [accountError, setAccountError] = createSignal<string | null>(null);
    const [pendingTarget, setPendingTarget] =
        createSignal<MobileTargetReference | null>(null);
    const [machineEndpoint, setMachineEndpoint] = createSignal<string | null | undefined>();
    const [pendingInvitation, setPendingInvitation] =
        createSignal<MachineControllerInvitation | null>(null);
    const [enrollmentError, setEnrollmentError] = createSignal<string | null>(null);
    const [scanningInvitation, setScanningInvitation] = createSignal(false);
    const [cameraSettingsNeeded, setCameraSettingsNeeded] = createSignal(false);
    let endpointField: HTMLInputElement | undefined;
    let invitationListenerStarting = false;
    let stopInvitationListener: (() => void) | null = null;
    let authListenerStarting = false;
    let stopAuthListener: (() => void) | null = null;
    let targetListenerStarting = false;
    let stopTargetListener: (() => void) | null = null;
    let redeemingAccountCode: string | null = null;
    let expiredAccountTokenCleared = false;
    let accountSignedOut = false;
    onCleanup(() => {
        stopInvitationListener?.();
        stopAuthListener?.();
        stopTargetListener?.();
        document.documentElement.classList.remove("mobile-scanner-active");
    });

    createEffect(() => {
        document.documentElement.classList.toggle(
            "mobile-scanner-active",
            scanningInvitation(),
        );
    });

    createEffect(() => {
        const loaded = runtime();
        if (!loaded) return;
        const token = loaded.accountToken;
        if (token && accountToken() === null && !accountSignedOut) {
            if (accountTokenExpiresWithin(token, 0)) {
                if (!expiredAccountTokenCleared) {
                    expiredAccountTokenCleared = true;
                    void loaded.clearAccountToken();
                }
                setAccountError("Your session expired. Sign in again to reconnect.");
            } else {
                setAccountToken(token);
                setAccessMode("account");
            }
        }
        if (loaded.pendingAccountCode) void completeAccountHandoff(loaded.pendingAccountCode, loaded);
        if (loaded.pendingTarget && pendingTarget() === null) {
            setPendingTarget(loaded.pendingTarget);
        }
        if (loaded.pendingInvitation && pendingInvitation() === null) {
            setPendingInvitation(loaded.pendingInvitation);
            setMachineEndpoint(loaded.pendingInvitation.endpoint);
            setAccessMode("direct");
        }
        if (
            loaded.native
            && accessMode() === null
            && loaded.credentials.length > 0
        ) {
            setMachineEndpoint(loaded.endpoint);
            setAccessMode("direct");
        }
        if (!loaded.native && accessMode() === null) {
            setAccessMode("direct");
            setMachineEndpoint(loaded.endpoint);
        }
        if (
            accessMode() === "direct"
            && machineEndpoint() === undefined
        ) {
            setMachineEndpoint(loaded.endpoint);
        }
    });

    function completeAccountHandoff(code: string, loaded: MobileRuntime) {
        if (redeemingAccountCode === code) return;
        redeemingAccountCode = code;
        void redeemMobileAccountHandoff(MOBILE_ACCOUNT_BASE, code)
            .then(async (token) => {
                await loaded.storeAccountToken(token);
                accountSignedOut = false;
                setAccountToken(token);
                setAccountError(null);
                setAccessMode("account");
            })
            .catch((error) => setAccountError(String(error)))
            .finally(() => {
                redeemingAccountCode = null;
            });
    }

    createEffect(() => {
        const loaded = runtime();
        if (!loaded?.native || authListenerStarting || stopAuthListener) return;
        authListenerStarting = true;
        void onMobileAuthCallback((code) => {
            completeAccountHandoff(code, loaded);
        }).then((stop) => {
            stopAuthListener = stop;
        }).finally(() => {
            authListenerStarting = false;
        });
    });

    createEffect(() => {
        const loaded = runtime();
        if (!loaded?.native || targetListenerStarting || stopTargetListener) return;
        targetListenerStarting = true;
        void onMobileTargetReference((target) => {
            setPendingTarget(target);
            if (accountToken()) setAccessMode("account");
        }).then((stop) => {
            stopTargetListener = stop;
        }).finally(() => {
            targetListenerStarting = false;
        });
    });

    // Invitation intake must exist before a Machine endpoint does. On iOS the
    // app can finish loading underneath the custom-scheme confirmation; mounting
    // this listener only inside MobileSession would leave the endpoint entry
    // screen unable to receive the invitation that supplies its own endpoint.
    createEffect(() => {
        const loaded = runtime();
        if (!loaded?.native || invitationListenerStarting || stopInvitationListener) return;
        invitationListenerStarting = true;
        void onMachineInvitation((invitation) => {
            setPendingInvitation(invitation);
            setMachineEndpoint(invitation.endpoint);
            setAccessMode("direct");
        }).then((stop) => {
            stopInvitationListener = stop;
        }).finally(() => {
            invitationListenerStarting = false;
        });
    });

    function enrollMachine() {
        try {
            setMachineEndpoint(saveMachineEndpoint(endpointField?.value ?? ""));
            setEnrollmentError(null);
        } catch (error) {
            setEnrollmentError(error instanceof Error ? error.message : String(error));
        }
    }

    async function scanMachineInvitation() {
        setEnrollmentError(null);
        setCameraSettingsNeeded(false);
        setScanningInvitation(true);
        try {
            let permission = await checkCameraPermissions();
            if (permission === "prompt") {
                permission = await requestCameraPermissions();
            }
            if (permission !== "granted") {
                setCameraSettingsNeeded(permission === "denied");
                throw new Error("Camera access is required to scan a Machine invitation.");
            }

            const scanned = await scan({
                cameraDirection: "back",
                formats: [BarcodeFormat.QRCode],
                windowed: true,
            });
            const invitation = parseMachineInvitationLink(scanned.content);
            if (!invitation) {
                throw new Error(
                    "That QR code is not a current GaugeDesk Machine invitation.",
                );
            }
            setPendingInvitation(invitation);
            setMachineEndpoint(invitation.endpoint);
        } catch (error) {
            const message = error instanceof Error ? error.message : String(error);
            // Closing the native scanner is a navigation act, not an enrollment
            // failure. Android and iOS spell the plugin cancellation differently.
            if (!/cancel(?:ed|led)/i.test(message)) setEnrollmentError(message);
        } finally {
            setScanningInvitation(false);
        }
    }

    async function cancelMachineInvitationScan() {
        try {
            await cancelBarcodeScan();
        } finally {
            setScanningInvitation(false);
        }
    }

    function accessPage(loaded: MobileRuntime): JSX.Element {
        const signedIn = () => accountToken() !== null;
        return (
            <div class="mobile-pairing-stage mobile-account-entry">
                <Show
                    when={scanningInvitation()}
                    fallback={
                        <form
                            class="pairing-entry"
                            data-mobile-access
                            data-machine-enrollment
                            onSubmit={(event) => {
                                event.preventDefault();
                                enrollMachine();
                            }}
                        >
                            <div class="pairing-head">GaugeDesk</div>
                            <div class="status">
                                {signedIn()
                                    ? "Pair a Machine to open its projects and chats."
                                    : "Sign in to open your projects wherever their Machines run."}
                            </div>
                            <Show when={!signedIn()}>
                                <button
                                    type="button"
                                    class="pairing-submit"
                                    data-mobile-sign-in
                                    onClick={() => {
                                        setAccountError(null);
                                        void beginMobileAccountLogin(MOBILE_ACCOUNT_BASE)
                                            .catch((error) => setAccountError(String(error)));
                                    }}
                                >
                                    sign in
                                </button>
                            </Show>
                            <Show when={accountError()}>
                                <div class="status mobile-enrollment-error" role="alert">
                                    {accountError()}
                                </div>
                            </Show>
                            <div class="mobile-enrollment-or">
                                <span>pair a Machine</span>
                            </div>
                            <Show when={loaded.credentials.length > 0}>
                                <div class="mobile-saved-machines">
                                    <div class="status">Saved on this phone</div>
                                    <For each={loaded.credentials}>
                                        {(credential) => (
                                            <button
                                                type="button"
                                                class="mobile-account-recent"
                                                onClick={() => {
                                                    setAccessMode("direct");
                                                    setMachineEndpoint(credential.endpoint);
                                                }}
                                            >
                                                {credential.machine}
                                            </button>
                                        )}
                                    </For>
                                </div>
                            </Show>
                            <div class="status">
                                Scan the one-use invitation shown by GaugeDesk on the
                                Machine you want this phone to follow.
                            </div>
                            <Show when={loaded.native}>
                                <button
                                    type="button"
                                    class="pairing-submit mobile-scan-invitation"
                                    data-machine-scan
                                    onClick={() => void scanMachineInvitation()}
                                >
                                    scan QR code
                                </button>
                                <div class="mobile-enrollment-or">
                                    <span>or enter its address</span>
                                </div>
                            </Show>
                            <input
                                ref={endpointField}
                                type="url"
                                inputmode="url"
                                autocomplete="url"
                                class="pairing-code-input"
                                data-machine-endpoint
                                placeholder="https://machine.example.com"
                                aria-label="Machine endpoint"
                            />
                            <Show when={enrollmentError()}>
                                <div class="status mobile-enrollment-error" role="alert">
                                    {enrollmentError()}
                                </div>
                            </Show>
                            <Show when={cameraSettingsNeeded()}>
                                <button
                                    type="button"
                                    class="pairing-submit mobile-camera-settings"
                                    onClick={() => void openAppSettings()}
                                >
                                    open camera settings
                                </button>
                            </Show>
                            <button type="submit" class="pairing-submit" data-machine-connect>
                                connect
                            </button>
                        </form>
                    }
                >
                    <div class="mobile-qr-scanner" data-machine-scanner>
                        <div class="mobile-qr-guidance">
                            Point the camera at the invitation QR code
                        </div>
                        <div class="mobile-qr-frame" aria-hidden="true" />
                        <button
                            type="button"
                            class="mobile-qr-cancel"
                            onClick={() => void cancelMachineInvitationScan()}
                        >
                            cancel
                        </button>
                    </div>
                </Show>
            </div>
        );
    }

    return (
        <div
            class="workbench mobile"
            classList={{ "mobile-scanning": scanningInvitation() }}
            data-mobile
            data-mobile-harness
        >
            <Show
                when={runtime()}
                fallback={
                    <Show
                        when={runtime.error}
                        fallback={
                            <div class="mobile-pairing-stage mobile-native-loading" role="status">
                                opening this device…
                            </div>
                        }
                    >
                        <div class="mobile-pairing-stage mobile-native-loading" role="alert">
                            <div>this device could not be opened</div>
                            <div class="pairing-error">
                                {runtime.error instanceof Error
                                    ? runtime.error.message
                                    : String(runtime.error)}
                            </div>
                            <button type="button" onClick={() => void runtimeActions.refetch()}>
                                try again
                            </button>
                        </div>
                    </Show>
                }
            >
                {(loaded) => (
                    <Show
                        when={accessMode() === "account" && accountToken()}
                        fallback={
                            <Show
                                when={machineEndpoint()}
                                fallback={accessPage(loaded())}
                            >
                                {(endpoint) => (
                                    <MobileSession
                                        runtime={{ ...loaded(), endpoint: endpoint() }}
                                        pendingInvitation={
                                            pendingInvitation() ?? loaded().pendingInvitation
                                        }
                                        onCredentialRejected={() => {
                                            clearMachineEndpoint();
                                            setPendingInvitation(null);
                                            setMachineEndpoint(null);
                                            setAccessMode(null);
                                            setEnrollmentError(
                                                "This Machine no longer trusts this device. Pair it again.",
                                            );
                                            void runtimeActions.refetch();
                                        }}
                                        onChangeMachine={() => {
                                            clearMachineEndpoint();
                                            setPendingInvitation(null);
                                            setMachineEndpoint(null);
                                            setAccessMode(null);
                                            void runtimeActions.refetch();
                                        }}
                                    />
                                )}
                            </Show>
                        }
                    >
                        <MobileAccountShell
                            runtime={loaded()}
                            token={accountToken()!}
                            pendingTarget={pendingTarget()}
                            onTargetConsumed={() => setPendingTarget(null)}
                            onToken={setAccountToken}
                            onSignOut={() => {
                                accountSignedOut = true;
                                setAccountToken(null);
                                setAccessMode(null);
                            }}
                            onPairMachine={() => setAccessMode(null)}
                        />
                    </Show>
                )}
            </Show>
        </div>
    );
}

interface ConnectedMobileRuntime extends MobileRuntime {
    readonly endpoint: string;
}

interface MobileProjectSummary {
    readonly project: ProjectNode;
    readonly freshness: "live" | "stale";
    readonly recent: readonly {
        readonly id: EngagementId;
        readonly title: string;
    }[];
}

function MobileAccountShell(props: {
    readonly runtime: MobileRuntime;
    readonly token: string;
    readonly pendingTarget: MobileTargetReference | null;
    readonly onTargetConsumed: () => void;
    readonly onToken: (token: string) => void;
    readonly onSignOut: () => void;
    readonly onPairMachine: () => void;
}): JSX.Element {
    const owner = decodeSubject(props.token) ?? "account:unresolved";
    let deviceStorage: Storage | null = null;
    try {
        deviceStorage = window.localStorage;
    } catch {
        deviceStorage = null;
    }
    const routeCache = new MobileRouteCache(owner, deviceStorage);
    const [routes, routeActions] = createResource(
        () => props.token,
        async () => {
            try {
                const live = await loadMobileHomeRoutes(
                    MOBILE_ACCOUNT_BASE,
                    () => props.token,
                );
                routeCache.save(live);
                return live;
            } catch (error) {
                const cached = routeCache.load();
                if (cached.length > 0) return cached;
                throw error;
            }
        },
    );
    const protectedCache = new MobileHomeCache<Workspace>(owner, deviceStorage);
    const draftCache = new MobileHomeCache<string>(
        owner,
        deviceStorage,
        "gw.mobile.drafts.v1",
    );
    const [homeStates, setHomeStates] =
        createSignal<Record<string, MobileHomeConnectionState>>({});
    let priorPool: MobileHomePool | null = null;
    const pool = createMemo(() => {
        const current = routes();
        const next = current
            ? new MobileHomePool(current, () => props.token, {
                resolveEndpoint: resolveMobileRouteEndpoint,
                closeRoute: closeMobileRelayRoute,
                onStateChange: (homeId, state) => {
                    setHomeStates((current) => ({
                        ...current,
                        [homeId]: state,
                    }));
                    if (
                        state === "grant-revoked"
                        || state === "device-untrusted"
                        || state === "policy-denied"
                    ) {
                        protectedCache.clearHome(homeId);
                        draftCache.clearHome(homeId);
                    } else if (state !== "live" && state !== "connecting") {
                        protectedCache.markHome(
                            homeId,
                            state === "offline" ? "offline" : "stale",
                        );
                    }
                },
            })
            : null;
        if (priorPool && priorPool !== next) void priorPool.closeAll();
        priorPool = next;
        return next;
    });
    const [selected, setSelected] = createSignal<{
        readonly project: ProjectId;
        readonly engagement: EngagementId | null;
        readonly target: MobileTargetReference | null;
    } | null>(null);
    const [projects] = createResource(
        () => {
            const directory = pool();
            const current = routes();
            return directory && current ? { directory, routes: current } : undefined;
        },
        async ({ directory, routes: current }) => {
            const firstRouteByHome = new Map<string, (typeof current)[number]>();
            for (const route of current) {
                if (!firstRouteByHome.has(route.homeId)) {
                    firstRouteByHome.set(route.homeId, route);
                }
            }
            const routedProjects = new Set(current.map((route) => route.project));
            const summaries: MobileProjectSummary[] = [];
            for (const route of firstRouteByHome.values()) {
                const routedAtHome = current.filter(
                    (candidate) => candidate.homeId === route.homeId,
                );
                const scopedWorkspaces: {
                    readonly workspace: Workspace;
                    readonly project: ProjectId;
                    readonly freshness: "live" | "stale";
                }[] = [];
                try {
                    const connection = await directory.connectProject(route.project);
                    const carriage = await connection.api.getWorkspaceCarriage();
                    const freshness =
                        carriage.freshness.marker === "live" ? "live" : "stale";
                    for (const routed of routedAtHome) {
                        const scoped = projectScopedWorkspace(
                            carriage.value,
                            routed.project,
                        );
                        if (!scoped) continue;
                        protectedCache.put({
                            homeId: connection.homeId,
                            project: routed.project,
                            key: "workspace",
                            value: scoped,
                            freshness,
                            updatedAt: carriage.freshness.generatedAt,
                        });
                        scopedWorkspaces.push({
                            workspace: scoped,
                            project: routed.project,
                            freshness,
                        });
                    }
                } catch {
                    for (const routed of routedAtHome) {
                        const cached = protectedCache.get(
                            route.homeId,
                            routed.project,
                            "workspace",
                        );
                        if (!cached) continue;
                        scopedWorkspaces.push({
                            workspace: cached.value,
                            project: routed.project,
                            freshness: "stale",
                        });
                    }
                }
                for (const scoped of scopedWorkspaces) {
                    const projectNode = scoped.workspace.projects.find(
                        (candidate) => candidate.id === scoped.project,
                    );
                    if (
                        !projectNode
                        || projectNode.homeId !== route.homeId
                        || !routedProjects.has(projectNode.id)
                    ) {
                        continue;
                    }
                    const chatIds = new Set(
                        projectNode.placements.flatMap((placement) =>
                            placement.chats.map((chat) => chat.id),
                        ),
                    );
                    summaries.push({
                        project: projectNode,
                        freshness: scoped.freshness,
                        recent: scoped.workspace.recent
                            .filter((chat) => chatIds.has(chat.id))
                            .map((chat) => ({ id: chat.id, title: chat.title })),
                    });
                }
            }
            return summaries.sort((left, right) =>
                left.project.name.localeCompare(right.project.name),
            );
        },
    );
    const [activeConnection] = createResource(
        () => {
            const target = selected();
            const directory = pool();
            return target && directory ? { target, directory } : undefined;
        },
        async ({ target, directory }): Promise<MobileHomeConnection> => {
            try {
                return await directory.connectProject(target.project);
            } catch (error) {
                const route = directory.routeFor(target.project);
                const cached = protectedCache.get(
                    route.homeId,
                    target.project,
                    "workspace",
                );
                if (!cached) throw error;
                const base = new MobileControlPlane(route.endpoint, {
                    bearer: () => props.token,
                });
                const api = new Proxy(base, {
                    get(instance, property) {
                        if (property === "getWorkspaceCarriage") {
                            return async (): Promise<ProjectionCarriage<Workspace>> => ({
                                value: cached.value,
                                freshness: {
                                    marker: "stale",
                                    generatedAt: cached.updatedAt,
                                    repairHint: "Reconnect to this Machine to refresh.",
                                },
                                clientRequestId: null,
                            });
                        }
                        if (property === "getTasks") return async () => [];
                        if (property === "subscribeWorkspace") return () => () => undefined;
                        const value = Reflect.get(instance, property, instance) as unknown;
                        return typeof value === "function" ? value.bind(instance) : value;
                    },
                });
                return {
                    homeId: route.homeId,
                    endpoint: route.endpoint,
                    api,
                    state: "offline",
                    lastUsedAt: Date.now(),
                };
            }
        },
    );

    createEffect(() => {
        const target = props.pendingTarget;
        const available = projects()?.some(
            (summary) => summary.project.id === target?.project,
        );
        if (!target || !available) return;
        setSelected({
            project: target.project,
            engagement:
                target.kind === "chat" || target.kind === "task"
                    ? target.id as EngagementId
                    : target.kind === "file"
                        ? target.engagement as EngagementId
                    : null,
            target,
        });
        props.onTargetConsumed();
    });

    let refreshingAccount = false;
    async function renewAccountToken() {
        if (refreshingAccount) return;
        refreshingAccount = true;
        try {
            const token = await refreshMobileAccountToken(
                MOBILE_ACCOUNT_BASE,
                props.token,
            );
            await props.runtime.storeAccountToken(token);
            props.onToken(token);
        } finally {
            refreshingAccount = false;
        }
    }
    createEffect(() => {
        if (accountTokenExpiresWithin(props.token, 10 * 60)) {
            void renewAccountToken().then(() => routeActions.refetch()).catch(() => {
                // The next authenticated projection gives the explicit repair outcome.
            });
        }
    });
    const refreshTimer = window.setInterval(() => {
        void renewAccountToken().catch(() => {
            // A failed proactive refresh never fabricates logout.
        });
    }, 40 * 60_000);
    const evictionTimer = window.setInterval(() => {
        void pool()?.evictIdle();
    }, 60_000);
    onCleanup(() => {
        window.clearInterval(refreshTimer);
        window.clearInterval(evictionTimer);
        void pool()?.closeAll();
    });

    async function signOut() {
        await pool()?.closeAll();
        protectedCache.clearAll();
        draftCache.clearAll();
        routeCache.clear();
        await props.runtime.clearAccountToken();
        props.onSignOut();
    }

    return (
        <Show
            when={selected() && activeConnection()}
            keyed
            fallback={
                <div class="mobile-project-browser" data-pane="nav">
                    <header class="mobile-project-browser-head">
                        <h1>Projects</h1>
                        <button type="button" onClick={() => void signOut()}>
                            sign out
                        </button>
                    </header>
                    <main class="mobile-project-browser-body">
                        <Show
                            when={!routes.loading && !projects.loading}
                            fallback={<div class="status">finding your projects…</div>}
                        >
                            <Show
                                when={!routes.error && !projects.error}
                                fallback={
                                    <div class="status mobile-enrollment-error" role="alert">
                                        {String(routes.error ?? projects.error)}
                                    </div>
                                }
                            >
                                <div class="mobile-account-project-list">
                                    <For
                                        each={projects() ?? []}
                                        fallback={
                                            <div class="mobile-project-empty">
                                                <div class="mobile-project-empty-title">
                                                    No projects connected
                                                </div>
                                                <div class="status">
                                                    Pair a Machine to open its projects,
                                                    chats, files, and tasks here.
                                                </div>
                                                <button
                                                    type="button"
                                                    class="pairing-submit"
                                                    onClick={props.onPairMachine}
                                                >
                                                    pair a Machine
                                                </button>
                                            </div>
                                        }
                                    >
                                        {(summary) => (
                                            <section class="mobile-account-project">
                                                <button
                                                    type="button"
                                                    class="pairing-submit"
                                                    onClick={() =>
                                                        setSelected({
                                                            project: summary.project.id,
                                                            engagement: null,
                                                            target: null,
                                                        })}
                                                >
                                                    {summary.project.name}
                                                    {summary.freshness === "stale"
                                                        ? " · offline"
                                                        : ""}
                                                </button>
                                                <For each={summary.recent.slice(0, 3)}>
                                                    {(chat) => (
                                                        <button
                                                            type="button"
                                                            class="mobile-account-recent"
                                                            onClick={() =>
                                                                setSelected({
                                                                    project: summary.project.id,
                                                                    engagement: chat.id,
                                                                    target: null,
                                                                })}
                                                        >
                                                            {chat.title}
                                                        </button>
                                                    )}
                                                </For>
                                            </section>
                                        )}
                                    </For>
                                </div>
                            </Show>
                        </Show>
                    </main>
                </div>
            }
        >
            {(connection) => (
                <MobileSession
                    runtime={{
                        ...props.runtime,
                        endpoint: connection.endpoint,
                    }}
                    account={{
                        connection,
                        connectionState: () =>
                            homeStates()[connection.homeId] ?? connection.state,
                        project: projects()!.find(
                            (summary) => summary.project.id === selected()!.project,
                        )!.project,
                        initialEngagement: selected()!.engagement,
                        initialTarget: selected()!.target,
                        draftCache,
                        onBack: () => setSelected(null),
                        onSignOut: () => void signOut(),
                    }}
                />
            )}
        </Show>
    );
}

function MobileSession(props: {
    readonly runtime: ConnectedMobileRuntime;
    readonly pendingInvitation?: MachineControllerInvitation | null;
    readonly onCredentialRejected?: () => void;
    readonly onChangeMachine?: () => void;
    readonly account?: {
        readonly connection: MobileHomeConnection;
        readonly connectionState: () => MobileHomeConnectionState;
        readonly project: ProjectNode;
        readonly initialEngagement: EngagementId | null;
        readonly initialTarget: MobileTargetReference | null;
        readonly draftCache: MobileHomeCache<string>;
        readonly onBack: () => void;
        readonly onSignOut: () => void;
    };
}): JSX.Element {
    const [machineSession, setMachineSession] = createSignal<string | null>(null);
    const [machineSessionExpiresAt, setMachineSessionExpiresAt] = createSignal(0);
    const [storedCredential, setStoredCredential] = createSignal<MachineCredential | null>(
        props.account
            ? null
            : props.runtime.credentials.find(
                (credential) => credential.endpoint === props.runtime.endpoint,
            ) ?? null,
    );
    const DEVICE = props.runtime.identity;
    const [pairing, setPairing] = createSignal<PairingState>(initialPairing);
    const [connection, setConnection] = createSignal<ConnectionState>(
        initialConnection({ identity: DEVICE, grants: [] }, Date.now()),
    );
    const [carousel, setCarousel] = createSignal<CarouselState>(initialCarousel);
    // The composer draft is held here rather than inside the shared controller so
    // it can ride the account draft cache on every keystroke (MOB-004: a draft
    // survives leaving the chat, restarting, and going offline). The controller
    // reads and writes it through its controlled-draft seam.
    const [draft, setDraftText] = createSignal("");
    // An inline merge/review approval card threaded in the chat transcript (MOB-031),
    // or `null` when the turn surfaced nothing to approve. It folds the same review
    // lifecycle the desktop output catalog drives, inline at the chat stop.
    const [approval, setApproval] = createSignal<ChatApprovalState | null>(null);
    const [engagement, setEngagement] = createSignal<EngagementId | null>(null);
    const [environment, setEnvironment] = createSignal<string | null>(
        props.account?.connection.homeId ?? null,
    );
    const [log, setLog] = createSignal<string[]>([]);
    const append = (line: string) => setLog((l) => [...l, line]);
    const api = props.account?.connection.api
        ?? new MobileControlPlane(props.runtime.endpoint, {
            machineSession,
            onSessionRejected: () => {
                setMachineSession(null);
                setMachineSessionExpiresAt(0);
                setConnection((state) =>
                    reduceConnection(state, { kind: "relay", reachable: false }),
                );
                append("Machine session rejected; proving this device again…");
            },
        });
    const browseApi = createMemo(() => {
        const project = props.account?.project;
        if (!project) return api;
        return new Proxy(api, {
            get(target, property) {
                if (property === "getWorkspaceCarriage") {
                    return async (): Promise<ProjectionCarriage<Workspace>> => {
                        const carriage = await target.getWorkspaceCarriage();
                        const chatIds = new Set(
                            project.placements.flatMap((placement) =>
                                placement.chats.map((chat) => chat.id),
                            ),
                        );
                        return {
                            ...carriage,
                            value: {
                                ...carriage.value,
                                projects: carriage.value.projects.filter(
                                    (candidate) => candidate.id === project.id,
                                ),
                                recent: carriage.value.recent.filter((chat) =>
                                    chatIds.has(chat.id),
                                ),
                                workstreams: project.placements.flatMap(
                                    (placement) => placement.workstreams,
                                ),
                                workTargets: [...project.targets],
                                personalPlacement:
                                    carriage.value.personalPlacement
                                    && project.placements.some(
                                        (placement) =>
                                            placement.placementId
                                            === carriage.value.personalPlacement,
                                    )
                                        ? carriage.value.personalPlacement
                                        : null,
                            },
                        };
                    };
                }
                const value = Reflect.get(target, property, target) as unknown;
                return typeof value === "function" ? value.bind(target) : value;
            },
        });
    });
    let resuming = false;
    let autoEnrollmentInvitationId: string | null = null;

    // The transcript of the selected chat (MOB-F2): a fold of the durable snapshot
    // plus the live SSE, exactly the desktop chat pane's source — so the mobile
    // Chat stop shows what the agent actually did, not just the consent surface.
    const [transcript, setTranscript] = createSignal<Transcript>(emptyTranscript);
    let unsubscribe: (() => void) | null = null;
    onCleanup(() => unsubscribe?.());

    // `wsKey` refreshes sibling projections (currently the task queue). The Browse
    // tree itself consumes reference-resolved deltas inside FacetBrowser (UX-12),
    // rather than using this key to refetch the whole workspace.
    const [wsKey, setWsKey] = createSignal(0);

    // The selected chat's worktree files (MOB-F: the Files pane mirrors the host's
    // worktree for the open chat, not a stub). `filesKey` bumps after a turn so a
    // change to the worktree is reflected. Only fetched once a chat is open.
    const [filesKey, setFilesKey] = createSignal(0);
    const [selectedFile, setSelectedFile] = createSignal<string | null>(null);
    const [files] = createResource(
        () => {
            const id = engagement();
            return id ? ([id, filesKey()] as const) : undefined;
        },
        ([id]) => api.getTree(id),
    );
    const [fileContent] = createResource(
        () => {
            const id = engagement();
            const path = selectedFile();
            return id && path ? ([id, path, filesKey()] as const) : undefined;
        },
        ([id, path]) => api.getFile(id, path),
    );

    // The human task queue (the `Next ③` header affordance, `mobile-client.md`):
    // the same `GET /tasks` projection the desktop TaskBar reads — review-needed
    // work, current-first — so the phone surfaces tasks at all (it previously had
    // no way to see them). Fetched only once paired; refetched on `wsKey` so a turn
    // settling, a chat created, or a desktop-side change re-derives the queue.
    const [tasks] = createResource(
        () => (props.account || pairing().step === "paired" ? wsKey() : undefined),
        () => api.getTasks(),
    );

    async function openCredentialSession(stored: MachineCredential) {
        const issued = await api.machineSessionChallenge(stored.grantId, DEVICE.id);
        const signature = await props.runtime.signChallenge(issued.challenge);
        const opened = await api.openMachineSession({
            challengeId: issued.challengeId,
            grantId: stored.grantId,
            device: DEVICE.id,
            credential: stored.credential,
            signature,
        });
        if (opened.machine !== stored.machine) {
            throw new Error("The session was issued by a different Machine");
        }
        setMachineSession(opened.session);
        setMachineSessionExpiresAt(opened.expiresAt);
        if (environment() !== opened.machine) {
            // The session response is the Machine's standing proof that this
            // exact device/grant is Active. Fold that fact through the same
            // pairing reducer as the legacy boundary-status path; otherwise
            // native enrollment succeeds while the UI remains forever at
            // "waiting for approval".
            setPairing((state) =>
                reducePairing(state, {
                    kind: "status",
                    status: {
                        phase: "Active",
                        bound: {
                            device: DEVICE.id,
                            bridgeGrant: bridgeGrantId(stored.grantId),
                        },
                        paired: true,
                    },
                }),
            );
            completePairing(opened.machine, stored.grantId);
        } else {
            setConnection((state) => reduceConnection(state, { kind: "relay", reachable: true }));
        }
    }

    // Session capabilities stay memory-only and are renewed with a fresh
    // device-key proof before expiry. This is the only mobile-specific session
    // concern; all project/chat/file commands continue through the shared routes.
    const refreshTimer = window.setInterval(() => {
        const stored = storedCredential();
        if (
            props.account
            ||
            !props.runtime.native
            || !stored
            || resuming
            || machineSessionExpiresAt() > Date.now() / 1_000 + 60
        ) {
            return;
        }
        resuming = true;
        void openCredentialSession(stored)
            .catch((error) => {
                append(`session refresh failed: ${String(error)}`);
                setMachineSession(null);
                setMachineSessionExpiresAt(0);
                setConnection((state) =>
                    reduceConnection(state, { kind: "relay", reachable: false }),
                );
            })
            .finally(() => {
                resuming = false;
            });
    }, 30_000);
    onCleanup(() => window.clearInterval(refreshTimer));

    // A native restart resumes from the opaque credential held in the Android
    // vault. The Machine issues a fresh challenge every time; no session token
    // is persisted in the webview.
    createEffect(() => {
        const stored = storedCredential();
        if (
            props.account
            || !props.runtime.native
            || !stored
            || machineSession()
            || resuming
        ) return;
        resuming = true;
        void openCredentialSession(stored)
            .catch(async (error) => {
                const reason = String(error);
                append(`session resume refused: ${reason}`);
                // The challenge/session endpoints use 403 only when the exact
                // grant, Machine or device proof is no longer valid. A 410 is a
                // spent/expired one-time challenge and a 404 may be route/version
                // drift; neither authorizes deleting a durable local grant.
                const definitivelyUntrusted = machineCredentialIsRejected(reason);
                if (definitivelyUntrusted) {
                    await props.runtime.removeCredential(stored.machine);
                    setStoredCredential(null);
                    setMachineSessionExpiresAt(0);
                    props.onCredentialRejected?.();
                }
                setPairing((state) =>
                    reducePairing(state, {
                        kind: "error",
                        reason: definitivelyUntrusted
                            ? "This Machine no longer trusts this device. Pair it again."
                            : "This Machine could not be reached. Your pairing is still saved.",
                    }),
                );
            })
            .finally(() => {
                resuming = false;
            });
    });

    createEffect(() => {
        const invitation = props.pendingInvitation;
        if (
            props.account
            ||
            !props.runtime.native
            || !invitation
            || storedCredential()
            || autoEnrollmentInvitationId === invitation.invitationId
        ) return;
        autoEnrollmentInvitationId = invitation.invitationId;
        void runMachineEnrollment(JSON.stringify(invitation));
    });
    const queueDepth = () => (tasks() ?? []).length;
    // Whether the pull-down full-queue sheet is open (local view state, not truth).
    const [queueOpen, setQueueOpen] = createSignal(false);

    // Jump to a task: open its chat and dismiss the sheet — the badge tap and a sheet
    // row resolve to the same (selection, pane), the spec's "tap jumps to the task".
    function jumpToTask(id: EngagementId) {
        setQueueOpen(false);
        void selectEngagement(id);
    }
    // The badge tap jumps to the *current* (first) navigable task; a no-op on an
    // empty queue. Onboarding `issue` tasks (ADR 0075) carry a whip work-item id,
    // not an engagement, so they are skipped here — every other ask names a chat.
    function jumpToCurrentTask() {
        const first = (tasks() ?? []).find((t) => t.kind !== "issue");
        if (first) jumpToTask(first.id as EngagementId);
    }

    // Load (or switch to) a chat: subscribe its transcript and jump to the Chat
    // pane. Routed through here from both the nav list (MOB-F1) and the post-pair
    // auto-create, so the transcript always tracks the selected chat.
    async function selectEngagement(id: EngagementId) {
        if (engagement() === id) {
            setCarousel((c) => reduceCarousel(c, tapGesture("chat")));
            return;
        }
        unsubscribe?.();
        setEngagement(id);
        const savedDraft = props.account?.draftCache.get(
            props.account.connection.homeId,
            props.account.project.id,
            `chat:${id}`,
        )?.value;
        // Restored without re-caching: `setDraftText`, not `setDraft`. The value
        // came from the cache, and writing it back would restamp its freshness as
        // though it had just been typed on this connection.
        setDraftText(savedDraft ?? "");
        setSelectedFile(null);
        setTranscript(emptyTranscript);
        setApproval(null);
        // A chat is selected → un-grey the chat/files panes and land on Chat.
        setCarousel((c) => applySelection(c, { chatSelected: true, fileSelected: false }));
        setCarousel((c) => reduceCarousel(c, tapGesture("chat")));
        try {
            setTranscript(fromSnapshot(await api.getTranscript(id)));
        } catch (e) {
            append(`transcript error: ${String(e)}`);
        }
        unsubscribe = api.subscribe(id, (ev) => setTranscript((t) => reduceTranscript(t, ev)));
    }

    let openedInitialEngagement = false;
    createEffect(() => {
        const initial = props.account?.initialEngagement;
        const target = props.account?.initialTarget;
        if (openedInitialEngagement || (!initial && !target)) return;
        openedInitialEngagement = true;
        void (async () => {
            if (initial) await selectEngagement(initial);
            if (!target) return;
            if (target.kind === "file") {
                openFile(target.id);
                return;
            }
            if (target.pane === "files") {
                setCarousel((state) => reduceCarousel(state, tapGesture("files")));
            }
        })();
    });

    function openFile(path: string) {
        setSelectedFile(path);
        setCarousel((state) =>
            applySelection(state, { chatSelected: true, fileSelected: true }),
        );
        setCarousel((state) => reduceCarousel(state, tapGesture("content")));
    }

    // ---- pairing handshake (real MOB-027 endpoints) -------------------------
    // The user submits a ticket → POST /pairing-requests opens + binds the
    // boundary → the owner accepts → we poll /pairing-status until the boundary
    // is Active (`paired`). In the browser e2e harness only, both parties are the
    // same loopback process and the harness performs the accept. Every step folds
    // a real server fact through the pure pairing reducer; the island only paints.
    async function runPairing(raw: string) {
        if (props.runtime.native) {
            await runMachineEnrollment(raw);
            return;
        }
        const ticket = parseTicket(raw);
        setPairing((s) => reducePairing(s, { kind: "ticket-entered", ticket }));
        if (ticket === null) return;
        try {
            const opened = await api.openPairing(DEVICE.id, ticket.bridgeGrant);
            setPairing((s) =>
                reducePairing(s, { kind: "request-accepted", pairingId: opened.pairingId }),
            );

            // Only the deterministic browser harness represents both parties.
            // Native devices wait for the Machine owner to approve the request.
            if (props.runtime.selfApprovePairing) {
                await api.acceptBoundary(opened.pairingId, "local-user");
            }

            // Poll the pairing status until the reducer settles it (paired/failed).
            const attempts = props.runtime.selfApprovePairing ? 20 : 300;
            const delay = props.runtime.selfApprovePairing ? 50 : 1_000;
            for (let i = 0; i < attempts; i++) {
                const status = parsePairingStatus(
                    (await api.pairingStatus(opened.pairingId)) as Parameters<typeof parsePairingStatus>[0],
                );
                setPairing((s) => reducePairing(s, { kind: "status", status }));
                if (status.paired) {
                    if (status.bound?.device !== DEVICE.id) {
                        throw new Error("The Machine approved a different device identity");
                    }
                    completePairing(ticket.environment, opened.bridgeGrant);
                    return;
                }
                await new Promise((r) => setTimeout(r, delay));
            }
            throw new Error("Pairing approval timed out");
        } catch (e) {
            setPairing((s) => reducePairing(s, { kind: "error", reason: String(e) }));
        }
    }

    async function runMachineEnrollment(raw: string) {
        let invitation: MachineControllerInvitation;
        try {
            invitation = JSON.parse(raw) as typeof invitation;
            if (
                invitation.version !== 1
                || !invitation.invitationId
                || !invitation.secret
                || !invitation.machine
                || !invitation.endpoint
                || invitation.endpoint.replace(/\/+$/, "") !== props.runtime.endpoint
            ) {
                throw new Error("invitation does not match this Machine");
            }
        } catch (error) {
            setPairing((state) =>
                reducePairing(state, {
                    kind: "error",
                    reason: error instanceof Error ? error.message : "invalid Machine invitation",
                }),
            );
            return;
        }

        setPairing((state) =>
            reducePairing(state, {
                kind: "ticket-entered",
                ticket: {
                    environment: scopeId(invitation.machine),
                    device: DEVICE.id,
                    bridgeGrant: null,
                },
            }),
        );
        try {
            const claimed = await api.claimMachineInvitation(
                invitation,
                DEVICE.id,
                DEVICE.deviceKey,
                "Mobile device",
            );
            const signature = await props.runtime.signChallenge(claimed.challenge);
            await api.proveMachineDevice(claimed.requestId, signature);
            setPairing((state) =>
                reducePairing(state, {
                    kind: "request-accepted",
                    pairingId: claimed.requestId,
                }),
            );
            for (let attempt = 0; attempt < 300; attempt++) {
                const status = await api.machineEnrollmentStatus(
                    claimed.requestId,
                    invitation.secret,
                );
                if (status.status === "rejected" || status.status === "revoked") {
                    throw new Error(`Machine enrollment was ${status.status}`);
                }
                if (status.status === "granted" && status.grantId && status.credential) {
                    const stored: MachineCredential = {
                        endpoint: invitation.endpoint.replace(/\/+$/, ""),
                        machine: invitation.machine,
                        grantId: status.grantId,
                        credential: status.credential,
                    };
                    await props.runtime.storeCredential(stored);
                    await openCredentialSession(stored);
                    setStoredCredential(stored);
                    return;
                }
                await new Promise((resolve) => setTimeout(resolve, 1_000));
            }
            throw new Error("Machine approval timed out");
        } catch (error) {
            setPairing((state) =>
                reducePairing(state, {
                    kind: "error",
                    reason: error instanceof Error ? error.message : String(error),
                }),
            );
        }
    }

    // Mint the held grant the boundary pinned and feed the connection machine: the
    // device now holds an active, device-bound grant for the paired environment.
    function completePairing(env: string, grant: string) {
        const held: BridgeGrant = {
            id: bridgeGrantId(grant),
            sourceAuthorityRootPubkey: publicKey("owner-root"),
            sourceAuthorityKeyId: "owner-key-0",
            targetEnvironment: env,
            targetRoute: "projection",
            deviceKey: DEVICE.deviceKey,
            governanceScope: env,
            expiry: Date.now() + 60 * 60 * 1000,
            active: true,
        };
        const local: LocalState = { identity: DEVICE, grants: [held] };
        setConnection((c) =>
            reduceConnection(
                reduceConnection(c, { kind: "grants-changed", grants: local.grants }),
                { kind: "address", environment: env },
            ),
        );
        setEnvironment(env);
        append(`paired → ${env}`);
        // Land on the Browse pane mirroring the host's real chats — don't auto-create a
        // placeholder chat or jump into one. The user picks a chat from the nav, or
        // starts one from the Chat tab (`startNewChat` below, the carousel's
        // selection-gated "new chat" affordance).
        setWsKey((k) => k + 1);
    }

    // Start a fresh chat on demand (the Chat tab's "new chat" affordance when none
    // is open) and select it, so "send" has a real control-plane surface. This is
    // the SAME "just chat" quick-start the desktop uses (`POST /chats` → a **work**
    // chat on the hidden Personal placement) — not an edit chat — so a chat started
    // on the device is the normal kind and shows up identically on the desktop.
    async function startNewChat() {
        try {
            const project = props.account?.project;
            const placement = project?.placements.find((candidate) => candidate.isDefault);
            const target = placement?.targetIds[0];
            const eng = project && placement && target
                ? {
                    id: await api.createChatUnderPlacement(
                        project.id,
                        placement.placementId,
                        "New chat",
                        target,
                    ),
                }
                : await api.createEngagement();
            await selectEngagement(eng.id);
        } catch (e) {
            append(`new chat error: ${String(e)}`);
        }
    }

    // ---- relay toggle (offline ⇄ online) ------------------------------------
    // Flip the relay reachability the connection machine reduces over. Offline is
    // the dropped-relay state: cached views still read, but `canCommand` is false,
    // so the banner shows and the composer's send gate refuses — one fold, two
    // surfaces (MOB-028). Online restores `active` and re-enables send.
    function setRelay(reachable: boolean) {
        setConnection((c) => reduceConnection(c, { kind: "relay", reachable }));
    }

    async function forgetDirectMachine() {
        const stored = storedCredential();
        if (!stored) return;
        await props.runtime.removeCredential(stored.machine);
        setMachineSession(null);
        setStoredCredential(null);
        props.onChangeMachine?.();
    }

    async function revokeDirectMachine() {
        const stored = storedCredential();
        if (!stored) return;
        await api.revokeMachineController(stored.grantId);
        await forgetDirectMachine();
    }

    // ---- send (the one standing command the client may issue) ---------------

    // Every draft change is cached for the open chat, so a draft survives leaving
    // the chat, restarting, and going offline. The shared composer clears the
    // draft when it takes a message, which lands here as an empty value and
    // retires the saved one — the same two writes the retired composer made, now
    // driven by one seam instead of two call sites.
    const cacheDraft = (value: string) => {
        const account = props.account;
        const id = engagement();
        if (!account || id === null) return;
        account.draftCache.put({
            homeId: account.connection.homeId,
            project: account.project.id,
            key: `chat:${id}`,
            value,
            freshness: account.connectionState() === "live" ? "live" : "offline",
            updatedAt: Date.now(),
        });
    };
    const setDraft = (value: string) => {
        setDraftText(value);
        cacheDraft(value);
    };

    // ---- inline approval (consent / release on the chat-stop card) ----------
    // Consent and release are standing review commands (INV-5/INV-7): we record the
    // optimistic step under a fresh ClientRequestId through the pure reducer; the
    // host issues the real `review` command and the answering projection folds back
    // through a `review` event. (In the loopback harness the card stays local until
    // a turn surfaces a proposal; the affordance and its gating are what MOB-031 adds.)
    function consent(proposalId: string) {
        append(`consent: ${proposalId}`);
        const rid = clientRequestId(`req-${Date.now()}`);
        setApproval((a) => (a ? reduceChatApproval(a, { kind: "consent", requestId: rid }) : a));
    }
    function release(proposalId: string) {
        append(`release: ${proposalId}`);
        const rid = clientRequestId(`req-${Date.now()}`);
        setApproval((a) => (a ? reduceChatApproval(a, { kind: "release", requestId: rid }) : a));
    }

    // Keep the connection clock fresh so an expiring grant is re-derived; harmless
    // for the e2e (the harness grant is hours out), but keeps the machine honest.
    createEffect(() => {
        const t = setInterval(() => setConnection((c) => reduceConnection(c, { kind: "tick", now: Date.now() })), 5_000);
        onCleanup(() => clearInterval(t));
    });

    const status = () => {
        if (!props.account) return connection().status;
        switch (props.account.connectionState()) {
            case "live":
                return "active" as const;
            case "grant-expired":
                return "expired" as const;
            case "grant-revoked":
            case "device-untrusted":
            case "needs-sign-in":
            case "policy-denied":
                return "revoked" as const;
            case "needs-admission":
            case "connecting":
            case "stale":
            case "offline":
                return "offline" as const;
        }
    };

    // The chat stop renders the one shared ChatPanel (ADR 0076) over this
    // Session, so the phone shows the same transcript, live-turn activity line,
    // and composer every other surface shows. A phone's narrower means are
    // declared as capabilities on the Session, not as a lesser composer.
    const session = createMobileSession({
        api,
        engagementId: engagement,
        transcript,
        connection: status,
        selectedFile,
        selectFile: (path) => (path === null ? setSelectedFile(null) : openFile(path)),
        worktreeRev: filesKey,
        onSettled: () => {
            setWsKey((k) => k + 1); // settle changes the sibling task-queue projection
            setFilesKey((k) => k + 1); // the turn may have changed the worktree
        },
        onSendFailed: setDraft,
        onStatus: append,
    });

    // Bound here rather than left to ChatPanel's default so the draft routes
    // through the account cache. Everything else is the shared controller's.
    const composerController = createSessionComposerController({
        scope: () => String(engagement() ?? "none"),
        busy: session.busy,
        capabilities: session.composerCapabilities,
        canCommand: session.canCommand,
        send: (text, images) => session.send(text, images),
        stop: session.stop,
        draft: { value: draft, set: setDraft },
        // The host owns the draft across selection changes: `selectEngagement`
        // restores the newly opened chat's cached draft itself. Letting the
        // controller clear on scope change would write that empty value straight
        // back through the cache seam and destroy the draft it had just restored.
        retainDraftOnScopeChange: true,
        onStatus: append,
    });

    // The four carousel panes. Chat is the committed MobileChat composer wired to a
    // real engagement; the others are light, real projections of the paired state —
    // the carousel only needs reachable panes to demonstrate navigation (MOB-014).
    const panes = (): Record<PaneKind, JSX.Element> => ({
        nav: (
            <div class="mobile-nav" data-pane="nav">
                {/* A small connection header (the e2e reads `data-paired-environment`). */}
                <div
                    class="mobile-nav-head status"
                    data-paired-environment
                    data-home-state={props.account?.connectionState()}
                >
                    {props.account ? "connected" : "paired"}: {environment() ?? "—"}
                    <Show when={props.account}>
                        <span> · {props.account?.connectionState()}</span>
                    </Show>
                    <Show when={props.account}>
                        <button type="button" onClick={() => props.account?.onBack()}>
                            projects
                        </button>
                        <button type="button" onClick={() => props.account?.onSignOut()}>
                            sign out
                        </button>
                    </Show>
                    <Show when={!props.account && props.runtime.native && storedCredential()}>
                        <button type="button" onClick={() => props.onChangeMachine?.()}>
                            Machines
                        </button>
                        <button type="button" onClick={() => void forgetDirectMachine()}>
                            forget on this phone
                        </button>
                        <button type="button" onClick={() => void revokeDirectMachine()}>
                            revoke access
                        </button>
                    </Show>
                </div>
                {/* The REAL workspace nav (MOB-F1): the same FacetBrowser the desktop
                    renders — Chats | Projects | Library, real chats, create/search —
                    so the device mirrors the host exactly and a chat opened or created
                    here is the same one the desktop shows. */}
                <FacetBrowser
                    api={browseApi()}
                    selected={engagement()}
                    onSelect={(id) => void selectEngagement(id)}
                    onOpenArchetypeSettings={() => undefined}
                    onOpenEngagement={() => undefined}
                    onOpenModelAccess={() => undefined}
                    onOpenProjectHome={() => undefined}
                    onOpenForkTree={() => undefined}
                    onChatDeleted={(id) => {
                        if (engagement() === id) {
                            unsubscribe?.();
                            setEngagement(null);
                            setDraftText("");
                            setTranscript(emptyTranscript);
                            setCarousel((c) =>
                                applySelection(c, { chatSelected: false, fileSelected: false }),
                            );
                        }
                    }}
                    onStatus={append}
                    deltaSync={!props.account}
                    onWorkspaceChange={() => setWsKey((k) => k + 1)}
                />
            </div>
        ),
        chat: (
            <div class="mobile-chat" data-pane="chat">
                {/* The one shared chat panel (ADR 0076): transcript, live-turn
                    activity, and composer — the same components the desktop and
                    every audience surface render. `bare` because this pane owns
                    its own flex container. The inline merge/review approval card
                    (MOB-031) threads into the transcript through the panel's
                    tail slot, which is where it belongs. */}
                <ChatPanel
                    bare
                    session={session}
                    composerController={composerController}
                    composerPlaceholder="Message…"
                    transcriptTail={
                        <Show when={approval()}>
                            {(a) => (
                                <ChatApprovalCard
                                    state={a()}
                                    connection={status()}
                                    onConsent={consent}
                                    onRelease={release}
                                />
                            )}
                        </Show>
                    }
                />
            </div>
        ),
        files: (
            <div class="mobile-files" data-pane="files">
                {/* Mirror the host's worktree for the open chat (MOB-F): the real
                    file tree, not a stub. */}
                <Show
                    when={engagement()}
                    fallback={<div class="status">open a chat to see its files</div>}
                >
                    <ul class="mobile-file-list" data-mobile-file-list>
                        <For
                            each={files() ?? []}
                            fallback={<li class="status">no files in this chat yet</li>}
                        >
                            {(f) => (
                                <li>
                                    <button
                                        type="button"
                                        class="mobile-file"
                                        classList={{ dir: f.isDir, active: selectedFile() === f.path }}
                                        data-file={f.path}
                                        disabled={f.isDir}
                                        onClick={() => !f.isDir && openFile(f.path)}
                                    >
                                        {f.path}
                                        {f.isDir ? "/" : ""}
                                    </button>
                                </li>
                            )}
                        </For>
                    </ul>
                </Show>
            </div>
        ),
        content: (
            <div class="mobile-content" data-pane="content">
                <Show
                    when={selectedFile()}
                    fallback={<div class="status">select a file in Files</div>}
                >
                    {(path) => (
                        <>
                            <div class="content-head">{path()}</div>
                            <pre class="mobile-file-content" data-mobile-file-content>
                                {fileContent.loading ? "loading…" : (fileContent() ?? "")}
                            </pre>
                        </>
                    )}
                </Show>
            </div>
        ),
    });

    return (
        <>
            <Show
                when={props.account || pairing().step === "paired"}
                fallback={
                    <div class="mobile-pairing-stage" data-mobile-stage="pairing">
                        <Show when={props.runtime.native}>
                            <div class="mobile-machine-current">
                                <span>{props.runtime.endpoint}</span>
                                <button type="button" onClick={() => props.onChangeMachine?.()}>
                                    change Machine
                                </button>
                            </div>
                        </Show>
                        <PairingFlow
                            state={pairing()}
                            onSubmitTicket={(raw) => void runPairing(raw)}
                            onRetry={() => setPairing(initialPairing)}
                            onDismiss={() => setPairing(initialPairing)}
                        />
                    </div>
                }
            >
                <div class="mobile-carousel-stage" data-mobile-stage="carousel">
                    {/* The top bar carries the context header, freshness dot, and the
                        `Next ③` task affordance (tap → current task, `⌄` → full queue
                        sheet). Its pane toggle is suppressed — the carousel island below
                        is the canonical toggle on the phone (and owns the "new chat"
                        smarts), so the bar would otherwise double it. */}
                    <TopBar
                        carousel={carousel()}
                        onState={setCarousel}
                        status={status()}
                        freshness={null}
                        chatTitle={null}
                        environment={environment()}
                        queueDepth={queueDepth()}
                        onJumpToTask={jumpToCurrentTask}
                        onOpenQueue={() => setQueueOpen(true)}
                        showToggle={false}
                    />
                    <Show when={queueOpen()}>
                        <QueueSheet
                            tasks={tasks() ?? []}
                            onJump={jumpToTask}
                            onClose={() => setQueueOpen(false)}
                        />
                    </Show>
                    <ConnectionBanner status={status()} />
                    {/* The relay toggle stands in for the platform's reachability
                        signal — the e2e flips it to drive offline ⇄ online. */}
                    <Show when={!props.account}>
                        <div
                            class="mobile-relay"
                            data-relay={status() === "active" ? "online" : "offline"}
                        >
                            <button
                                type="button"
                                data-relay-online
                                onClick={() => setRelay(true)}
                            >
                                go online
                            </button>
                            <button
                                type="button"
                                data-relay-offline
                                onClick={() => setRelay(false)}
                            >
                                go offline
                            </button>
                        </div>
                    </Show>
                    <Carousel
                        state={carousel()}
                        onState={setCarousel}
                        panes={panes()}
                        onNewChat={() => void startNewChat()}
                    />
                    <ul class="mobile-log" data-mobile-log>
                        <For each={log()}>{(line) => <li>{line}</li>}</For>
                    </ul>
                </div>
            </Show>
        </>
    );
}
