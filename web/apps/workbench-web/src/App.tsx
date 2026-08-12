/**
 * The workbench shell (`navigation.md` B1): a four-panel layout under a top
 * human-task-queue bar. It is a thin renderer — it renders projections and
 * submits commands; it never owns a lifecycle transition (`INV-5`).
 *
 *   ┌ task bar: human task queue ──────────────────────────────────┐
 *   ├──────────┬───────────────┬───────────────────┬──────────────┤
 *   │ nav      │ chat lane     │ content viewer    │ WORKSPACE     │
 *   │ (facets) │ (two-tier B4) │ files / turn diff │ worktree files│
 *   └──────────┴───────────────┴───────────────────┴──────────────┘
 *
 * The content viewer's Diff is the **review surface for the merge lifecycle**:
 * the human admits (advance `main`) or rejects (isolate) the turn (D1).
 */

// Side effect, and it must run before anything renders: registers this
// build's wasm loaders for every host that renders `App`, not just the
// standalone entry (see wasm-modules.ts).
import "./wasm-modules";
import { createEffect, createMemo, createResource, createSignal, For, on, onCleanup, Show, untrack, type Accessor } from "solid-js";
import {
    authority,
    bearer,
    beginLogin,
    clientRequestId,
    consumeCallbackToken,
    endSession,
    startSessionRefresh,
    reportedClientBuild,
    type ArchetypeId,
    describeFailure,
    type EngagementId,
    type ProjectId,
    Rejected,
    scopeId,
    type MergeAction,
    type MergePhase,
    type MergeState,
    type ClientRequestId,
    parseHomeInvitation,
    parseNativeHandoffCode,
    type HomeInvitationPreview,
    type PlacementPolicy,
} from "@gaugewright/control-plane-client";
import { WorkbenchControlPlane, controlPlaneBase } from "./workbench-control-plane";
import { captureHomeDiscovery, type HomeDiscoveryFailure } from "./home-bootstrap";
import { desktopUpdateAllowed } from "./desktop-update";
import "@gaugewright/gw-embed";
import {
    AgentSettings,
    BASIC_COMPOSER_CAPABILITIES,
    ChatPanel,
    ChatPaneHeader,
    changedUserFiles,
    chatIdFromSearch,
    ContentViewer,
    QuarantineIndex,
    ContextPanel,
    DeploymentPanel,
    createSessionComposerController,
    deriveFreshness,
    gemState,
    type GemState,
    displayChatTitle,
    emptyTranscript as empty,
    EngagementPane,
    Environment,
    ENABLED_MODELS_SETTING,
    fileFromSearch,
    freshnessEventForMarker,
    FacetBrowser,
    forkSource,
    FreshnessBanner,
    fromSnapshot,
    type ImageRef,
    ComposerModelBar,
    Icon,
    initialFreshness,
    isPlaceholderTitle,
    loadTranscriptFilterPrefs as loadPrefs,
    type ComposerMode,
    modelAcceptsImages,
    modelKey,
    modelOptions,
    type ModelOption,
    ForkTreePanel,
    OpenSettingsMenu as SettingsMenu,
    ProjectHomePanel,
    ProjectModelAccessPanel,
    parseEnabledModels,
    panelManifest,
    pendingUserAfterSnapshot,
    readChatModel,
    readChatProvider,
    readChatThinking,
    reduceFreshness,
    reduceTranscript as reduce,
    localTurnActivity,
    saveTranscriptFilterPrefs as savePrefs,
    createIndexedDbOutboxStore,
    loadDefaultComposerMode,
    saveDefaultComposerMode,
    searchWithChat,
    searchWithFile,
    SessionProvider,
    SessionComposer,
    Shelf,
    FirstRunOverlay,
    TaskBar,
    thinkingLevelsFor,
    titleFromPrompt,
    type ChatRunTone,
    type FreshnessState,
    type Session,
    type Transcript,
    TranscriptFilterMenu,
    Workspace,
    WorkbenchShell,
    createWorkbenchShellState,
    writeChatModelPin,
    UNIVERSAL_COMPOSER_CAPABILITIES,
    writeChatThinking,
} from "@gaugewright/workbench-ui";
import { isMobileHarness, MobileApp } from "@gaugewright/mobile-web";

const api = new WorkbenchControlPlane(controlPlaneBase());
// Desktop chooses the local callback flow; a hosted Home chooses the device-code
// flow. Builds can still suppress the action if their runtime ships neither.
const codexLoginAvailable = import.meta.env.VITE_CODEX_LOGIN !== "false";
const localDevLogin = import.meta.env.VITE_LOCAL_DEV_LOGIN === "true";
// The welcome overlay's account step is offered only where the composition's
// control plane serves the OIDC login shell (the hub-split hosted builds and the
// dev-login harness); the core desktop build has no account plane to sign in to.
const accountLoginAvailable = import.meta.env.VITE_HOME_SPLIT === "true" || localDevLogin;
// OIDC login (ID-3): if we just returned from `/auth/callback`, capture the id-token
// from the URL fragment before the first request, then hand the bearer to the
// transport so gated `/admin/*` calls carry it. Signed-out / single-user local is the
// no-op default (no header sent).
consumeCallbackToken();
api.setBearer(bearer());
// Hosted Console (ADR 0077): keep the `.gaugewright.com` cookie session alive by pinging
// `/auth/refresh` on a timer under the id-token's ~1h life. No-op on the loopback desktop.
startSessionRefresh(controlPlaneBase());

/** Read an ordinary project invitation into memory, then immediately remove its
 * capability from the address bar/history. It is never copied into storage. */
/** The public edge's custom domain.
 *
 * Not a `workers.dev` subdomain: the previous default named the founder's
 * *personal* Cloudflare account, which the DR-0044 migration moved away from, so
 * it would have pointed every new deployment at an account being decommissioned.
 * A custom domain survives the account it is served from.
 */
const PUBLIC_EDGE_ORIGIN = "https://panels.gaugewright.com";

function consumeHomeInvitation(): string {
    if (typeof window === "undefined") return "";
    try {
        const url = new URL(window.location.href);
        if (url.pathname !== "/invite") return "";
        const invite = url.searchParams.get("d") ?? "";
        url.searchParams.delete("d");
        url.pathname = "/";
        window.history.replaceState(null, "", `${url.pathname}${url.search}${url.hash}`);
        return invite;
    } catch {
        return "";
    }
}

const initialHomeInvitation = consumeHomeInvitation();

/** True inside the Tauri desktop shell (v2 injects this), false in a plain
 *  browser / e2e build — gates native-only affordances like the folder picker. */
const isTauri = () => typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;

export interface WorkbenchAppProps {
    /** Optional Environment supplied by a higher capability composition. */
    readonly environmentAction?: {
        readonly label: string;
        readonly available: Accessor<boolean>;
        readonly open: () => void;
    };
    /** Enterprise composition's active-member placement floor. Presence means
     * engagement acceptance fails closed until the authenticated read resolves. */
    readonly placementPolicy?: Accessor<PlacementPolicy | undefined>;
    /** Hosted higher-band compositions receive the current tenant as routing
     * context only; the Hub remains responsible for membership/capability
     * admission. */
    readonly onTenantContextChange?: (tenant: string | null) => void;
    /** Account and managed-service dashboard. Hosted GaugeDesk sends missing-
     * Home setup here instead of becoming a second management surface. */
    readonly hubUrl?: string;
    /** Where a person with no Home yet gets one. The first-run surface offers
     * this as its single primary act (DESK-4): installing GaugeDesk and signing
     * in there makes that computer the person's first Home. */
    readonly downloadUrl?: string;
}

function WorkbenchApp(props: WorkbenchAppProps = {}) {
    // The mobile projection-client flow harness (MOB-029) is addressed directly at
    // `?mobile=1` / `#mobile`, composing the committed D-MOBILE islands (pairing,
    // carousel, composer, connection banner) over the real control plane. It is a
    // sibling entry to the desktop workbench, not a media-query variant of it.
    if (isMobileHarness()) return <MobileApp />;

    const [homeState, { refetch: refetchHome }] = createResource(() =>
        captureHomeDiscovery(() => api.bootstrapHome()),
    );
    const homeFailure = createMemo<HomeDiscoveryFailure | null>(() => {
        const state = homeState();
        return state?.kind === "failure" ? state : null;
    });
    const homeNeedsLogin = createMemo(() => homeFailure()?.authentication ?? false);
    const [homeEndpoint, setHomeEndpoint] = createSignal("");
    const [homeError, setHomeError] = createSignal("");
    const [homeBusy, setHomeBusy] = createSignal(false);
    const [homeInvite, setHomeInvite] = createSignal(initialHomeInvitation);
    const signOutAccount = async () => {
        await endSession(controlPlaneBase());
        // A reload drops every memory-only Home admission and authenticated projection along
        // with the now-expired account cookie, returning the shell to Home discovery/login.
        window.location.replace("/");
    };
    const invitationPreview = createMemo<HomeInvitationPreview | null>(() => {
        const invite = homeInvite();
        if (!invite) return null;
        try {
            return parseHomeInvitation(invite);
        } catch {
            return null;
        }
    });
    const connectHome = async () => {
        setHomeBusy(true);
        setHomeError("");
        try {
            await api.connectHome(homeEndpoint());
            await refetchHome();
        } catch (error) {
            setHomeError(String(error));
        } finally {
            setHomeBusy(false);
        }
    };
    const acceptHomeInvite = async () => {
        if (!homeInvite()) return;
        setHomeBusy(true);
        setHomeError("");
        try {
            await api.acceptHomeInvitation(homeInvite());
            setHomeInvite("");
            await refetchHome();
        } catch (error) {
            setHomeError(String(error));
        } finally {
            setHomeBusy(false);
        }
    };

    const [selected, setSelected] = createSignal<EngagementId | null>(null);
    const [status, setStatus] = createSignal("ready");
    const clientBuild = reportedClientBuild();
    const [desktopUpdate, setDesktopUpdate] = createSignal<{
        readonly kind: "checking" | "current" | "available" | "restricted" | "error" | "installing";
        readonly version?: string;
        readonly update?: import("@tauri-apps/plugin-updater").Update;
    } | null>(isTauri() ? { kind: "checking" } : null);

    async function checkDesktopUpdate() {
        if (!isTauri()) return;
        setDesktopUpdate({ kind: "checking" });
        try {
            const [policy, updater] = await Promise.all([
                api.softwareUpdatePolicy(),
                import("@tauri-apps/plugin-updater"),
            ]);
            const update = await updater.check();
            if (!update) {
                setDesktopUpdate({ kind: "current" });
            } else if (desktopUpdateAllowed(policy)) {
                setDesktopUpdate({ kind: "available", version: update.version, update });
            } else {
                await update.close();
                setDesktopUpdate({ kind: "restricted", version: update.version });
            }
        } catch {
            // Version information remains useful even when release discovery is
            // unavailable. Do not turn an unreachable update service into a warning.
            setDesktopUpdate({ kind: "error" });
        }
    }

    async function installDesktopUpdate() {
        const candidate = desktopUpdate();
        if (candidate?.kind !== "available" || !candidate.update) return;
        setDesktopUpdate({ kind: "installing", version: candidate.version });
        try {
            // Re-read policy at the moment of installation: a stale discovery
            // result must never outlive a newly tightened organization ceiling.
            if (!desktopUpdateAllowed(await api.softwareUpdatePolicy())) {
                await candidate.update.close();
                setDesktopUpdate({ kind: "restricted", version: candidate.version });
                return;
            }
            await candidate.update.downloadAndInstall();
            const { invoke } = await import("@tauri-apps/api/core");
            await invoke("restart_app");
        } catch {
            setDesktopUpdate({ kind: "error" });
        }
    }

    if (isTauri()) void checkDesktopUpdate();
    // A pulse the in-chat "no model attached" action bumps to open the Account panel
    // (LLM-1): the transcript surfaces the refusal, this opens where you fix it.
    const [accountRequest, setAccountRequest] = createSignal(0);
    // FED-7: an OS-delivered `gaugewright://invite` deep link. The Tauri shell dispatches it as a
    // `gw-deep-link` DOM CustomEvent (plain event, not IPC), which we route into the Devices
    // consent flow. A browser build simply never receives one.
    const [inviteDeepLink, setInviteDeepLink] = createSignal("");
    // Desktop → Hub account session (ADR 0123, LOGIN-4): the local control
    // plane custodies the session; this resource is the surfaces' non-secret
    // view. Reading status also lets the control plane refresh a session
    // nearing expiry, so the periodic read keeps an open desktop signed in.
    const [hubSession, { refetch: refetchHubSession }] = createResource(() =>
        api.hubSessionStatus().catch(() => null),
    );
    if (typeof window !== "undefined") {
        const keepAlive = window.setInterval(() => void refetchHubSession(), 5 * 60 * 1000);
        onCleanup(() => window.clearInterval(keepAlive));
    }
    // What the signed-in account reaches (ADR 0114): Homes and opaque
    // project-to-Home routes, proxied by the control plane with its sealed
    // bearer. Only fetched while a live session exists.
    const [hubReach] = createResource(
        () => hubSession()?.linked === true && !hubSession()?.expired,
        () => api.hubSessionReach().catch(() => null),
    );
    if (typeof window !== "undefined") {
        const onDeepLink = (e: Event) => {
            const url = (e as CustomEvent).detail;
            if (typeof url !== "string") return;
            // ADR 0123 (LOGIN-2): a native account sign-in return. The deep link
            // carries only the one-time code; the control plane redeems it with
            // its held verifier and custodies the session — status surfaces read
            // the result from `/account/hub-session` (server truth).
            const handoffCode = parseNativeHandoffCode(url);
            if (handoffCode) {
                void api
                    .hubSessionCallback(handoffCode)
                    .then(() => refetchHubSession())
                    .catch(() => {});
                return;
            }
            if (url.startsWith("gaugewright://invite")) {
                setInviteDeepLink(url);
            }
        };
        window.addEventListener("gw-deep-link", onDeepLink);
        onCleanup(() => window.removeEventListener("gw-deep-link", onDeepLink));
    }
    const [agentSettings, setAgentSettings] = createSignal<{ id: ArchetypeId; name: string } | null>(null);
    // The per-project Engagement pane (FED-7), opened from a project node.
    const [engagement, setEngagement] = createSignal<{ id: ProjectId; name: string } | null>(null);
    // LLM-2: the per-project model-access panel (pin a BYOK key at project scope).
    const [modelAccess, setModelAccess] = createSignal<{ id: ProjectId; name: string } | null>(null);
    // UX-2: the per-project home panel (recent runs, outputs under review, audit rollup).
    const [projectHome, setProjectHome] = createSignal<{ id: ProjectId; name: string } | null>(null);
    // UX-8: the fork-tree panel (chat fork lineage); holds the chat that opened it.
    const [forkTreeFor, setForkTreeFor] = createSignal<EngagementId | null>(null);
    const [deployment, setDeployment] = createSignal<{
        // Carried so a drain knows which project's quarantine it lands in. The
        // facet browser already produced it; the signal used to drop it.
        projectId: string;
        projectName: string;
        placementId: import("@gaugewright/control-plane-client").PlacementId;
        archetypeName: string;
        reviewChatId?: EngagementId;
    } | null>(null);

    // Mirror the workspace *live* across clients over the workspace event stream
    // (the sibling of the per-chat SSE): the server pushes a "changed" ping whenever
    // the library mutates — a chat created on another client (a paired mobile device)
    // appears here at once, no polling. `navTick` is the nav's refresh key.
    //
    // It is bumped by: the workspace event stream (below), a turn settling
    // (`runPrompt`), creating a chat (`startNewChat`), and keep/discard (`onMerge`).
    // It deliberately does NOT fold in `status`: `status` is transient action
    // feedback ("turn complete", "ingested 3 files"), not a workspace change, and
    // refetching the whole nav on every status message both wasted a `GET /workspace`
    // per keystroke-ish action and churned the tree (round-13 follow-up).
    const [navTick, setNavTick] = createSignal(0);
    const bumpNav = () => setNavTick((k) => k + 1);
    createEffect(() => {
        const home = homeState();
        if (!home || home.kind === "none" || home.kind === "failure") return;
        const stop = api.subscribeWorkspace(bumpNav);
        onCleanup(stop);
    });

    // Keep the transport's bearer in lock-step with the login session (ID-3), so a
    // sign-out (or sign-in without a full reload) takes effect on the next request.
    createEffect(() => api.setBearer(bearer()));
    const navRefresh = () => navTick();

    // Desktop projection freshness (RF-E4): the shell consumes projections bare
    // over HTTP/SSE, so a dropped fetch would otherwise leave the UI silently stuck
    // on a stale view. We fold each main projection load's success/failure into one
    // pure freshness reducer (workbench-ui/desktop-freshness.ts); when a refresh fails the
    // FreshnessBanner surfaces an explicit "couldn't refresh — retry" affordance
    // wired to re-run the failed loads. This layers ON TOP of the SSE path — the
    // live stream is untouched; this only tracks the request/response projections.
    const [freshness, setFreshness] = createSignal<FreshnessState>(initialFreshness);
    const [freshNow, setFreshNow] = createSignal(Date.now());
    const markLoadOk = () => setFreshness((s) => reduceFreshness(s, { kind: "ok", now: Date.now() }));
    const markLoadFail = (e: unknown) =>
        setFreshness((s) => reduceFreshness(s, { kind: "fail", error: `couldn't refresh — ${String(e)}` }));
    // Re-derive against a live clock so a `stale` view ages into `stuck` on its own.
    createEffect(() => {
        const t = setInterval(() => setFreshNow(Date.now()), 5_000);
        onCleanup(() => clearInterval(t));
    });
    const freshnessStatus = () => deriveFreshness(freshness(), freshNow());

    const [run, { refetch: refetchRun }] = createResource(selected, async (id) => {
        try {
            const r = await api.getRun(scopeId(id));
            markLoadOk();
            return r;
        } catch (e) {
            // The run projection still falls back to Init so the UI renders, but the
            // failure now feeds the freshness signal (it no longer reads as success).
            markLoadFail(e);
            return { phase: "Init" as const, admittedOnce: false };
        }
    });
    // diff/merge: on failure feed the freshness signal but keep the LAST good value
    // (createResource preserves the prior value when the fetcher returns rather than
    // throws). That is the whole point of RF-E4 — a dropped refresh must leave the UI
    // on its last-known view with a staleness caveat, not crash the render or blank
    // the panel. A `throw` here would put the resource into an error state and reads
    // like `merge()?.phase` would re-throw; returning the prior value avoids that.
    const [diff, { refetch: refetchDiff, mutate: setDiff }] = createResource<string, EngagementId>(
        selected,
        async (id, info) => {
            try {
                const d = await api.engagementDiff(id);
                markLoadOk();
                return d;
            } catch (e) {
                markLoadFail(e);
                return info.value ?? "";
            }
        },
    );
    const [merge, { refetch: refetchMerge }] = createResource<MergeState | null, EngagementId>(
        selected,
        async (id, info) => {
            try {
                // UX-13: the merge review is the desktop's highest-stakes surface, so it
                // reads through the freshness carriage and honors a server-declared
                // non-live marker (stale/partial/redacted) as `server-stale` — held data
                // shown with a caveat — rather than rendering it as fresh.
                const c = await api.getMergeCarriage(id);
                setFreshness((s) =>
                    reduceFreshness(s, freshnessEventForMarker(c.freshness.marker, c.freshness.repairHint, Date.now())),
                );
                return c.value;
            } catch (e) {
                markLoadFail(e);
                return info.value ?? null;
            }
        },
    );
    // Retry the main projection loads (the freshness-banner affordance). A success
    // on any of them flips the reducer back to `fresh`; this re-runs them all.
    function retryProjections() {
        void Promise.allSettled([refetchRun(), refetchDiff(), refetchMerge(), refetchChatInfo()]);
    }

    // The selected chat's raw `.agent-config.json` — read so the composer model picker
    // (LLM-1, ADR 0062) can show the per-chat model and write a new one back without
    // clobbering the rest of the config. Not a freshness-fed projection (it is config,
    // not run truth), so it stays out of markLoadOk/Fail.
    const [chatConfig, { refetch: refetchChatConfig }] = createResource<string, EngagementId>(
        selected,
        async (id) => {
            try {
                return await api.getConfig(id);
            } catch {
                return "{}";
            }
        },
    );
    const chatModel = () => readChatModel(chatConfig() ?? "");
    const chatProvider = () => readChatProvider(chatConfig() ?? "");
    const chatThinking = () => readChatThinking(chatConfig() ?? "");
    // The model picker + reasoning-effort toggle offer only what the operator's linked
    // accounts actually provide (LLM-1, ADR 0062), derived from the GaugeDesk catalog.
    // Keyed on `selected` so opening/switching a chat — the only time the picker shows —
    // re-reads the linked providers (a key linked or the codex OAuth signed in elsewhere
    // shows up on the next chat open). Failures degrade to "nothing linked" → just Default.
    // Keyed on selected-or-startup: the picker also serves the no-selection
    // quick-start composer (same component, same commands — ADR 0112 doctrine),
    // so the linked providers load before any chat exists and still refresh on
    // every chat switch.
    const [linkedCreds] = createResource(() => selected() ?? "startup", () => api.accountCredentials().catch(() => []));
    const [codexCred] = createResource(() => selected() ?? "startup", () => api.codexStatus().catch(() => null));
    // First-run credential gate (ADR 0075 Phase 0): a startup-time (not selection-
    // keyed) read of whether *any* LLM credential is linked. `undefined` while
    // loading — we never flash the welcome before we know. `refetch*` re-check
    // after the overlay links one, which flips `hasAnyCredential` and dismisses it.
    const [startupCreds, { refetch: refetchStartupCreds }] = createResource(() =>
        api.accountCredentials().catch(() => []),
    );
    const [startupCodex, { refetch: refetchStartupCodex }] = createResource(() =>
        api.codexStatus().catch(() => null),
    );
    // Whether the default runtime actually needs a credential (server truth): off
    // under the scripted fake agent (dev/e2e), so the overlay never blocks a
    // no-credential test. Fail toward showing setup if the probe fails.
    const [credentialRequired] = createResource(() =>
        api.onboardingStatus().then((s) => s.credentialRequired).catch(() => true),
    );
    const [firstRunDismissed, setFirstRunDismissed] = createSignal(false);
    const hasAnyCredential = (): boolean | undefined => {
        const creds = startupCreds();
        const codex = startupCodex();
        if (creds === undefined || codex === undefined) return undefined; // still loading
        return creds.some((c) => c.linked) || Boolean(codex?.linked);
    };
    const showFirstRun = () =>
        credentialRequired() === true && hasAnyCredential() === false && !firstRunDismissed();
    // The operator's curated "which models show" preference (managed in the Account panel,
    // persisted in the account-settings KV). `null` = never curated → default-visible subset.
    const [acctSettings] = createResource(() => selected() ?? "startup", () => api.accountSettings().catch((): Record<string, string> => ({})));
    const linkedAccounts = createMemo(() => {
        const ps = (linkedCreds() ?? []).filter((c) => c.linked).map((c) => c.provider);
        if (codexCred()?.linked) ps.push("openai-codex");
        return ps;
    });
    const enabledModels = createMemo(() => parseEnabledModels(acctSettings()?.[ENABLED_MODELS_SETTING]));
    // The engine's resolved no-pin default (provider + model), so the picker's
    // first row names what "Default" actually runs. Startup-time server truth (it
    // changes only with host config); a failed probe degrades to the blind
    // "Default" label rather than blocking the picker.
    const [resolvedDefault] = createResource(() => api.defaultModel().catch(() => null));
    // With no chat open, the same picker pins the model/effort the FIRST message
    // will run with — held here, applied to the new chat's config by
    // startNewChat, then cleared. The composer is one component either way.
    const [pendingPin, setPendingPin] = createSignal<{ id: string; provider: string } | null>(null);
    const [pendingThinking, setPendingThinking] = createSignal("");
    const paneModel = () =>
        selected()
            ? { id: chatModel(), provider: chatProvider() }
            : pendingPin() ?? { id: "", provider: "" };
    const modelChoices = createMemo<ModelOption[]>(() =>
        modelOptions(
            linkedAccounts(),
            enabledModels(),
            paneModel(),
            undefined,
            resolvedDefault() ?? null,
        ),
    );
    // The current pin as the `<select>` value: `provider:id`, or "" for Default.
    const modelValue = () => (paneModel().id ? modelKey(paneModel()) : "");
    // The reasoning-effort options follow the pinned model; the toggle only shows when the
    // model supports thinking (more than just "off"). "" = the model's own default effort.
    const effortLevels = createMemo(() => thinkingLevelsFor(linkedAccounts(), paneModel().id, paneModel().provider));
    const showEffort = createMemo(() => effortLevels().some((l) => l !== "off"));
    // openai-generic (ADR 0083) has no catalog — its model id is free-text. Offer the
    // entry when such an account is linked; typing one pins `openai-generic:<id>`.
    const showCustomModel = createMemo(() => linkedAccounts().includes("openai-generic"));
    const [customModel, setCustomModel] = createSignal("");
    async function pinCustomModel(value: string) {
        const id = value.trim();
        if (!id) return;
        await pickModel(`openai-generic:${id}`);
        setCustomModel("");
    }

    // Pin a model for this chat: the picker's option value is `provider:id` (empty =
    // Default → clear the override). Writes `model`+`provider`, preserving every other key.
    // With no chat open, the choice is held as the pending pin for the chat the
    // quick-start composer is about to mint.
    async function pickModel(value: string) {
        const i = value.indexOf(":");
        const pin = value === "" ? { id: "", provider: "" } : { id: value.slice(i + 1), provider: value.slice(0, i) };
        const id = selected();
        if (!id) {
            setPendingPin(value === "" ? null : pin);
            return;
        }
        try {
            await api.putConfig(id, writeChatModelPin(chatConfig() ?? "{}", pin));
            await refetchChatConfig();
        } catch (e) {
            setStatus(`couldn't set the model — ${String(e)}`);
        }
    }
    // Pin the reasoning effort for this chat; "" clears it (model default).
    async function pickThinking(level: string) {
        const id = selected();
        if (!id) {
            setPendingThinking(level);
            return;
        }
        try {
            await api.putConfig(id, writeChatThinking(chatConfig() ?? "{}", level));
            await refetchChatConfig();
        } catch (e) {
            setStatus(`couldn't set reasoning effort — ${String(e)}`);
        }
    }
    // The files a turn actually changed, read from the diff (round-7 #3). The
    // Changes tab auto-renders the diff; View should not sit empty with a "pick a
    // file" hint when the turn touched exactly one file. When it did, and nothing
    // is selected yet, auto-open that file in View — one populated panel, not one
    // populated and one empty for the same just-modified file. We only ever fill an
    // *empty* selection, never override a file the user picked themselves.
    // The selected chat's lineage + kind (ADR 0035). The chat's KIND is its root,
    // fixed at creation: rooted on an archetype ⇒ `edit`, on a placement ⇒ `work`.
    // We resolve it (and the displayed lineage) from the workspace projection: for
    // a work chat the lineage is `archetype · project`; for an edit chat it is
    // `archetype · Library`.
    // The open chat's header facts (title, lineage, kind, project) are a **library
    // projection**, so they must track the workspace event stream — not just the
    // selection. Keying on `navTick` too means a rename (or any library change to
    // this chat, incl. from another client) re-resolves the header live, the same
    // way the nav does. Guarded so no selection ⇒ no fetch.
    const [chatInfo, { refetch: refetchChatInfo }] = createResource(
        () => (selected() ? ([selected()!, navTick()] as const) : false),
        async ([id]) => {
        const ws = await api.getWorkspace();
        // Work chats live under a project's placement → lineage is archetype · project.
        for (const p of ws.projects) {
            for (const pl of p.placements) {
                const c = pl.chats.find((c) => c.id === id);
                if (c) {
                    const target = p.targets.find((target) => target.id === c.targetId);
                    return {
                        kind: c.kind,
                        lineage: `${pl.archetypeName} · ${p.name}`,
                        // What the header names as this chat's context. Personal is the
                        // catch-all placement every chat falls back to, so naming it
                        // spends header width on a constant: the slot stays empty and
                        // disappears instead.
                        context: ws.personalPlacement === pl.placementId ? "" : p.name,
                        // The gem's inputs, read from the same projection fields the
                        // navigation row reads, so the two cannot disagree.
                        conflict: c.conflict,
                        // The line this chat's work lands on: its workstream when it is
                        // homed to one, else the work target — the default mainline is a
                        // workstream of one.
                        workstream: ws.workstreams.find((w) => w.id === c.workstream)?.name
                            ?? target?.name ?? String(c.targetId),
                        title: c.title,
                        target: target?.name ?? String(c.targetId),
                        targetKind: c.targetKind,
                        targetConcurrency: target?.concurrency,
                        basis: c.targetBasis,
                        candidate: c.candidateRevision,
                        acts: c.availableActs,
                        // The project this chat lives in drives the network-egress
                        // bar (RF-B3): only a project-rooted (work) chat has one.
                        project: { id: p.id, name: p.name, networkIsolated: p.networkIsolated },
                    };
                }
            }
        }
        // Edit chats live under an archetype → lineage is archetype · Library.
        for (const a of ws.archetypes) {
            const c = a.chats.find((c) => c.id === id);
            if (c) {
                const target = ws.workTargets.find((target) => target.id === c.targetId);
                return {
                    kind: c.kind,
                    lineage: `${a.name} · Library`,
                    // An edit chat's context is the method it edits.
                    context: a.name,
                    conflict: c.conflict,
                    workstream: ws.workstreams.find((w) => w.id === c.workstream)?.name
                        ?? target?.name ?? String(c.targetId),
                    title: c.title,
                    target: target?.name ?? String(c.targetId),
                    targetKind: c.targetKind,
                    targetConcurrency: target?.concurrency,
                    basis: c.targetBasis,
                    candidate: c.candidateRevision,
                    acts: c.availableActs,
                };
            }
        }
        // Fallback to the flat recent list (archetype name only).
        const r = ws.recent.find((c) => c.id === id);
        return {
            kind: r?.kind ?? "work",
            lineage: r?.archetype ?? "",
            // The flat recent list carries the archetype only — no project to name.
            context: "",
            conflict: false,
            changes: false,
            workstream: r
                ? (ws.workTargets.find((target) => target.id === r.targetId)?.name ?? String(r.targetId))
                : "",
            title: r?.title ?? "",
            target: r ? (ws.workTargets.find((target) => target.id === r.targetId)?.name ?? String(r.targetId)) : "",
            targetKind: r?.targetKind,
            targetConcurrency: r ? ws.workTargets.find((target) => target.id === r.targetId)?.concurrency : undefined,
            basis: r?.targetBasis,
            candidate: r?.candidateRevision,
            acts: r?.availableActs,
        };
        },
    );
    const chatKind = () => chatInfo()?.kind ?? "work";
    const lineage = () => chatInfo()?.lineage ?? "";
    // The chat's own name for the header (round-6 #6): two chats under one method
    // share a lineage (`Email helper · Marketing`), so the header must show the
    // chat's title to tell them apart. Reuse the shared placeholder rule so a
    // still-unnamed chat reads "Untitled" rather than the raw "new chat" token.
    const chatTitle = () => displayChatTitle(chatInfo()?.title ?? "");
    // What this chat belongs to, for the header's context slot. The Personal project
    // is the catch-all, so it names nothing; `lineage` itself is left alone because
    // `methodName` still parses the method out of it for the composer caption.
    const headerContext = () => chatInfo()?.context ?? "";
    // The line's sync state in words. `basis === candidate` means the line holds no
    // work this chat has not landed — which is what "up to date" says. Deliberately
    // not a count: the projection carries two revisions, not a distance between them,
    // and inventing "2 ahead" from data that cannot support it would be a lie.
    const workstreamState = () => {
        const info = chatInfo();
        if (!info?.workstream) return "";
        if (!info.basis || !info.candidate) return "";
        return info.basis === info.candidate ? "up to date" : "changes pending";
    };
    // Fork lineage (#3): the source this chat was copied from (from the "(fork)"
    // suffix), so the empty state can explain what a fork is and what carried over.
    const forkOf = () => forkSource(chatInfo()?.title ?? "");
    // The method name driving this chat (round-6 #6): the lineage is
    // `method · project` (work) or `method · Library` (edit), so the part before
    // the "·" is the method — used to name it in the composer caption instead of
    // the hardcoded "assistant".
    const methodName = () => (lineage().split("·")[0] ?? "").trim();

    // The project the open chat lives in (RF-B3): drives the bottom-left network
    // bar. Only a project-rooted work chat has one — an edit chat or the hidden
    // Personal default resolves to `null`, so the bar reads-only there.
    const currentProject = () => chatInfo()?.project ?? null;
    // Tell the control plane which project is open, so work resolves to *that*
    // project's Home rather than one selected Home (DESK-3). Several Homes stay
    // connected at once; this only decides which one serves the work in hand.
    createEffect(() => {
        api.setCurrentProject((currentProject()?.id ?? null) as ProjectId | null);
    });
    const [networkBusy, setNetworkBusy] = createSignal(false);
    async function toggleNetworkIsolated() {
        const p = currentProject();
        if (!p || networkBusy()) return;
        setNetworkBusy(true);
        try {
            await api.setProjectNetworkIsolated(p.id, !p.networkIsolated);
            await refetchChatInfo();
        } finally {
            setNetworkBusy(false);
        }
    }

    // Auto-title (#4): a brand-new chat is created with a generic placeholder
    // ("new chat", "edit chat", …). The first thing the user types is the obvious
    // title, so on the first message of a still-unnamed, still-empty chat we adopt
    // a trimmed version of it — All chats stops filling with identical "new chat"
    // rows. We only ever overwrite a known placeholder, never a user-chosen name.
    // (PLACEHOLDER_TITLES / isPlaceholderTitle / titleFromPrompt are shared with the
    // nav + task bar via state/chat-title.)
    async function maybeAutoTitle(id: EngagementId, prompt: string) {
        const current = (chatInfo()?.title ?? "").trim();
        // "First message" must be judged from the DURABLE snapshot, not the live
        // transcript: runPrompt echoes the user's line into `live` optimistically
        // (round-7 #6) *before* calling this, so transcript().lines is already 1.
        // Reading the snapshot (admitted records only) keeps the first-turn check
        // honest — otherwise auto-title never fires and chats stay "Untitled".
        const isFirst = snapshot().lines.length === 0;
        if (!isFirst || !isPlaceholderTitle(current)) return;
        const title = titleFromPrompt(prompt);
        if (!title) return;
        try {
            await api.renameChat(id, title);
            // The header title comes from chatInfo (keyed on `selected`, which didn't
            // change), so refetch it or the header keeps showing the old placeholder.
            await refetchChatInfo();
        } catch {
            /* titling is best-effort; a failed rename must never block the turn */
        }
    }

    // The transcript is a projection of durable truth: a **snapshot** of admitted
    // records (refetched per engagement, survives reloads) concatenated with the
    // **live** SSE reduction of the in-progress turn. No client-only history.
    const [snapshot, setSnapshot] = createSignal<Transcript>(empty);
    const [live, setLive] = createSignal<Transcript>(empty);
    const [pendingSend, setPendingSend] = createSignal<{
        id: EngagementId;
        rid: ClientRequestId;
        text: string;
        baselineLines: number;
    } | null>(null);
    const transcript = (): Transcript => ({
        lines: [...snapshot().lines, ...live().lines],
        openText: live().openText,
    });
    async function loadSnapshot(id: EngagementId) {
        try {
            const repaired = fromSnapshot(await api.getTranscript(id));
            setSnapshot(repaired);
            const pending = pendingSend();
            setLive(
                pending?.id === id
                    ? pendingUserAfterSnapshot(repaired, pending.text, pending.baselineLines)
                    : empty,
            );
        } catch {
            /* a fresh engagement has no snapshot */
        }
    }
    // The optimistic send, modeled as an **explicit pending command** (app-stack.md,
    // "Optimistic UI models pending commands explicitly"): when a turn starts we echo
    // the user's line into the live transcript at once and record a `clientRequestId`
    // for the in-flight command. Reconciliation is the transcript's snapshot-repair
    // model (the doctrine's named transcript mechanism): on settle OR rejection we
    // re-read the durable snapshot, which retires the optimistic echo — a kept turn
    // shows the admitted line, a failed/rejected turn drops it (no dangling echo).
    let nextRid = 1;
    const retireSend = (rid: ClientRequestId) =>
        setPendingSend((p) => (p?.rid === rid ? null : p));
    const [draft, setDraft] = createSignal("");
    // The unselected Chat pane is a real quick-start surface, not a dead-end
    // status message. Keep its draft distinct from an open chat's composer so
    // switching or opening a chat never carries text across conversations.
    const [emptyChatDraft, setEmptyChatDraft] = createSignal("");
    // The pane's draft, routed to whichever backing signal applies: ONE composer
    // component serves both the open-chat and quick-start states (same controls,
    // same commands where they're meaningful — no second, lesser UI).
    const paneDraft = () => (selected() ? draft() : emptyChatDraft());
    const setPaneDraft = (value: string) => (selected() ? setDraft(value) : setEmptyChatDraft(value));
    // Per-chat agent run state (round-13): one global `busy` can't represent
    // concurrent agents. `runTones` is the *live, local* state of turns this client
    // started (working / error). The needs-review state is server truth from the
    // tasks projection, so it survives reload and reflects other clients too. They
    // fold in `runToneOf`. `busy()` (the selected chat's gate) is derived from it.
    const [runTones, setRunTones] = createSignal<Record<string, "working" | "error">>({});
    const setRunTone = (id: EngagementId, tone: "working" | "error" | null) =>
        setRunTones((s) => {
            const next = { ...s };
            if (tone) next[String(id)] = tone;
            else delete next[String(id)];
            return next;
        });
    const [tasks] = createResource(navRefresh, () => api.getTasks().catch(() => []));
    const reviewSet = () => new Set((tasks() ?? []).map((t) => String(t.id)));
    const runToneOf = (id: EngagementId | null): ChatRunTone | undefined => {
        if (!id) return undefined;
        const local = runTones()[String(id)];
        if (local) return local; // working / error — a live turn is the most current fact
        if (reviewSet().has(String(id))) return "review";
        return undefined;
    };
    const busy = () => runToneOf(selected()) === "working";
    const [activity, setActivity] = createSignal(""); // what the agent is doing now
    // The agent's pending approvals from the last turn (UX-3): an `extension_ui_request`
    // the runtime surfaced but did not auto-confirm — answered out-of-band via the
    // resource-access / export grant flow. Shown as an inline confirm notice.
    const [pendingApprovals, setPendingApprovals] = createSignal<string[]>([]);
    // Pending approvals are per-chat: clear them when the selected chat changes so one
    // chat's held requests never bleed into another's view.
    createEffect(() => {
        selected();
        setPendingApprovals([]);
    });
    const [streamReady, setStreamReady] = createSignal(false);
    // Transcript view prefs (which event types show, what opens expanded): pure
    // view state. Toggles apply live for the session but are NOT auto-persisted —
    // the filter is a working state. "Save as default" (below) is what writes the
    // current filter to localStorage as the user's persistent default; on load we
    // seed from that saved default (else the factory defaults).
    const filterStorage = typeof window === "undefined" ? null : window.localStorage;
    const [filterPrefs, setFilterPrefs] = createSignal(loadPrefs(filterStorage));
    // Persist the current filter as the user's default (the "Save as default"
    // action). Reverting to it is just re-seeding from storage.
    const saveFilterDefault = () => savePrefs(filterStorage, filterPrefs());
    // The composer's *default* delivery mode. The mode itself is per chat and the
    // controller owns it; this is only what a chat you have not chosen for opens
    // as, so it is one value with one write — set from the mode menu, not from a
    // settings screen built for a single preference.
    const [defaultComposerMode, setDefaultComposerMode] = createSignal(
        loadDefaultComposerMode(filterStorage),
    );
    const makeModeDefault = (mode: ComposerMode) => {
        setDefaultComposerMode(mode);
        saveDefaultComposerMode(filterStorage, mode);
    };
    const [selectedFile, setSelectedFile] = createSignal<string | null>(null);
    // The inbound queue the content pane is showing (ADR 0110 §7). The queue is
    // the *project's*; the chat is only where a reviewer acts from — so both are
    // held, and the surface closes when you navigate away from that chat rather
    // than lingering over an unrelated one.
    const [reviewing, setReviewing] = createSignal<{ project: string; chat: EngagementId } | null>(null);
    const reviewingProject = () => reviewing()?.project ?? null;
    // `chat` is passed explicitly rather than read from `selected()`: the top bar
    // opens the chat and the surface in one gesture, and the selection signal may
    // not have settled on the new chat yet when this runs.
    const setReviewingProject = (project: string | null, chat?: EngagementId | null) => {
        const on = chat ?? selected();
        setReviewing(project && on ? { project, chat: on } : null);
    };
    const workbenchShell = createWorkbenchShellState({
        selection: () => ({
            chatSelected: selected() !== null,
            fileSelected: selectedFile() !== null,
        }),
    });
    const [showShelf, setShowShelf] = createSignal(false);
    // "Add files"/"Add a file" in the browser open native OS pickers via these hidden
    // inputs; their contents are uploaded (UX-14 / UX-1 / ENTSEC-5). The desktop shell
    // takes the native-path route instead (see addFiles/addFile).
    let addFolderInput: HTMLInputElement | undefined;
    let addFileInput: HTMLInputElement | undefined;
    // The context-sources panel (RF-E1 / O-1): lists what context the chat holds.
    const [showSources, setShowSources] = createSignal(false);

    // On selecting an engagement, load its durable transcript snapshot, then
    // subscribe to live SSE (appending the in-progress turn). Switching back or
    // reloading rebuilds from the snapshot — the chat is durable, not client-only.
    createEffect(() => {
        const id = selected();
        if (!id) return;
        setStreamReady(false);
        setSelectedFile(null);
        // Leaving the chat a review was opened from closes the surface: an inbound
        // queue shown over an unrelated chat reads as that chat's, and the verdict
        // is submitted from whichever chat is open.
        if (reviewing() && reviewing()!.chat !== id) setReviewing(null);
        setSnapshot(empty);
        setLive(empty);
        void loadSnapshot(id);
        const unsubscribe = api.subscribe(
            id,
            (ev) => {
                setLive((t) => reduce(t, ev));
                // Reflect what the agent is doing, live, from the operational stream.
                if (ev.type === "text") setActivity("writing…");
                else if (ev.type === "tool") setActivity("using a tool…");
                else if (ev.type === "blocked") setActivity("effect blocked by the membrane");
            },
            () => setStreamReady(true),
        );
        onCleanup(unsubscribe);
    });

    // Auto-open the single changed file in View (round-7 #3). A one-way side effect
    // keyed explicitly on the diff (`on`, not an ambient effect): when the diff
    // settles and the turn touched exactly one user-facing file, and the user hasn't
    // picked a file of their own (read untracked, so this never re-fires on the
    // user's own selection), select it so View and Changes agree.
    createEffect(
        on(diff, (d) => {
            const changed = changedUserFiles(d ?? "");
            if (changed.length === 1 && untrack(selectedFile) === null) setSelectedFile(changed[0]);
        }),
    );

    // Opening a chat is ONE behavior, wherever it's triggered from (any nav facet,
    // the task bar, or creating a new chat): select it and put the cursor in the
    // composer. Every entry point calls this — there is no per-facet variation.
    // (Microtask-deferred so the composer, mounted by <Show> on first selection,
    // exists before we focus it.)
    let composerEl: HTMLTextAreaElement | undefined;
    function openChat(id: EngagementId) {
        setSelected(id);
        // UX-4: mirror the selection into the URL (`?chat=<id>`) so it's deep-linkable.
        if (typeof window !== "undefined") {
            window.history.replaceState(null, "", searchWithChat(window.location.search, id));
        }
        // A folded chat reopens, and a narrow shell navigates straight to it.
        workbenchShell.openPane("chat", { chatSelected: true, fileSelected: false });
        queueMicrotask(() => composerEl?.focus());
    }

    // UX-4: mirror the in-chat file selection into the URL (`?chat=<id>&file=<path>`) so a
    // file open within a chat is deep-linkable too. A separate effect from the chat mirror
    // (searchWithChat/searchWithFile each preserve the other's param), so it composes cleanly
    // and clears `file` whenever no file is open (including the reset on a chat switch).
    if (typeof window !== "undefined") {
        createEffect(() => {
            const path = selectedFile();
            window.history.replaceState(null, "", searchWithFile(window.location.search, path));
        });
    }

    // UX-4: restore a deep-linked chat (`?chat=<id>`) and the file open within it
    // (`&file=<path>`) on first load — best-effort, after sync setup. A stale chat id just
    // yields an empty transcript (handled); the file is restored after the chat's snapshot
    // load resets the per-chat selection, so a stale path simply resolves to no open file.
    if (typeof window !== "undefined") {
        const urlChat = chatIdFromSearch(window.location.search);
        const urlFile = fileFromSearch(window.location.search);
        if (urlChat)
            queueMicrotask(() => {
                openChat(urlChat as EngagementId);
                if (urlFile) queueMicrotask(() => setSelectedFile(urlFile));
            });
    }

    // Start a fresh chat on the hidden Personal default placement (ADR 0036) — the
    // same "just start typing" path as the nav's "+ new chat". Wired to the mobile
    // carousel's Chat tab so it's never a dead control when no chat is open yet.
    async function startNewChat(initialPrompt?: string, images: ImageRef[] = []) {
        const prompt = initialPrompt?.trim();
        try {
            const eng = await api.createEngagement();
            // The quick-start composer's model/effort choices were held as pending
            // pins (no chat existed to own them); write them into the new chat's
            // config before its first turn so the first message runs with them.
            const pin = pendingPin();
            const thinking = pendingThinking();
            if (pin || thinking) {
                try {
                    let cfg = "{}";
                    if (pin) cfg = writeChatModelPin(cfg, pin);
                    if (thinking) cfg = writeChatThinking(cfg, thinking);
                    await api.putConfig(eng.id, cfg);
                } catch {
                    setStatus("couldn't carry the model choice onto the new chat");
                }
                setPendingPin(null);
                setPendingThinking("");
            }
            setStatus("new chat");
            bumpNav(); // surface the new chat in the nav (the event stream also will)
            openChat(eng.id); // selects it and (on mobile) brings the chat pane on-screen
            if (prompt) {
                // Let the selected-chat effect subscribe before the first turn starts;
                // otherwise an eager turn can race the fresh transcript reset.
                queueMicrotask(() => void runPrompt(eng.id, prompt, images).catch(() => undefined));
            }
        } catch (e) {
            setStatus(`couldn't start a chat — ${String(e)}`);
        }
    }


    // Stop a running turn (run-chat.md): requests WhippleScript cancellation; the in-flight
    // task POST then resolves as failed and the composer re-enables.
    async function stopTurn() {
        const id = selected();
        if (!id) return;
        setActivity("stopping…");
        try {
            await api.stopTurn(id);
        } catch (e) {
            setStatus(`stop error: ${String(e)}`);
        }
    }

    // Run exactly one prompt as a turn. The single primitive behind both an
    // immediate send and a queue drain. On settle it swaps the live operational
    // stream for the now-durable transcript, then pumps the queue so the next
    // queued message runs automatically — turns chain without a round-trip to the human.
    async function runPrompt(
        id: EngagementId,
        prompt: string,
        images: ImageRef[] = [],
        // The outbox id this message was composed under (ADR 0137 §3). It becomes
        // the turn's idempotency key, so a resend after an uncertain dispatch is
        // answered by the receipt rather than guessed at by the client.
        composedId?: string,
    ) {
        // This turn may run in the background while the user looks at a different
        // chat, so every *display-mutating* side effect is gated on `isCurrent()` —
        // the running chat's transcript/diff/status must never clobber whatever chat
        // is on screen (round-13). The per-chat run tone is set regardless, so the
        // chat's dot in Browse reflects its own state.
        const isCurrent = () => selected() === id;
        const rid = clientRequestId(`${id}:${nextRid++}`);
        setRunTone(id, "working");
        if (isCurrent()) {
            setActivity("thinking…");
            setStatus("tasking agent…");
            // Immediate feedback (round-7 #6): echo the user's message into the
            // transcript the instant the turn starts — only when this chat is the one
            // on screen, else we'd inject it into the displayed chat's transcript. The
            // echo is an optimistic pending command, retired by snapshot-repair below.
            setPendingSend({ id, rid, text: prompt, baselineLines: snapshot().lines.length });
            setLive((t) => reduce(t, { type: "user", text: prompt }));
        }
        // Adopt the first message as the chat's title before the transcript fills.
        await maybeAutoTitle(id, prompt);
        setPendingApprovals([]); // a fresh turn clears the prior turn's pending approvals
        try {
            const res = (await api.runTask(id, prompt, images, composedId)) as {
                pending_approvals?: string[];
                run_phase?: string;
                diff?: string;
                error?: string;
            };
            if (isCurrent()) setPendingApprovals(res?.pending_approvals ?? []);
            // A turn can return 200 yet have *failed* (e.g. the model rejected an
            // attached image): the runtime error rides `run_phase`/`error`, not an HTTP
            // status. Report it honestly instead of a blanket "turn complete" — the
            // reason itself is also a durable transcript line (loadSnapshot shows it).
            const failed = res?.run_phase === "Failed";
            setRunTone(id, failed ? "error" : null);
            bumpNav(); // refresh nav + tasks (auto-title, review dot)
            if (isCurrent()) {
                setStatus(
                    failed
                        ? `turn failed${res?.error ? ` — ${res.error}` : ""}`
                        : "turn complete",
                );
                await Promise.all([loadSnapshot(id), refetchRun(), refetchDiff(), refetchMerge()]);
                // A default clean turn has already synchronized by the time the
                // projections refresh, so the branch-vs-line diff is empty. Keep
                // the response's turn diff on screen for this settled turn: it is
                // evidence of what just happened, not unresolved merge state.
                if (typeof res?.diff === "string") setDiff(res.diff);
            }
            if (failed) throw new Error(res?.error || "The turn failed.");
        } catch (e) {
            setRunTone(id, "error");
            if (isCurrent()) {
                // A rejection (INV-2) surfaces its reason; either way repair from the
                // durable snapshot so a failed turn leaves no dangling optimistic echo.
                setStatus(describeFailure("run that turn", e));
                await loadSnapshot(id);
                // A rejected command will never acquire a later admitted user event,
                // so do not carry the pending echo beyond this repair.
                setLive(empty);
            }
            throw e;
        } finally {
            retireSend(rid);
            if (isCurrent()) {
                setActivity("");
            }
        }
    }

    async function onMerge(action: MergeAction, target?: EngagementId) {
        const id = target ?? selected();
        if (!id) return;
        try {
            const m = await api.mergeCommand(id, action);
            // Plain, consistent status (#1): one verb per outcome, never the raw
            // phase token ("review: Rejected") or a "you couldn't" framing.
            const statusFor: Partial<Record<MergePhase, string>> = {
                Advanced: "kept into the shared copy",
                Integrated: "kept into the shared copy",
                // A `Rejected` merge is a conflict (couldn't be merged) or a user discard —
                // don't call a conflict a "discard" (UX-7).
                Rejected:
                    m.git_outcome === "Conflict"
                        ? "conflicted — repair it in the changes view"
                        : "discarded — nothing was kept",
                Clean: "ready to review",
                Repairing: "fixing up a conflict…",
            };
            setStatus(statusFor[m.phase] ?? "ready to review");
            bumpNav(); // keep/discard changes the task queue → refresh nav + review dots
            await Promise.all([refetchMerge(), refetchDiff(), loadSnapshot(id)]);
        } catch (e) {
            setStatus(e instanceof Rejected ? `couldn't do that — ${e.reason}` : `something went wrong — ${String(e)}`);
        }
    }

    async function ingestPath(path: string) {
        const id = selected();
        if (!id || !path) return;
        try {
            const c = await api.ingestContext(id, path);
            setStatus(`ingested ${c} file(s)`);
            await Promise.all([refetchDiff(), refetchMerge()]);
        } catch (e) {
            setStatus(`context error: ${String(e)}`);
        }
    }

    // Files too big to inline as text are skipped rather than uploaded — the ingest
    // endpoint stores content as text, so binaries/blobs don't round-trip anyway.
    const MAX_UPLOAD_BYTES = 1024 * 1024;

    // Browser context ingest: a native picker (folder or single file) hands us
    // `File`s; we read their text and upload it (ENTSEC-5). No absolute path is
    // involved — browsers hide those — so this is the path-free counterpart to the
    // desktop shell's native-path ingest. Called from the hidden inputs' onChange.
    async function uploadPickedFiles(input: HTMLInputElement | undefined) {
        const id = selected();
        if (!id || !input) return;
        const picked = Array.from(input.files ?? []);
        input.value = ""; // let the same folder/file be picked again later
        if (!picked.length) return;
        const files: { name: string; content: string }[] = [];
        const skipped: string[] = [];
        for (const f of picked) {
            if (f.size > MAX_UPLOAD_BYTES) {
                skipped.push(f.name);
                continue;
            }
            try {
                files.push({ name: f.name, content: await f.text() });
            } catch {
                skipped.push(f.name);
            }
        }
        if (!files.length) {
            setStatus(`nothing ingested — ${skipped.length} file(s) too large or unreadable`);
            return;
        }
        try {
            const n = await api.ingestContextUpload(id, files);
            setStatus(skipped.length ? `ingested ${n} file(s); skipped ${skipped.length}` : `ingested ${n} file(s)`);
            await Promise.all([refetchDiff(), refetchMerge()]);
        } catch (e) {
            setStatus(`context error: ${String(e)}`);
        }
    }

    // "add files": in the desktop shell, open the native OS folder picker (which
    // returns a real path the backend ingests by copying recursively); in the
    // browser, open the native folder picker and upload the files' contents.
    async function addFiles() {
        if (!isTauri()) {
            addFolderInput?.click();
            return;
        }
        const { open } = await import("@tauri-apps/plugin-dialog");
        const dir = await open({
            directory: true,
            multiple: false,
            title: "Add a folder of files for this chat",
        });
        if (typeof dir === "string") await ingestPath(dir);
    }

    // "add a file" (UX-1): single-file native picker. Desktop ingests the path; the
    // browser opens the native file picker and uploads the file's contents.
    async function addFile() {
        if (!isTauri()) {
            addFileInput?.click();
            return;
        }
        const { open } = await import("@tauri-apps/plugin-dialog");
        const file = await open({
            directory: false,
            multiple: false,
            title: "Add a single file for this chat",
        });
        if (typeof file === "string") await ingestPath(file);
    }

    async function saveOutputToDisk(resourceId: string) {
        const id = selected();
        if (!id || !isTauri()) return null;
        const { open } = await import("@tauri-apps/plugin-dialog");
        const dest = await open({
            directory: true,
            multiple: false,
            title: "Save this output to a folder",
        });
        if (typeof dest !== "string") return null;
        const result = await api.exportResourceToDisk(id, resourceId, dest);
        setStatus(`saved ${result.exported.length} output file(s) to ${result.dest}`);
        return result;
    }

    const phase = createMemo(() => run()?.phase ?? "—");

    // The selected chat's state, folded by the SAME pure function the navigation row
    // uses (`gemState`). This used to be a second derivation with its own precedence
    // and its own inputs, and the two disagreed: the row could paint `error`, which
    // this could not express, so an errored turn showed a red row beside a calm
    // "Ready". Feed one fold from one set of inputs and agreement is structural.
    //
    // That fold also took a `changes` input until ADR 0136 retired the per-change
    // review hold. A clean candidate no longer waits for a person, so the input could
    // only ever be false; the run tone is the one thing left that can say "review".
    const chatConflict = () => chatInfo()?.conflict
        || merge()?.phase === "Repairing"
        || (merge()?.phase === "Rejected" && merge()?.git_outcome === "Conflict");
    const chatState = createMemo<GemState>(() => gemState({
        tone: runToneOf(selected()),
        conflict: chatConflict(),
    }));
    // The state as words — for assistive technology and the browser lane. Colour is
    // never the only carrier of the state.
    const STATE_LABEL: Record<GemState, string> = {
        idle: "Ready",
        working: "Working",
        review: "Needs review",
        error: "Error",
        conflict: "Conflict",
    };

    async function attachTarget(
        projectId: import("@gaugewright/control-plane-client").ProjectId,
        _projectName: string,
        kind: "external-vcs" | "external-folder",
    ) {
        if (!isTauri()) {
            setStatus("attaching an existing machine folder is available in the desktop app");
            return;
        }
        const { open } = await import("@tauri-apps/plugin-dialog");
        const path = await open({
            directory: true,
            multiple: false,
            title: kind === "external-vcs" ? "Attach a Git repository" : "Attach a folder",
        });
        if (typeof path !== "string") return;
        const name = path.replace(/[\\/]+$/, "").split(/[\\/]/).pop() || "Attached files";
        try {
            await api.attachTarget(projectId, name, kind, path);
            setStatus(kind === "external-vcs"
                ? `attached ${name} with native Git authority`
                : `attached ${name} with compare-before-write concurrency`);
            bumpNav();
        } catch (error) {
            setStatus(`couldn't attach ${name} — ${String(error)}`);
        }
    }

    // The four pane bodies, defined once and reused by both shells (the desktop
    // grid and the mobile Carousel). They are plain accessors so the island stays
    // projection-agnostic: it receives ready-rendered panes and only decides which
    // one is on screen.
    const navPane = () => (
        <FacetBrowser
            api={api}
            selected={selected()}
            onSelect={openChat}
            onOpenArchetypeSettings={(id, name) => setAgentSettings({ id, name })}
            onOpenEngagement={(id, name) => setEngagement({ id, name })}
            onOpenModelAccess={(id, name) => setModelAccess({ id, name })}
            onOpenProjectHome={(id, name) => setProjectHome({ id, name })}
            onDeployPlacement={setDeployment}
            onAttachTarget={(id, name, kind) => void attachTarget(id, name, kind)}
            onOpenForkTree={(chat) => setForkTreeFor(chat)}
            onChatDeleted={(id) => selected() === id && setSelected(null)}
            onStatus={setStatus}
            runToneOf={runToneOf}
            refreshKey={navRefresh()}
        />
    );

    // The network-egress bar (RF-B3), pinned bottom-left of the nav column. It
    // reflects the open chat's project posture: open (the app default — the agent
    // can reach the model, and with no per-host proxy yet, any host) or isolated
    // (fail-closed). Clicking toggles it for that project. With no project-rooted
    // chat open (an edit chat / the Personal default) there's nothing to manage, so
    // it shows a muted, read-only hint.
    const networkBar = () => (
        <div class="network-bar" classList={{ isolated: !!currentProject()?.networkIsolated }}>
            <div class="network-bar-status">
                <Show
                    when={currentProject()}
                    fallback={
                        <span class="network-bar-label" title="Open a project's work chat to manage its network egress.">
                            <span class="network-bar-dot" /> Network · open
                        </span>
                    }
                >
                    {(p) => (
                        <button
                            type="button"
                            class="network-bar-toggle"
                            data-testid="network-toggle"
                            disabled={networkBusy()}
                            title={
                                p().networkIsolated
                                    ? `“${p().name}” is network-isolated — the agent can't reach the model. Click to open egress.`
                                    : `“${p().name}” has open network egress — the agent can reach any host. Click to isolate (fail-closed).`
                            }
                            onClick={toggleNetworkIsolated}
                        >
                            <span class="network-bar-dot" />
                            {p().networkIsolated ? "Network · isolated" : "Network · open"}
                        </button>
                    )}
                </Show>
                <span class="network-version" data-app-version>GaugeDesk v{clientBuild.version}</span>
                <Show when={desktopUpdate()?.kind === "available"}>
                    <button class="desktop-update" data-desktop-update type="button" onClick={() => void installDesktopUpdate()}>
                        Update to v{desktopUpdate()?.version}
                    </button>
                </Show>
                <Show when={desktopUpdate()?.kind === "checking" || desktopUpdate()?.kind === "installing"}>
                    <span class="network-version" data-update-state>{desktopUpdate()?.kind === "installing" ? "Installing update…" : "Checking for updates…"}</span>
                </Show>
                <Show when={desktopUpdate()?.kind === "restricted"}>
                    <span class="network-version" data-update-restricted title="The available stable release is outside this organization's allowed release channels.">
                        Update v{desktopUpdate()?.version} is managed by your organization
                    </span>
                </Show>
            </div>
            {/* Settings (FED-7): a gear to the right of the network toggle; opens the
                settings menu → Devices, the single device-management modal. */}
            <SettingsMenu
                api={api}
                placementPolicy={props.placementPolicy}
                codexLoginAvailable={codexLoginAvailable}
                managedInferenceEditable={import.meta.env.VITE_HOME_SPLIT !== "true"}
                librarySyncAvailable={import.meta.env.VITE_HOME_SPLIT !== "true"}
                openAccount={accountRequest}
                openInvite={inviteDeepLink}
                onSignOut={signOutAccount}
                environmentAction={props.environmentAction}
            />
        </div>
    );

    const composerModelToolbar = (stacked?: boolean) => (
        <ComposerModelBar
            options={modelChoices()}
            value={modelValue()}
            onPick={(key) => void pickModel(key)}
            effortLevels={showEffort() ? effortLevels() : []}
            effort={selected() ? chatThinking() : pendingThinking()}
            onPickEffort={(level) => void pickThinking(level)}
            stacked={stacked}
            customModel={showCustomModel()
                ? {
                    value: customModel(),
                    onInput: setCustomModel,
                    onCommit: (value) => void pinCustomModel(value),
                }
                : undefined}
        />
    );

    // One controller drives both the selected Session and quick-start. The
    // Environment changes only its explicit capabilities and turn primitive.
    const desktopComposerController = createSessionComposerController({
        defaultMode: defaultComposerMode,
        // Durable on the owner's own machine (ADR 0137): a queued or stashed
        // message survives a reload, a chat switch and an outage. IndexedDB
        // rather than a string store because attachments are bytes.
        outbox: createIndexedDbOutboxStore(),
        scope: () => selected() ? String(selected()) : "quick-start",
        busy: () => selected() ? busy() : false,
        capabilities: () => selected()
            ? UNIVERSAL_COMPOSER_CAPABILITIES
            : BASIC_COMPOSER_CAPABILITIES,
        send: async (text, images, composedId) => {
            const id = selected();
            if (id) {
                await runPrompt(id, text, [...images], composedId);
            } else {
                await startNewChat(text, [...images]);
            }
        },
        // With a chat selected this sends a turn, which carries the composed id as
        // its idempotency key and is refused on a second application (ADR 0137
        // §3). With nothing selected it *creates a chat* and then runs a turn, and
        // only the turn half is keyed — so a resend there would mint a second
        // chat, which is worse than the message waiting for a person. The
        // guarantee is claimed exactly where it holds.
        appliesComposedIdOnce: () => Boolean(selected()),
        stop: stopTurn,
        draft: { value: paneDraft, set: setPaneDraft },
        retainDraftOnScopeChange: true,
        modelToolbar: composerModelToolbar,
        acceptsImages: () => modelAcceptsImages({ id: chatModel(), provider: chatProvider() }),
        onStatus: setStatus,
    });

    /** The composer's fork, which is not `forkAt`. `forkAt` branches from an
     *  existing transcript entry and leaves you reading history; this branches at
     *  the head and carries what you were *about* to say into the new line, so
     *  the message you drafted is the first thing the branch runs.
     *
     *  The draft goes; the queue does not. What is queued was queued for this
     *  conversation — silently moving it would be the composer deciding that the
     *  messages you lined up here belong somewhere else. Attachments travel with
     *  the draft because they are part of that one composed message.
     *
     *  Refuses rather than half-acts: if the branch cannot be made, the draft
     *  stays where it is and the failure is reported. */
    async function forkWithDraft() {
        const id = selected();
        if (!id) return;
        const composed = desktopComposerController.takeComposed();
        if (!composed) return;
        try {
            const branch = await api.forkChat(id);
            openChat(branch);
            await runPrompt(branch, composed.text, [...composed.images]);
        } catch (error) {
            composed.restore();
            setStatus(`couldn't fork this chat — ${String(error)}`);
        }
    }

    const paneComposer = () => (
        <SessionComposer
            audience={false}
            controller={desktopComposerController}
            onFork={selected() ? () => void forkWithDraft() : undefined}
            defaultMode={defaultComposerMode()}
            onSetDefaultMode={makeModeDefault}
            quickStart={!selected()}
            placeholder={selected() && chatKind() === "edit"
                ? `Describe what to change about ${methodName() || "this archetype"}…`
                : "task the agent…"}
            inputRef={(element) => {
                composerEl = element;
                if (!selected()) queueMicrotask(() => element.focus());
            }}
        />
    );

    const contentPane = () => (
        <>
            <h2>Content</h2>
            <Show when={selected()} keyed fallback={<div class="status">Open a chat, then pick a file to read it — and review changes — here.</div>}>
                {(id) => (
                    <SessionProvider value={desktopEnvironment.openSession(id).session}>
                        {/* The review surface takes the pane rather than a fourth tab
                            inside the viewer (ADR 0110 §7, GATE-6). A tab would imply
                            inbound material is another view of the selected workspace
                            file; it is the one kind of content no agent can reach, and
                            putting it in that tab strip would place it in the file
                            namespace the protection is stated over. */}
                        <Show when={reviewingProject()} keyed fallback={<ContentViewer />}>
                            {(project) => (
                                <div class="viewer">
                                    <div class="tabs" data-viewer-tabs>
                                        <span class="tab active" data-tab="inbound">inbound</span>
                                        <span class="status viewer-filename">awaiting your review</span>
                                        <button
                                            class="ghost"
                                            data-inbound-close
                                            onClick={() => setReviewingProject(null)}
                                        >
                                            back to files
                                        </button>
                                    </div>
                                    <QuarantineIndex project={project} />
                                </div>
                            )}
                        </Show>
                    </SessionProvider>
                )}
            </Show>
        </>
    );

    const filesPane = () => (
        <>
            <h2>
                Files
                <Show when={selected()}>
                    {/* Durable context upload lives here (UX-14), not the chat
                        composer: a folder or single file is copied into this chat's
                        workspace and persists. The composer's paperclip is the
                        separate, message-scoped attach. */}
                    <span class="header-actions">
                        <button
                            class="icon-btn"
                            aria-label="Add files"
                            title="Add a folder of files for the agent to work with (copied into this chat's workspace)"
                            onClick={addFiles}
                        >
                            <Icon name="add-folder" />
                        </button>
                        <button
                            class="icon-btn"
                            aria-label="Add a file"
                            title="Add a single file for the agent to work with (copied into this chat's workspace)"
                            onClick={addFile}
                        >
                            <Icon name="add-files" />
                        </button>
                    </span>
                </Show>
            </h2>
            {/* Hidden native pickers behind the header's "Add files"/"Add a file"
                buttons (browser build). `webkitdirectory` (set via ref — it isn't a
                typed JSX attribute) makes the first a folder picker; the second is a
                single-file picker. Selected files' contents are uploaded (ENTSEC-5).
                Kept outside `.composer` so composer input steps don't match them. */}
            <input
                ref={(el) => {
                    addFolderInput = el;
                    el.setAttribute("webkitdirectory", "");
                }}
                type="file"
                multiple
                data-add-folder-input
                style={{ display: "none" }}
                onChange={() => void uploadPickedFiles(addFolderInput)}
            />
            <input
                ref={(el) => (addFileInput = el)}
                type="file"
                data-add-file-input
                style={{ display: "none" }}
                onChange={() => void uploadPickedFiles(addFileInput)}
            />
            <Show when={selected()} keyed fallback={<div class="status">Each chat's working files are listed here.</div>}>
                {(id) => (
                    <SessionProvider value={desktopEnvironment.openSession(id).session}>
                        <Workspace />
                    </SessionProvider>
                )}
            </Show>
        </>
    );

    const chatPane = () => (
        <>
            <ChatPaneHeader
                title={selected() ? chatTitle() : undefined}
                kind={selected() ? chatKind() : undefined}
                tone={selected() ? runToneOf(selected()) : undefined}
                conflict={selected() ? chatConflict() : undefined}
                statusLabel={selected() ? STATE_LABEL[chatState()] : undefined}
                statusPhase={selected() ? phase() : undefined}
                context={selected() ? headerContext() : undefined}
                contextKind={selected() ? chatKind() : undefined}
                workstream={selected() ? chatInfo()?.workstream : undefined}
                workstreamState={selected() ? workstreamState() : undefined}
                connection={selected() ? freshnessStatus() : undefined}
                mobile={workbenchShell.isMobile()}
                onCollapse={() => workbenchShell.setCollapsed("chat", true)}
                actions={
                    <Show when={selected()}>
                        <span class="header-actions">
                        <TranscriptFilterMenu
                            prefs={filterPrefs()}
                            onChange={setFilterPrefs}
                            onSaveDefault={saveFilterDefault}
                        />
                        <button
                            class="icon-btn"
                            data-open-sources
                            aria-label="Sources"
                            title="See the context this chat is working with — attached files and its archetype"
                            onClick={() => setShowSources(true)}
                        >
                            <Icon name="sources" />
                        </button>
                        <button
                            class="icon-btn"
                            aria-label="History"
                            title="A timeline of everything that's happened in this chat, plus the review surface"
                            onClick={() => setShowShelf(true)}
                        >
                            <Icon name="history" />
                        </button>
                        </span>
                    </Show>
                }
            />
            <Show when={selected()}>
                {/* WS-H: the chat header carries no permanent "private draft" caption
                    and no manual pull/discard buttons — a chat targets one shared line
                    (default mainline = workstream of one) and co-rooted sync is greedy
                    and automatic (WS-D). Keep/discard is the review surface (Changes
                    tab); shared-line status surfaces only when named/shared or in
                    conflict (WS-H b,c). The header is quiet by default. */}
                <Show when={pendingApprovals().length > 0}>
                    <div class="approval-notice" data-pending-approvals role="status">
                        <strong>Waiting for your approval</strong>
                        <ul>
                            <For each={pendingApprovals()}>{(a) => <li>{a}</li>}</For>
                        </ul>
                        <span class="muted">
                            The agent asked to do the above and is holding until you grant it
                            (in the sources/access panel) — nothing happens without your OK.
                        </span>
                    </div>
                </Show>
            </Show>
            <Show
                when={selected()}
                fallback={
                    <>
                        {/* The pane keeps its normal anatomy with no chat open: an
                            empty transcript area absorbing the slack (with one quiet
                            line of guidance) and THE SAME composer component docked
                            at the bottom — not a second, lesser input at the top. */}
                        <div class="transcript empty-chat-welcome" data-empty-chat-welcome>
                            <p class="empty-chat-hint">
                                No chat is open. Task the agent below — your first
                                message starts a chat in Personal.
                            </p>
                        </div>
                        {paneComposer()}
                    </>
                }
            >
                {/* Desktop projection-freshness notice (RF-E4): chromeless while
                    fresh; on a failed refresh it surfaces the staleness + a retry
                    that re-runs the failed loads. */}
                <FreshnessBanner
                    status={freshnessStatus()}
                    error={freshness().error}
                    onRetry={retryProjections}
                />
                <Show when={streamReady()}>
                    <span data-testid="stream-ready" style={{ display: "none" }} />
                </Show>
                {/* Fork first-view note (#3): on the fork's empty transcript, explain
                    the copy-semantics established round 1 #2 — files came along, the
                    conversation started fresh — so the lineage is legible at a glance. */}
                <Show when={forkOf() && transcript().lines.length === 0}>
                    <div class="fork-note" data-fork-note>
                        Started as a copy of <strong>{forkOf()}</strong> — its files came along, the conversation starts fresh here.
                    </div>
                </Show>
                <ChatPanel
                    session={activeDesktopSession()!}
                    bare
                    prefs={filterPrefs()}
                    pendingSend={pendingSend()?.id === selected() ? pendingSend()?.rid : undefined}
                    onResolveCredential={() => setAccountRequest((n) => n + 1)}
                    transcriptTail={
                        <Show when={busy()}>
                            <div class="working" data-testid="agent-working">
                                <span class="pulse" />
                                agent working{activity() ? ` — ${activity()}` : ""}
                            </div>
                        </Show>
                    }
                    composerController={desktopComposerController}
                    composerInputRef={(element) => { composerEl = element; }}
                    onForkWithDraft={selected() ? () => void forkWithDraft() : undefined}
                    defaultMode={defaultComposerMode()}
                    onSetDefaultMode={makeModeDefault}
                />
            </Show>
        </>
    );

    // The shared overlays (archetype settings, history shelf) sit above whichever
    // shell is active, so both the desktop grid and the mobile carousel mount them.
    const overlays = () => (
        <>
            <Show when={agentSettings()}>
                {(a) => (
                    <div class="modal-overlay" onClick={() => setAgentSettings(null)}>
                        <div onClick={(e) => e.stopPropagation()}>
                            <AgentSettings
                                api={api}
                                id={a().id}
                                name={a().name}
                                onClose={() => setAgentSettings(null)}
                            />
                        </div>
                    </div>
                )}
            </Show>

            <Show when={engagement()}>
                {(e) => (
                    <EngagementPane
                        api={api}
                        project={e().id}
                        projectName={e().name}
                        onClose={() => setEngagement(null)}
                    />
                )}
            </Show>

            <Show when={modelAccess()}>
                {(e) => (
                    <ProjectModelAccessPanel
                        api={api}
                        project={e().id}
                        projectName={e().name}
                        onClose={() => setModelAccess(null)}
                    />
                )}
            </Show>

            <Show when={projectHome()}>
                {(e) => (
                    <ProjectHomePanel
                        api={api}
                        project={e().id}
                        projectName={e().name}
                        onOpenChat={(chat) => {
                            setProjectHome(null);
                            openChat(chat as EngagementId);
                        }}
                        onClose={() => setProjectHome(null)}
                    />
                )}
            </Show>

            <Show when={forkTreeFor()}>
                {(chat) => (
                    <ForkTreePanel
                        api={api}
                        highlight={chat()}
                        onOpenChat={(id) => {
                            setForkTreeFor(null);
                            openChat(id as EngagementId);
                        }}
                        onClose={() => setForkTreeFor(null)}
                    />
                )}
            </Show>

            <Show when={deployment()}>{(selectedDeployment) => (
                <DeploymentPanel
                    api={api}
                    selection={selectedDeployment()}
                    defaultEdgeOrigin={import.meta.env.VITE_PUBLIC_EDGE_ORIGIN
                        || PUBLIC_EDGE_ORIGIN}
                    defaultFundingRef={import.meta.env.VITE_PUBLIC_FUNDING_REF
                        || ""}
                    defaultCredentialRef={import.meta.env.VITE_PUBLIC_CREDENTIAL_REF
                        || "credential:production:openai:v1"}
                    onClose={() => setDeployment(null)}
                />
            )}</Show>

            <Show when={selected() && showShelf()}>
                <Shelf
                    api={api}
                    scope={scopeId(selected()!)}
                    id={selected()!}
                    onSaveOutputToDisk={isTauri() ? saveOutputToDisk : undefined}
                    onClose={() => setShowShelf(false)}
                />
            </Show>

            <Show when={selected() && showSources()}>
                <ContextPanel
                    api={api}
                    id={selected()!}
                    refreshKey={status()}
                    onClose={() => setShowSources(false)}
                />
            </Show>
        </>
    );

    // The local Environment (ADR 0076) owns the desktop's identity, placement
    // adapter, and panel manifest. It mints a fixed-id Session leaf whenever the
    // active engagement changes; the shell no longer hand-builds a mutable-id
    // Session as a second producer.
    const desktopSessionFor = (id: EngagementId): Session => ({
        api,
        engagementId: () => id,
        worktreeRev: status,
        selectedFile,
        selectFile: (path) => setSelectedFile(path),
        reviewingProject,
        reviewProject: (project) => setReviewingProject(project),
        diff: () => diff() ?? "",
        mergePhase: () => merge()?.phase ?? null,
        mergeConflicted: () => merge()?.phase === "Rejected" && merge()?.git_outcome === "Conflict",
        chatKind,
        methodName,
        transcript,
        busy: () => selected() === id && busy(),
        turnActivity: localTurnActivity(() => selected() === id && busy(), transcript),
        composerCapabilities: () => UNIVERSAL_COMPOSER_CAPABILITIES,
        // The desktop's control plane is co-resident, so there is no transport
        // between this panel and the runtime that can be down on its own. A
        // failing command fails as a turn, which the composer already reports.
        canCommand: () => true,
        merge: (action) => void onMerge(action),
        onContentSaved: () => void Promise.all([refetchDiff(), refetchMerge()]),
        send: async (text, images = [], composedId) => {
            // A leaf may outlive one render turn during a selection change. Refuse
            // to route its command to a different engagement.
            if (selected() !== id) throw new Error("This chat is no longer selected.");
            await runPrompt(id, text, [...images], composedId);
        },
        // This leaf always has an engagement, so the composed id is always the
        // turn's idempotency key and a resend is always answerable (ADR 0137 §3).
        appliesComposedIdOnce: true,
        stop: async () => {
            if (selected() !== id) throw new Error("This chat is no longer selected.");
            await stopTurn();
        },
        forkAt: (entryId) => {
            if (selected() !== id) return;
            void api.forkChatAt(id, entryId).then(openChat);
        },
    });
    const desktopEnvironment = new Environment({
        identity: { kind: "local", subject: "local:personal" },
        controlPlane: api,
        manifest: panelManifest(["chat", "viewer", "files"]),
        sessionFactory: (_controlPlane, id) => ({
            session: desktopSessionFor(id),
            dispose: () => undefined,
        }),
    });
    const activeDesktopSession = createMemo(() => {
        const id = selected();
        return id ? desktopEnvironment.openSession(id).session : undefined;
    });
    const noHomeState = createMemo(() => {
        const state = homeState();
        return state?.kind === "none" ? state : null;
    });
    // Whether the person asked for the advanced/recovery Home affordances
    // (endpoint entry, registered Homes, account reach). Off by default so a new
    // person meets one act, not a control panel.
    const [homeRecovery, setHomeRecovery] = createSignal(false);
    const HomeSetup = () => {
        // A person with a valid account and no Home yet is an ordinary starting
        // state, not an error (`experience/desk.md`). It gets one page whose single
        // primary act is a way to *get* a Home; the endpoint/picker affordances
        // below are recovery, revealed on request rather than met on arrival.
        if (import.meta.env.VITE_HOME_SPLIT === "true" && !homeInvite() && !homeRecovery()) {
            const downloadUrl = props.downloadUrl
                || import.meta.env.VITE_DOWNLOAD_URL
                || "https://gaugewright.com/gaugedesk/download";
            return (
                <Show when={noHomeState()}>
                    <div class="homegate-scrim" data-home-setup>
                        <section class="homegate-card" aria-labelledby="homegate-title">
                            <p class="homegate-kicker">Welcome to GaugeDesk</p>
                            <h1 id="homegate-title">Your work needs a Home</h1>
                            <p class="homegate-lede">
                                Projects, chats, and files live on a Home — a computer you
                                control — rather than in this browser. Install GaugeDesk and
                                sign in there, and that computer becomes your first Home.
                                This page then opens it from anywhere you sign in.
                            </p>
                            <a
                                class="firstrun-connect"
                                data-home-download
                                href={downloadUrl}
                                rel="noreferrer"
                            >
                                Download GaugeDesk
                            </a>
                            <p class="homegate-auth-note">
                                GaugeWright-hosted Homes, where we run one for you, are coming.
                                {" "}
                                <button
                                    type="button"
                                    class="homegate-link"
                                    data-home-recovery
                                    onClick={() => setHomeRecovery(true)}
                                >
                                    Already have a Home?
                                </button>
                            </p>
                        </section>
                    </div>
                </Show>
            );
        }
        return (
            <Show when={noHomeState()}>
                {(state) => <div class="homegate-scrim" data-home-setup>
                    <section class="homegate-card" aria-labelledby="homegate-title">
                    <p class="homegate-kicker">Free account</p>
                    <h1 id="homegate-title">Choose where your projects run</h1>
                    <p class="homegate-lede">
                        Your account and invitations live here. Project files, event logs, and
                        agents stay on the Home you choose—your computer, another team’s Home,
                        or a paid Cloud Home.
                    </p>

                    <Show when={homeInvite()}>
                        <Show
                            when={invitationPreview()}
                            fallback={<div class="homegate-notice homegate-error" role="alert">
                                This project invitation is malformed or uses an unsafe Home endpoint.
                            </div>}
                        >
                            {(invite) => <div class="homegate-invite">
                                <div>
                                    <strong>Project invitation</strong>
                                    <span>
                                        Join {invite().project} on {invite().homeId}. Your free account
                                        uses the owner’s Home; it does not create hosted work here.
                                    </span>
                                    <small>{invite().endpoint}</small>
                                </div>
                                <button
                                    type="button"
                                    disabled={homeBusy()}
                                    onClick={() => void acceptHomeInvite()}
                                >
                                    {homeBusy() ? "Joining…" : "Accept invitation"}
                                </button>
                            </div>}
                        </Show>
                    </Show>

                    <Show when={state().routes.length > 0}>
                        <div class="homegate-notice">
                            You have {state().routes.length} shared project route
                            {state().routes.length === 1 ? "" : "s"}. Opening one connects to its
                            owner’s Home; it does not use hosted storage from your free account.
                        </div>
                    </Show>

                    <Show when={state().homes.length > 0}>
                        <div class="homegate-homes">
                            <span class="homegate-label">Registered Homes</span>
                            <For each={state().homes}>
                                {(home) => (
                                    <button
                                        type="button"
                                        class="homegate-home"
                                        disabled={homeBusy()}
                                        onClick={() => void api.selectHome(home.id).then(() => refetchHome())}
                                    >
                                        <span>{home.id}</span>
                                        <small>{home.endpoint}</small>
                                    </button>
                                )}
                            </For>
                        </div>
                    </Show>

                    <Show when={(hubReach()?.homes.length ?? 0) + (hubReach()?.routes.length ?? 0) > 0}>
                        <div class="homegate-homes" data-hub-reach>
                            <span class="homegate-label">
                                Through your GaugeWright account
                                {hubReach()?.person ? ` — ${hubReach()?.person}` : ""}
                            </span>
                            <For each={hubReach()?.homes ?? []}>
                                {(home) => (
                                    <button
                                        type="button"
                                        class="homegate-home"
                                        disabled={homeBusy()}
                                        onClick={() => {
                                            setHomeEndpoint(home.endpoint);
                                            void connectHome();
                                        }}
                                    >
                                        <span>{home.id}</span>
                                        <small>{home.endpoint}</small>
                                    </button>
                                )}
                            </For>
                            <For each={hubReach()?.routes ?? []}>
                                {(route) => (
                                    <button
                                        type="button"
                                        class="homegate-home"
                                        disabled={homeBusy() || !route.endpoint}
                                        onClick={() => {
                                            setHomeEndpoint(route.endpoint);
                                            void connectHome();
                                        }}
                                    >
                                        <span>{route.project}</span>
                                        <small>{route.endpoint || `via relay — ${route.homeId}`}</small>
                                    </button>
                                )}
                            </For>
                        </div>
                    </Show>

                    <label class="homegate-field">
                        <span class="homegate-label">Connect a computer or private Home</span>
                        <div class="homegate-connect-row">
                            <input
                                value={homeEndpoint()}
                                onInput={(event) => setHomeEndpoint(event.currentTarget.value)}
                                placeholder="https://home.example.com"
                                aria-label="Home endpoint"
                            />
                            <button
                                type="button"
                                disabled={homeBusy() || !homeEndpoint().trim()}
                                onClick={() => void connectHome()}
                            >
                                {homeBusy() ? "Connecting…" : "Connect"}
                            </button>
                        </div>
                    </label>

                    <Show when={props.environmentAction?.available()}>
                        <div class="homegate-cloud">
                            <div>
                                <strong>Manage machines</strong>
                                <span>Connect a self-managed machine or add a managed machine in Administration.</span>
                            </div>
                            <button type="button" onClick={() => props.environmentAction?.open()}>
                                Open Administration
                            </button>
                        </div>
                    </Show>
                    <p class="homegate-auth-note">
                        {localDevLogin
                            ? "This isolated local account never contacts Google or the production GaugeWright Hub."
                            : "Google sign-in identifies your GaugeWright account. Connecting OpenAI or another model provider is a separate authorization in Account settings."}
                    </p>
                    <Show when={homeError()}>
                        <p class="homegate-error" role="alert">{homeError()}</p>
                    </Show>
                    </section>
                </div>}
            </Show>
        );
    };
    // One shell at a time: `<Show>` lazily mounts only the active branch, so the
    // inactive layout never builds (no double-mounted FacetBrowser / Workspace).
    return (
        <>
            <Show when={homeState.loading}>
                <div class="homegate-scrim" data-home-loading>
                    <section class="homegate-card"><p class="homegate-lede">Finding your Home…</p></section>
                </div>
            </Show>
            <Show when={homeFailure()}>
                <div class="homegate-scrim" data-home-error>
                    <section class="homegate-card">
                        <h1>{homeNeedsLogin() ? "Sign in to find your Home" : "We couldn’t load your Homes"}</h1>
                        <p class="homegate-lede">
                            {homeNeedsLogin()
                                ? localDevLogin
                                    ? "Enter the isolated local account, then Home discovery will continue automatically."
                                    : "Your GaugeWright session is missing or expired. Sign in with Google, then Home discovery will continue automatically."
                                : "The account Hub could not be reached. Retry when the connection is available."}
                        </p>
                        <div class="homegate-connect-row">
                            <Show when={homeNeedsLogin()}>
                                <button
                                    class="firstrun-connect"
                                    data-home-sign-in
                                    type="button"
                                    onClick={() => beginLogin(controlPlaneBase())}
                                >
                                    {localDevLogin ? "Enter local dev account" : "Sign in with Google"}
                                </button>
                            </Show>
                            <button
                                class="firstrun-connect"
                                type="button"
                                onClick={() => void refetchHome()}
                            >
                                Retry
                            </button>
                        </div>
                    </section>
                </div>
            </Show>
            <Show when={!homeState.loading && !homeFailure()}>
                <HomeSetup />
            </Show>
            {/* First-run credential gate (ADR 0075 Phase 0): overlays both shells
                until a model is connected, then dismisses itself. */}
            <Show
                when={
                    !homeState.loading &&
                    !homeFailure() &&
                    homeState()?.kind !== "none" &&
                    showFirstRun()
                }
            >
                <FirstRunOverlay
                    api={api}
                    productName="GaugeDesk"
                    codexLoginAvailable={codexLoginAvailable}
                    account={accountLoginAvailable || hubSession()?.available ? {
                        label: localDevLogin ? "Enter local dev account" : "Sign in with Google",
                        // The overlay renders only after home discovery succeeded, which in
                        // hub-split mode already required an authenticated session; the
                        // bearer covers the local-OIDC fragment flow, and the desktop's
                        // hub session covers the native handoff (ADR 0123).
                        signedIn: () =>
                            bearer() !== null ||
                            import.meta.env.VITE_HOME_SPLIT === "true" ||
                            (hubSession()?.linked === true && !hubSession()?.expired),
                        subject: () => authority() ?? hubSession()?.person ?? null,
                        begin: () => {
                            if (accountLoginAvailable) {
                                beginLogin(controlPlaneBase());
                                return;
                            }
                            // Desktop: the control plane mints and holds the verifier and
                            // returns the Hub login URL for the system browser; the
                            // gaugewright:// return completes the handoff.
                            void api
                                .hubSessionStart()
                                .then(({ url }) => {
                                    window.open(url, "_blank", "noopener,noreferrer");
                                })
                                .catch(() => {});
                        },
                    } : undefined}
                    onConnected={() => {
                        void refetchStartupCreds();
                        void refetchStartupCodex();
                    }}
                    onDismiss={() => setFirstRunDismissed(true)}
                />
            </Show>
            <Show when={!homeState.loading && !homeFailure() && homeState()?.kind !== "none"}>
                <WorkbenchShell
                    state={workbenchShell}
                    taskBar={() => (
                        <TaskBar
                            api={api}
                            selected={selected()}
                            refreshKey={navRefresh()}
                            onSelect={openChat}
                            onReviewInbound={(project, id) => setReviewingProject(project, id)}
                        />
                    )}
                    nav={navPane}
                    navFooter={networkBar}
                    chat={chatPane}
                    content={contentPane}
                    files={filesPane}
                    overlays={overlays}
                    onNewChat={() => void startNewChat()}
                />
            </Show>
        </>
    );
}

/** GaugeDesk is the workbench on both desktop and web. Account, organization,
 * Home, billing, backup, and deployment management live in GaugeWright Hub;
 * the hosted transport flag changes routing only, never the application shell.
 */
export function App(props: WorkbenchAppProps = {}) {
    if (isMobileHarness()) return <MobileApp />;
    const tenant = typeof window === "undefined"
        ? null
        : new URLSearchParams(window.location.search).get("tenant");
    createEffect(() => props.onTenantContextChange?.(tenant));
    return <WorkbenchApp {...props} />;
}
