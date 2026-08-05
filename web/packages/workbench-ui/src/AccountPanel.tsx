/**
 * **Your account** (ACCT-1, ADR 0053): the operator's own surface — linked LLM
 * provider accounts, the trusted-device registry, and settings. Distinct from the
 * org Admin Console (a company you administer) and from Devices (federation pairing).
 *
 * A thin renderer over `/account/*`. The linked credential's token is write-only: you
 * link a provider, but the token is never read back (sealed server-side, SEC-4).
 */

import { createResource, createSignal, For, onCleanup, Show, type JSX } from "solid-js";
import type {
    AccountDevice,
    AccountFacility,
    AccountInvitation,
    AccountSignInMethod,
    AccountTenant,
    LinkedProvider,
    ManagedInferenceBilling,
    ManagedInferencePlan,
    ManagedPlanStatus,
    CodexLoginStart,
    CodexStatus,
} from "@gaugewright/control-plane-client";
import {
    ADVANCEMENT_RULES_SETTING,
    parseAdvancementScopes,
    serializeAdvancementScopes,
} from "./advancement";
import {
    ATTENTION_RULES_SETTING,
    ATTENTION_SIGNALS,
    parseAttentionRules,
    serializeAttentionRules,
    type AttentionLevel,
    type AttentionSignal,
} from "./attention";
import { waitForCodexLink } from "./codex-link-poll";
import type { HubSessionStatus } from "@gaugewright/control-plane-client";
import {
    defaultVisibleKeys,
    ENABLED_MODELS_SETTING,
    modelKey,
    parseEnabledModels,
    pickableModels,
    providerTakesCustomModel,
    serializeEnabledModels,
} from "./model-picker";

const PROVIDERS = ["openai", "anthropic", "openai-generic"];

/** Enrollment time is account evidence, not presence. Legacy records honestly
 * report that their original join time was not recorded. */
export function deviceAddedLabel(enrolledAt: number): string {
    if (!Number.isFinite(enrolledAt) || enrolledAt <= 0) {
        return "Added before enrollment dates were recorded";
    }
    const date = new Date(enrolledAt * 1000);
    return Number.isNaN(date.getTime())
        ? "Added before enrollment dates were recorded"
        : `Added ${date.toLocaleDateString()}`;
}

/** Current-session copy is intentionally separate from a durable linked sign-in method. */
export function signInMethodLabel(method: AccountSignInMethod | undefined): string {
    return method?.label.trim() || "Current session";
}

export function managedInferenceWriteAvailable(editable: boolean | undefined): boolean {
    return editable !== false;
}

export interface AccountPanelApi {
    accountSignInMethod(): Promise<AccountSignInMethod>;
    accountCredentials(): Promise<LinkedProvider[]>;
    accountDevices(): Promise<AccountDevice[]>;
    accountInvitations(): Promise<AccountInvitation[]>;
    acceptAccountInvitation(tenantId: string): Promise<AccountTenant>;
    codexStatus(): Promise<CodexStatus>;
    codexLoginStart(): Promise<CodexLoginStart>;
    codexLoginCancel(): Promise<void>;
    accountLinkCredential(provider: string, token: string, baseUrl?: string): Promise<void>;
    accountUnlinkCredential(provider: string): Promise<void>;
    accountManagedInference(): Promise<ManagedInferenceBilling>;
    accountSetManagedInference(plan: ManagedInferencePlan): Promise<void>;
    accountRevokeDevice(id: string): Promise<void>;
    accountSettings(): Promise<Record<string, string>>;
    accountSetSetting(key: string, value: string): Promise<void>;
    accountFacilities(): Promise<AccountFacility[]>;
    accountAttachFacility(input: {
        id: string;
        kind?: string;
        displayName?: string;
    }): Promise<AccountFacility>;
    accountDetachFacility(id: string): Promise<void>;
    accountPublishLibrarySync(): Promise<void>;
    accountPullLibrarySync(): Promise<{ found: boolean; merged: number }>;
    /** Desktop → Hub account sign-in (ADR 0123, LOGIN-4). Optional: only the
     * co-resident desktop control plane custodies a Hub session; compositions
     * without these methods simply do not render the account-session section. */
    hubSessionStatus?(): Promise<HubSessionStatus>;
    hubSessionStart?(): Promise<{ url: string }>;
    hubSessionSignOut?(): Promise<void>;
}

export function AccountPanel(props: {
    api: AccountPanelApi;
    /** Whether this runtime offers an OpenAI authorization flow. */
    codexLoginAvailable?: boolean;
    /** Hosted billing owns managed-plan writes; those compositions project the
     * plan and usage here but must not offer the local self-managed editor. */
    managedInferenceEditable?: boolean;
    /** Library sync requires the sovereign root key held by the co-resident
     * desktop. Shared hosted sessions must not offer this process-local action. */
    librarySyncAvailable?: boolean;
    onClose: () => void;
}): JSX.Element {
    const [tick, setTick] = createSignal(0);
    const refresh = () => setTick((t) => t + 1);
    const [status, setStatus] = createSignal("");

    // Projection reads settle to undefined on failure instead of erroring the
    // resource: reading an errored resource throws mid-render (the Devices
    // crash class, 2026-07-31), and a control plane may not serve every
    // account facade (e.g. /auth/session is hosted-only) — each section
    // already renders its absent-value fallback for undefined.
    const soft = <T,>(read: () => Promise<T>) => async (): Promise<T | undefined> => {
        try {
            return await read();
        } catch {
            return undefined;
        }
    };
    const [credentials] = createResource(tick, soft(() => props.api.accountCredentials()));
    const [signInMethod] = createResource(tick, soft(() => props.api.accountSignInMethod()));
    const [devices] = createResource(tick, soft(() => props.api.accountDevices()));
    const [invitations] = createResource(tick, soft(() => props.api.accountInvitations()));
    const [managed] = createResource(tick, soft(() => props.api.accountManagedInference()));
    const [facilities] = createResource(tick, soft(() => props.api.accountFacilities()));
    // Desktop → Hub account session (ADR 0123, LOGIN-4): server truth from the
    // local control plane; reading status also lets the control plane refresh a
    // session nearing expiry. Compositions without the seam render no section.
    const [hubSession] = createResource(
        tick,
        soft(() => props.api.hubSessionStatus?.() ?? Promise.resolve(null)),
    );
    let hubPanelDisposed = false;
    onCleanup(() => {
        hubPanelDisposed = true;
    });
    const startHubSignIn = async () => {
        const started = await props.api.hubSessionStart?.();
        if (!started) return;
        window.open(started.url, "_blank", "noopener,noreferrer");
        setStatus("finish signing in in your browser — this panel updates by itself");
        // The deep-linked return lands in the control plane; poll status until
        // the session appears (bounded — the person may abandon the tab).
        for (let attempt = 0; attempt < 60 && !hubPanelDisposed; attempt += 1) {
            await new Promise((resolve) => setTimeout(resolve, 2000));
            const current = await props.api.hubSessionStatus?.().catch(() => null);
            if (current?.linked) {
                setStatus("signed in");
                setTick((t) => t + 1);
                return;
            }
        }
    };
    const hubSignOut = async () => {
        await props.api.hubSessionSignOut?.();
        setTick((t) => t + 1);
    };
    // Codex OAuth (LLM-1, ADR 0062): presence + expiry in GaugeDesk's sealed
    // account store. `authUrl` holds the link as a manual
    // fallback if the popup is blocked.
    const [codex] = createResource(tick, soft(() => props.api.codexStatus()));
    const [authUrl, setAuthUrl] = createSignal("");
    const [deviceCode, setDeviceCode] = createSignal("");
    const codexExpiry = () => {
        const e = codex()?.expires;
        return e ? new Date(e).toLocaleDateString() : null;
    };
    // The sign-in finishes in an external tab and the credential lands server-side,
    // so after starting it we poll the status projection and update on our own —
    // the manual refresh link stays only as the fallback for a very slow flow.
    let disposed = false;
    onCleanup(() => {
        disposed = true;
    });
    let watchingLink = false;
    const linkCodex = async () => {
        setStatus("starting OpenAI sign-in…");
        setAuthUrl("");
        setDeviceCode("");
        // A re-sign-in starts with the old credential still linked, so completion
        // is "the expiry changed", not "a credential exists" — baseline it here.
        const baselineExpires = codex()?.expires ?? null;
        try {
            const login = await props.api.codexLoginStart();
            const url = login.mode === "browser" ? login.url : login.login.verificationUrl;
            setAuthUrl(url);
            if (login.mode === "device") setDeviceCode(login.login.userCode);
            window.open(url, "_blank", "noopener,noreferrer");
            setStatus(login.mode === "device"
                ? `enter code ${login.login.userCode} on the OpenAI page — this panel updates by itself`
                : "finish the OpenAI sign-in in your browser — this panel updates by itself");
        } catch (e) {
            setStatus(`could not start sign-in: ${e instanceof Error ? e.message : String(e)}`);
            return;
        }
        if (watchingLink) return; // a prior click's watcher is already at it
        watchingLink = true;
        try {
            const linked = await waitForCodexLink(() => props.api.codexStatus(), {
                baselineExpires,
                cancelled: () => disposed,
            });
            if (disposed) return;
            if (linked) {
                setAuthUrl("");
                setDeviceCode("");
                setStatus("signed in ✓");
                refresh();
            } else {
                setStatus("couldn't confirm the sign-in — finish it in the browser, then use refresh");
            }
        } finally {
            watchingLink = false;
        }
    };
    const cancelCodex = async () => {
        try {
            await props.api.codexLoginCancel();
            setAuthUrl("");
            setDeviceCode("");
            setStatus("OpenAI sign-in cancelled");
            refresh();
        } catch (e) {
            setStatus(`could not cancel sign-in: ${e instanceof Error ? e.message : String(e)}`);
        }
    };

    const [provider, setProvider] = createSignal("openai");
    const [token, setToken] = createSignal("");
    // The OpenAI-compatible endpoint, shown + required only for openai-generic (ADR 0083).
    const [endpoint, setEndpoint] = createSignal("");
    const needsEndpoint = () => providerTakesCustomModel(provider());

    const link = async () => {
        if (!token()) {
            setStatus("paste a token first");
            return;
        }
        if (needsEndpoint() && !endpoint().trim()) {
            setStatus("enter the endpoint URL first");
            return;
        }
        try {
            await props.api.accountLinkCredential(
                provider(),
                token(),
                needsEndpoint() ? endpoint().trim() : undefined,
            );
            setToken("");
            setEndpoint("");
            setStatus(`linked ${provider()} ✓`);
            refresh();
        } catch (e) {
            setStatus(`could not link: ${e instanceof Error ? e.message : String(e)}`);
        }
    };
    const unlink = async (p: string) => {
        try {
            await props.api.accountUnlinkCredential(p);
            setStatus(`unlinked ${p}`);
            refresh();
        } catch (e) {
            setStatus(`could not unlink: ${e instanceof Error ? e.message : String(e)}`);
        }
    };
    const revoke = async (id: string) => {
        try {
            await props.api.accountRevokeDevice(id);
            setStatus(`revoked ${id}`);
            refresh();
        } catch (e) {
            setStatus(`could not revoke: ${e instanceof Error ? e.message : String(e)}`);
        }
    };
    const acceptInvitation = async (invitation: AccountInvitation) => {
        try {
            const tenant = await props.api.acceptAccountInvitation(invitation.tenantId);
            setStatus(`joined ${tenant.displayName} ✓`);
            refresh();
        } catch (e) {
            setStatus(`could not accept invitation: ${e instanceof Error ? e.message : String(e)}`);
        }
    };
    const librarySync = () => (facilities() ?? []).find((facility) =>
        facility.kind === "library_sync" && facility.status === "active"
    );
    const enableLibrarySync = async () => {
        try {
            await props.api.accountAttachFacility({
                id: "library-sync",
                kind: "library_sync",
                displayName: "Library sync",
            });
            await props.api.accountPublishLibrarySync();
            setStatus("library sync enabled and published ✓");
            refresh();
        } catch (e) {
            setStatus(`could not enable library sync: ${e instanceof Error ? e.message : String(e)}`);
        }
    };
    const publishLibrarySync = async () => {
        try {
            await props.api.accountPublishLibrarySync();
            setStatus("account published to library sync ✓");
        } catch (e) {
            setStatus(`could not publish library sync: ${e instanceof Error ? e.message : String(e)}`);
        }
    };
    const pullLibrarySync = async () => {
        try {
            const result = await props.api.accountPullLibrarySync();
            setStatus(result.found
                ? `library sync merged ${result.merged} record${result.merged === 1 ? "" : "s"} ✓`
                : "library sync has no published account yet");
            refresh();
        } catch (e) {
            setStatus(`could not pull library sync: ${e instanceof Error ? e.message : String(e)}`);
        }
    };
    const disableLibrarySync = async () => {
        const facility = librarySync();
        if (!facility) return;
        try {
            await props.api.accountDetachFacility(facility.id);
            setStatus("library sync disabled");
            refresh();
        } catch (e) {
            setStatus(`could not disable library sync: ${e instanceof Error ? e.message : String(e)}`);
        }
    };

    const [managedPlan, setManagedPlan] = createSignal("");
    const [managedStatus, setManagedStatus] = createSignal<ManagedPlanStatus | "">("");
    const [managedIncluded, setManagedIncluded] = createSignal("");
    const saveManaged = async () => {
        const plan = managedPlan() || managed()?.plan?.plan || "managed";
        const state = managedStatus() || managed()?.plan?.status || "suspended";
        const included = Number(
            managedIncluded() || String(managed()?.plan?.included_tokens ?? 0),
        );
        try {
            await props.api.accountSetManagedInference({
                plan,
                status: state,
                included_tokens: Number.isFinite(included) ? Math.max(0, included) : 0,
            });
            setStatus(`managed plan ${state} ✓`);
            refresh();
        } catch (e) {
            setStatus(`could not update managed plan: ${e instanceof Error ? e.message : String(e)}`);
        }
    };

    const isLinked = (p: string) => (credentials() ?? []).some((c) => c.provider === p);

    // --- which models appear in the composer picker (LLM-1) ---------------------------
    // The catalog gives every model the linked accounts can run; this section lets the
    // operator choose which of them show in the per-chat picker. The choice persists in
    // the account-settings KV; absent → the default-visible subset (so the checklist is
    // pre-ticked with what the picker shows today).
    const [modelSettings, { refetch: refetchModelSettings }] = createResource(
        tick,
        soft(() => props.api.accountSettings()),
    );
    const linkedAccounts = () => {
        const ps = (credentials() ?? []).filter((c) => c.linked).map((c) => c.provider);
        if (codex()?.linked) ps.push("openai-codex");
        return ps;
    };
    const allModels = () => pickableModels(linkedAccounts());
    const effectiveEnabled = () =>
        parseEnabledModels(modelSettings()?.[ENABLED_MODELS_SETTING]) ?? defaultVisibleKeys(linkedAccounts());
    async function toggleModel(key: string, on: boolean) {
        const next = new Set(effectiveEnabled());
        if (on) next.add(key);
        else next.delete(key);
        try {
            await props.api.accountSetSetting(ENABLED_MODELS_SETTING, serializeEnabledModels(next));
            refetchModelSettings();
        } catch (e) {
            setStatus(`could not update models: ${e instanceof Error ? e.message : String(e)}`);
        }
    }

    // --- advancement (ATTN-3, ADR 0082 §4): what auto-keeps without review ------------
    // One comma-separated scopes field editing the single writes-within rule. Empty =
    // everything holds (fail-closed). The unwaivable guards (config touch, external
    // reads) live server-side and are stated, not configurable.
    const advancementScopes = () =>
        parseAdvancementScopes(modelSettings()?.[ADVANCEMENT_RULES_SETTING]).join(", ");
    const [scopesDraft, setScopesDraft] = createSignal<string | null>(null);
    async function saveAdvancementScopes() {
        const draft = scopesDraft();
        if (draft === null) return;
        const scopes = draft.split(",").map((s) => s.trim()).filter(Boolean);
        try {
            await props.api.accountSetSetting(
                ADVANCEMENT_RULES_SETTING,
                serializeAdvancementScopes(scopes),
            );
            setScopesDraft(null);
            refetchModelSettings();
            setStatus(scopes.length ? "auto-keep scopes saved" : "auto-keep off — everything holds for review");
        } catch (e) {
            setStatus(`could not update auto-keep — ${e instanceof Error ? e.message : String(e)}`);
        }
    }

    // --- attention (ATTN-2, ADR 0082 §3): when a chat should ask for you --------------
    // One row per signal, rendered from the shared schema; each change writes the
    // whole (shallow) rules doc back to the account-settings KV the server's
    // task-queue projection evaluates.
    const attention = () => parseAttentionRules(modelSettings()?.[ATTENTION_RULES_SETTING]);
    async function setAttention(signal: AttentionSignal, level: AttentionLevel) {
        const next = { ...attention(), [signal]: level };
        try {
            await props.api.accountSetSetting(ATTENTION_RULES_SETTING, serializeAttentionRules(next));
            refetchModelSettings();
        } catch (e) {
            setStatus(`could not update attention — ${e instanceof Error ? e.message : String(e)}`);
        }
    }

    return (
        <div class="modal-overlay" onClick={() => props.onClose()}>
            <div
                class="modal account-panel"
                data-account-panel
                onClick={(e) => e.stopPropagation()}
                onKeyDown={(e) => e.key === "Escape" && props.onClose()}
            >
                <div class="modal-head">
                    <h3>Your account</h3>
                    <button type="button" onClick={() => props.onClose()}>
                        close
                    </button>
                </div>

                <section class="admin-section" data-account-sign-in-method>
                    <h4>Sign-in</h4>
                    <p class="member-row">
                        <span>Signed in with <strong>{signInMethodLabel(signInMethod())}</strong>.</span>
                    </p>
                    <p class="muted">
                        This describes the current browser session. Additional sign-in methods and
                        recovery choices are managed only when their account controls are available.
                    </p>
                </section>

                <section class="admin-section" data-account-invitations>
                    <h4>Workspace invitations</h4>
                    <ul class="member-list">
                        <For
                            each={invitations()}
                            fallback={<li class="muted">No pending invitations.</li>}
                        >
                            {(invitation) => (
                                <li class="member-row" data-account-invitation={invitation.tenantId}>
                                    <span>
                                        <span class="member-id">{invitation.displayName}</span>
                                        <small class="muted">Invited as {invitation.role}</small>
                                    </span>
                                    <button
                                        type="button"
                                        class="tree-action"
                                        aria-label={`Accept invitation to ${invitation.displayName}`}
                                        onClick={() => void acceptInvitation(invitation)}
                                    >
                                        accept
                                    </button>
                                </li>
                            )}
                        </For>
                    </ul>
                </section>

                <Show when={hubSession()?.available}>
                    <section class="admin-section" data-hub-session>
                        <h4>GaugeWright account</h4>
                        <Show
                            when={hubSession()?.linked}
                            fallback={<>
                                <p class="muted">
                                    Sign in with Google to reach your projects, Homes, and
                                    invitations. This is separate from model access below.
                                </p>
                                <button
                                    type="button"
                                    class="tree-action"
                                    data-hub-session-signin
                                    onClick={() => void startHubSignIn()}
                                >
                                    Sign in with Google
                                </button>
                            </>}
                        >
                            <div
                                class="member-row"
                                data-hub-session-state={hubSession()?.expired ? "expired" : "linked"}
                            >
                                <span>
                                    {hubSession()?.person ?? "signed in"}
                                    {hubSession()?.expired ? " — session expired" : ""}
                                </span>
                                <Show when={!hubSession()?.expired}>
                                    <span class="badge">signed in</span>
                                </Show>
                                <button
                                    type="button"
                                    class="tree-action"
                                    data-hub-session-signout
                                    onClick={() => void hubSignOut()}
                                >
                                    Sign out
                                </button>
                            </div>
                        </Show>
                    </section>
                </Show>

                <Show
                    when={props.codexLoginAvailable ?? true}
                    fallback={<section class="admin-section" data-codex-oauth-unavailable>
                        <h4>OpenAI model access</h4>
                        <p class="muted">
                            GaugeWright account sign-in does not authorize OpenAI. Link an OpenAI
                            API key below, or enable OpenAI account sign-in for this runtime.
                        </p>
                    </section>}
                >
                    <section class="admin-section" data-codex-oauth>
                        <h4>OpenAI model access (codex)</h4>
                        <p class="muted">
                            Connect your OpenAI account so the agent can run on the codex
                            endpoint — the default. No API key needed. This authorizes model
                            access only; it is not a GaugeWright sign-in.
                        </p>
                        <div class="member-row" data-codex-status={codex()?.linked ? (codex()?.expired ? "expired" : "linked") : "none"}>
                            <span>
                                {codex()?.linked
                                    ? codex()?.expired
                                        ? `connected — expired${codexExpiry() ? ` (${codexExpiry()})` : ""}`
                                        : `connected${codexExpiry() ? ` — valid to ${codexExpiry()}` : ""}`
                                    : "not connected"}
                            </span>
                            <Show when={codex()?.linked && !codex()?.expired}>
                                <span class="badge">linked</span>
                            </Show>
                            <button type="button" class="tree-action" data-codex-signin onClick={linkCodex}>
                                {codex()?.linked ? "reconnect" : "Connect OpenAI account"}
                            </button>
                        </div>
                        <Show when={authUrl()}>
                            <p class="muted">
                                <Show when={deviceCode()}>
                                    Enter code <code data-codex-device-code>{deviceCode()}</code> at{" "}
                                </Show>
                                If the browser didn't open,{" "}
                                <a href={authUrl()} target="_blank" rel="noopener noreferrer">open the sign-in page</a>.
                                {" "}When done,{" "}
                                <button type="button" class="link-btn" data-codex-refresh onClick={refresh}>
                                    refresh
                                </button>
                                <Show when={deviceCode()}>
                                    {" or "}<button type="button" class="link-btn" data-codex-cancel onClick={cancelCodex}>
                                        cancel
                                    </button>
                                </Show>{" "}
                                to confirm.
                            </p>
                        </Show>
                    </section>
                </Show>

                {/* Linked LLM accounts */}
                <section class="admin-section">
                    <h4>Linked AI accounts</h4>
                    <p class="muted">
                        Link a provider so your agents use your account. The token is sealed —
                        it is never shown again.
                    </p>
                    <ul class="member-list">
                        <For
                            each={credentials()}
                            fallback={<li class="muted">No accounts linked yet.</li>}
                        >
                            {(c) => (
                                <li class="member-row" data-linked={c.provider}>
                                    <span class="member-id">{c.provider}</span>
                                    <span class="badge">linked</span>
                                    <button
                                        type="button"
                                        class="tree-action"
                                        onClick={() => unlink(c.provider)}
                                    >
                                        unlink
                                    </button>
                                </li>
                            )}
                        </For>
                    </ul>
                    <div class="admin-invite">
                        <select
                            data-account-provider
                            value={provider()}
                            onChange={(e) => setProvider(e.currentTarget.value)}
                        >
                            <For each={PROVIDERS}>
                                {(p) => (
                                    <option value={p}>
                                        {p}
                                        {isLinked(p) ? " (linked)" : ""}
                                    </option>
                                )}
                            </For>
                        </select>
                        <Show when={needsEndpoint()}>
                            <input
                                data-account-endpoint
                                type="url"
                                value={endpoint()}
                                onInput={(e) => setEndpoint(e.currentTarget.value)}
                                placeholder="endpoint URL (e.g. https://api.together.xyz/v1)"
                            />
                        </Show>
                        <input
                            data-account-token
                            type="password"
                            value={token()}
                            onInput={(e) => setToken(e.currentTarget.value)}
                            placeholder="paste API key / token"
                        />
                        <button type="button" class="tree-action" data-account-link onClick={link}>
                            link
                        </button>
                    </div>
                </section>

                <section class="admin-section" data-managed-inference>
                    <h4>Managed inference</h4>
                    <p class="muted">
                        Use GaugeDesk-managed model access instead of a linked key. Suspending the
                        plan blocks future managed calls only; prior chats and usage stay intact.
                    </p>
                    <p class="muted" data-managed-usage>
                        {managed()?.usage.runs ?? 0} runs · {managed()?.usage.total_tokens ?? 0} tokens
                        {managed()?.usage.overage_tokens
                            ? ` · ${managed()?.usage.overage_tokens} over included usage`
                            : ""}
                    </p>
                    <Show
                        when={managedInferenceWriteAvailable(props.managedInferenceEditable)}
                        fallback={
                            <p class="muted" data-managed-inference-read-only>
                                Managed plan changes are controlled by billing for this hosted account.
                            </p>
                        }
                    >
                        {/* Each control carries a visible label — a row of unlabeled
                            plan/status/number fields was a guessing game. */}
                        <div class="admin-invite managed-plan-row">
                            <label class="settings-field">
                                <span class="settings-label">plan</span>
                                <input
                                    value={managedPlan() || managed()?.plan?.plan || ""}
                                    onInput={(e) => setManagedPlan(e.currentTarget.value)}
                                    placeholder="plan"
                                />
                            </label>
                            <label class="settings-field">
                                <span class="settings-label">status</span>
                                <select
                                    value={managedStatus() || managed()?.plan?.status || "suspended"}
                                    onChange={(e) => setManagedStatus(e.currentTarget.value as ManagedPlanStatus)}
                                >
                                    <option value="active">active</option>
                                    <option value="suspended">suspended</option>
                                    <option value="lapsed">lapsed</option>
                                </select>
                            </label>
                            <label class="settings-field">
                                <span class="settings-label">included tokens</span>
                                <input
                                    type="number"
                                    min="0"
                                    value={managedIncluded() || String(managed()?.plan?.included_tokens ?? 0)}
                                    onInput={(e) => setManagedIncluded(e.currentTarget.value)}
                                />
                            </label>
                            <button type="button" class="tree-action" onClick={saveManaged}>
                                save managed plan
                            </button>
                        </div>
                    </Show>
                </section>

                {/* Which models show in the composer picker (LLM-1) */}
                <section class="admin-section" data-model-settings>
                    <h4>Models in the picker</h4>
                    <Show
                        when={linkedAccounts().length}
                        fallback={<p class="muted">Link an account above to choose its models.</p>}
                    >
                        <p class="muted">
                            Choose which of your linked accounts' models appear in the per-chat
                            picker. Unchecked models stay available — they're just hidden from the
                            dropdown.
                        </p>
                        <ul class="member-list model-checklist">
                            <For each={allModels()}>
                                {(m) => {
                                    const key = modelKey(m);
                                    return (
                                        <li class="model-check-row" data-model-toggle={key}>
                                            <label class="admin-check model-check">
                                                <input
                                                    type="checkbox"
                                                    checked={effectiveEnabled().has(key)}
                                                    onChange={(e) => void toggleModel(key, e.currentTarget.checked)}
                                                />
                                                <span>{m.label}</span>
                                            </label>
                                            <Show when={!m.primary}>
                                                <span class="badge" title="Available through this account, beyond its native model set">extra</span>
                                            </Show>
                                        </li>
                                    );
                                }}
                            </For>
                        </ul>
                    </Show>
                </section>

                {/* Attention (ATTN-2): when a chat should ask for you */}
                <section class="admin-section" data-attention-settings>
                    <h4>Attention</h4>
                    <p class="muted">
                        When a chat should ask for you. <strong>Task bar</strong> queues it
                        up top; <strong>chat dot</strong> only marks the chat in the tree;
                        <strong> quiet</strong> keeps it in the transcript.
                    </p>
                    <ul class="member-list">
                        <For each={ATTENTION_SIGNALS}>
                            {(m) => (
                                <li class="member-row" data-attention-signal={m.signal}>
                                    <span class="member-id" title={m.hint}>
                                        {m.label}
                                    </span>
                                    <select
                                        value={attention()[m.signal]}
                                        onChange={(e) =>
                                            void setAttention(
                                                m.signal,
                                                e.currentTarget.value as AttentionLevel,
                                            )
                                        }
                                    >
                                        <option value="queue">task bar</option>
                                        <option value="badge">chat dot only</option>
                                        <option value="mute">quiet</option>
                                    </select>
                                </li>
                            )}
                        </For>
                    </ul>
                </section>

                {/* Advancement (ATTN-3): what auto-keeps without review */}
                <section class="admin-section" data-advancement-settings>
                    <h4>Auto-keep</h4>
                    <p class="muted">
                        Keep a turn's work into the shared copy automatically when it{" "}
                        <em>only</em> touches these paths (comma-separated:{" "}
                        <code>docs/**</code>, <code>*.md</code>, or an exact path). Empty =
                        everything waits for your review. A change to the assistant's
                        permissions, or a turn that read someone else's content, always
                        waits — no scope can override that.
                    </p>
                    <div class="admin-invite">
                        <input
                            data-advancement-scopes
                            placeholder="e.g. docs/**, *.md"
                            value={scopesDraft() ?? advancementScopes()}
                            onInput={(e) => setScopesDraft(e.currentTarget.value)}
                            onKeyDown={(e) => e.key === "Enter" && void saveAdvancementScopes()}
                        />
                        <button
                            type="button"
                            class="tree-action"
                            disabled={scopesDraft() === null}
                            onClick={() => void saveAdvancementScopes()}
                        >
                            save
                        </button>
                    </div>
                </section>

                <Show when={props.librarySyncAvailable}>
                    <section class="admin-section" data-library-sync>
                        <h4>Library sync</h4>
                        <p class="muted">
                            Keep sealed account settings and opaque Home routes available when this
                            device is offline. GaugeWright's blind directory can route and store the
                            ciphertext, but cannot open it.
                        </p>
                        <Show
                            when={librarySync()}
                            fallback={<button
                                type="button"
                                class="tree-action"
                                data-library-sync-enable
                                onClick={() => void enableLibrarySync()}
                            >
                                enable and publish
                            </button>}
                        >
                            <div class="member-row">
                                <span><span class="badge">active</span></span>
                                <button type="button" class="tree-action" data-library-sync-publish onClick={() => void publishLibrarySync()}>
                                    publish now
                                </button>
                                <button type="button" class="tree-action" data-library-sync-pull onClick={() => void pullLibrarySync()}>
                                    pull now
                                </button>
                                <button type="button" class="tree-action" data-library-sync-disable onClick={() => void disableLibrarySync()}>
                                    disable
                                </button>
                            </div>
                        </Show>
                    </section>
                </Show>

                {/* Trusted devices */}
                <section class="admin-section">
                    <h4>Trusted devices</h4>
                    <ul class="member-list">
                        <For
                            each={devices()}
                            fallback={<li class="muted">No devices enrolled yet.</li>}
                        >
                            {(d) => (
                                <li class="member-row" data-device={d.id}>
                                    <span>
                                        <span class="member-id">{d.label || d.id}</span>
                                        <small class="muted">{deviceAddedLabel(d.enrolledAt)}</small>
                                    </span>
                                    <span class="member-status">{d.status}</span>
                                    <Show when={d.status === "active"}>
                                        <button
                                            type="button"
                                            class="tree-action"
                                            onClick={() => revoke(d.id)}
                                        >
                                            revoke
                                        </button>
                                    </Show>
                                </li>
                            )}
                        </For>
                    </ul>
                </section>

                <p class="status" data-account-status>
                    {status()}
                </p>
            </div>
        </div>
    );
}
