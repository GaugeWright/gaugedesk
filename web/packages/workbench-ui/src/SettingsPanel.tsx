/**
 * **Settings** over the live control plane: the container that projects `/account/*`
 * into the {@link SettingsModel} {@link SettingsSurface} renders, and turns the
 * surface's intents back into route calls.
 *
 * It replaces `AccountPanel`, which mixed both jobs — eleven sections of markup
 * interleaved with the reads and writes behind them — in one 882-line component. The
 * split is the point: the surface can be driven from a bench and looked at, and this
 * file can be read for what the account actually supports without scrolling past
 * layout.
 *
 * Only what the control plane really has is projected. Where a room would otherwise
 * describe something that does not exist — a per-credential name the store has no
 * column for, a way to give up an OAuth account the routes never offered — the model
 * says so rather than the surface offering a control that silently fails.
 */

import { createMemo, createResource, createSignal, onCleanup, type JSX } from "solid-js";
import type {
    AccountDevice,
    AccountSignInMethod,
    FederationPeer,
    ManagedInferencePlan,
} from "@gaugewright/control-plane-client";
import {
    ADVANCEMENT_RULES_SETTING,
    parseAdvancementScopes,
    serializeAdvancementScopes,
} from "./advancement";
import {
    ATTENTION_RULES_SETTING,
    parseAttentionRules,
    serializeAttentionRules,
    type AttentionLevel,
    type AttentionSignal,
} from "./attention";
import { waitForCodexLink } from "./codex-link-poll";
import {
    catalogWithEndpointModels,
    defaultVisibleKeys,
    ENABLED_MODELS_SETTING,
    ENDPOINT_MODELS_SETTING,
    modelKey,
    parseEnabledModels,
    parseEndpointModels,
    pickableModels,
    serializeEnabledModels,
    serializeEndpointModels,
} from "./model-picker";
import type { AccountPanelApi } from "./account-api";
import { SettingsSurface, type SettingsModel, type SettingsRoom } from "./SettingsSurface";

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

/** How long before a credential's expiry counts as "soon". A week is long enough to
 *  renew at a convenient moment and short enough that the warning still means today's
 *  work is at risk — the surface only decides how to say it, not when. */
const EXPIRES_SOON_MS = 7 * 24 * 60 * 60 * 1000;

export function expiresSoon(expires: number | null | undefined, now = Date.now()): boolean {
    if (!expires) return false;
    const at = expires * 1000;
    return Number.isFinite(at) && at > now && at - now <= EXPIRES_SOON_MS;
}

/** What can be added, and how each one is authorized. A provider is a *kind* of
 *  credential, so this list never shrinks as credentials are added to it. */
const PROVIDERS: SettingsModel["models"]["providers"] = [
    {
        pin: "openai-codex",
        label: "OpenAI (Codex)",
        auth: "account",
        // That Anthropic serves Claude is the definition; that Codex also serves the
        // regular OpenAI catalog is the fact a reader cannot infer from the name.
        note: "also serves the OpenAI catalog",
    },
    { pin: "openai", label: "OpenAI", auth: "key" },
    { pin: "anthropic", label: "Anthropic", auth: "key" },
    { pin: "openai-generic", label: "OpenAI-compatible endpoint", auth: "endpoint" },
];

const PROVIDER_LABEL = new Map(PROVIDERS.map((p) => [p.pin, p.label]));

export interface SettingsPanelApi extends AccountPanelApi {
    /** The separate authorities admitted to work here (FED-1). Their pairing is a
     *  handshake of its own; Settings lists the standing result. */
    listPeers(): Promise<FederationPeer[]>;
    revokePeer(authority: string): Promise<void>;
}

export interface SettingsPanelProps {
    readonly api: SettingsPanelApi;
    /** Whether this runtime can complete the OpenAI authorization flow. */
    readonly codexLoginAvailable?: boolean;
    /** Hosted billing owns managed-plan writes; those compositions project the plan
     *  and usage but must not offer the local editor. */
    readonly managedInferenceEditable?: boolean;
    /** Library sync needs the sovereign root key the co-resident desktop holds. */
    readonly librarySyncAvailable?: boolean;
    /** Where the account and its organizations are actually administered. Absent →
     *  the room does not point at a Hub this composition cannot reach. */
    readonly hubUrl?: string;
    /** `desk` is a browser thin client and deliberately not an account surface
     *  (ADR 0130/0131): it offers the other three rooms and claims no account. */
    readonly accountAvailable?: boolean;
    /** The two device flows are multi-step handshakes with a surface of their own;
     *  Settings lists what they produced and hands off to start a new one. */
    readonly onEnrollDevice: () => void;
    readonly onPairParty: () => void;
    readonly onClose: () => void;
    /** Which room to land in. Whoever opened Settings usually knows what for — an
     *  in-chat "no model attached" refusal means Model access, not the first tab. */
    readonly initialRoom?: SettingsRoom;
}

export function SettingsPanel(props: SettingsPanelProps): JSX.Element {
    const [room, setRoom] = createSignal<SettingsRoom>(props.initialRoom ?? "account");
    const [tick, setTick] = createSignal(0);
    const refresh = () => setTick((t) => t + 1);
    const [status, setStatus] = createSignal("");

    // Projection reads settle to undefined on failure instead of erroring the resource:
    // reading an errored resource throws mid-render (the Devices crash class,
    // 2026-07-31), and a control plane need not serve every account facade.
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
    const [peers] = createResource(tick, soft(() => props.api.listPeers()));
    const [codex] = createResource(tick, soft(() => props.api.codexStatus()));
    const [settings, { refetch: refetchSettings }] = createResource(
        tick,
        soft(() => props.api.accountSettings()),
    );
    const [hubSession] = createResource(
        tick,
        soft(() => props.api.hubSessionStatus?.() ?? Promise.resolve(null)),
    );

    let disposed = false;
    onCleanup(() => {
        disposed = true;
    });

    /** Run a write, report it, and re-read. One wrapper so no action can quietly
     *  swallow its own failure — the pre-split panel repeated this at every call and
     *  the surface has one place to show the result. */
    const act = async (describe: string, run: () => Promise<string | void>) => {
        try {
            const said = await run();
            if (disposed) return;
            setStatus(said || `${describe} ✓`);
            refresh();
        } catch (e) {
            if (disposed) return;
            setStatus(`could not ${describe} — ${e instanceof Error ? e.message : String(e)}`);
        }
    };

    /** A write whose result the room already shows — the ticked box, the moved segment.
     *  Narrating it would only put a line under a control that already changed; a
     *  failure still has to be said, because there the control snapped back. */
    const quietly = async (describe: string, run: () => Promise<void>) => {
        try {
            await run();
            if (!disposed) setStatus("");
        } catch (e) {
            if (disposed) return;
            setStatus(`could not ${describe} — ${e instanceof Error ? e.message : String(e)}`);
        }
    };

    // --- model access -------------------------------------------------------------
    const endpointModels = () => parseEndpointModels(settings()?.[ENDPOINT_MODELS_SETTING]);
    const catalog = createMemo(() => catalogWithEndpointModels(endpointModels()));
    const linkedAccounts = createMemo(() => {
        const pins = (credentials() ?? []).filter((c) => c.linked).map((c) => c.provider);
        if (codex()?.linked) pins.push("openai-codex");
        return pins;
    });

    // A sign-in opened in the browser and not yet finished. It belongs to the flow
    // rather than to a credential — the credential does not exist until it completes.
    const [pendingSignIn, setPendingSignIn] = createSignal<SettingsModel["models"]["signIn"]>();
    let watchingLink = false;
    const startCodexSignIn = async () => {
        setStatus("");
        // A re-sign-in starts with the old credential still linked, so completion is
        // "the expiry changed", not "a credential exists" — baseline it here.
        const baselineExpires = codex()?.expires ?? null;
        try {
            const login = await props.api.codexLoginStart();
            const url = login.mode === "browser" ? login.url : login.login.verificationUrl;
            setPendingSignIn({
                pin: "openai-codex",
                label: PROVIDER_LABEL.get("openai-codex") ?? "OpenAI (Codex)",
                mode: login.mode,
                code: login.mode === "device" ? login.login.userCode : undefined,
                url,
            });
            window.open(url, "_blank", "noopener,noreferrer");
        } catch (e) {
            setStatus(`could not start sign-in — ${e instanceof Error ? e.message : String(e)}`);
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
            setPendingSignIn(undefined);
            setStatus(linked ? "signed in ✓" : "couldn't confirm the sign-in — finish it in the browser");
            refresh();
        } finally {
            watchingLink = false;
        }
    };

    const codexCredential = (): SettingsModel["models"]["credentials"][number] | null => {
        const cx = codex();
        if (!cx?.linked) return null;
        const on = cx.expires ? new Date(cx.expires * 1000).toLocaleDateString() : null;
        return {
            id: "openai-codex",
            pin: "openai-codex",
            status: cx.expired ? "expired" : "connected",
            expiresSoon: !cx.expired && expiresSoon(cx.expires),
            detail: on ? (cx.expired ? `expired ${on}` : `valid to ${on}`) : undefined,
            // The routes can start this sign-in but never end it: there is no unlink for
            // the OAuth credential, so the row does not offer one that would 404.
            removable: false,
        };
    };

    const modelCredentials = createMemo<SettingsModel["models"]["credentials"]>(() => {
        const rows: SettingsModel["models"]["credentials"][number][] = [];
        const cx = codexCredential();
        if (cx) rows.push(cx);
        for (const c of credentials() ?? []) {
            if (!c.linked) continue;
            rows.push({
                // The store keys a credential by its provider — one per provider, no name
                // and no second key. That is why the id *is* the pin here.
                id: c.provider,
                pin: c.provider,
                status: "connected",
                models: c.provider === "openai-generic" ? endpointModels() : undefined,
                removable: true,
            });
        }
        return rows;
    });

    const enabledModels = () =>
        parseEnabledModels(settings()?.[ENABLED_MODELS_SETTING]) ?? defaultVisibleKeys(linkedAccounts(), catalog());
    const picker = createMemo<SettingsModel["models"]["picker"]>(() => {
        const all = pickableModels(linkedAccounts(), catalog());
        // Which credentials could each model name be served by. Two accounts reaching the
        // same model is the question the old flat checklist could not answer.
        const providersByName = new Map<string, Set<string>>();
        for (const m of all) {
            if (!providersByName.has(m.name)) providersByName.set(m.name, new Set());
            providersByName.get(m.name)!.add(m.provider);
        }
        const enabled = enabledModels();
        return all.map((m) => ({
            key: modelKey(m),
            label: m.label,
            runsOn: PROVIDER_LABEL.get(m.provider) ?? m.provider,
            alsoVia: [...(providersByName.get(m.name) ?? [])]
                .filter((p) => p !== m.provider)
                .map((p) => PROVIDER_LABEL.get(p) ?? p),
            primary: m.primary,
            enabled: enabled.has(modelKey(m)),
        }));
    });

    const writeEndpointModels = (ids: readonly string[]) =>
        props.api.accountSetSetting(ENDPOINT_MODELS_SETTING, serializeEndpointModels(ids));

    // --- devices ------------------------------------------------------------------
    const librarySyncFacility = () =>
        (facilities() ?? []).find((f) => f.kind === "library_sync" && f.status === "active");

    const model = createMemo<SettingsModel>(() => ({
        status: status(),
        account: {
            signInMethod: signInMethodLabel(signInMethod()),
            hub: {
                available: Boolean(hubSession()?.available),
                linked: Boolean(hubSession()?.linked),
                person: hubSession()?.person ?? undefined,
                expired: Boolean(hubSession()?.expired),
            },
            invitations: (invitations() ?? []).map((i) => ({
                tenantId: i.tenantId,
                displayName: i.displayName,
                role: i.role,
            })),
        },
        models: {
            // A runtime that cannot complete the OAuth flow does not list the provider
            // that only exists through it.
            providers: PROVIDERS.filter((p) => p.pin !== "openai-codex" || (props.codexLoginAvailable ?? true)),
            credentials: modelCredentials(),
            signIn: pendingSignIn(),
            accountSignInAvailable: props.codexLoginAvailable ?? true,
            managed: managedModel(),
            picker: picker(),
        },
        devices: {
            devices: (devices() ?? []).map((d: AccountDevice) => ({
                id: d.id,
                label: d.label || d.id,
                added: deviceAddedLabel(d.enrolledAt),
                status: d.status,
            })),
            peers: (peers() ?? []).map((p) => ({
                id: p.authority,
                authority: p.authority,
                status: p.active ? "active" : "revoked",
            })),
            librarySync: props.librarySyncAvailable ? Boolean(librarySyncFacility()) : null,
        },
        behaviour: {
            attention: parseAttentionRules(settings()?.[ATTENTION_RULES_SETTING]),
            autoKeep: parseAdvancementScopes(settings()?.[ADVANCEMENT_RULES_SETTING]),
        },
    }));

    function managedModel(): SettingsModel["models"]["managed"] {
        const billing = managed();
        const editable = managedInferenceWriteAvailable(props.managedInferenceEditable);
        // Nothing to show and nothing to set up: this composition has no managed
        // inference, so the room says nothing about it.
        if (!billing || (!billing.plan && !editable)) return null;
        return {
            plan: billing.plan?.plan ?? null,
            state: billing.plan?.status ?? "suspended",
            includedTokens: billing.plan?.included_tokens ?? 0,
            runs: billing.usage.runs,
            tokens: billing.usage.total_tokens,
            overage: billing.usage.overage_tokens,
            editable,
        };
    }

    return (
        <SettingsSurface
            model={model()}
            room={room()}
            onRoom={setRoom}
            onClose={() => props.onClose()}
            accountAvailable={props.accountAvailable ?? true}
            actions={{
                hubSignIn: () => void startHubSignIn(),
                hubSignOut: () => void act("sign out", async () => {
                    await props.api.hubSessionSignOut?.();
                    return "signed out";
                }),
                acceptInvitation: (tenantId) => void act("accept the invitation", async () => {
                    const tenant = await props.api.acceptAccountInvitation(tenantId);
                    return `joined ${tenant.displayName} ✓`;
                }),
                openHub: props.hubUrl
                    ? () => window.open(props.hubUrl!, "_blank", "noopener,noreferrer")
                    : undefined,

                signInToProvider: () => void startCodexSignIn(),
                cancelSignIn: () => {
                    // Both modes leave the server holding something: a device login it is
                    // polling for, or a browser helper sitting on the fixed loopback
                    // callback port. Dropping only our own waiting state left that port
                    // held, and the next sign-in failed on it.
                    setPendingSignIn(undefined);
                    void act("cancel the sign-in", async () => {
                        await props.api.codexLoginCancel();
                        return "sign-in cancelled";
                    });
                },
                linkKey: ({ pin, token, endpoint }) => void act(`link ${pin}`, async () => {
                    if (!token) throw new Error("paste a token first");
                    if (pin === "openai-generic" && !endpoint?.trim()) {
                        throw new Error("enter the endpoint URL first");
                    }
                    await props.api.accountLinkCredential(pin, token, endpoint?.trim() || undefined);
                }),
                removeCredential: (id) => void act(`remove ${id}`, () => props.api.accountUnlinkCredential(id)),
                addEndpointModel: (_credentialId, modelId) => void act("add the model", async () => {
                    await writeEndpointModels([...endpointModels(), modelId]);
                    await refetchSettings();
                    return `added ${modelId} ✓`;
                }),
                removeEndpointModel: (_credentialId, modelId) => void act("remove the model", async () => {
                    await writeEndpointModels(endpointModels().filter((id) => id !== modelId));
                    await refetchSettings();
                    return `removed ${modelId}`;
                }),
                toggleModel: (key, on) => void quietly("update the picker", async () => {
                    const next = new Set(enabledModels());
                    if (on) next.add(key);
                    else next.delete(key);
                    await props.api.accountSetSetting(ENABLED_MODELS_SETTING, serializeEnabledModels(next));
                    await refetchSettings();
                }),
                setManagedPlan: ({ plan, state, includedTokens }) => void act("update the plan", async () => {
                    const next: ManagedInferencePlan = {
                        plan,
                        status: state,
                        included_tokens: includedTokens,
                    };
                    await props.api.accountSetManagedInference(next);
                    return `managed plan ${state} ✓`;
                }),

                enrollDevice: () => props.onEnrollDevice(),
                pairParty: () => props.onPairParty(),
                revokeDevice: (id) => void act(`revoke ${id}`, () => props.api.accountRevokeDevice(id)),
                disconnectParty: (authority) => void act(`disconnect ${authority}`, () => props.api.revokePeer(authority)),
                setLibrarySync: (on) => void act(on ? "turn on library sync" : "turn off library sync", async () => {
                    if (!on) {
                        const facility = librarySyncFacility();
                        if (facility) await props.api.accountDetachFacility(facility.id);
                        return "library sync off";
                    }
                    await props.api.accountAttachFacility({
                        id: "library-sync",
                        kind: "library_sync",
                        displayName: "Library sync",
                    });
                    await props.api.accountPublishLibrarySync();
                    return "library sync on, and published ✓";
                }),
                publishLibrary: () => void act("publish", async () => {
                    await props.api.accountPublishLibrarySync();
                    return "published ✓";
                }),
                pullLibrary: () => void act("pull", async () => {
                    const result = await props.api.accountPullLibrarySync();
                    return result.found
                        ? `merged ${result.merged} record${result.merged === 1 ? "" : "s"} ✓`
                        : "nothing published to pull yet";
                }),

                setAttention: (signal: AttentionSignal, level: AttentionLevel) =>
                    void quietly("update attention", async () => {
                        const next = { ...parseAttentionRules(settings()?.[ATTENTION_RULES_SETTING]), [signal]: level };
                        await props.api.accountSetSetting(ATTENTION_RULES_SETTING, serializeAttentionRules(next));
                        await refetchSettings();
                    }),
                addAutoKeep: (glob) => void act("add the scope", async () => {
                    await writeAutoKeep([...autoKeep(), glob]);
                    return `auto-keep covers ${glob}`;
                }),
                removeAutoKeep: (glob) => void act("remove the scope", async () => {
                    const next = autoKeep().filter((g) => g !== glob);
                    await writeAutoKeep(next);
                    return next.length ? `auto-keep no longer covers ${glob}` : "auto-keep off — everything holds for review";
                }),
            }}
        />
    );

    function autoKeep(): string[] {
        return parseAdvancementScopes(settings()?.[ADVANCEMENT_RULES_SETTING]);
    }
    async function writeAutoKeep(scopes: readonly string[]): Promise<void> {
        await props.api.accountSetSetting(ADVANCEMENT_RULES_SETTING, serializeAdvancementScopes(scopes));
        await refetchSettings();
    }

    async function startHubSignIn(): Promise<void> {
        const started = await props.api.hubSessionStart?.().catch(() => null);
        if (!started) {
            setStatus("could not start sign-in");
            return;
        }
        window.open(started.url, "_blank", "noopener,noreferrer");
        setStatus("finish signing in in your browser — this panel updates by itself");
        // The deep-linked return lands in the control plane; poll until the session
        // appears (bounded — the person may abandon the tab).
        for (let attempt = 0; attempt < 60 && !disposed; attempt += 1) {
            await new Promise((resolve) => setTimeout(resolve, 2000));
            const current = await props.api.hubSessionStatus?.().catch(() => null);
            if (current?.linked) {
                setStatus("signed in ✓");
                refresh();
                return;
            }
        }
    }
}
