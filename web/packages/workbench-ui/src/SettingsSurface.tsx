/**
 * The **Settings** surface behind the account menu — the room the menu is a door to.
 *
 * It replaces a single 882-line modal that carried eleven sections in one scroll
 * across four unrelated concerns, with devices listed both inside it and beside it
 * in a second modal of its own. The material is the same; what changes is that a
 * reader looking for "which models can agents run" no longer scrolls past workspace
 * invitations and auto-keep path globs to find it.
 *
 * The rooms are the concerns, not the screens they came from:
 *
 *   Account       who you are, and what you have been invited to
 *   Model access  which models agents may run, and whose credentials pay
 *   Devices       what can reach your work: this computer, your phones, other parties
 *   Behaviour     when a chat asks for you, and what it keeps without asking
 *
 * Presentational: every value arrives as {@link SettingsModel} and every mutation
 * leaves through {@link SettingsActions}, so the surface can be driven by the
 * prototype bench and by the real control-plane client without changing.
 */
import { For, Show, createSignal, type JSX } from "solid-js";
// The attention vocabulary already exists and is shared with the reducer that
// consumes it; re-declaring it here would let the surface and the engine drift.
import {
    ATTENTION_SIGNALS,
    type AttentionLevel,
    type AttentionSignal,
} from "./attention";

export type SettingsRoom = "account" | "models" | "devices" | "behaviour";

/** The managed plan's lifecycle, restated rather than imported: this surface takes a
 *  model and returns intents, and knows nothing of the control-plane client. */
export type ManagedPlanState = "active" | "suspended" | "lapsed";

export interface SettingsModel {
    /** The last operation's outcome, in the operator's words. One line for the whole
     *  surface: a failed write must be visible from wherever it was started. */
    readonly status?: string;
    readonly account: {
        /** How this session authenticated — descriptive, not a control. */
        readonly signInMethod: string;
        readonly hub: {
            readonly available: boolean;
            readonly linked: boolean;
            readonly person?: string;
            readonly expired?: boolean;
            /** A sign-in started and not yet returned (LOGIN-7). `url` is the Hub
             *  login page; `opened` is whether the runtime managed to open a
             *  browser at it — when it could not, the row leads with the link
             *  instead of claiming a browser that never appeared. */
            readonly pending?: {
                readonly url: string;
                readonly opened: boolean;
            } | null;
        };
        readonly invitations: readonly {
            readonly tenantId: string;
            readonly displayName: string;
            readonly role: string;
        }[];
    };
    readonly models: {
        /** What you can add. A provider is a *kind* of credential, not a thing you have
         *  one of, so it never leaves this list when you add one. */
        readonly providers: readonly {
            readonly pin: string;
            readonly label: string;
            /** How adding it works: signed into through the browser, a pasted key, or a
             *  user-configured endpoint. The add form follows this. */
            readonly auth: "account" | "key" | "endpoint";
            /** Whether its model ids are the operator's to declare (no shipped
             *  catalog). The add form then asks for the first one with the
             *  credential, because a credential with no model reaches nothing —
             *  the picker stayed empty after linking an endpoint until the
             *  operator found the "add models" expander on their own. */
            readonly declaresModels?: boolean;
            /** Only what the reader cannot infer. "Anthropic serves the Claude catalog"
             *  is the definition, not a fact; Codex *also* serving the OpenAI catalog is. */
            readonly note?: string;
        }[];
        /** What you have. A list rather than a flag per provider, so the day the store can
         *  key a credential by something other than its provider — two OpenAI keys with
         *  different limits, a personal and a work Codex account — this surface only needs
         *  a way to tell them apart, not a new shape. Today it holds one per provider. */
        readonly credentials: readonly {
            readonly id: string;
            readonly pin: string;
            readonly status: "connected" | "expired";
            /** Still valid, but close enough to expiry that renewing now beats being
             *  interrupted later. The host owns the threshold — it knows the refresh
             *  window; the surface only decides how to say it. */
            readonly expiresSoon?: boolean;
            /** Expiry, endpoint URL — whatever this kind of credential has to report. */
            readonly detail?: string;
            /** Model ids registered for an endpoint credential. GaugeDesk cannot
             *  enumerate an arbitrary OpenAI-compatible endpoint, so the ids are the
             *  operator's to declare. */
            readonly models?: readonly string[];
            /** Whether this credential can be given up from here. An OAuth account
             *  GaugeDesk can start but not end is stated as permanent rather than
             *  offered a button that would fail. */
            readonly removable: boolean;
        }[];
        /** A sign-in opened in the browser and not yet finished. It belongs to the flow,
         *  not to a credential — the credential does not exist until it completes. */
        readonly signIn?: {
            readonly pin: string;
            readonly label: string;
            readonly mode: "browser" | "device";
            readonly code?: string;
            readonly url?: string;
        };
        readonly accountSignInAvailable: boolean;
        /** Null where this composition has no managed inference at all. A plan of `null`
         *  inside a present object is different: managed inference exists here and none is
         *  set up yet, which only an operator who can edit it needs to see. */
        readonly managed: {
            readonly plan: string | null;
            readonly state: ManagedPlanState;
            readonly includedTokens: number;
            readonly runs: number;
            readonly tokens: number;
            readonly overage: number;
            /** Hosted billing owns the plan; those compositions show it and don't offer
             *  a local editor that would write against the wrong authority. */
            readonly editable: boolean;
        } | null;
        readonly picker: readonly {
            readonly key: string;
            readonly label: string;
            /** The credential that will actually run it. */
            readonly runsOn: string;
            /** Other credentials that could serve the same model but do not win. */
            readonly alsoVia: readonly string[];
            readonly primary: boolean;
            readonly enabled: boolean;
        }[];
    };
    readonly devices: {
        /** Your own phones and tablets: a device subkey under the *same* authority,
         *  fully trusted. Enrolled by a `machine-enroll` link or QR. */
        readonly devices: readonly {
            readonly id: string;
            readonly label: string;
            readonly added: string;
            readonly status: string;
        }[];
        /** A *different* authority's machine, admission-gated, paired by ticket
         *  exchange. A separate trust act — never the same link as a device. */
        readonly peers: readonly {
            readonly id: string;
            readonly authority: string;
            readonly status: string;
        }[];
        /** Null where this composition holds no root key to seal a library with, so the
         *  section is absent rather than a switch that cannot be thrown. */
        readonly librarySync: boolean | null;
    };
    readonly behaviour: {
        /** Only the levels. The signals themselves — which exist, what they are called,
         *  and what each defaults to — come from {@link ATTENTION_SIGNALS}, which mirrors
         *  the server evaluator. A surface that takes the list from its caller can render
         *  signals the evaluator has never heard of, which is exactly what happened while
         *  prototyping this room. Absent means the shipped default. */
        readonly attention: Readonly<Partial<Record<AttentionSignal, AttentionLevel>>>;
        /** Path globs, as a set rather than one comma-separated string: they are added
         *  and removed individually, and a free-text field makes a typo in one entry
         *  silently rewrite the rest. */
        readonly autoKeep: readonly string[];
    };
}

export interface SettingsActions {
    readonly hubSignIn?: () => void;
    /** The manual return (LOGIN-7): the pasted `gaugewright://auth/callback…`
     *  link — or its bare code — from a browser whose OS never routed the
     *  scheme back to the app. */
    readonly hubFinishSignIn?: (pasted: string) => void;
    /** Put the pending sign-in away without finishing it. The Hub-held
     *  verifier simply expires; nothing needs cancelling server-side. */
    readonly hubDismissSignIn?: () => void;
    readonly hubSignOut?: () => void;
    readonly acceptInvitation?: (tenantId: string) => void;
    readonly linkKey?: (input: { pin: string; token: string; endpoint?: string; model?: string }) => void;
    readonly addEndpointModel?: (credentialId: string, modelId: string) => void;
    readonly removeEndpointModel?: (credentialId: string, modelId: string) => void;
    readonly signInToProvider?: (pin: string) => void;
    readonly cancelSignIn?: () => void;
    readonly removeCredential?: (credentialId: string) => void;
    readonly openHub?: () => void;
    readonly enrollDevice?: () => void;
    readonly pairParty?: () => void;
    readonly disconnectParty?: (peerId: string) => void;
    readonly toggleModel?: (key: string, on: boolean) => void;
    readonly setManagedPlan?: (plan: { plan: string; state: ManagedPlanState; includedTokens: number }) => void;
    readonly revokeDevice?: (id: string) => void;
    readonly setLibrarySync?: (on: boolean) => void;
    readonly publishLibrary?: () => void;
    readonly pullLibrary?: () => void;
    readonly setAttention?: (signal: AttentionSignal, level: AttentionLevel) => void;
    readonly addAutoKeep?: (glob: string) => void;
    readonly removeAutoKeep?: (glob: string) => void;
}

/** The three places a raised signal can surface, most insistent first. */
const LEVEL_CHOICES: readonly { level: AttentionLevel; label: string; hint: string }[] = [
    { level: "queue", label: "Task bar", hint: "Queued up top as a task waiting on you." },
    { level: "badge", label: "Chat dot", hint: "Marked in the tree only; nothing is queued." },
    { level: "mute", label: "Quiet", hint: "Left in the transcript; nothing announces it." },
];

const ROOMS: { readonly id: SettingsRoom; readonly label: string }[] = [
    { id: "account", label: "Account" },
    { id: "models", label: "Model access" },
    { id: "devices", label: "Devices" },
    { id: "behaviour", label: "Behaviour" },
];

export interface SettingsSurfaceProps {
    readonly model: SettingsModel;
    readonly actions?: SettingsActions;
    readonly room: SettingsRoom;
    readonly onRoom: (room: SettingsRoom) => void;
    readonly onClose: () => void;
    /** `desk` holds no account (ADR 0130/0131): the Account room is not offered. */
    readonly accountAvailable?: boolean;
}

export function SettingsSurface(props: SettingsSurfaceProps): JSX.Element {
    // The form's default must be a provider the form can actually link. Defaulting to
    // the first account of any kind selected Codex, which is signed into rather than
    // pasted and is therefore not an option here — leaving the select rendering blank.
    // The list shows accounts you have. Everything you could add is behind one door,
    // whatever way it authenticates — a reader should not have to know in advance that
    // one provider is signed into and another is pasted.
    const chosen = () => props.model.models.providers.find((p) => p.pin === provider());
    const [provider, setProvider] = createSignal("");
    const [token, setToken] = createSignal("");
    const [endpoint, setEndpoint] = createSignal("");
    // The first model id for a provider that declares its own (the add form).
    const [firstModel, setFirstModel] = createSignal("");
    const [newModel, setNewModel] = createSignal("");
    const [openCredential, setOpenCredential] = createSignal<string | null>(null);
    const [adding, setAdding] = createSignal(false);
    // The managed-plan editor's drafts. `null` = untouched, so a field the operator has
    // not typed in follows the server's value as it refreshes instead of pinning the
    // value that happened to be there when the room opened.
    const [planDraft, setPlanDraft] = createSignal<string | null>(null);
    const [stateDraft, setStateDraft] = createSignal<ManagedPlanState | null>(null);
    const [includedDraft, setIncludedDraft] = createSignal<string | null>(null);
    // At most one sign-in is in flight, and only device mode has anything to show.
    const deviceSignIn = () => {
        const flow = props.model.models.signIn;
        return flow?.mode === "device" && flow.code ? flow : null;
    };
    // The manual sign-in return (LOGIN-7): what the person pasted back from the
    // browser. Cleared when it is handed off, not when it fails to parse — a
    // near-miss paste should stay visible to be corrected.
    const [returnPaste, setReturnPaste] = createSignal("");
    const [autoKeep, setAutoKeep] = createSignal<string | null>(null);
    // `serializeAdvancementScopes` strips `**` — accepting it here would show a chip the
    // stored document never contains.
    const addableGlob = () => {
        const value = autoKeep()?.trim();
        return value && value !== "**" ? value : null;
    };

    const rooms = () => ROOMS.filter((r) => r.id !== "account" || (props.accountAvailable ?? true));
    const current = () => rooms().find((r) => r.id === props.room) ?? rooms()[0]!;

    return (
        <>
        {/* Device mode asks the reader to carry a code to another screen. That is a
            task with a beginning and an end, so it gets a prompt that can be finished
            and dismissed — not a permanent line in the accounts list. */}
        <Show when={deviceSignIn()}>
            {/* Every way out a modal normally has: the overlay, Escape, and the explicit
                control. A prompt that can only be dismissed by finishing the flow it
                describes traps anyone who started it by accident. */}
            {(pending) => (
                <div class="modal-overlay device-overlay" onClick={() => props.actions?.cancelSignIn?.()}>
                    <div
                        class="modal device-modal"
                        data-device-signin
                        tabindex="-1"
                        ref={(el) => queueMicrotask(() => el.focus())}
                        onClick={(e) => e.stopPropagation()}
                        onKeyDown={(e) => e.key === "Escape" && props.actions?.cancelSignIn?.()}
                    >
                        <div class="modal-head">
                            <h3>Finish signing in</h3>
                            {/* Named, because a journey that drives this flow has to
                                address the code and the way out of it, and matching a
                                class or the word "cancel" is how the last set of
                                selectors here quietly stopped matching anything. */}
                            <button type="button" data-device-cancel
                                onClick={() => props.actions?.cancelSignIn?.()}>cancel</button>
                        </div>
                        <p class="muted">Enter this code on the page that opened in your browser.</p>
                        <p class="settings-device-code" data-device-code>{pending().code}</p>
                        <Show when={pending().url}>
                            {(url) => <p class="muted device-url">{url()}</p>}
                        </Show>
                        <p class="muted">This panel updates by itself when you are done.</p>
                    </div>
                </div>
            )}
        </Show>
        <div class="modal-overlay" onClick={() => props.onClose()}>
            <div
                class="modal settings-modal"
                data-settings-surface
                onClick={(e) => e.stopPropagation()}
                onKeyDown={(e) => e.key === "Escape" && props.onClose()}
            >
                <div class="modal-head">
                    <h3>Settings</h3>
                    <button type="button" onClick={() => props.onClose()}>close</button>
                </div>

                <div class="settings-body">
                    <nav class="settings-rooms" aria-label="Settings sections">
                        <For each={rooms()}>
                            {(room) => (
                                <button
                                    type="button"
                                    class="settings-room"
                                    classList={{ active: props.room === room.id }}
                                    data-settings-room={room.id}
                                    aria-current={props.room === room.id}
                                    onClick={() => props.onRoom(room.id)}
                                >
                                    {room.label}
                                </button>
                            )}
                        </For>
                    </nav>

                    <div class="settings-room-body" data-settings-room-body={current().id}>
                        {/* ---- Account -------------------------------------------------- */}
                        <Show when={props.room === "account"}>
                            {/* One identity, one row. This was two sections — "Sign-in:
                                signed in with Google" above "GaugeWright account:
                                <address> · signed in" — which is the same fact under two
                                headings, and the pill restated what the sentence beside it
                                already said. */}
                            <section class="admin-section" data-account-identity>
                                <h4>Account</h4>
                                {/* Where no Hub session is custodied here there is nothing to
                                    sign into from this window — only the session that is
                                    already open, stated rather than offered as a control. */}
                                <Show
                                    when={props.model.account.hub.available}
                                    fallback={
                                        <div class="settings-row" data-account-session-only>
                                            <span class="settings-row-main">
                                                {/* The label stands alone rather than being read into a
                                                    sentence: it is "Google" when the method is known and
                                                    "Current session" when it is not, and only one of those
                                                    survives being prefixed with "signed in with". */}
                                                <span class="settings-row-name">{props.model.account.signInMethod}</span>
                                                <span class="settings-row-note">
                                                    How this window is authenticated. Sign-in methods and
                                                    recovery are managed where the account lives.
                                                </span>
                                            </span>
                                            <span class="settings-row-meta" />
                                            <span class="settings-row-action" />
                                        </div>
                                    }
                                >
                                <Show
                                    when={props.model.account.hub.linked}
                                    fallback={<>
                                        <div class="settings-row">
                                            <span class="settings-row-main">
                                                <span class="settings-row-name">Not signed in</span>
                                                <span class="settings-row-note">Sign in to reach your projects, Homes, and invitations.</span>
                                            </span>
                                            <span class="settings-row-meta" />
                                            <span class="settings-row-action">
                                                <button type="button" class="tree-action" data-hub-session-signin
                                                    onClick={() => props.actions?.hubSignIn?.()}>
                                                    Sign in with Google
                                                </button>
                                            </span>
                                        </div>
                                        {/* A sign-in that left for the browser and has not come back
                                            (LOGIN-7). Two ways it goes wrong, two visible ways out:
                                            no browser opened → the link itself, to carry anywhere;
                                            the return never arrived → paste it back by hand. */}
                                        <Show when={props.model.account.hub.pending}>
                                            {(pending) => (
                                                <div class="settings-row-detail" data-hub-session-pending>
                                                    <p class="muted">
                                                        {pending().opened
                                                            ? "Finish signing in in your browser — this panel updates by itself. If no browser opened, use this link:"
                                                            : "A browser could not be opened. Copy this link into any browser to sign in:"}
                                                    </p>
                                                    <div class="admin-invite">
                                                        <input
                                                            data-hub-session-url
                                                            readonly
                                                            value={pending().url}
                                                            onFocus={(e) => e.currentTarget.select()}
                                                        />
                                                        <button
                                                            type="button"
                                                            class="tree-action"
                                                            data-hub-session-copy
                                                            onClick={() => void navigator.clipboard?.writeText(pending().url).catch(() => {})}
                                                        >copy</button>
                                                    </div>
                                                    <p class="muted">
                                                        If the browser ends on a <code>gaugewright://…</code> link
                                                        instead of returning here, paste that link (or its code):
                                                    </p>
                                                    <div class="admin-invite">
                                                        <input
                                                            data-hub-session-paste
                                                            value={returnPaste()}
                                                            onInput={(e) => setReturnPaste(e.currentTarget.value)}
                                                            onKeyDown={(e) => {
                                                                if (e.key !== "Enter" || !returnPaste().trim()) return;
                                                                props.actions?.hubFinishSignIn?.(returnPaste());
                                                                setReturnPaste("");
                                                            }}
                                                            placeholder="gaugewright://auth/callback#code=…"
                                                        />
                                                        <button
                                                            type="button"
                                                            class="tree-action"
                                                            data-hub-session-finish
                                                            disabled={!returnPaste().trim()}
                                                            onClick={() => {
                                                                props.actions?.hubFinishSignIn?.(returnPaste());
                                                                setReturnPaste("");
                                                            }}
                                                        >finish sign-in</button>
                                                        <button
                                                            type="button"
                                                            class="tree-action"
                                                            data-hub-session-dismiss
                                                            onClick={() => props.actions?.hubDismissSignIn?.()}
                                                        >dismiss</button>
                                                    </div>
                                                </div>
                                            )}
                                        </Show>
                                    </>}
                                >
                                    <div
                                        class="settings-row"
                                        data-hub-session
                                        data-hub-session-state={props.model.account.hub.expired ? "expired" : "linked"}
                                    >
                                        <span class="settings-row-main">
                                            <span class="settings-row-name">
                                                {props.model.account.hub.person ?? "signed in"}
                                            </span>
                                            <span class="settings-row-note">
                                                signed in with {props.model.account.signInMethod}
                                            </span>
                                        </span>
                                        <span class="settings-row-meta">
                                            <Show when={props.model.account.hub.expired}>
                                                <span class="badge badge-warn">session expired</span>
                                            </Show>
                                        </span>
                                        <span class="settings-row-action">
                                            <button type="button" class="tree-action" data-hub-session-signout
                                                onClick={() => props.actions?.hubSignOut?.()}>
                                                Sign out
                                            </button>
                                        </span>
                                    </div>
                                </Show>
                                </Show>
                            </section>

                            <section class="admin-section" data-account-invitations>
                                <h4>Organizations</h4>
                                <ul class="settings-list">
                                    <For each={props.model.account.invitations} fallback={<li class="muted">No pending invitations.</li>}>
                                        {(invite) => (
                                            <li class="settings-row" data-account-invitation={invite.tenantId}>
                                                <span class="settings-row-main">
                                                    <span class="settings-row-name">{invite.displayName}</span>
                                                    <span class="settings-row-note">Invited as {invite.role}</span>
                                                </span>
                                                <span class="settings-row-meta" />
                                                <span class="settings-row-action">
                                                    <button type="button" class="tree-action" onClick={() => props.actions?.acceptInvitation?.(invite.tenantId)}>
                                                        accept
                                                    </button>
                                                </span>
                                            </li>
                                        )}
                                    </For>
                                </ul>
                                {/* Only where a Hub is actually reachable: a link to a place
                                    this composition cannot open is worse than no link. */}
                                <Show when={props.actions?.openHub}>
                                    {(open) => (
                                        <p class="settings-section-foot">
                                            <button type="button" class="link-button" data-open-hub onClick={() => open()()}>
                                                manage in the Hub ↗
                                            </button>
                                        </p>
                                    )}
                                </Show>
                            </section>
                        </Show>

                        {/* ---- Model access --------------------------------------------- */}
                        <Show when={props.room === "models"}>
                            <section class="admin-section" data-model-credentials>
                                <h4>Model credentials</h4>
                                <ul class="settings-list">
                                    <For each={props.model.models.credentials} fallback={<li class="muted">None yet.</li>}>
                                        {(c) => {
                                            const provider = () => props.model.models.providers.find((p) => p.pin === c.pin);
                                            // The second line carries whatever the provider and the
                                            // credential have to report. Built as a list rather than
                                            // nested ternaries, which is how the expiry silently fell
                                            // out of one of the branches.
                                            const sub = () => [provider()?.note, c.detail].filter(Boolean).join(" · ");
                                            return (
                                                <>
                                                    <li class="settings-row" data-credential={c.id}>
                                                        <span class="settings-row-main">
                                                            <span class="settings-row-name">{provider()?.label ?? c.pin}</span>
                                                            <Show when={sub()}>
                                                                <span class="settings-row-note">{sub()}</span>
                                                            </Show>
                                                        </span>
                                                        <span class="settings-row-meta">
                                                            <span class="badge" data-auth-kind={provider()?.auth}>
                                                                {provider()?.auth === "account" ? "account" : provider()?.auth === "key" ? "API key" : "endpoint"}
                                                            </span>
                                                            <Show when={c.status === "expired"}>
                                                                <span class="badge badge-warn">expired</span>
                                                            </Show>
                                                            {/* Distinct from expired: nothing is broken yet, so it
                                                                reads as a heads-up rather than a fault. */}
                                                            <Show when={c.status !== "expired" && c.expiresSoon}>
                                                                <span class="badge badge-soon">expires soon</span>
                                                            </Show>
                                                        </span>
                                                        <span class="settings-row-action">
                                                            {/* Whether a credential declares its own model rows is
                                                                the model's answer (`models` present), not a guess from
                                                                how it authorizes. OpenRouter is a *key* provider that
                                                                still declares rows, and gating on `auth` would leave
                                                                its list built but unreachable. */}
                                                            <Show when={c.models !== undefined}>
                                                                <button
                                                                    type="button"
                                                                    class="tree-action"
                                                                    aria-expanded={openCredential() === c.id}
                                                                    onClick={() => setOpenCredential(openCredential() === c.id ? null : c.id)}
                                                                >
                                                                    {(c.models?.length ?? 0) === 0
                                                                        ? "add models"
                                                                        : `${c.models!.length} model${c.models!.length === 1 ? "" : "s"}`}
                                                                    {" "}
                                                                    {openCredential() === c.id ? "▾" : "▸"}
                                                                </button>
                                                            </Show>
                                                            {/* Renewing is only meaningful for a credential you sign
                                                                into; a pasted key is replaced, not reconnected. */}
                                                            <Show when={provider()?.auth === "account" && (c.status === "expired" || c.expiresSoon)}>
                                                                <button type="button" class="tree-action"
                                                                    onClick={() => props.actions?.signInToProvider?.(c.pin)}>Reconnect ↗</button>
                                                            </Show>
                                                            <Show when={c.removable}>
                                                                <button type="button" class="tree-action"
                                                                    onClick={() => props.actions?.removeCredential?.(c.id)}>remove</button>
                                                            </Show>
                                                        </span>
                                                    </li>

                                                    <Show when={openCredential() === c.id}>
                                                        <li class="settings-row-detail" data-endpoint-models={c.id}>
                                                            <ul class="settings-chips">
                                                                <For each={c.models ?? []} fallback={<li class="muted">No models added yet.</li>}>
                                                                    {(id) => (
                                                                        <li class="settings-chip" data-endpoint-model={id}>
                                                                            <span>{id}</span>
                                                                            <button type="button" aria-label={`Remove ${id}`}
                                                                                onClick={() => props.actions?.removeEndpointModel?.(c.id, id)}>×</button>
                                                                        </li>
                                                                    )}
                                                                </For>
                                                            </ul>
                                                            <div class="admin-invite">
                                                                <input
                                                                    value={newModel()}
                                                                    onInput={(e) => setNewModel(e.currentTarget.value)}
                                                                    onKeyDown={(e) => {
                                                                        if (e.key !== "Enter" || !newModel().trim()) return;
                                                                        props.actions?.addEndpointModel?.(c.id, newModel().trim());
                                                                        setNewModel("");
                                                                    }}
                                                                    placeholder={c.pin === "openrouter"
                                                                        ? "route id, e.g. anthropic/claude-sonnet-4.5"
                                                                        : "model id, e.g. llama-3.3-70b-instruct"}
                                                                />
                                                                <button type="button" class="tree-action" disabled={!newModel().trim()}
                                                                    onClick={() => { props.actions?.addEndpointModel?.(c.id, newModel().trim()); setNewModel(""); }}
                                                                >add</button>
                                                            </div>
                                                        </li>
                                                    </Show>
                                                </>
                                            );
                                        }}
                                    </For>

                                    {/* A sign-in in flight is a credential that does not exist yet;
                                        it sits where it will land rather than beside the button that
                                        started it. */}
                                    <Show when={props.model.models.signIn}>
                                        {(flow) => (
                                            <li class="settings-row" data-signin-pending={flow().pin}>
                                                <span class="settings-row-main">
                                                    <span class="settings-row-name">{flow().label}</span>
                                                    <span class="settings-waiting">
                                                        <span class="settings-waiting-dot" aria-hidden="true" />
                                                        Waiting for your browser…
                                                    </span>
                                                </span>
                                                <span class="settings-row-meta" />
                                                <span class="settings-row-action">
                                                    <button type="button" class="tree-action"
                                                        onClick={() => props.actions?.cancelSignIn?.()}>cancel</button>
                                                </span>
                                            </li>
                                        )}
                                    </Show>
                                </ul>

                                <Show
                                    when={adding()}
                                    fallback={<button type="button" class="tree-action" data-add-credential-open
                                        onClick={() => { setProvider(props.model.models.providers[0]?.pin ?? ""); setToken(""); setEndpoint(""); setFirstModel(""); setAdding(true); }}
                                    >add a credential</button>}
                                >
                                    <div class="admin-invite" data-add-credential>
                                        {/* Every provider, always: adding one credential does not
                                            use the provider up. */}
                                        <select data-account-provider value={provider()} onChange={(e) => setProvider(e.currentTarget.value)}>
                                            <For each={props.model.models.providers}>
                                                {(p) => <option value={p.pin}>{p.label}</option>}
                                            </For>
                                        </select>
                                        <Show
                                            when={chosen()?.auth !== "account"}
                                            fallback={
                                                <button
                                                    type="button"
                                                    class="tree-action"
                                                    data-add-signin
                                                    disabled={!props.model.models.accountSignInAvailable}
                                                    title={props.model.models.accountSignInAvailable
                                                        ? "Opens your browser to sign in; this panel updates by itself."
                                                        : "This runtime cannot open the sign-in flow."}
                                                    onClick={() => { props.actions?.signInToProvider?.(provider()); setAdding(false); }}
                                                >Sign in ↗</button>
                                            }
                                        >
                                            <Show when={chosen()?.auth === "endpoint"}>
                                                <input data-account-endpoint type="url" value={endpoint()} onInput={(e) => setEndpoint(e.currentTarget.value)}
                                                    placeholder="endpoint URL" />
                                            </Show>
                                            <input data-account-token type="password" value={token()} onInput={(e) => setToken(e.currentTarget.value)}
                                                placeholder="paste API key / token" />
                                            <Show when={chosen()?.declaresModels}>
                                                <input data-account-model value={firstModel()} onInput={(e) => setFirstModel(e.currentTarget.value)}
                                                    placeholder={provider() === "openrouter"
                                                        ? "route id, e.g. anthropic/claude-sonnet-4.5"
                                                        : "model id, e.g. llama-3.3-70b-instruct"} />
                                            </Show>
                                            <button type="button" class="tree-action" data-account-link
                                                onClick={() => {
                                                    props.actions?.linkKey?.({
                                                        pin: provider(),
                                                        token: token(),
                                                        endpoint: endpoint() || undefined,
                                                        model: chosen()?.declaresModels ? firstModel() || undefined : undefined,
                                                    });
                                                    setAdding(false);
                                                }}
                                            >add</button>
                                        </Show>
                                        <button type="button" class="tree-action" onClick={() => setAdding(false)}>cancel</button>
                                    </div>
                                </Show>
                            </section>

                            <section class="admin-section" data-model-routing>
                                <h4>Shown in the picker</h4>
                                {/* One line, because the rows already carry the answer: each
                                    says what runs it, and "also via" appears only on the rows
                                    where two accounts overlap. */}
                                <p class="muted">Unchecked models still work; they are hidden from the per-chat picker.</p>
                                <Show
                                    when={props.model.models.picker.length}
                                    fallback={<p class="muted">Link an account above to choose its models.</p>}
                                >
                                    <ul class="member-list model-checklist">
                                        <For each={props.model.models.picker}>
                                            {(m) => (
                                                <li class="model-check-row" data-model-toggle={m.key}>
                                                    <label class="admin-check model-check">
                                                        <input
                                                            type="checkbox"
                                                            checked={m.enabled}
                                                            onChange={(e) => props.actions?.toggleModel?.(m.key, e.currentTarget.checked)}
                                                        />
                                                        <span>{m.label}</span>
                                                    </label>
                                                    <span class="model-runs-on">runs on {m.runsOn}</span>
                                                    <Show when={m.alsoVia.length}>
                                                        <span class="model-also-via">also via {m.alsoVia.join(", ")}</span>
                                                    </Show>
                                                </li>
                                            )}
                                        </For>
                                    </ul>
                                </Show>
                            </section>

                            {/* Managed inference is not something every composition has; where
                                there is none the section is absent rather than an empty frame
                                implying something is missing. */}
                            <Show when={props.model.models.managed}>
                                {(managed) => (
                                    <section class="admin-section" data-managed-inference>
                                        <h4>Managed inference</h4>
                                        <div class="settings-row">
                                            <span class="settings-row-main">
                                                <span class="settings-row-name">
                                                    {managed().plan ?? "No plan set up"}
                                                </span>
                                                <span class="settings-row-note" data-managed-usage>
                                                    {managed().runs} runs · {managed().tokens.toLocaleString()} tokens
                                                    {managed().overage ? ` · ${managed().overage.toLocaleString()} over included` : ""}
                                                </span>
                                            </span>
                                            <span class="settings-row-meta">
                                                <Show when={managed().plan}>
                                                    <span class="badge" data-managed-state={managed().state}>{managed().state}</span>
                                                </Show>
                                            </span>
                                            <span class="settings-row-action" />
                                        </div>
                                        {/* Suspending blocks future managed calls only; it does not
                                            rewrite chats or usage that already happened. */}
                                        <Show
                                            when={managed().editable}
                                            fallback={<p class="muted" data-managed-inference-read-only>
                                                Plan changes are controlled by billing for this account.
                                            </p>}
                                        >
                                            <div class="admin-invite managed-plan-row">
                                                <label class="settings-field">
                                                    <span class="settings-label">plan</span>
                                                    <input
                                                        value={planDraft() ?? managed().plan ?? ""}
                                                        onInput={(e) => setPlanDraft(e.currentTarget.value)}
                                                        placeholder="plan"
                                                    />
                                                </label>
                                                <label class="settings-field">
                                                    <span class="settings-label">status</span>
                                                    <select
                                                        value={stateDraft() ?? managed().state}
                                                        onChange={(e) => setStateDraft(e.currentTarget.value as ManagedPlanState)}
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
                                                        value={includedDraft() ?? String(managed().includedTokens)}
                                                        onInput={(e) => setIncludedDraft(e.currentTarget.value)}
                                                    />
                                                </label>
                                                <button
                                                    type="button"
                                                    class="tree-action"
                                                    data-managed-save
                                                    onClick={() => {
                                                        const included = Number(includedDraft() ?? managed().includedTokens);
                                                        props.actions?.setManagedPlan?.({
                                                            plan: planDraft() ?? managed().plan ?? "managed",
                                                            state: stateDraft() ?? managed().state,
                                                            includedTokens: Number.isFinite(included) ? Math.max(0, included) : 0,
                                                        });
                                                        setPlanDraft(null);
                                                        setStateDraft(null);
                                                        setIncludedDraft(null);
                                                    }}
                                                >save plan</button>
                                            </div>
                                        </Show>
                                    </section>
                                )}
                            </Show>
                        </Show>

                        {/* ---- Devices --------------------------------------------------- */}
                        <Show when={props.room === "devices"}>
                            {/* Two trust acts, kept apart because they are not the same
                                link and not the same trust. A phone becomes a device subkey
                                under *your* authority; another party's machine is paired by
                                ticket and admission-gated. Offering one button for both was
                                the mistake this section exists to avoid. */}
                            <section class="admin-section" data-your-devices>
                                <h4>Your devices</h4>
                                <ul class="settings-list">
                                    <For each={props.model.devices.devices} fallback={<li class="muted">No devices enrolled yet.</li>}>
                                        {(d) => (
                                            <li class="settings-row" data-device={d.id}>
                                                <span class="settings-row-main">
                                                    <span class="settings-row-name">{d.label}</span>
                                                    <span class="settings-row-note">{d.added}</span>
                                                </span>
                                                <span class="settings-row-meta">
                                                    <span class="member-status">{d.status}</span>
                                                </span>
                                                <span class="settings-row-action">
                                                    <Show when={d.status === "active"}>
                                                        <button type="button" class="tree-action" onClick={() => props.actions?.revokeDevice?.(d.id)}>revoke</button>
                                                    </Show>
                                                </span>
                                            </li>
                                        )}
                                    </For>
                                </ul>
                                <button type="button" class="tree-action" onClick={() => props.actions?.enrollDevice?.()}>
                                    add a phone or tablet
                                </button>
                            </section>

                            <section class="admin-section" data-connected-parties>
                                <h4>Connected parties</h4>
                                <p class="muted">Disconnecting blocks future work; it does not rewrite what already happened.</p>
                                <ul class="settings-list">
                                    <For each={props.model.devices.peers} fallback={<li class="muted">No parties connected.</li>}>
                                        {(peer) => (
                                            <li class="settings-row" data-peer={peer.id}>
                                                <span class="settings-row-main">
                                                    <span class="settings-row-name">{peer.authority}</span>
                                                </span>
                                                <span class="settings-row-meta">
                                                    <span class="member-status">{peer.status}</span>
                                                </span>
                                                <span class="settings-row-action">
                                                    <button type="button" class="tree-action"
                                                        onClick={() => props.actions?.disconnectParty?.(peer.id)}>disconnect</button>
                                                </span>
                                            </li>
                                        )}
                                    </For>
                                </ul>
                                <button type="button" class="tree-action" onClick={() => props.actions?.pairParty?.()}>
                                    connect a separate party
                                </button>
                            </section>

                            <Show when={props.model.devices.librarySync !== null}>
                            <section class="admin-section" data-library-sync>
                                <h4>Library sync</h4>
                                <div class="settings-row">
                                    <span class="settings-row-main">
                                        <span class="settings-row-name">
                                            {props.model.devices.librarySync ? "On" : "Off"}
                                        </span>
                                        <span class="settings-row-note">
                                            Your settings and Home routes, sealed — the directory stores the
                                            ciphertext and cannot open it.
                                        </span>
                                    </span>
                                    <span class="settings-row-meta">
                                        {/* Publish and pull are maintenance on something that syncs by
                                            itself, so they sit quietly beside the state rather than
                                            presenting as three equal choices. */}
                                        <Show when={props.model.devices.librarySync}>
                                            <button type="button" class="link-button" onClick={() => props.actions?.publishLibrary?.()}>publish now</button>
                                            <button type="button" class="link-button" onClick={() => props.actions?.pullLibrary?.()}>pull now</button>
                                        </Show>
                                    </span>
                                    <span class="settings-row-action">
                                        <button
                                            type="button"
                                            class="tree-action"
                                            onClick={() => props.actions?.setLibrarySync?.(!props.model.devices.librarySync)}
                                        >{props.model.devices.librarySync ? "turn off" : "turn on"}</button>
                                    </span>
                                </div>
                            </section>
                            </Show>
                        </Show>

                        {/* ---- Behaviour ------------------------------------------------ */}
                        <Show when={props.room === "behaviour"}>
                            <section class="admin-section" data-attention-settings>
                                <h4>Attention</h4>
                                <ul class="settings-list attention-list">
                                    <For each={ATTENTION_SIGNALS}>
                                        {(meta) => {
                                            const level = () => props.model.behaviour.attention[meta.signal] ?? meta.defaultAttention;
                                            return (
                                                <li class="settings-row" data-attention-signal={meta.signal}>
                                                    <span class="settings-row-main">
                                                        <span class="settings-row-name">{meta.label}</span>
                                                        <span class="settings-row-note">{meta.hint}</span>
                                                    </span>
                                                    <span class="settings-row-meta" />
                                                    <span class="settings-row-action">
                                                        {/* Three fixed choices, so they are shown rather than
                                                            hidden behind a select: the row states its own
                                                            options, and choosing is one click instead of two.
                                                            It also retires the paragraph that had to explain
                                                            what the three words meant. */}
                                                        <span class="segmented" role="radiogroup" aria-label={meta.label}>
                                                            <For each={LEVEL_CHOICES}>
                                                                {(choice) => (
                                                                    <button
                                                                        type="button"
                                                                        role="radio"
                                                                        class="segment"
                                                                        classList={{ active: level() === choice.level }}
                                                                        aria-checked={level() === choice.level}
                                                                        title={choice.hint}
                                                                        data-level={choice.level}
                                                                        onClick={() => props.actions?.setAttention?.(meta.signal, choice.level)}
                                                                    >{choice.label}</button>
                                                                )}
                                                            </For>
                                                        </span>
                                                    </span>
                                                </li>
                                            );
                                        }}
                                    </For>
                                </ul>
                            </section>

                            <section class="admin-section" data-advancement-settings>
                                <h4>Auto-keep</h4>
                                <p class="muted">
                                    Keep a turn automatically when it <em>only</em> touches these paths.
                                    Empty means everything waits. A permissions change, or a turn that
                                    read someone else's content, always waits — no scope overrides that.
                                </p>
                                <ul class="settings-chips">
                                    <For each={props.model.behaviour.autoKeep} fallback={<li class="muted">Nothing auto-keeps; every turn waits.</li>}>
                                        {(glob) => (
                                            <li class="settings-chip" data-auto-keep={glob}>
                                                <span>{glob}</span>
                                                <button type="button" aria-label={`Remove ${glob}`}
                                                    onClick={() => props.actions?.removeAutoKeep?.(glob)}>×</button>
                                            </li>
                                        )}
                                    </For>
                                </ul>
                                <div class="admin-invite">
                                    <input
                                        placeholder="path or glob, e.g. docs/**"
                                        value={autoKeep() ?? ""}
                                        onInput={(e) => setAutoKeep(e.currentTarget.value)}
                                        onKeyDown={(e) => {
                                            if (e.key !== "Enter" || !addableGlob()) return;
                                            props.actions?.addAutoKeep?.(addableGlob()!);
                                            setAutoKeep("");
                                        }}
                                    />
                                    <button
                                        type="button"
                                        class="tree-action"
                                        disabled={!addableGlob()}
                                        title={autoKeep()?.trim() === "**"
                                            ? "“**” is everything, which is not a scope — the evaluator drops it."
                                            : undefined}
                                        onClick={() => { props.actions?.addAutoKeep?.(addableGlob()!); setAutoKeep(""); }}
                                    >add</button>
                                </div>
                            </section>
                        </Show>
                    </div>
                </div>

                {/* One status line for the whole surface, outside the rooms: an operation
                    started in one room and the report of how it went must not be separated
                    by a click on the room beside it. */}
                <Show when={props.model.status}>
                    <p class="status" data-account-status role="status">{props.model.status}</p>
                </Show>
            </div>
        </div>
        </>
    );
}