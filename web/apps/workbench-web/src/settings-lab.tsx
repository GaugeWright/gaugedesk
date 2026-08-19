/**
 * Prototype bench for the bottom-left account menu and the Settings surface behind
 * it. It runs the real component against the real stylesheet, so what is agreed
 * here is what ships — the menu below is `AccountMenu` itself, not a mock of it.
 *
 * Served in development only (`/settings-lab.html`); no shipped bundle names this
 * entry.
 */
import { createSignal, For, Show } from "solid-js";
import { createStore, produce } from "solid-js/store";
import { render } from "solid-js/web";
import {
    AccountMenu,
    SettingsSurface,
    type SettingsActions,
    type AccountMenuItem,
    type MenuComposition,
    type SettingsModel,
    type SettingsRoom,
} from "@gaugewright/workbench-ui";
import "@gaugewright/workbench-ui/styles.css";

/** Fixture standing in for the control-plane projections, so the surface can be
 *  judged with real content rather than lorem. Every field maps to something the
 *  882-line panel already reads today. */
/** The surface takes a deeply `readonly` model — that is the contract, and it should
 *  stay that way. The bench is the thing that mutates, so it holds a writable view of
 *  the same shape; it stays assignable to what the surface accepts. */
type Mutable<T> = {
    -readonly [K in keyof T]: T[K] extends readonly (infer U)[] ? Mutable<U>[]
        : T[K] extends object | undefined ? Mutable<NonNullable<T[K]>> | Extract<T[K], undefined>
        : T[K];
};

const INITIAL: SettingsModel = {
    account: {
        signInMethod: "Google",
        hub: { available: true, linked: true, person: "jamesjscully@gmail.com", expired: false },
        invitations: [
            { tenantId: "theorya", displayName: "Theorya", role: "member" },
            { tenantId: "wanamaker", displayName: "Wanamaker Institute", role: "admin" },
        ],
    },
    models: {
        providers: [
            { pin: "openai-codex", label: "OpenAI (Codex)", auth: "account", note: "also serves the OpenAI catalog" },
            { pin: "anthropic", label: "Anthropic", auth: "key" },
            { pin: "openai", label: "OpenAI", auth: "key" },
            { pin: "xai", label: "xAI (Grok)", auth: "key" },
            { pin: "openai-generic", label: "OpenAI-compatible", auth: "endpoint" },
        ],
        // One per provider, because that is how the store keys them. The bench holds the
        // states nobody can reach on demand against a live control plane — a credential
        // near expiry, one already expired — but never a shape the store cannot produce.
        credentials: [
            {
                id: "openai-codex", pin: "openai-codex", status: "connected",
                expiresSoon: true, detail: "valid to 15 Aug 2026",
                // The routes can start this sign-in but never end it.
                removable: false,
            },
            { id: "anthropic", pin: "anthropic", status: "connected", removable: true },
            { id: "openai", pin: "openai", status: "expired", removable: true },
            {
                id: "openai-generic",
                pin: "openai-generic",
                status: "connected",
                models: ["llama-3.3-70b-instruct", "qwen2.5-coder-32b"],
                removable: true,
            },
        ],
        accountSignInAvailable: true,
        managed: {
            plan: "managed", state: "active", includedTokens: 2_000_000,
            runs: 128, tokens: 2_410_553, overage: 410_553, editable: true,
        },
        picker: [
            { key: "anthropic:claude-opus-5", label: "Claude Opus 5", runsOn: "Anthropic", alsoVia: [], primary: true, enabled: true },
            { key: "anthropic:claude-sonnet-5", label: "Claude Sonnet 5", runsOn: "Anthropic", alsoVia: [], primary: true, enabled: true },
            { key: "openai-codex:gpt-5-codex", label: "GPT-5 Codex", runsOn: "OpenAI (Codex)", alsoVia: [], primary: true, enabled: true },
            { key: "openai-codex:gpt-5", label: "GPT-5", runsOn: "OpenAI (Codex)", alsoVia: ["OpenAI"], primary: false, enabled: false },
            { key: "openai-generic:llama-3.3-70b-instruct", label: "llama-3.3-70b-instruct", runsOn: "OpenAI-compatible", alsoVia: [], primary: true, enabled: true },
        ],
    },
    devices: {
        devices: [
            { id: "d-phone", label: "Pixel 9", added: "added 3 Aug 2026", status: "active" },
            { id: "d-tablet", label: "iPad mini", added: "added 2 Jan 2026", status: "revoked" },
        ],
        peers: [
            { id: "p-1", authority: "Theorya · Dana's MacBook", status: "connected" },
        ],
        librarySync: true,
    },
    behaviour: {
        // Levels only; the signals come from ATTENTION_SIGNALS. Two here are left at
        // their shipped defaults to exercise the absent case.
        attention: { conflict: "queue", "turn-settled": "badge" },
        autoKeep: ["docs/**", "*.md"],
    },
};

function Bench() {
    const [open, setOpen] = createSignal<string | null>("desktop");
    const [section, setSection] = createSignal<SettingsRoom>("account");
    const [settingsOpen, setSettingsOpen] = createSignal(true);
    const [accountAvailable, setAccountAvailable] = createSignal(true);
    // The bench owns real state: a prototype whose controls call into `undefined` cannot
    // be walked through, and the device prompt in particular became a screen with no exit
    // because its cancel had nothing behind it.
    const [model, setModel] = createStore<Mutable<SettingsModel>>(
        structuredClone(INITIAL) as Mutable<SettingsModel>,
    );
    const credential = (id: string) => model.models.credentials.findIndex((c) => c.id === id);
    let nextId = 5;
    const actions: SettingsActions = {
        signInToProvider: (pin) => setModel("models", "signIn", {
            pin,
            label: model.models.providers.find((p) => p.pin === pin)?.label ?? pin,
            mode: "device", code: "WDJB-MJHT", url: "openai.com/device",
        }),
        cancelSignIn: () => setModel("models", "signIn", undefined),
        removeCredential: (id) => setModel("models", "credentials",
            (list) => list.filter((c) => c.id !== id)),
        linkKey: ({ pin, endpoint }) => setModel("models", "credentials", produce((list) => {
            list.push({ id: `c${nextId++}`, pin, status: "connected",
                detail: endpoint || undefined, models: endpoint ? [] : undefined, removable: true });
        })),
        // Replaced whole rather than mutated in place: `Mutable` lifts the readonly off
        // each property, not off the objects behind them.
        setManagedPlan: (next) => setModel("models", "managed", (m) => (m ? { ...m, ...next } : m)),
        addEndpointModel: (id, modelId) => setModel("models", "credentials", credential(id), produce((c) => {
            c.models = [...(c.models ?? []), modelId];
        })),
        removeEndpointModel: (id, modelId) => setModel("models", "credentials", credential(id), produce((c) => {
            c.models = (c.models ?? []).filter((m) => m !== modelId);
        })),
        toggleModel: (key, on) => setModel("models", "picker",
            model.models.picker.findIndex((m) => m.key === key), "enabled", on),
        acceptInvitation: (tenantId) => setModel("account", "invitations",
            (list) => list.filter((i) => i.tenantId !== tenantId)),
        hubSignOut: () => setModel("account", "hub", "linked", false),
        hubSignIn: () => setModel("account", "hub", "linked", true),
        revokeDevice: (id) => setModel("devices", "devices",
            model.devices.devices.findIndex((d) => d.id === id), "status", "revoked"),
        setLibrarySync: (on) => setModel("devices", "librarySync", on),
        setAttention: (signal, level) => setModel("behaviour", "attention", signal, level),
        addAutoKeep: (glob) => setModel("behaviour", "autoKeep", (list) => [...list, glob]),
        removeAutoKeep: (glob) => setModel("behaviour", "autoKeep", (list) => list.filter((g) => g !== glob)),
        disconnectParty: (id) => setModel("devices", "peers", (list) => list.filter((p) => p.id !== id)),
        openHub: () => window.open("https://hub.gaugewright.com", "_blank", "noopener"),
    };

    const items = (composition: MenuComposition, signedIn: boolean): AccountMenuItem[] => {
        const rows: AccountMenuItem[] = [
            { id: "settings", label: "Settings", hint: "Ctrl+,", run: () => { setSection("account"); setSettingsOpen(true); } },
            { id: "devices", label: "Devices", submenu: true, run: () => { setSection("devices"); setSettingsOpen(true); } },
            { id: "sep-1", label: "", separator: true, run: () => {} },
            { id: "whats-new", label: "What's new", run: () => {} },
            { id: "help", label: "Help", run: () => {} },
        ];
        // `desk` holds no account, so it offers no session verb — the row would be a
        // control with nothing behind it (ADR 0130/0131).
        if (composition === "desk") return rows;
        rows.push({ id: "sep-2", label: "", separator: true, run: () => {} });
        rows.push(signedIn
            ? { id: "sign-out", label: "Sign out", danger: true, run: () => {} }
            : { id: "sign-in", label: "Sign in", run: () => {} });
        return rows;
    };

    const cases: { key: string; title: string; note: string; composition: MenuComposition; identity: Parameters<typeof AccountMenu>[0]["identity"]; reach?: string }[] = [
        {
            key: "desktop",
            title: "Desktop · signed in",
            note: "The trigger answers who and what plan without being opened.",
            composition: "desktop",
            identity: { name: "James Scully", email: "jamesjscully@gmail.com", edition: "Personal" },
            reach: "this computer",
        },
        {
            key: "signed-out",
            title: "Desktop · signed out",
            note: "Signed out is a stated state with its own mark, and the verb flips to Sign in.",
            composition: "desktop",
            identity: null,
            reach: "this computer",
        },
        {
            key: "desk",
            title: "Desk · browser client",
            note: "Not an account surface: it names the Home it reaches and offers no session verb.",
            composition: "desk",
            identity: null,
            reach: "Jack's iMac",
        },
    ];

    return (
        <div class="lab">
            <header class="lab-head">
                <h1>Account menu &amp; Settings</h1>
                <p>
                    The real <code>AccountMenu</code> against the real stylesheet. The menu is a
                    door, not a room: every row either states a fact or opens a surface that owns
                    its own navigation.
                </p>
            </header>

            <section class="lab-row">
                <For each={cases}>
                    {(c) => (
                        <div class="lab-case">
                            <h2>{c.title}</h2>
                            <p class="lab-note">{c.note}</p>
                            <div class="lab-stage">
                                <AccountMenu
                                    composition={c.composition}
                                    identity={c.identity}
                                    reach={c.reach}
                                    version="0.4.5"
                                    items={items(c.composition, c.identity !== null)}
                                    open={open() === c.key}
                                    onToggle={() => setOpen(open() === c.key ? null : c.key)}
                                />
                            </div>
                        </div>
                    )}
                </For>
            </section>

            <section class="lab-settings">
                <h2>Behind “Settings”</h2>
                <p class="lab-note">
                    The real <code>SettingsSurface</code> with real controls. Today one modal
                    carries eleven sections in one scroll across four concerns, and Devices
                    appears both inside it and beside it in a second modal. Same material,
                    four rooms.
                </p>
                <div class="lab-actions">
                    <button type="button" class="tree-action" onClick={() => setSettingsOpen(true)}>
                        open Settings
                    </button>
                    <label class="lab-toggle">
                        <input
                            type="checkbox"
                            checked={!accountAvailable()}
                            onChange={(e) => setAccountAvailable(!e.currentTarget.checked)}
                        />
                        <span>as desk (no account room)</span>
                    </label>
                </div>
                <Show when={settingsOpen()}>
                    <SettingsSurface
                        model={model}
                        actions={actions}
                        room={section() as SettingsRoom}
                        onRoom={(r) => setSection(r)}
                        onClose={() => setSettingsOpen(false)}
                        accountAvailable={accountAvailable()}
                    />
                </Show>
            </section>
        </div>
    );
}

const root = document.getElementById("root");
if (root) render(() => <Bench />, root);
