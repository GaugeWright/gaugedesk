/**
 * Open-source **account menu** slot for the workbench build. It keeps local/free
 * surfaces reachable while excluding enterprise governance and private managed-service
 * UI modules from the open bundle.
 *
 * The menu is a door, not a room: it names who you are and where to go. Everything with
 * more than one control is behind Settings, which owns its own navigation. That is why
 * the gear became an identity — the old trigger could not say whether you were signed
 * in, and its three items opened one modal carrying four unrelated concerns.
 */

import { createEffect, createSignal, ErrorBoundary, on, Show, type Accessor, type JSX } from "solid-js";
import type { PlacementPolicy } from "@gaugewright/control-plane-client";
import { AccountMenu, type AccountMenuItem, type MenuComposition } from "./AccountMenu";
import { SettingsPanel, type SettingsPanelApi } from "./SettingsPanel";
import type { SettingsRoom } from "./SettingsSurface";
import { DevicesModal, type DevicesModalApi } from "./DevicesModal";

export interface SettingsMenuApi extends SettingsPanelApi, DevicesModalApi {}

/** Optional product Environment supplied by a composing application. The open
 *  workbench owns the menu seam but knows nothing about enterprise modules. */
export interface SettingsEnvironmentAction {
    readonly label: string;
    readonly available: Accessor<boolean>;
    readonly open: () => void;
}

/** A settings modal that throws during render must degrade to a visible,
 *  closable failure notice — a silent dead click is indistinguishable from a
 *  broken button and leaves no way back (the Devices crash of 2026-07-31). */
function SettingsModalBoundary(props: {
    surface: string;
    onClose: () => void;
    children: JSX.Element;
}): JSX.Element {
    return (
        <ErrorBoundary
            fallback={(error) => (
                <div class="modal-overlay" onClick={() => props.onClose()}>
                    <div class="modal" onClick={(e) => e.stopPropagation()}>
                        <div class="modal-head">
                            <h3>{props.surface}</h3>
                            <button type="button" onClick={() => props.onClose()}>close</button>
                        </div>
                        <p class="status" role="alert" data-settings-modal-error>
                            This panel failed to render: {String(error)}
                        </p>
                    </div>
                </div>
            )}
        >
            {props.children}
        </ErrorBoundary>
    );
}

export function SettingsMenu(props: {
    api: SettingsMenuApi;
    environment?: string;
    /** Whether this runtime can complete the local Codex OAuth helper flow. */
    codexLoginAvailable?: boolean;
    /** Whether this composition owns managed-plan mutations locally. */
    managedInferenceEditable?: boolean;
    /** Whether this composition holds the sovereign desktop root key needed
     * for library publish/pull. */
    librarySyncAvailable?: boolean;
    /** Which composition is rendering — it decides whether the menu claims an
     *  account at all (ADR 0130/0131). Defaults to the desktop workbench. */
    composition?: MenuComposition;
    /** The signed-in person, if this composition has one. */
    identity?: Accessor<{ name: string; email?: string; edition?: string } | null>;
    /** This client's build. Reported once in the menu rather than spent on permanent
     *  chrome beside the network state. */
    version?: string;
    /** The Home this client reaches — the only identity a browser client has. */
    reach?: string;
    /** Where the account and its organizations are administered. */
    hubUrl?: string;
    /** A monotonically increasing counter; each increment opens Settings at the Account
     *  room. Lets another surface (e.g. an in-chat "no model" prompt) open settings. */
    openAccount?: Accessor<number>;
    /** FED-7: an OS-delivered `gaugewright://invite` deep link. Each non-empty value opens the
     *  Devices modal seeded with that link, so its consent preview renders immediately. */
    openInvite?: Accessor<string>;
    /** End the authenticated account session. Omitted on surfaces without account login. */
    onSignOut?: () => void | Promise<void>;
    /** A capability-gated Environment action supplied by the app composition. */
    environmentAction?: SettingsEnvironmentAction;
    /** Authenticated org floor supplied only by an enrolled composition. */
    placementPolicy?: Accessor<PlacementPolicy | undefined>;
    /** How this runtime opens a URL in the person's browser — the desktop shell's
     *  seam, since its webview silently drops `window.open`. Passed through to
     *  Settings; absent means `window.open` (right for browser builds). */
    openExternal?: (url: string) => Promise<boolean>;
}): JSX.Element {
    const [menuOpen, setMenuOpen] = createSignal(false);
    const [devicesOpen, setDevicesOpen] = createSignal(false);
    const [settingsOpen, setSettingsOpen] = createSignal(false);
    // Which room Settings lands in for *this* opening. Held here because the opener knows
    // the reason: the menu's own row means Account, an in-chat model refusal means Model
    // access. Remounting Settings each time is what makes the seed take.
    const [settingsRoom, setSettingsRoom] = createSignal<SettingsRoom>("account");
    const openSettingsAt = (room: SettingsRoom) => {
        setSettingsRoom(room);
        setSettingsOpen(true);
    };
    const [inviteSeed, setInviteSeed] = createSignal("");
    const [signOutBusy, setSignOutBusy] = createSignal(false);
    const [signOutError, setSignOutError] = createSignal("");

    const composition = () => props.composition ?? "desktop";
    // `desk` reaches an account's work without holding the account (ADR 0130/0131), so
    // neither the trigger nor the Account room claims one there.
    const accountAvailable = () => composition() !== "desk";

    const signOut = async () => {
        if (!props.onSignOut || signOutBusy()) return;
        setSignOutBusy(true);
        setSignOutError("");
        try {
            await props.onSignOut();
            setMenuOpen(false);
        } catch (error) {
            setSignOutError(error instanceof Error ? error.message : "Sign out failed. Please try again.");
        } finally {
            setSignOutBusy(false);
        }
    };

    const items = (): AccountMenuItem[] => {
        const rows: AccountMenuItem[] = [
            {
                id: "settings",
                label: "Settings",
                submenu: true,
                run: () => {
                    setMenuOpen(false);
                    openSettingsAt("account");
                },
            },
            {
                id: "devices",
                label: "Add a device or party",
                submenu: true,
                run: () => {
                    setMenuOpen(false);
                    setDevicesOpen(true);
                },
            },
        ];
        if (props.environmentAction?.available()) {
            rows.push({
                id: "environment",
                label: props.environmentAction.label,
                submenu: true,
                run: () => {
                    setMenuOpen(false);
                    props.environmentAction?.open();
                },
            });
        }
        // The session verb follows the session, not the presence of a handler — that is
        // how the gear came to offer "Sign out" to someone who was signed out. Where this
        // composition holds no account at all there is no verb to offer.
        if (accountAvailable()) {
            rows.push({ id: "session-rule", label: "", separator: true, run: () => {} });
            if (!props.identity?.()) {
                // The trigger reads "Sign in"; this is where that promise is kept.
                rows.push({
                    id: "sign-in",
                    label: "Sign in",
                    run: () => {
                        setMenuOpen(false);
                        openSettingsAt("account");
                    },
                });
            } else if (props.onSignOut) {
                rows.push({
                    id: "sign-out",
                    label: signOutBusy() ? "Signing out…" : "Sign out",
                    danger: true,
                    run: () => void signOut(),
                });
            }
        }
        return rows;
    };

    // Open Settings when an external request comes in (defer the initial run so we never
    // pop it open on mount).
    createEffect(
        on(
            () => props.openAccount?.() ?? 0,
            () => {
                setMenuOpen(false);
                openSettingsAt("account");
            },
            { defer: true },
        ),
    );

    // FED-7: open the Devices modal, seeded with the deep-linked invite, when one arrives
    // (defer so a value present at mount never auto-pops the modal).
    createEffect(
        on(
            () => props.openInvite?.() ?? "",
            (url) => {
                if (!url) return;
                setMenuOpen(false);
                setSettingsOpen(false);
                setInviteSeed(url);
                setDevicesOpen(true);
            },
            { defer: true },
        ),
    );

    return (
        <>
            <AccountMenu
                composition={composition()}
                identity={props.identity?.() ?? null}
                version={props.version ?? ""}
                reach={props.reach}
                items={items()}
                open={menuOpen()}
                onToggle={() => setMenuOpen((o) => !o)}
            />
            <Show when={signOutError()}>
                <div class="settings-menu-error" role="alert">{signOutError()}</div>
            </Show>

            <Show when={devicesOpen()}>
                <SettingsModalBoundary
                    surface="Devices"
                    onClose={() => {
                        setDevicesOpen(false);
                        setInviteSeed("");
                    }}
                >
                    <DevicesModal
                        api={props.api}
                        environment={props.environment}
                        placementPolicy={props.placementPolicy}
                        initialInviteLink={inviteSeed()}
                        onClose={() => {
                            setDevicesOpen(false);
                            setInviteSeed("");
                        }}
                    />
                </SettingsModalBoundary>
            </Show>

            <Show when={settingsOpen()}>
                <SettingsModalBoundary surface="Settings" onClose={() => setSettingsOpen(false)}>
                    <SettingsPanel
                        api={props.api}
                        codexLoginAvailable={props.codexLoginAvailable}
                        managedInferenceEditable={props.managedInferenceEditable}
                        librarySyncAvailable={props.librarySyncAvailable}
                        accountAvailable={accountAvailable()}
                        initialRoom={settingsRoom()}
                        hubUrl={props.hubUrl}
                        openExternal={props.openExternal}
                        // Enrolling a phone and pairing a separate party are multi-step
                        // handshakes the Devices modal owns; Settings lists their standing
                        // result and hands off rather than growing a second copy of them.
                        onEnrollDevice={() => {
                            setSettingsOpen(false);
                            setDevicesOpen(true);
                        }}
                        onPairParty={() => {
                            setSettingsOpen(false);
                            setDevicesOpen(true);
                        }}
                        onClose={() => setSettingsOpen(false)}
                    />
                </SettingsModalBoundary>
            </Show>
        </>
    );
}
