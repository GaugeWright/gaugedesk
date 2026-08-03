/**
 * Open-source settings slot for the workbench build. It keeps local/free surfaces
 * reachable while excluding enterprise governance and private managed-service UI
 * modules from the open bundle.
 */

import { createEffect, createSignal, ErrorBoundary, on, Show, type Accessor, type JSX } from "solid-js";
import type { PlacementPolicy } from "@gaugewright/control-plane-client";
import { AccountPanel, type AccountPanelApi } from "./AccountPanel";
import { DevicesModal, type DevicesModalApi } from "./DevicesModal";

export interface SettingsMenuApi extends AccountPanelApi, DevicesModalApi {}

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
    /** A monotonically increasing counter; each increment opens the Account panel.
     *  Lets another surface (e.g. an in-chat "no model" prompt) open settings. */
    openAccount?: Accessor<number>;
    /** FED-7: an OS-delivered `gaugewright://invite` deep link. Each non-empty value opens the
     *  Devices modal seeded with that link, so its consent preview renders immediately. */
    openInvite?: Accessor<string>;
    /** End the authenticated account session. Omitted on surfaces without account login. */
    onSignOut?: () => void | Promise<void>;
    /** A labelled trigger lets the hosted Console expose this as an account menu
     * instead of reusing the workbench's icon-only settings control. */
    triggerLabel?: string;
    /** A capability-gated Environment action supplied by the app composition. */
    environmentAction?: SettingsEnvironmentAction;
    /** Authenticated org floor supplied only by an enrolled composition. */
    placementPolicy?: Accessor<PlacementPolicy | undefined>;
}): JSX.Element {
    const [menuOpen, setMenuOpen] = createSignal(false);
    const [devicesOpen, setDevicesOpen] = createSignal(false);
    const [accountOpen, setAccountOpen] = createSignal(false);
    const [inviteSeed, setInviteSeed] = createSignal("");
    const [signOutBusy, setSignOutBusy] = createSignal(false);
    const [signOutError, setSignOutError] = createSignal("");

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

    // Open the Account panel when an external request comes in (defer the initial run
    // so we never pop it open on mount).
    createEffect(
        on(
            () => props.openAccount?.() ?? 0,
            () => {
                setMenuOpen(false);
                setAccountOpen(true);
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
                setAccountOpen(false);
                setInviteSeed(url);
                setDevicesOpen(true);
            },
            { defer: true },
        ),
    );

    return (
        <div class="settings-anchor">
            <button
                type="button"
                class="settings-gear"
                classList={{ active: menuOpen(), "settings-gear-labeled": Boolean(props.triggerLabel) }}
                data-settings
                title={props.triggerLabel ?? "Settings"}
                aria-label={props.triggerLabel ?? "Settings"}
                aria-haspopup="menu"
                aria-expanded={menuOpen()}
                onClick={() => setMenuOpen((o) => !o)}
            >
                {props.triggerLabel ?? "⚙"}
            </button>

            <Show when={menuOpen()}>
                <div class="popover-catcher" onClick={() => setMenuOpen(false)} />
                <div
                    class="settings-popover"
                    role="menu"
                    data-settings-menu
                    data-open-settings-menu
                    onKeyDown={(e) => e.key === "Escape" && setMenuOpen(false)}
                >
                    <button
                        type="button"
                        class="settings-option"
                        role="menuitem"
                        data-settings-devices
                        title="Your devices, and connecting a separate party"
                        onClick={() => {
                            setMenuOpen(false);
                            setDevicesOpen(true);
                        }}
                    >
                        Devices
                    </button>
                    <button
                        type="button"
                        class="settings-option"
                        role="menuitem"
                        data-settings-account
                        title="Your linked AI accounts, devices, and settings"
                        onClick={() => {
                            setMenuOpen(false);
                            setAccountOpen(true);
                        }}
                    >
                        Your account
                    </button>
                    <Show when={props.environmentAction?.available()}>
                        <button
                            type="button"
                            class="settings-option"
                            role="menuitem"
                            data-settings-environment
                            onClick={() => {
                                setMenuOpen(false);
                                props.environmentAction?.open();
                            }}
                        >
                            {props.environmentAction?.label}
                        </button>
                    </Show>
                    <Show when={props.onSignOut}>
                        <div class="settings-separator" role="separator" />
                        <button
                            type="button"
                            class="settings-option settings-sign-out"
                            role="menuitem"
                            data-settings-sign-out
                            disabled={signOutBusy()}
                            onClick={() => void signOut()}
                        >
                            {signOutBusy() ? "Signing out…" : "Sign out"}
                        </button>
                        <Show when={signOutError()}>
                            <div class="settings-menu-error" role="alert">{signOutError()}</div>
                        </Show>
                    </Show>
                </div>
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

            <Show when={accountOpen()}>
                <SettingsModalBoundary surface="Your account" onClose={() => setAccountOpen(false)}>
                    <AccountPanel
                        api={props.api}
                        codexLoginAvailable={props.codexLoginAvailable}
                        managedInferenceEditable={props.managedInferenceEditable}
                        librarySyncAvailable={props.librarySyncAvailable}
                        onClose={() => setAccountOpen(false)}
                    />
                </SettingsModalBoundary>
            </Show>
        </div>
    );
}
