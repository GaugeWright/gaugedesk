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
import { PRODUCT_ANALYTICS_SETTING, type PlacementPolicy, type ProductAnalyticsPolicy } from "@gaugewright/control-plane-client";
import { AccountMenu, type AccountMenuItem, type MenuComposition } from "./AccountMenu";
import { SettingsPanel, type SettingsPanelApi } from "./SettingsPanel";
import type { SettingsRoom } from "./SettingsSurface";
import { DevicesModal, type DevicesModalApi } from "./DevicesModal";
import { LocalProjectTransferDialog, localProjectTransferLabel, type LocalProjectTransferOffer } from "./LocalProjectTransferDialog";

export interface SettingsMenuApi extends SettingsPanelApi, DevicesModalApi {
    productAnalyticsPolicy?(tenant: string): Promise<ProductAnalyticsPolicy>;
    productAnalyticsSetTenantDisabled?(tenant: string, disabled: boolean): Promise<void>;
}

/** Optional product Environment supplied by a composing application. The open
 *  workbench owns the menu seam but knows nothing about enterprise modules. */
export interface SettingsEnvironmentAction {
    readonly label: string;
    readonly available: Accessor<boolean>;
    readonly open: () => void;
}

/** Person-scoped GaugeApp destinations supplied by a hosted composition.
 * When present they replace the legacy modal rows rather than being added beside
 * them: Account Settings is the replacement surface, not a second settings UI. */
export interface SettingsGaugeAppAction {
    readonly id: string;
    readonly label: string;
    readonly open: () => void;
}

export interface SettingsAccountChoice {
    readonly person: string;
    readonly label: string;
    readonly selected: boolean;
    readonly expired: boolean;
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
    /** The same pulse for the Model access room: the composer's "Add a model…"
     *  when nothing is pickable opens where a model comes from. */
    openModels?: Accessor<number>;
    /** Settings changed something the account holds (a credential, a declared
     *  model, the picker's enabled set); the composition re-reads what it
     *  projects from the account. */
    onAccountChanged?: () => void;
    /** FED-7: an OS-delivered `gaugewright://invite` deep link. Each non-empty value opens the
     *  Devices modal seeded with that link, so its consent preview renders immediately. */
    openInvite?: Accessor<string>;
    /** End the authenticated account session. Omitted on surfaces without account login. */
    onSignOut?: () => void | Promise<void>;
    /** Begin the composition-owned account ceremony. GaugeApp compositions use
     * this instead of reopening the retired local Settings account room. */
    onSignIn?: () => void | Promise<void>;
    /** A capability-gated Environment action supplied by the app composition. */
    environmentAction?: SettingsEnvironmentAction;
    /** Server-discovered Account Settings pages. An empty admitted list is
     * rendered as empty; it never falls back to the retired modal. */
    gaugeAppActions?: Accessor<readonly SettingsGaugeAppAction[]>;
    /** Retained sign-ins shown only after Change account is opened. */
    accountChoices?: Accessor<readonly SettingsAccountChoice[]>;
    onSelectAccount?: (person: string) => void;
    onAddAccount?: () => void;
    onUseLocal?: () => void;
    /** The selected native local account has no external sign-in to end. */
    localAccount?: Accessor<boolean>;
    /** Signed-out projects on this computer the signed-in account could
     *  receive (DR-0328 §7). The menu offers the move only while it is set. */
    localProjectTransfer?: Accessor<LocalProjectTransferOffer | null>;
    onTransferLocalProjects?: (projects: readonly string[]) => Promise<void>;
    switchingAccount?: Accessor<boolean>;
    accountSwitchError?: Accessor<string>;
    /** Authenticated org floor supplied only by an enrolled composition. */
    placementPolicy?: Accessor<PlacementPolicy | undefined>;
    /** Hosted product analytics is anchored to the selected account and tenant. */
    analyticsAvailable?: boolean;
    analyticsTenant?: Accessor<{ readonly id: string; readonly personal: boolean } | null>;
    /** How this runtime opens a URL in the person's browser — the desktop shell's
     *  seam, since its webview silently drops `window.open`. Passed through to
     *  Settings; absent means `window.open` (right for browser builds). */
    openExternal?: (url: string) => Promise<boolean>;
}): JSX.Element {
    const [menuOpen, setMenuOpen] = createSignal(false);
    const [accountPickerOpen, setAccountPickerOpen] = createSignal(false);
    const [devicesOpen, setDevicesOpen] = createSignal(false);
    const [settingsOpen, setSettingsOpen] = createSignal(false);
    const [privacyOpen, setPrivacyOpen] = createSignal(false);
    const [transferOpen, setTransferOpen] = createSignal(false);
    const transferOffer = () => (props.onTransferLocalProjects && !props.localAccount?.()
        ? props.localProjectTransfer?.() ?? null
        : null);
    const [privacyPolicy, setPrivacyPolicy] = createSignal<ProductAnalyticsPolicy | null>(null);
    const [privacyBusy, setPrivacyBusy] = createSignal(false);
    const [privacyError, setPrivacyError] = createSignal("");
    const loadPrivacy = async () => {
        const tenant = props.analyticsTenant?.();
        if (!tenant || !props.api.productAnalyticsPolicy) return;
        setPrivacyBusy(true);
        setPrivacyError("");
        setPrivacyPolicy(null);
        try {
            setPrivacyPolicy(await props.api.productAnalyticsPolicy(tenant.id));
        } catch {
            setPrivacyPolicy(null);
            setPrivacyError("Privacy settings are unavailable. Try again.");
        } finally {
            setPrivacyBusy(false);
        }
    };
    const changePrivacy = async (kind: "person" | "tenant", enabled: boolean) => {
        const tenant = props.analyticsTenant?.();
        if (!tenant || !props.api.productAnalyticsPolicy || !props.api.productAnalyticsSetTenantDisabled) return;
        setPrivacyBusy(true);
        setPrivacyError("");
        try {
            if (kind === "person") {
                await props.api.accountSetSetting(PRODUCT_ANALYTICS_SETTING, enabled ? "true" : "false");
            } else {
                await props.api.productAnalyticsSetTenantDisabled(tenant.id, !enabled);
            }
            setPrivacyPolicy(await props.api.productAnalyticsPolicy(tenant.id));
        } catch {
            setPrivacyError("Could not change the privacy setting. Try again.");
        } finally {
            setPrivacyBusy(false);
        }
    };
    // Which room Settings lands in for *this* opening. Held here because the opener knows
    // the reason: the menu's own row means Account, an in-chat model refusal means Model
    // access. Remounting Settings each time is what makes the seed take.
    const [settingsRoom, setSettingsRoom] = createSignal<SettingsRoom>("account");
    const openSettingsAt = (room: SettingsRoom) => {
        setSettingsRoom(room);
        setSettingsOpen(true);
    };
    const [inviteSeed, setInviteSeed] = createSignal("");
    const [signInBusy, setSignInBusy] = createSignal(false);
    const [signInError, setSignInError] = createSignal("");
    const [signOutBusy, setSignOutBusy] = createSignal(false);
    const [signOutError, setSignOutError] = createSignal("");

    const toggleMenu = () => {
        if (!menuOpen()) {
            // A failure belongs to the opening in which it happened. Reopening
            // starts a fresh attempt instead of resurrecting an obsolete alert.
            setSignInError("");
            setSignOutError("");
        }
        setAccountPickerOpen(false);
        setMenuOpen((open) => !open);
    };

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

    const signIn = async () => {
        if (!props.onSignIn || signInBusy()) return;
        setSignInBusy(true);
        setSignInError("");
        try {
            await props.onSignIn();
            setMenuOpen(false);
        } catch (error) {
            setSignInError(error instanceof Error ? error.message : "Sign in could not be started. Please try again.");
        } finally {
            setSignInBusy(false);
        }
    };

    const items = (): AccountMenuItem[] => {
        if (accountPickerOpen()) {
            const busy = props.switchingAccount?.() ?? false;
            return [
                { id: "account-picker-back", label: "‹ Account menu", run: () => setAccountPickerOpen(false) },
                { id: "account-picker-rule", label: "", separator: true, run: () => {} },
                ...(props.accountChoices?.() ?? []).map((account): AccountMenuItem => ({
                    id: `account-${account.person}`,
                    label: account.label,
                    hint: account.selected ? "Current" : account.expired ? "Sign in again" : undefined,
                    disabled: busy || account.selected || account.expired,
                    run: () => props.onSelectAccount?.(account.person),
                })),
                { id: "account-picker-actions-rule", label: "", separator: true, run: () => {} },
                { id: "add-account", label: "Add account", disabled: busy, run: () => {
                    setMenuOpen(false);
                    setAccountPickerOpen(false);
                    props.onAddAccount?.();
                } },
                ...(props.onUseLocal ? [{
                    id: "use-local", label: "Local account", hint: props.localAccount?.() ? "Current" : undefined,
                    disabled: busy || props.localAccount?.(),
                    run: () => props.onUseLocal?.(),
                }] : []),
            ];
        }
        const supplied = props.gaugeAppActions;
        const rows: AccountMenuItem[] = supplied
            ? supplied().map((action) => ({
                id: `gaugeapp-${action.id}`,
                label: action.label,
                submenu: true,
                run: () => {
                    setMenuOpen(false);
                    action.open();
                },
            }))
            : [
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
        if (accountAvailable() && props.analyticsAvailable && props.analyticsTenant?.()
            && props.api.productAnalyticsPolicy && props.api.productAnalyticsSetTenantDisabled) {
            rows.push({
                id: "privacy-analytics",
                label: "Privacy & analytics",
                submenu: true,
                run: () => {
                    setMenuOpen(false);
                    setPrivacyOpen(true);
                    void loadPrivacy();
                },
            });
        }
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
        const offer = transferOffer();
        if (offer && offer.projects.length > 0) {
            rows.push({
                id: "move-local-projects",
                label: localProjectTransferLabel(offer.account),
                submenu: true,
                run: () => {
                    setMenuOpen(false);
                    setTransferOpen(true);
                },
            });
        }
        if ((props.accountChoices?.().length ?? 0) > 0 || props.onUseLocal) {
            rows.push({
                id: "change-account",
                label: "Change account",
                submenu: true,
                run: () => setAccountPickerOpen(true),
            });
        }
        // The session verb follows the session, not the presence of a handler — that is
        // how the gear came to offer "Sign out" to someone who was signed out. Where this
        // composition holds no account at all there is no verb to offer.
        if (accountAvailable()) {
            rows.push({ id: "session-rule", label: "", separator: true, run: () => {} });
            if (!props.identity?.() || props.localAccount?.()) {
                // The trigger reads "Sign in"; this is where that promise is kept.
                rows.push({
                    id: "sign-in",
                    label: signInBusy() ? "Starting sign in…" : "Sign in",
                    disabled: signInBusy(),
                    run: () => {
                        if (props.onSignIn) void signIn();
                        else {
                            setMenuOpen(false);
                            openSettingsAt("account");
                        }
                    },
                });
            } else if (props.onSignOut) {
                rows.push({
                    id: "sign-out",
                    label: signOutBusy() ? "Signing out…" : "Sign out",
                    danger: true,
                    disabled: signOutBusy(),
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

    createEffect(on(
        () => props.analyticsTenant?.()?.id,
        () => {
            setPrivacyOpen(false);
            setPrivacyPolicy(null);
        },
        { defer: true },
    ));

    createEffect(
        on(
            () => props.openModels?.() ?? 0,
            () => {
                setMenuOpen(false);
                openSettingsAt("models");
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
                status={signInError() || signOutError() || (accountPickerOpen() ? props.accountSwitchError?.() : "")}
                open={menuOpen()}
                onToggle={toggleMenu}
            />

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
                        onChanged={props.onAccountChanged}
                        onClose={() => setSettingsOpen(false)}
                    />
                </SettingsModalBoundary>
            </Show>
            <Show when={transferOpen() && transferOffer()}>
                {(offer) => (
                    <SettingsModalBoundary surface="Move signed-out projects" onClose={() => setTransferOpen(false)}>
                        <LocalProjectTransferDialog
                            offer={offer()}
                            onMove={(projects) => props.onTransferLocalProjects!(projects)}
                            onClose={() => setTransferOpen(false)}
                        />
                    </SettingsModalBoundary>
                )}
            </Show>
            <Show when={privacyOpen()}>
                <SettingsModalBoundary surface="Privacy & analytics" onClose={() => setPrivacyOpen(false)}>
                    <div class="modal-overlay" onClick={() => setPrivacyOpen(false)}>
                        <div class="modal privacy-analytics-modal" onClick={(event) => event.stopPropagation()}>
                            <div class="modal-head">
                                <h3>Privacy & analytics</h3>
                                <button type="button" onClick={() => setPrivacyOpen(false)}>close</button>
                            </div>
                            <p>GaugeDesk measures feature use and whether actions complete or fail to improve the product. Events include your account, selected organization, app version, and platform. They do not include your chats, prompts, files, names, or credentials.</p>
                            <Show when={privacyPolicy()} fallback={<p role="status">{privacyBusy() ? "Loading privacy settings…" : privacyError()}</p>}>
                                {(policy) => <>
                                    <label>
                                        <input
                                            type="checkbox"
                                            checked={policy().person_enabled}
                                            disabled={privacyBusy()}
                                            onChange={(event) => void changePrivacy("person", event.currentTarget.checked)}
                                        />
                                        Share product usage from this account
                                    </label>
                                    <Show when={!props.analyticsTenant?.()?.personal && policy().can_manage_tenant}>
                                        <label>
                                            <input
                                                type="checkbox"
                                                checked={!policy().tenant_disabled}
                                                disabled={privacyBusy() || policy().tenant_locked_off}
                                                onChange={(event) => void changePrivacy("tenant", event.currentTarget.checked)}
                                            />
                                            Allow product analytics for this organization
                                        </label>
                                    </Show>
                                    <Show when={policy().tenant_disabled}>
                                        <p>Product analytics is off for this organization, regardless of your account setting.{policy().tenant_locked_off ? " This setting is locked by GaugeWright for a regulated organization." : ""}</p>
                                    </Show>
                                </>}
                            </Show>
                            <Show when={privacyPolicy() && privacyError()}><p role="alert">{privacyError()}</p></Show>
                            <p><a href="https://gaugewright.com/privacy" target="_blank" rel="noopener noreferrer">Privacy notice</a></p>
                        </div>
                    </div>
                </SettingsModalBoundary>
            </Show>
        </>
    );
}
