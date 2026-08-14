/**
 * The workbench's bottom-left **account menu** — the prototype of the surface that
 * replaces the settings gear.
 *
 * The gear it replaces answered nothing: it never said who you were or whether you
 * were signed in (sign-out rendered on a handler being supplied, not on session
 * state), and its three items hid a single modal carrying eleven sections across
 * four unrelated concerns — identity, model access, behaviour, and machines — with
 * devices listed both there and beside it.
 *
 * The rule this menu keeps: **the menu is a door, not a room.** It names who you
 * are, what this client is, and where to go. Anything with more than one control
 * belongs behind Settings, which owns its own navigation.
 *
 * The trigger is the identity, so session state is legible without opening
 * anything — the previous surface could only answer "am I signed in?" from inside
 * the modal it gated.
 */
import { For, Show, type JSX } from "solid-js";

/**
 * Which composition is rendering. It changes what the menu may offer, rather than
 * being decorated onto each item: `desk` is a browser thin client of the
 * federation model and deliberately **not an account surface** (ADR 0130/0131), so
 * it names the Home it reaches instead of an account; `enterprise` adds governance
 * its bundle owns and the open build must not import.
 */
export type MenuComposition = "desktop" | "desk" | "enterprise";

export interface MenuIdentity {
    readonly name: string;
    readonly email?: string;
    /** The edition or plan this account carries, shown beside the name. */
    readonly edition?: string;
}

export interface AccountMenuItem {
    readonly id: string;
    readonly label: string;
    /** A rule between groups. Declared, not inferred from the id: matching on a
     *  magic id renders any near-miss (`separator-2`) as an empty, clickable row. */
    readonly separator?: boolean;
    /** Shown right-aligned: a keyboard shortcut, or a value the row reports. */
    readonly hint?: string;
    /** Renders a disclosure arrow — the row opens a further surface, not an action. */
    readonly submenu?: boolean;
    readonly danger?: boolean;
    readonly run: () => void;
}

export interface AccountMenuProps {
    readonly composition: MenuComposition;
    /** The signed-in person, or `null`. `null` is a real state, not a missing prop. */
    readonly identity: MenuIdentity | null;
    /** This client's build, reported once — not spent on permanent chrome. */
    readonly version: string;
    /** The Home this client reaches. The only identity `desk` has to show. */
    readonly reach?: string;
    readonly items: readonly AccountMenuItem[];
    readonly open: boolean;
    readonly onToggle: () => void;
}

export function AccountMenu(props: AccountMenuProps): JSX.Element {
    // `desk` never claims an account. Everywhere else, an absent identity is stated
    // rather than left blank, so "signed out" and "still loading" cannot look alike.
    const showsAccount = () => props.composition !== "desk";
    const triggerLabel = () => {
        if (!showsAccount()) return props.reach ?? "This computer";
        return props.identity?.name ?? "Sign in";
    };
    // The second line only when it adds something. A name already proves the session, and
    // "Sign in" already states its absence, so restating either under itself is two lines
    // saying one thing. The trigger holds its height so signing in doesn't shift the column.
    const triggerDetail = () => {
        if (!showsAccount()) return "browser client";
        return props.identity?.edition ?? null;
    };
    const initials = () => {
        const name = props.identity?.name;
        if (!showsAccount() || !name) return null;
        return name.split(/\s+/).slice(0, 2).map((part) => part[0]?.toUpperCase() ?? "").join("");
    };

    return (
        <div class="account-anchor">
            <button
                type="button"
                class="account-trigger"
                classList={{ active: props.open }}
                data-account-menu-trigger
                aria-haspopup="menu"
                aria-expanded={props.open}
                onClick={() => props.onToggle()}
            >
                <Show
                    when={initials()}
                    fallback={<span class="account-avatar account-avatar-anon" aria-hidden="true">◇</span>}
                >
                    {(text) => <span class="account-avatar" aria-hidden="true">{text()}</span>}
                </Show>
                <span class="account-trigger-text">
                    <span class="account-trigger-name">{triggerLabel()}</span>
                    <Show when={triggerDetail()}>
                        {(detail) => <span class="account-trigger-detail">{detail()}</span>}
                    </Show>
                </span>
                <span class="account-trigger-caret" aria-hidden="true">⌃</span>
            </button>

            <Show when={props.open}>
                <div class="popover-catcher" onClick={() => props.onToggle()} />
                <div class="account-popover" role="menu" data-account-menu>
                    {/* The header states the account rather than repeating the trigger:
                        the trigger carries the name, so this carries the address that
                        proves *which* account it is. */}
                    <div class="account-menu-head">
                        <Show
                            when={showsAccount()}
                            fallback={
                                <>
                                    <span class="account-menu-identity">{props.reach ?? "This computer"}</span>
                                    <span class="account-menu-sub">
                                        This browser reaches your work; it holds no account.
                                    </span>
                                </>
                            }
                        >
                            <span class="account-menu-identity">
                                {props.identity?.email ?? props.identity?.name ?? "Not signed in"}
                            </span>
                            <Show when={props.reach}>
                                {(home) => <span class="account-menu-sub">on {home()}</span>}
                            </Show>
                        </Show>
                        <span class="account-menu-version" data-app-version>GaugeDesk v{props.version}</span>
                    </div>

                    <For each={props.items}>
                        {(item) => (
                            <Show
                                when={!item.separator}
                                fallback={<div class="account-menu-separator" role="separator" />}
                            >
                                <button
                                    type="button"
                                    class="account-menu-item"
                                    classList={{ danger: item.danger }}
                                    role="menuitem"
                                    data-account-menu-item={item.id}
                                    onClick={() => item.run()}
                                >
                                    <span class="account-menu-label">{item.label}</span>
                                    <Show when={item.hint}>
                                        {(hint) => <span class="account-menu-hint">{hint()}</span>}
                                    </Show>
                                    <Show when={item.submenu}>
                                        <span class="account-menu-more" aria-hidden="true">›</span>
                                    </Show>
                                </button>
                            </Show>
                        )}
                    </For>
                </div>
            </Show>
        </div>
    );
}
