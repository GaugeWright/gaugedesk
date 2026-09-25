/**
 * A right-click context menu — the nav's CRUD affordance (ADR 0027). A node
 * opens this with a list of actions; it positions at the cursor and dismisses on
 * outside-click or Escape.
 *
 * Destructive actions use an **inline confirm** (a second click on a "confirm"
 * row), never a browser `confirm()` dialog — modal dialogs block automation and
 * are disallowed in this environment.
 */

import { createEffect, createSignal, For, onCleanup, Show } from "solid-js";
import { Icon, type IconName } from "./icons";

export interface MenuItem {
    readonly label: string;
    readonly run: () => void;
    readonly icon?: IconName;
    /** Marks the chosen option in a menu used as a single-choice picker. */
    readonly selected?: boolean;
    /** Destructive items require a confirming second click. */
    readonly danger?: boolean;
    /** An optional one-line explanation, carried on the item's **tooltip** (not a
     *  visible sub-line) — explains a menu action in plain words on hover (#2 round
     *  5; sub-line removed round-12 E). */
    readonly hint?: string;
    /** An optional one-line warning shown under the label *while armed* — used to
     *  state a destructive action's blast radius before the confirming second
     *  click (round-6 #6), e.g. "also removes 2 methods and their chats". */
    readonly confirmHint?: string;
}

export interface MenuState {
    readonly x: number;
    readonly y: number;
    readonly items: MenuItem[];
}

export function ContextMenu(props: { menu: MenuState | null; onClose: () => void }) {
    const [confirming, setConfirming] = createSignal<number | null>(null);
    // The on-screen position. We open at the cursor, then clamp so the menu never
    // spills past the viewport edge — a tall nav tree puts nodes near the bottom,
    // and an un-clamped menu would open below the fold with its lower items
    // unclickable (a forgiveness/self-evident-actions defect, not just a test snag).
    const [pos, setPos] = createSignal<{ x: number; y: number } | null>(null);
    let menuEl: HTMLDivElement | undefined;
    // A freshly opened (or closed) menu starts unarmed, and is re-clamped to fit.
    createEffect(() => {
        const m = props.menu;
        setConfirming(null);
        setPos(m ? { x: m.x, y: m.y } : null);
        if (!m || typeof window === "undefined") return;
        // Measure after the menu has painted, then nudge it fully on-screen.
        queueMicrotask(() => {
            if (!menuEl) return;
            const r = menuEl.getBoundingClientRect();
            const pad = 6;
            const x = Math.max(pad, Math.min(m.x, window.innerWidth - r.width - pad));
            const y = Math.max(pad, Math.min(m.y, window.innerHeight - r.height - pad));
            setPos({ x, y });
        });
    });

    // A *native* document listener (Solid delegates events, so synthetic
    // stopPropagation inside the menu wouldn't shield this). Ignore clicks landing
    // inside the menu; any other click dismisses it.
    const onDocClick = (e: MouseEvent) => {
        if (menuEl && e.target instanceof Node && menuEl.contains(e.target)) return;
        props.onClose();
    };
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && props.onClose();
    document.addEventListener("click", onDocClick);
    document.addEventListener("keydown", onKey);
    onCleanup(() => {
        document.removeEventListener("click", onDocClick);
        document.removeEventListener("keydown", onKey);
    });

    return (
        <Show when={props.menu}>
            {(m) => (
                <div
                    ref={menuEl}
                    class="context-menu"
                    role="menu"
                    style={{ left: `${(pos() ?? m()).x}px`, top: `${(pos() ?? m()).y}px` }}
                >
                    <For each={m().items}>
                        {(item, i) => (
                            <button
                                class="menu-item"
                                role={item.selected === undefined ? "menuitem" : "menuitemradio"}
                                aria-checked={item.selected}
                                // The explanatory hint rides on the tooltip, not a visible
                                // sub-line (round-12 E): no help sub-lines anywhere.
                                title={item.hint}
                                classList={{ danger: item.danger, confirming: confirming() === i(), "has-hint": !!item.confirmHint && confirming() === i() }}
                                onClick={() => {
                                    if (item.danger && confirming() !== i()) {
                                        setConfirming(i());
                                        return;
                                    }
                                    props.onClose();
                                    item.run();
                                }}
                            >
                                <Show when={item.selected !== undefined}>
                                    <span class="menu-item-check" aria-hidden="true">{item.selected ? "✓" : ""}</span>
                                </Show>
                                <Show when={item.icon} keyed>{(icon) => <Icon name={icon} class="menu-item-icon" />}</Show>
                                <span class="menu-item-label">{confirming() === i() ? `confirm: ${item.label}` : item.label}</span>
                                {/* The destructive blast-radius warning is NOT a help
                                    sub-line — it appears only while armed, at the moment
                                    of an irreversible confirm, where a tooltip can't be
                                    seen (round-6 #6). It stays. */}
                                <Show when={item.confirmHint && confirming() === i()}>
                                    <span class="menu-item-hint warn">{item.confirmHint}</span>
                                </Show>
                            </button>
                        )}
                    </For>
                </div>
            )}
        </Show>
    );
}
