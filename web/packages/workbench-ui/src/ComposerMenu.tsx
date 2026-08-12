/**
 * The composer's settings control: a quiet text button that opens a menu above
 * itself.
 *
 * Model, effort and the default delivery mode are all the same kind of thing —
 * a value the next turn will run under — so they are all the same object. They
 * sit in the sans register (`--ui`) rather than the serif chrome register: these
 * report values, and values are read, not operated.
 */
import { createSignal, Show, type JSX } from "solid-js";
import { Icon, type IconName } from "./icons";

export function ComposerMenuButton(props: {
    readonly label: string;
    readonly title: string;
    /** Names the `data-*-picker` hook and the menu's `data-*-menu` sibling. */
    readonly testAttr: string;
    /** Row caption used by the compact expander's stacked form. */
    readonly rowLabel: string;
    readonly stacked?: boolean;
    /** Leading glyph, for settings whose value is itself iconic (the mode). */
    readonly icon?: IconName;
    readonly children: (close: () => void) => JSX.Element;
}): JSX.Element {
    const [open, setOpen] = createSignal(false);
    return (
        <span class="composer-menu-anchor" classList={{ row: props.stacked }}>
            <Show when={props.stacked}>
                <span class="composer-menu-row-label">{props.rowLabel}</span>
            </Show>
            <button
                class="composer-menu-btn"
                type="button"
                {...{ [`data-${props.testAttr}-picker`]: "" }}
                aria-haspopup="menu"
                aria-expanded={open()}
                title={props.title}
                onClick={() => setOpen((was) => !was)}
            >
                <Show when={props.icon}>
                    <Icon name={props.icon!} class="lead" />
                </Show>
                <span>{props.label}</span>
                <Icon name="chevron" class="chev" />
            </button>
            <Show when={open()}>
                <div class="popover-catcher" onClick={() => setOpen(false)} />
                <div
                    class="composer-menu"
                    role="menu"
                    {...{ [`data-${props.testAttr}-menu`]: "" }}
                    onKeyDown={(event) => event.key === "Escape" && setOpen(false)}
                >
                    {props.children(() => setOpen(false))}
                </div>
            </Show>
        </span>
    );
}
