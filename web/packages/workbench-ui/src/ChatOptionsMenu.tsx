/** Secondary chat controls behind one clearly named top-left menu. */
import { createSignal, Show, type JSX } from "solid-js";
import { Icon } from "./icons";
import { TranscriptFilterMenu } from "./TranscriptFilterMenu";
import { isFiltering, type FilterPrefs } from "./transcript-filter";

export interface ChatOptionsMenuProps {
    readonly prefs: FilterPrefs;
    readonly onFilterChange: (next: FilterPrefs) => void;
    readonly onSaveFilterDefault: () => void;
    readonly onHistory: () => void;
    readonly onSources: () => void;
}

export function ChatOptionsMenu(props: ChatOptionsMenuProps): JSX.Element {
    const [open, setOpen] = createSignal(false);
    const [view, setView] = createSignal<"options" | "filters">("options");
    const [position, setPosition] = createSignal({ left: 0, top: 0 });
    let trigger: HTMLButtonElement | undefined;
    const show = () => {
        const rect = trigger?.getBoundingClientRect();
        if (rect) setPosition({
            left: Math.max(6, Math.min(rect.left, window.innerWidth - 248)),
            top: rect.bottom + 4,
        });
        setOpen(true);
    };
    const close = () => {
        setOpen(false);
        setView("options");
    };
    const openSurface = (run: () => void) => {
        close();
        run();
    };

    return (
        <div class="chat-options-anchor">
            <button
                ref={trigger}
                type="button"
                class="chat-options-trigger"
                classList={{ active: open() }}
                data-chat-options-trigger
                aria-label="Chat menu"
                title="Chat menu"
                aria-haspopup="menu"
                aria-expanded={open()}
                onClick={() => open() ? close() : show()}
            >
                <Icon name="menu" />
            </button>
            <Show when={open()}>
                <div class="popover-catcher" onClick={close} />
                <div
                    class="chat-options-popover"
                    data-chat-options-menu
                    role={view() === "options" ? "menu" : "dialog"}
                    aria-label={view() === "options" ? "Chat options" : "Chat filters"}
                    style={{ left: `${position().left}px`, top: `${position().top}px`,
                        "max-height": `${Math.max(160, window.innerHeight - position().top - 8)}px` }}
                    onKeyDown={(event) => {
                        if (event.key === "Escape") {
                            event.stopPropagation();
                            view() === "filters" ? setView("options") : close();
                        }
                    }}
                >
                    <Show when={view() === "options"} fallback={
                        <TranscriptFilterMenu
                            prefs={props.prefs}
                            onChange={props.onFilterChange}
                            onSaveDefault={props.onSaveFilterDefault}
                            onBack={() => setView("options")}
                        />
                    }>
                        <button type="button" role="menuitem" class="chat-options-item"
                            data-open-filters onClick={() => setView("filters")}>
                            Filters <span class="chat-options-item-detail">{isFiltering(props.prefs) ? "On" : ""}</span>
                        </button>
                        <button type="button" role="menuitem" class="chat-options-item"
                            data-open-history onClick={() => openSurface(props.onHistory)}>
                            History
                        </button>
                        <button type="button" role="menuitem" class="chat-options-item"
                            data-open-sources onClick={() => openSurface(props.onSources)}>
                            Context sources
                        </button>
                    </Show>
                </div>
            </Show>
        </div>
    );
}
