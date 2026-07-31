/**
 * The transcript **filter** control: an icon button in the chat header that opens
 * a small popover for tuning how the chat log paints. You can hide each message
 * type and each individual tool (grep, ls, read, write, …), and — for a tool whose
 * calls carry detail — choose whether it opens expanded by default. Tools are
 * organized under group headers (Commands / File writes / File reads / Other);
 * a group header toggles all its tools at once. Pure view state: it edits the
 * {@link FilterPrefs} the host owns and persists, nothing about run truth.
 */

import { createRenderEffect, createSignal, For, Show, type JSX } from "solid-js";
import { Icon } from "./icons";
import {
    defaultPrefs,
    isFiltering,
    MESSAGE_LEAD,
    MESSAGE_TAIL,
    TOOL_GROUPS,
    type FilterPrefs,
    type MessageCategory,
    type ToolPref,
} from "./transcript-filter";
import { type ToolId } from "./tool-verb";

export function TranscriptFilterMenu(props: {
    prefs: FilterPrefs;
    onChange: (next: FilterPrefs) => void;
    /** Persist the current filter as the user's default (survives reloads). */
    onSaveDefault: () => void;
}): JSX.Element {
    const [open, setOpen] = createSignal(false);
    // Brief "Saved" acknowledgement so the persist action has visible feedback —
    // it otherwise changes nothing on screen.
    const [saved, setSaved] = createSignal(false);
    const saveDefault = () => {
        props.onSaveDefault();
        setSaved(true);
    };

    // Any edit invalidates a prior "Saved" acknowledgement (the working filter now
    // differs from what was persisted).
    const change = (next: FilterPrefs) => {
        setSaved(false);
        props.onChange(next);
    };
    const setMessage = (id: MessageCategory, visible: boolean) =>
        change({ ...props.prefs, messages: { ...props.prefs.messages, [id]: visible } });
    const setTool = (id: ToolId, patch: Partial<ToolPref>) =>
        change({
            ...props.prefs,
            tools: { ...props.prefs.tools, [id]: { ...props.prefs.tools[id], ...patch } },
        });
    const setGroup = (ids: readonly ToolId[], visible: boolean) => {
        const tools = { ...props.prefs.tools };
        for (const id of ids) tools[id] = { ...tools[id], visible };
        change({ ...props.prefs, tools });
    };

    return (
        <span class="filter-anchor">
            <button
                class="icon-btn"
                classList={{ active: open(), "filter-on": isFiltering(props.prefs) }}
                data-transcript-filter
                aria-label="Filter the chat log"
                aria-haspopup="menu"
                aria-expanded={open()}
                title="Filter the chat log — hide message and tool types, set what opens expanded"
                onClick={() => {
                    setSaved(false);
                    setOpen((o) => !o);
                }}
            >
                <Icon name="filter" />
            </button>

            <Show when={open()}>
                {/* A transparent catcher so a click anywhere else dismisses the menu. */}
                <div class="popover-catcher" onClick={() => setOpen(false)} />
                <div
                    class="filter-popover"
                    role="menu"
                    data-transcript-filter-menu
                    onKeyDown={(e) => e.key === "Escape" && setOpen(false)}
                >
                    <div class="filter-head">
                        <span class="filter-col-show">show</span>
                        <span class="filter-col-name" />
                        <span class="filter-col-exp">open</span>
                    </div>

                    <For each={MESSAGE_LEAD}>
                        {(m) => (
                            <MessageRow
                                label={m.label}
                                id={m.id}
                                checked={props.prefs.messages[m.id]}
                                onToggle={(v) => setMessage(m.id, v)}
                            />
                        )}
                    </For>

                    <For each={TOOL_GROUPS}>
                        {(grp) => {
                            const ids = grp.tools.map((t) => t.id);
                            const shown = () => ids.filter((id) => props.prefs.tools[id].visible).length;
                            const allOn = () => shown() === ids.length;
                            const someOn = () => shown() > 0 && !allOn();
                            return (
                                <>
                                    <div class="filter-row group" data-filter-group-row={grp.group}>
                                        <input
                                            type="checkbox"
                                            class="filter-show"
                                            data-filter-visible={grp.group}
                                            aria-label={`Show all ${grp.label}`}
                                            checked={allOn()}
                                            ref={(el) => createRenderEffect(() => (el.indeterminate = someOn()))}
                                            onChange={(e) => setGroup(ids, e.currentTarget.checked)}
                                        />
                                        <span class="filter-group-name">{grp.label}</span>
                                        <span class="filter-exp-gap" />
                                    </div>
                                    <For each={grp.tools}>
                                        {(t) => (
                                            <div class="filter-row tool" data-filter-tool-row={t.id}>
                                                <input
                                                    type="checkbox"
                                                    class="filter-show"
                                                    data-filter-tool={t.id}
                                                    aria-label={`Show ${t.label}`}
                                                    checked={props.prefs.tools[t.id].visible}
                                                    onChange={(e) => setTool(t.id, { visible: e.currentTarget.checked })}
                                                />
                                                <span class="filter-name">{t.label}</span>
                                                <Show when={t.expandable} fallback={<span class="filter-exp-gap" />}>
                                                    <input
                                                        type="checkbox"
                                                        class="filter-exp"
                                                        data-filter-expanded={t.id}
                                                        aria-label={`Open ${t.label} expanded by default`}
                                                        title="Open expanded by default"
                                                        disabled={!props.prefs.tools[t.id].visible}
                                                        checked={props.prefs.tools[t.id].expanded}
                                                        onChange={(e) => setTool(t.id, { expanded: e.currentTarget.checked })}
                                                    />
                                                </Show>
                                            </div>
                                        )}
                                    </For>
                                </>
                            );
                        }}
                    </For>

                    <For each={MESSAGE_TAIL}>
                        {(m) => (
                            <MessageRow
                                label={m.label}
                                id={m.id}
                                checked={props.prefs.messages[m.id]}
                                onToggle={(v) => setMessage(m.id, v)}
                            />
                        )}
                    </For>

                    <div class="filter-actions">
                        <button
                            type="button"
                            class="filter-save"
                            classList={{ saved: saved() }}
                            data-filter-save
                            title="Persist this filter as your default — it'll be applied on every reload"
                            onClick={saveDefault}
                        >
                            {saved() ? "Saved ✓" : "Save as default"}
                        </button>
                        <button
                            type="button"
                            class="filter-reset"
                            data-filter-reset
                            title="Restore the product defaults (this session)"
                            onClick={() => change(defaultPrefs)}
                        >
                            Reset
                        </button>
                    </div>
                </div>
            </Show>
        </span>
    );
}

function MessageRow(props: {
    label: string;
    id: MessageCategory;
    checked: boolean;
    onToggle: (visible: boolean) => void;
}): JSX.Element {
    return (
        <div class="filter-row" data-filter-row={props.id}>
            <input
                type="checkbox"
                class="filter-show"
                data-filter-visible={props.id}
                aria-label={`Show ${props.label}`}
                checked={props.checked}
                onChange={(e) => props.onToggle(e.currentTarget.checked)}
            />
            <span class="filter-name">{props.label}</span>
            <span class="filter-exp-gap" />
        </div>
    );
}
