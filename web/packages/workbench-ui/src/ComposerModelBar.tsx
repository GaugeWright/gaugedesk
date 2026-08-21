/**
 * The composer's **model + effort** bar.
 *
 * Both controls used to be native `<select>` elements sitting at the reading
 * start of a toolbar below the message field — the model one at `flex: 1`, which
 * made the widest, loudest thing in the composer the least-used decision in it.
 * They are settings, not actions: they state what the next turn will run on, and
 * they only need to be *reachable*, not prominent.
 *
 * Both are now the same object — a quiet text button that opens a menu. They sit
 * in the sans register (`--ui`) rather than the serif chrome register: they are
 * values being reported, not chrome being operated, and the model ids they carry
 * ("GPT-5.1 Codex") read as data.
 *
 * Dropping the native controls also drops the `color-scheme: dark` workaround
 * they needed: the option popup was a white sheet under light `--ink` text on
 * engines that don't honour the hint on the popup.
 */
import { createMemo, For, Show, type JSX } from "solid-js";
import { ComposerMenuButton } from "./ComposerMenu";
import { modelKey, type ModelOption } from "./model-picker";

/** Ascending rank for the catalog's reasoning levels. The catalog lists them in
 *  order today, but the menu's ordering is a claim about the scale, so it is
 *  asserted here rather than inherited from array order. */
const EFFORT_RANK: Record<string, number> = {
    off: 0,
    minimal: 1,
    low: 2,
    medium: 3,
    high: 4,
    xhigh: 5,
};

export interface ComposerModelBarProps {
    /** Catalog + linked-account models, already filtered to what's reachable. */
    readonly options: readonly ModelOption[];
    /** The selected `modelKey`, or `""` for the archetype's default. */
    readonly value: string;
    readonly onPick: (key: string) => void;
    /** Reasoning levels the pinned model supports. Absent or all-`off` hides the control. */
    readonly effortLevels?: readonly string[];
    /** The pinned level, or `""` for the model's own default. */
    readonly effort?: string;
    readonly onPickEffort?: (level: string) => void;
    /** Free-text model entry for endpoint-configurable providers (ADR 0083). It
     *  lives inside the model menu rather than as a second top-level control —
     *  it is the same decision, taken a different way. */
    readonly customModel?: {
        readonly value: string;
        readonly onInput: (value: string) => void;
        readonly onCommit: (value: string) => void;
    };
    /** Stacked rows instead of an inline pair — how the narrow rail's expander
     *  menu presents the same two controls. */
    readonly stacked?: boolean;
}

export function ComposerModelBar(props: ComposerModelBarProps): JSX.Element {
    const effortLevels = createMemo(() =>
        [...(props.effortLevels ?? [])]
            .filter((level) => level !== "off")
            .sort((a, b) => (EFFORT_RANK[a] ?? 99) - (EFFORT_RANK[b] ?? 99)),
    );
    const selected = () =>
        props.options.find((option) => (option.id ? modelKey(option) : "") === props.value);
    return (
        <div class="composer-models" classList={{ stacked: props.stacked }}>
            <ComposerMenuButton
                label={selected()?.label ?? "Default model"}
                title="Model for this chat — overrides the Agent's default for this conversation only"
                testAttr="model"
                stacked={props.stacked}
                rowLabel="Model"
            >
                {(close) => (
                    <>
                        <For each={props.options}>
                            {(option) => {
                                const key = option.id ? modelKey(option) : "";
                                return (
                                    <button
                                        class="composer-menu-item"
                                        classList={{ selected: key === props.value }}
                                        type="button"
                                        role="menuitemradio"
                                        aria-checked={key === props.value}
                                        data-model-option={key}
                                        onClick={() => {
                                            props.onPick(key);
                                            close();
                                        }}
                                    >
                                        <span>{option.label}</span>
                                        <Show when={option.provider}>
                                            <small>{option.provider}</small>
                                        </Show>
                                    </button>
                                );
                            }}
                        </For>
                        <Show when={props.customModel}>
                            <label class="composer-menu-custom">
                                <span>Custom model id</span>
                                <input
                                    data-custom-model
                                    aria-label="Custom model id for this chat"
                                    placeholder="e.g. llama-3.3-70b"
                                    value={props.customModel!.value}
                                    onInput={(event) => props.customModel!.onInput(event.currentTarget.value)}
                                    onKeyDown={(event) => {
                                        if (event.key !== "Enter") return;
                                        props.customModel!.onCommit(event.currentTarget.value);
                                        close();
                                    }}
                                />
                            </label>
                        </Show>
                    </>
                )}
            </ComposerMenuButton>

            <Show when={effortLevels().length > 0 && props.onPickEffort}>
                <ComposerMenuButton
                    label={props.effort || "auto"}
                    title="Reasoning effort for this chat — higher is more deliberate (slower, costlier); auto uses the model's own setting"
                    testAttr="effort"
                    stacked={props.stacked}
                    rowLabel="Effort"
                >
                    {(close) => (
                        // `auto` leads because it is the unpinned state: getting back
                        // to the model's own setting stays inside the same control.
                        <For each={["", ...effortLevels()]}>
                            {(level) => (
                                <button
                                    class="composer-menu-item"
                                    classList={{ selected: level === (props.effort ?? "") }}
                                    type="button"
                                    role="menuitemradio"
                                    aria-checked={level === (props.effort ?? "")}
                                    data-effort-level={level || "auto"}
                                    onClick={() => {
                                        props.onPickEffort!(level);
                                        close();
                                    }}
                                >
                                    <span>{level || "auto"}</span>
                                </button>
                            )}
                        </For>
                    )}
                </ComposerMenuButton>
            </Show>
        </div>
    );
}
