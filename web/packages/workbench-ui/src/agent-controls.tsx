/**
 * The controls an Agent's settings and a Panel agent's public contract share:
 * one model select and one ability-preset picker, so the two pages choose a
 * model and an ability ceiling the same way (DR-0308).
 */

import { For, splitProps, type JSX } from "solid-js";
import type { AgentAbility } from "@gaugewright/control-plane-client";
import { Option } from "./PanelAgentControls";
import type { ModelOption } from "./model-picker";

export const AGENT_ABILITY_PRESETS: ReadonlyArray<{
    name: string;
    value: AgentAbility[];
}> = [
    {
        name: "Chat only",
        value: [],
    },
    {
        name: "Read workspace",
        value: ["workspace.read"],
    },
    {
        name: "Create artifacts",
        value: ["workspace.read", "workspace.write"],
    },
    {
        name: "Run workspace commands",
        value: ["workspace.read", "workspace.write", "command.run"],
    },
];

/** Abilities admitted on top of any preset. Each page offers its own control
 *  for the ones it exposes; the rest ride along unchanged. */
const OPTIONAL_ABILITIES: readonly AgentAbility[] = ["tracker.file", "question.ask"];

export function presetAbilities(abilities: readonly AgentAbility[]): AgentAbility[] {
    return abilities.filter((ability) => !OPTIONAL_ABILITIES.includes(ability)).sort();
}

export function optionalAbilities(abilities: readonly AgentAbility[]): AgentAbility[] {
    return abilities.filter((ability) => OPTIONAL_ABILITIES.includes(ability));
}

/** Why an option beyond the agent's own abilities is disabled. */
export const BEYOND_AGENT_ABILITIES = "Give the agent this ability under its own Abilities first.";

/** The four presets as one radio group. A preset beyond `ceiling` is
 *  disabled unless it is the current one, and says why. `children` adds the
 *  page's own optional abilities beneath. */
export function AbilityPresets(props: {
    name: string;
    abilities: readonly AgentAbility[];
    ceiling?: readonly AgentAbility[];
    onChange: (preset: AgentAbility[]) => void;
    children?: JSX.Element;
}): JSX.Element {
    const current = () => JSON.stringify(presetAbilities(props.abilities));
    const withinCeiling = (preset: readonly AgentAbility[]) =>
        props.ceiling === undefined || preset.every((ability) => props.ceiling!.includes(ability));
    return <div class="pa-options" role="radiogroup" aria-label="Abilities">
        <For each={AGENT_ABILITY_PRESETS}>{(preset) => {
            const checked = () => current() === JSON.stringify([...preset.value].sort());
            const beyond = () => !checked() && !withinCeiling(preset.value);
            return <Option type="radio" name={props.name} checked={checked()}
                disabled={beyond()}
                title={beyond() ? BEYOND_AGENT_ABILITIES : undefined}
                detail={beyond() ? BEYOND_AGENT_ABILITIES : undefined}
                label={preset.name}
                onChange={() => props.onChange([...preset.value])} />;
        }}</For>
        {props.children}
    </div>;
}

/** The default row's wording on every model dropdown: the resolved default by
 *  name ("GPT-6.1 Sol (default)"), or "Default" when none resolves. */
export function defaultModelLabel(choices: readonly ModelOption[]): string {
    return choices.find((choice) => !choice.id)?.label ?? "Default";
}

export interface ModelSelectOption {
    readonly value: string;
    readonly label: string;
}

/** A model dropdown. The value "" is the default row. */
export function ModelSelect(props: {
    options: readonly ModelSelectOption[];
    value: string;
    onChange: (value: string) => void;
} & Omit<JSX.SelectHTMLAttributes<HTMLSelectElement>, "value" | "onChange">): JSX.Element {
    const [local, rest] = splitProps(props, ["options", "value", "onChange"]);
    return <select class="pa-input" {...rest} value={local.value}
        onChange={(event) => local.onChange(event.currentTarget.value)}>
        <For each={local.options}>{(option) =>
            <option value={option.value} selected={option.value === local.value}>{option.label}</option>}</For>
    </select>;
}
