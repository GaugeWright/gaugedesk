/**
 * GaugeDesk-owned runtime selection for an archetype. Method behavior and tool
 * authority live in the authored WhippleScript package; this surface owns only
 * host/provider choices such as the preferred model.
 *
 * Round 5 (#5): this editor used to be a single raw `{}` JSON textarea labelled
 * "Advanced … leave it as {} to use the defaults" — so the one beginner
 * instruction the empty state gives ("set what this method does in settings")
 * dead-ended at a field that told the beginner not to touch it. There was nowhere
 * to express, in plain words, how the method should behave. We now lead with a
 * plain-language model field and demote raw provider settings to Advanced. The
 * package draft is edited in an edit chat and frozen by Publish.
 */

import { createEffect, createMemo, createResource, createSignal, Show } from "solid-js";
import { PanelContractEditor } from "./PanelContractEditor";
import { Option } from "./PanelAgentControls";
import { AbilityPresets, defaultModelLabel, ModelSelect, optionalAbilities } from "./agent-controls";
import { PUBLIC_ABILITY_CHOICES } from "./panel-agent-presentation";
import type { ModelOption } from "./model-picker";

export { AGENT_ABILITY_PRESETS, optionalAbilities, presetAbilities } from "./agent-controls";
import "./panel-agent.css";
import {
    type AgentAbility,
    type AgentKind,
    type ArchetypeId,
    type PanelPublicProfile,
} from "@gaugewright/control-plane-client";

/** Turn a raw parser error (often double-wrapped JSON with a line/column) into one
 *  plain sentence (#2). The raw JSON is only the Advanced surface now, so we tell
 *  the user *what's wrong* in their terms rather than leaking the parser's object. */
export function plainConfigError(raw: string): string {
    const ungranted = /public ability `([^`]+)` is not granted to the authored agent/.exec(raw);
    if (ungranted) {
        const name = PUBLIC_ABILITY_CHOICES.find((choice) => choice.value === ungranted[1])?.name ?? ungranted[1];
        return `Visitors can't be given “${name}” because the agent itself doesn't have it. `
            + "Give the agent that ability under Abilities, or untick it for visitors.";
    }
    if (/package-owned|\.whipple\/draft/i.test(raw)) {
        return "Behavior and tools are package-owned — change them in an edit chat, then publish.";
    }
    if (/trailing characters|expected|EOF|column|invalid|parse/i.test(raw)) {
        return "That isn't valid settings text — check for a stray character or a missing comma, bracket, or quote.";
    }
    // An unexpected (non-parse) failure: keep it short, drop the "Error:" prefix.
    return raw.replace(/^Error:\s*/, "").trim() || "Couldn't save those settings.";
}

/** The GaugeDesk runtime setting exposed by the plain form. */
interface FormConfig {
    model: string;
}

/** Read the subset the form controls out of a parsed config object. Unknown/missing
 *  fields fall back to the safe defaults the boundary itself uses. */
export function readFormConfig(parsed: unknown): FormConfig {
    const o = (parsed ?? {}) as Record<string, unknown>;
    return {
        model: typeof o.model === "string" ? o.model : "",
    };
}

/** Fold the form values back into a config object, preserving any other keys that
 *  were already there (so the Advanced JSON and the form never fight). */
export function writeFormConfig(prev: unknown, form: FormConfig): Record<string, unknown> {
    const base = (typeof prev === "object" && prev ? { ...(prev as Record<string, unknown>) } : {}) as Record<string, unknown>;
    // Model: omit the key entirely when blank, so "default" stays the default.
    if (form.model.trim()) base.model = form.model.trim();
    else delete base.model;
    delete base.policy;
    delete base.tools;
    return base;
}

export interface AgentSettingsApi {
    getArchetypeConfig(id: ArchetypeId): Promise<string>;
    setArchetypeConfig(id: ArchetypeId, config: string): Promise<void>;
    getArchetypeAbilities(id: ArchetypeId): Promise<AgentAbility[]>;
    setArchetypeAbilities(id: ArchetypeId, abilities: AgentAbility[]): Promise<void>;
    getPanelProfile(id: ArchetypeId): Promise<PanelPublicProfile>;
    setPanelProfile(id: ArchetypeId, profile: PanelPublicProfile): Promise<PanelPublicProfile>;
}

export interface AgentSettingsProps {
    api: AgentSettingsApi;
    id: ArchetypeId;
    name: string;
    kind: AgentKind;
    refreshKey?: number;
    /** The models this person can reach, as the composer offers them. */
    modelChoices?: readonly ModelOption[];
    onClose: () => void;
    onSaved?: () => void;
}


/** The preferred-model options: the default row first, then each reachable
 *  model once by id (the Agent's config pins an id, not a provider), with a
 *  saved model kept even when it is no longer reachable. */
export function preferredModelChoices(
    choices: readonly ModelOption[],
    current: string,
): { value: string; label: string }[] {
    const options = [{ value: "", label: defaultModelLabel(choices) }];
    for (const choice of choices) {
        if (choice.id && !options.some((option) => option.value === choice.id)) {
            options.push({ value: choice.id, label: choice.label });
        }
    }
    if (current && !options.some((option) => option.value === current)) {
        options.push({ value: current, label: current });
    }
    return options;
}

export function AgentSettings(props: AgentSettingsProps) {
    const [loaded, { refetch: refetchConfig }] = createResource(
        () => [props.id, props.refreshKey] as const,
        ([id]) => props.api.getArchetypeConfig(id),
    );
    const [loadedAbilities, { refetch: refetchAbilities }] = createResource(
        () => [props.id, props.refreshKey] as const,
        ([id]) => props.api.getArchetypeAbilities(id),
    );
    const [loadedPanel, { refetch: refetchPanel }] = createResource(
        () => props.kind === "panel" ? [props.id, props.refreshKey] as const : null,
        ([id]) => props.api.getPanelProfile(id),
    );
    // The raw JSON the Advanced section edits. Until the user touches Advanced it
    // tracks the loaded config; the form edits flow through it too, so saving always
    // sends one coherent document.
    const [raw, setRaw] = createSignal<string | null>(null);
    const [msg, setMsg] = createSignal("");
    const [showAdvanced, setShowAdvanced] = createSignal(false);
    const [selectedAbilities, setSelectedAbilities] = createSignal<AgentAbility[] | null>(
        null,
    );
    const [panelDraft, setPanelDraft] = createSignal<PanelPublicProfile | null>(null);
    const [panelDirty, setPanelDirty] = createSignal(false);
    const text = () => raw() ?? loaded() ?? "{}";

    // Parse the current text for the form. If the raw JSON is mid-edit and invalid,
    // the form falls back to defaults (and we keep editing through Advanced).
    const parsed = createMemo<unknown>(() => {
        try {
            return JSON.parse(text());
        } catch {
            return null;
        }
    });
    const form = createMemo(() => readFormConfig(parsed()));
    const rawIsValid = () => parsed() !== null;
    const abilities = () => selectedAbilities() ?? loadedAbilities() ?? [];
    const panel = () => panelDraft() ?? loadedPanel() ?? null;

    createEffect(() => {
        const loadedProfile = loadedPanel();
        if (loadedProfile && !panelDirty()) setPanelDraft(loadedProfile);
    });

    function updateForm(patch: Partial<FormConfig>) {
        const next = writeFormConfig(parsed() ?? {}, { ...form(), ...patch });
        setRaw(JSON.stringify(next, null, 2));
        setMsg("");
    }

    async function save() {
        try {
            // A Panel profile's public abilities must be within the agent's own
            // abilities as saved. When this save widens the agent to make room
            // for a visitor ability, the agent's abilities go first; otherwise
            // the profile does, so narrowing both at once is admitted too.
            const profile = props.kind === "panel" ? panel() : null;
            if (props.kind === "panel" && !profile) throw new Error("Panel profile is still loading.");
            const saved = loadedAbilities() ?? [];
            const abilitiesFirst = profile !== null
                && profile.public_abilities.some((ability) => !saved.includes(ability));
            if (abilitiesFirst) await props.api.setArchetypeAbilities(props.id, abilities());
            if (profile) await props.api.setPanelProfile(props.id, profile);
            if (!abilitiesFirst) await props.api.setArchetypeAbilities(props.id, abilities());
            await props.api.setArchetypeConfig(props.id, text());
            setPanelDirty(false);
            setRaw(null);
            setSelectedAbilities(null);
            await Promise.all([refetchConfig(), refetchAbilities(), ...(props.kind === "panel" ? [refetchPanel()] : [])]);
            setMsg("saved");
            props.onSaved?.();
        } catch (e) {
            setMsg(plainConfigError(String(e)));
        }
    }

    return (
        <main class="agent-settings-content pa-root" data-config-editor>
            {/* The pane's own top strip, shared with its fold control, as the
                chat pane's "MAIN · EDIT CHAT" is. */}
            <header class="agent-settings-head">
                <span class="content-empty-title" data-agent-settings-title>Agent settings · {props.name}</span>
                <button type="button" class="agent-settings-close" data-agent-settings-close aria-label="Close agent settings"
                    title="Close" onClick={props.onClose}>×</button>
            </header>
            <div class="agent-settings-body">
            <article class="agent-settings-page">

            <Show
                when={
                    !loaded.error && !loadedAbilities.error && !loadedPanel.error &&
                    (loaded.state === "ready" || raw() !== null) &&
                    loadedAbilities.state === "ready"
                }
                fallback={<Show when={loaded.error ?? loadedAbilities.error ?? loadedPanel.error}
                    fallback={<div class="status">loading…</div>}>
                    {(reason) => <div class="status" role="alert">
                        Agent settings unavailable: {String(reason())}
                        <button type="button" onClick={() => {
                            void Promise.all([refetchConfig(), refetchAbilities(),
                                ...(props.kind === "panel" ? [refetchPanel()] : [])]).catch(() => undefined);
                        }}>Retry</button>
                    </div>}
                </Show>}
            >
                <div data-settings-form>
                    <Show when={props.kind === "panel" && panel()}>
                        {(profile) => <PanelContractEditor
                            profile={profile()}
                            authoredAbilities={abilities()}
                            defaultModelLabel={defaultModelLabel(props.modelChoices ?? [])}
                            onChange={(next) => { setPanelDraft(next); setPanelDirty(true); setMsg(""); }} />}
                    </Show>

                    {/* A Panel agent's own model and abilities are not what visitors
                        get — the contract above is — so its heading names them apart. */}
                    <section class={props.kind === "panel" ? "pa-section divided" : "pa-section"}>
                        <Show when={props.kind === "panel"}>
                            <div class="pa-section-head"><h3>The agent itself</h3></div>
                        </Show>
                        <label class="pa-field">
                            <span>Preferred model</span>
                            <ModelSelect data-settings-model
                                options={preferredModelChoices(props.modelChoices ?? [], form().model)}
                                value={form().model}
                                onChange={(model) => updateForm({ model })} />
                        </label>

                        <fieldset class="pa-field pa-fieldset" data-settings-abilities>
                            <legend>Abilities</legend>
                            <AbilityPresets name="agent-abilities" abilities={abilities()}
                                onChange={(preset) => {
                                    setSelectedAbilities([...preset, ...optionalAbilities(abilities())]);
                                    setMsg("");
                                }}>
                                <Option type="checkbox" checked={abilities().includes("tracker.file")}
                                    label="File project tasks"
                                    onChange={(checked) => {
                                        setSelectedAbilities(checked
                                            ? [...abilities(), "tracker.file"]
                                            : abilities().filter((ability) => ability !== "tracker.file"));
                                        setMsg("");
                                    }} />
                            </AbilityPresets>
                        </fieldset>
                    </section>
                </div>

                {/* The raw JSON is now a collapsed power-user surface, not the only
                    way in (#5). It edits the same document the form does. */}
                <button
                    type="button"
                    class="settings-advanced-toggle"
                    data-settings-advanced-toggle
                    onClick={() => setShowAdvanced((v) => !v)}
                >
                    {showAdvanced() ? "▾" : "▸"} Advanced
                </button>
                <Show when={showAdvanced()}>
                    <textarea
                        class="config-text"
                        data-config-text
                        spellcheck={false}
                        value={text()}
                        onInput={(e) => { setRaw(e.currentTarget.value); setMsg(""); }}
                    />
                    <Show when={!rawIsValid()}>
                        <div class="status" data-config-status>Not valid JSON.</div>
                    </Show>
                </Show>
            </Show>

            <div class="bar agent-settings-save">
                <button type="button" class="pa-button primary" data-settings-save onClick={save}>Save</button>
                <span class="status" data-config-status>{msg()}</span>
            </div>
            </article>
            </div>
        </main>
    );
}
