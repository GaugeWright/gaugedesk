/**
 * The Panel-agent public contract, edited in place (ADR 0143 §2, PANEL-12).
 *
 * One editor for the two places a draft contract is edited: the opened Panel
 * agent in the Content pane, and Agent Settings.
 * It edits a value and reports the next one; who loads and saves the profile
 * is the caller's business, so the two surfaces cannot drift in what a
 * contract is while differing in when it is written.
 *
 * It speaks the owner's language: panels and abilities by their plain names,
 * retention in hours and days, sizes in megabytes. The wire names live in
 * `panel-agent-presentation.ts`, and the few that still need to be editable by
 * hand — an exact model ID and the collection schema — sit under Advanced. No
 * provider is authored here: who pays for a deployment chooses it (DR-0272).
 *
 * Three parts of the contract are not edited here. Its starting files are what
 * the builder — the agent's edit chat — writes. Its default panel has no effect on
 * what a visitor sees (the host page lays the panels out), so it simply follows
 * the first panel that is on. And its branding is not the owner's to set: the
 * panels carry the GaugeWright mark, and removing it is a paid white-label
 * lever of the hosting entitlement (`experience/embed-surface.md`), so the
 * attribution field keeps whatever value it already holds.
 */

import { For, Show, type JSX } from "solid-js";
import type { AgentAbility, PanelPublicProfile, PublicPanelComponent } from "@gaugewright/control-plane-client";
import { Option } from "./PanelAgentControls";
import { AbilityPresets, BEYOND_AGENT_ABILITIES, ModelSelect } from "./agent-controls";
import {
    collectionPathProblem,
    DEFAULT_COLLECTED_PATH,
    durationParts,
    MAX_COLLECTED_FILE_MB,
    PANEL_CHOICES,
    panelModelChoices,
    secondsFrom,
    withPinnedModel,
    WORK_CHAT_DEFAULT_MODEL,
    type DurationUnit,
} from "./panel-agent-presentation";
import "./panel-agent.css";

const MEGABYTE = 1_048_576;

/** A number of hours or days, read and written in seconds. */
function DurationInput(props: {
    seconds: number;
    units: readonly DurationUnit[];
    label: string;
    onChange: (seconds: number) => void;
}): JSX.Element {
    const parts = () => durationParts(props.seconds);
    return <span class="pa-affix">
        <input class="pa-input" type="number" min="1" aria-label={props.label} value={parts().value}
            onInput={(event) => {
                const value = event.currentTarget.valueAsNumber;
                if (Number.isFinite(value) && value > 0) props.onChange(secondsFrom(value, parts().unit));
            }} />
        <select aria-label={`${props.label} unit`} value={parts().unit}
            onChange={(event) => props.onChange(secondsFrom(parts().value, event.currentTarget.value as DurationUnit))}>
            <For each={props.units}>{(unit) => <option value={unit}>{unit}</option>}</For>
        </select>
    </span>;
}

export function PanelContractEditor(props: {
    /** The default row's wording, shared with the agent's own model field. */
    defaultModelLabel?: string;
    profile: PanelPublicProfile;
    onChange: (next: PanelPublicProfile) => void;
    /** The abilities the authored agent has. A public ability outside them is
     *  refused on save, so it is offered only once the agent has it. Unknown
     *  when absent, and then every ability is offered. */
    authoredAbilities?: readonly AgentAbility[];
}): JSX.Element {
    const profile = () => props.profile;
    function update(change: (profile: PanelPublicProfile) => PanelPublicProfile) {
        props.onChange(change(props.profile));
    }

    function togglePanel(component: PublicPanelComponent, checked: boolean) {
        update((current) => {
            const components = PANEL_CHOICES.map((choice) => choice.value)
                .filter((value) => checked
                    ? value === component || current.panels.components.includes(value)
                    : value !== component && current.panels.components.includes(value));
            if (components.length === 0) return current;
            return {
                ...current,
                panels: {
                    ...current.panels,
                    components,
                    default_component: components.includes(current.panels.default_component)
                        ? current.panels.default_component
                        : components[0]!,
                },
            };
        });
    }

    function toggleAbility(ability: AgentAbility, checked: boolean) {
        update((current) => ({
            ...current,
            public_abilities: checked
                ? [...new Set([...current.public_abilities, ability])]
                : current.public_abilities.filter((value) => value !== ability),
        }));
    }

    const abilityUnavailable = (ability: AgentAbility) =>
        props.authoredAbilities !== undefined && !props.authoredAbilities.includes(ability);
    const askUnavailable = () =>
        abilityUnavailable("question.ask") && !profile().public_abilities.includes("question.ask");
    const retentionProblem = () => profile().retention.absolute_ttl_seconds < profile().retention.idle_ttl_seconds
        ? "A conversation can't be deleted before it stops being resumable. Make the second number at least the first."
        : "";
    const pathProblems = () => (profile().collection?.exportable_paths ?? [])
        .map(collectionPathProblem).filter(Boolean);
    const pinned = () => profile().model.pinned ?? "";
    const models = () => panelModelChoices(pinned());
    const setModel = (model: string) => update((current) => withPinnedModel(current, model));

    return <div class="pa-root" data-panel-public-profile>
        <section class="pa-section" data-panel-contract-panels>
            <div class="pa-section-head">
                <h3>What visitors see</h3>
            </div>
            <div class="pa-chips" role="group" aria-label="Panels">
                <For each={PANEL_CHOICES}>{(choice) => {
                    const checked = () => profile().panels.components.includes(choice.value);
                    const only = () => checked() && profile().panels.components.length === 1;
                    return <label class="pa-chip" title={only() ? "A Panel agent shows at least one panel." : choice.detail}>
                        <input type="checkbox" checked={checked()} disabled={only()}
                            onChange={(event) => togglePanel(choice.value, event.currentTarget.checked)} />
                        {choice.name}
                    </label>;
                }}</For>
            </div>
        </section>

        <section class="pa-section" data-panel-contract-abilities>
            <div class="pa-section-head">
                <h3>What the agent can do for visitors</h3>
            </div>
            {/* The same presets as the agent's own abilities, capped by them. */}
            <AbilityPresets name="panel-public-abilities" abilities={profile().public_abilities}
                ceiling={props.authoredAbilities}
                onChange={(preset) => update((current) => ({
                    ...current,
                    public_abilities: [...preset, ...current.public_abilities.filter((ability) => ability === "question.ask")],
                }))}>
                <Option type="checkbox" checked={profile().public_abilities.includes("question.ask")}
                    disabled={askUnavailable()}
                    title={askUnavailable() ? BEYOND_AGENT_ABILITIES : undefined}
                    detail={askUnavailable() ? BEYOND_AGENT_ABILITIES : undefined}
                    label="Ask questions"
                    onChange={(next) => toggleAbility("question.ask", next)} />
            </AbilityPresets>
            <Show when={props.authoredAbilities !== undefined
                && profile().public_abilities.some((ability) => !props.authoredAbilities!.includes(ability))}>
                <p class="pa-error">Something ticked here is beyond what the agent itself can do, so saving will be refused. Untick it, or give the agent that ability under its own Abilities.</p>
            </Show>
        </section>

        <section class="pa-section" data-panel-contract-model>
            <div class="pa-section-head">
                <h3>Model</h3>
            </div>
            <div class="pa-fields">
                {/* A select, not an input with a datalist: a datalist offers only the
                    suggestions matching what the field already holds, so a saved model
                    hid every other one (WS-597). */}
                <label class="pa-field"><span>Model</span>
                    <ModelSelect data-panel-contract-model-choice value={pinned()} onChange={setModel}
                        options={models().map((choice) => ({
                            value: choice.value,
                            label: choice.value === WORK_CHAT_DEFAULT_MODEL ? props.defaultModelLabel ?? "Default" : choice.name,
                        }))} /></label>
            </div>
            <details class="pa-advanced"><summary>Advanced</summary><div class="pa-fields">
                <label class="pa-field"><span>Model ID</span>
                    <input class="pa-input" spellcheck={false} placeholder="Work-chat default" value={pinned()}
                        onInput={(event) => setModel(event.currentTarget.value)} /></label>
            </div></details>
        </section>

        <section class="pa-section" data-panel-contract-retention>
            <div class="pa-section-head">
                <h3>Conversation history</h3>
            </div>
            <div class="pa-fields">
                <label class="pa-field"><span>Resumable for</span>
                    <DurationInput label="Resumable for" units={["hours", "days"]} seconds={profile().retention.idle_ttl_seconds}
                        onChange={(idle_ttl_seconds) => update((current) => ({ ...current, retention: { ...current.retention, idle_ttl_seconds } }))} />
                    <small>after the visitor's last message</small></label>
                <label class="pa-field"><span>Deleted after at most</span>
                    <DurationInput label="Deleted after at most" units={["hours", "days"]} seconds={profile().retention.absolute_ttl_seconds}
                        onChange={(absolute_ttl_seconds) => update((current) => ({ ...current, retention: { ...current.retention, absolute_ttl_seconds } }))} />
                    <small>from when it started</small></label>
            </div>
            <Show when={retentionProblem()}><p class="pa-error">{retentionProblem()}</p></Show>
            <div class="pa-options">
                <Option type="checkbox" checked={profile().retention.transcript_retained}
                    label="Keep the transcript"
                    onChange={(transcript_retained) => update((current) => ({ ...current, retention: { ...current.retention, transcript_retained } }))} />
                <Option type="checkbox" checked={profile().retention.workspace_retained}
                    label="Keep the visitor's files"
                    onChange={(workspace_retained) => update((current) => ({ ...current, retention: { ...current.retention, workspace_retained } }))} />
            </div>
        </section>

        <section class="pa-section" data-panel-contract-collection>
            <div class="pa-section-head">
                <h3>Send results to the project Inbox</h3>
            </div>
            <Option type="checkbox" checked={profile().collection !== null}
                label="Collect results"
                onChange={(checked) => update((current) => ({ ...current, collection: checked ? {
                    exportable_paths: [DEFAULT_COLLECTED_PATH],
                    transcript_eligible: false,
                    schema_ref: "gaugewright.panel-output/v1",
                    recipient_class: "project",
                    max_artifact_bytes: MEGABYTE,
                } : null }))} />
            <Show when={profile().collection}>{(collection) => <>
                <label class="pa-field"><span>Files to collect</span>
                    <textarea class="pa-input" rows={2} spellcheck={false} placeholder="outbox/*" aria-invalid={pathProblems().length > 0}
                        value={collection().exportable_paths.join("\n")}
                        onInput={(event) => update((current) => ({ ...current, collection: current.collection && {
                            ...current.collection,
                            exportable_paths: event.currentTarget.value.split("\n").map((line) => line.trim()).filter(Boolean),
                        } }))} /></label>
                <small>Files the agent puts in outbox/. The visitor's panels never show them.</small>
                <For each={pathProblems()}>{(problem) => <p class="pa-error">{problem}</p>}</For>
                <div class="pa-fields">
                    <label class="pa-field"><span>Largest file</span>
                        <span class="pa-affix"><input class="pa-input" type="number" min="1" max={MAX_COLLECTED_FILE_MB} step="1"
                            value={Math.max(1, Math.round(collection().max_artifact_bytes / MEGABYTE))}
                            onInput={(event) => {
                                const megabytes = event.currentTarget.valueAsNumber;
                                if (!Number.isFinite(megabytes) || megabytes < 1) return;
                                update((current) => ({ ...current, collection: current.collection && {
                                    ...current.collection,
                                    max_artifact_bytes: Math.min(MAX_COLLECTED_FILE_MB, Math.round(megabytes)) * MEGABYTE,
                                } }));
                            }} /><span>MB</span></span></label>
                </div>
                <Option type="checkbox" checked={collection().transcript_eligible}
                    label="Include the conversation transcript"
                    onChange={(transcript_eligible) => update((current) => ({ ...current, collection: current.collection && { ...current.collection, transcript_eligible } }))} />
                <Show when={!collection().exportable_paths.length && !collection().transcript_eligible}>
                    <p class="pa-error">Name at least one file to collect, or include the transcript.</p>
                </Show>
                <details class="pa-advanced"><summary>Advanced</summary><div class="pa-fields">
                    <label class="pa-field"><span>Result format</span>
                        <input class="pa-input" spellcheck={false} value={collection().schema_ref}
                            onInput={(event) => update((current) => ({ ...current, collection: current.collection && { ...current.collection, schema_ref: event.currentTarget.value } }))} /></label>
                    <label class="pa-field"><span>Recipient class</span>
                        <input class="pa-input" spellcheck={false} value={collection().recipient_class}
                            onInput={(event) => update((current) => ({ ...current, collection: current.collection && { ...current.collection, recipient_class: event.currentTarget.value } }))} /></label>
                </div></details>
            </>}</Show>
        </section>
    </div>;
}
