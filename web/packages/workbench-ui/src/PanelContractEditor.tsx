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
 * hand — base URL, credential class, collection schema — sit under Advanced.
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
import {
    collectionPathProblem,
    DEFAULT_COLLECTED_PATH,
    durationParts,
    MAX_COLLECTED_FILE_MB,
    PANEL_CHOICES,
    PROVIDER_CHOICES,
    PUBLIC_ABILITY_CHOICES,
    secondsFrom,
    withProvider,
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
    const retentionProblem = () => profile().retention.absolute_ttl_seconds < profile().retention.idle_ttl_seconds
        ? "A conversation can't be deleted before it stops being resumable. Make the second number at least the first."
        : "";
    const pathProblems = () => (profile().collection?.exportable_paths ?? [])
        .map(collectionPathProblem).filter(Boolean);
    const knownProvider = () => PROVIDER_CHOICES.some((choice) => choice.value === profile().provider.provider);
    const models = () => PROVIDER_CHOICES.find((choice) => choice.value === profile().provider.provider)?.models ?? [];

    return <div class="pa-root" data-panel-public-profile>
        <section class="pa-section" data-panel-contract-panels>
            <div class="pa-section-head">
                <h3>What visitors see</h3>
                <p>The panels a website can show. Your site decides how to lay them out.</p>
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
                <p>Never more than the agent itself can do. With nothing ticked, it only chats.</p>
            </div>
            <div class="pa-options">
                <For each={PUBLIC_ABILITY_CHOICES}>{(choice) => {
                    const checked = () => profile().public_abilities.includes(choice.value);
                    const unavailable = () => abilityUnavailable(choice.value);
                    return <Option type="checkbox" checked={checked()} disabled={unavailable() && !checked()}
                        title={unavailable() ? "The agent itself can't do this, so visitors can't be given it." : undefined}
                        label={choice.name}
                        detail={unavailable() ? "The agent itself can't do this." : choice.detail}
                        onChange={(next) => toggleAbility(choice.value, next)} />;
                }}</For>
            </div>
            <Show when={props.authoredAbilities !== undefined
                && profile().public_abilities.some((ability) => !props.authoredAbilities!.includes(ability))}>
                <p class="pa-error">Something ticked here is beyond what the agent itself can do, so saving will be refused. Untick it.</p>
            </Show>
        </section>

        <section class="pa-section" data-panel-contract-model>
            <div class="pa-section-head">
                <h3>Model</h3>
                <p>The model that answers visitors.</p>
            </div>
            <div class="pa-fields">
                <label class="pa-field"><span>Provider</span>
                    <select class="pa-input" value={profile().provider.provider}
                        onChange={(event) => update((current) => ({ ...current, provider: withProvider(current.provider, event.currentTarget.value) }))}>
                        <For each={PROVIDER_CHOICES}>{(choice) => <option value={choice.value}>{choice.name}</option>}</For>
                        <Show when={!knownProvider()}><option value={profile().provider.provider}>{profile().provider.provider}</option></Show>
                    </select></label>
                <label class="pa-field"><span>Model</span>
                    <input class="pa-input" list="pa-model-suggestions" spellcheck={false} value={profile().provider.model}
                        onInput={(event) => update((current) => ({ ...current, provider: { ...current.provider, model: event.currentTarget.value } }))} />
                    <datalist id="pa-model-suggestions"><For each={models()}>{(model) => <option value={model} />}</For></datalist>
                </label>
            </div>
            <details class="pa-advanced"><summary>Advanced</summary><div class="pa-fields">
                <label class="pa-field"><span>API address</span>
                    <input class="pa-input" spellcheck={false} value={profile().provider.base_url}
                        onInput={(event) => update((current) => ({ ...current, provider: { ...current.provider, base_url: event.currentTarget.value } }))} />
                    <small>The provider's origin. The client adds the API path.</small></label>
                <label class="pa-field"><span>Key type</span>
                    <input class="pa-input" spellcheck={false} value={profile().provider.credential_class}
                        onInput={(event) => update((current) => ({ ...current, provider: { ...current.provider, credential_class: event.currentTarget.value } }))} />
                    <small>A deployment's own key must be stored under this type.</small></label>
            </div></details>
        </section>

        <section class="pa-section" data-panel-contract-retention>
            <div class="pa-section-head">
                <h3>Conversation history</h3>
                <p>The longest any deployment may keep a visitor's conversation. Each deployment can choose shorter.</p>
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
                    label="Keep the transcript" detail="A returning visitor sees the conversation so far."
                    onChange={(transcript_retained) => update((current) => ({ ...current, retention: { ...current.retention, transcript_retained } }))} />
                <Option type="checkbox" checked={profile().retention.workspace_retained}
                    label="Keep the visitor's files" detail="Files made in the session are still there when they return."
                    onChange={(workspace_retained) => update((current) => ({ ...current, retention: { ...current.retention, workspace_retained } }))} />
            </div>
        </section>

        <section class="pa-section" data-panel-contract-collection>
            <div class="pa-section-head">
                <h3>Send results to the project Inbox</h3>
                <p>Collect what the agent produces for visitors. It arrives sealed in the Inbox of the project that deploys it, and stays apart from your work until you admit it.</p>
            </div>
            <Option type="checkbox" checked={profile().collection !== null}
                label="Collect results" detail="Off: nothing leaves a visitor's session."
                onChange={(checked) => update((current) => ({ ...current, collection: checked ? {
                    exportable_paths: [DEFAULT_COLLECTED_PATH],
                    transcript_eligible: false,
                    schema_ref: "gaugewright.panel-output/v1",
                    recipient_class: "project",
                    max_artifact_bytes: MEGABYTE,
                } : null }))} />
            <Show when={profile().collection}>{(collection) => <>
                <label class="pa-field"><span>Files to collect</span>
                    <textarea class="pa-input" rows={2} spellcheck={false} aria-invalid={pathProblems().length > 0}
                        value={collection().exportable_paths.join("\n")}
                        onInput={(event) => update((current) => ({ ...current, collection: current.collection && {
                            ...current.collection,
                            exportable_paths: event.currentTarget.value.split("\n").map((line) => line.trim()).filter(Boolean),
                        } }))} />
                    <small>One per line, inside <code>artifacts/</code>: a file such as <code>artifacts/brief.pdf</code>, or every file in a folder, such as <code>artifacts/*</code>.</small></label>
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
                            }} /><span>MB</span></span>
                        <small>Up to {MAX_COLLECTED_FILE_MB} MB.</small></label>
                </div>
                <Option type="checkbox" checked={collection().transcript_eligible}
                    label="Include the conversation transcript" detail="Collect what was said, as well as the files."
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
