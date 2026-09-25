/**
 * The Panel-agent public contract, edited in place (ADR 0143 §2, PANEL-12).
 *
 * One editor for the two places a draft contract is edited: the opened Panel
 * agent in the Content pane, where it sits beside Preview, and Agent Settings.
 * It edits a value and reports the next one; who loads and saves the profile
 * is the caller's business, so the two surfaces cannot drift in what a
 * contract is while differing in when it is written.
 */

import { createSignal, For, Show, type JSX } from "solid-js";
import type { AgentAbility, PanelPublicProfile, PublicPanelComponent } from "@gaugewright/control-plane-client";

export function PanelContractEditor(props: {
    profile: PanelPublicProfile;
    onChange: (next: PanelPublicProfile) => void;
    /** Something the owner should read that is not a change, such as a missing path. */
    onNotice?: (message: string) => void;
}): JSX.Element {
    const [newFilePath, setNewFilePath] = createSignal("welcome.md");
    const [newFileMedia, setNewFileMedia] = createSignal("text/markdown");
    const [newFileBody, setNewFileBody] = createSignal("");

    function updatePanel(update: (profile: PanelPublicProfile) => PanelPublicProfile) {
        props.onChange(update(props.profile));
    }

    function togglePanel(component: PublicPanelComponent, checked: boolean) {
        updatePanel((profile) => {
            const components = checked
                ? [...new Set([...profile.panels.components, component])]
                : profile.panels.components.filter((value) => value !== component);
            if (components.length === 0) return profile;
            return {
                ...profile,
                panels: {
                    ...profile.panels,
                    components,
                    default_component: components.includes(profile.panels.default_component)
                        ? profile.panels.default_component
                        : components[0],
                },
            };
        });
    }

    function togglePublicAbility(ability: AgentAbility, checked: boolean) {
        updatePanel((profile) => ({
            ...profile,
            public_abilities: checked
                ? [...new Set([...profile.public_abilities, ability])]
                : profile.public_abilities.filter((value) => value !== ability),
        }));
    }

    async function addInitialFile() {
        const path = newFilePath().trim();
        if (!path) return props.onNotice?.("Initial content needs a path.");
        const bytes = [...new TextEncoder().encode(newFileBody())];
        const digest = await crypto.subtle.digest("SHA-256", new Uint8Array(bytes));
        const sha256 = [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
        updatePanel((profile) => ({
            ...profile,
            initial_workspace: [
                ...profile.initial_workspace.filter((file) => file.path !== path),
                { path, media_type: newFileMedia().trim() || "text/plain", sha256, bytes },
            ],
        }));
        setNewFileBody("");
    }

    return <section class="admin-section" data-panel-public-profile>
        <h3>Panel contract</h3>
        <fieldset class="settings-field"><legend class="settings-label">Published panels</legend>
            <For each={(["gw-chat", "gw-viewer", "gw-files", "gw-chats"] as PublicPanelComponent[])}>{(component) =>
                <label class="settings-checkbox"><input type="checkbox"
                    checked={props.profile.panels.components.includes(component)}
                    onChange={(event) => togglePanel(component, event.currentTarget.checked)} /> {component}</label>}
            </For>
            <label class="settings-field"><span class="settings-label">Default panel</span><select class="settings-input"
                value={props.profile.panels.default_component}
                onChange={(event) => updatePanel((value) => ({ ...value, panels: { ...value.panels, default_component: event.currentTarget.value as PublicPanelComponent } }))}>
                <For each={props.profile.panels.components}>{(component) => <option value={component}>{component}</option>}</For>
            </select></label>
            <label class="settings-checkbox"><input type="checkbox"
                checked={props.profile.panels.attribution === "white_label_eligible"}
                onChange={(event) => updatePanel((value) => ({ ...value, panels: { ...value.panels, attribution: event.currentTarget.checked ? "white_label_eligible" : "gauge_wright" } }))} /> Allow white-label branding</label>
        </fieldset>

        <fieldset class="settings-field"><legend class="settings-label">Public abilities</legend>
            <p class="status">The deployed agent receives only this subset of its authored package abilities.</p>
            <For each={(["workspace.read", "workspace.write", "command.run", "question.ask"] as AgentAbility[])}>{(ability) =>
                <label class="settings-checkbox"><input type="checkbox" checked={props.profile.public_abilities.includes(ability)}
                    onChange={(event) => togglePublicAbility(ability, event.currentTarget.checked)} /> {ability}</label>}
            </For>
        </fieldset>

        <div class="deployment-field-grid">
            <label class="settings-field"><span class="settings-label">Provider</span><input class="settings-input" value={props.profile.provider.provider}
                onInput={(event) => updatePanel((value) => ({ ...value, provider: { ...value.provider, provider: event.currentTarget.value } }))} /></label>
            <label class="settings-field"><span class="settings-label">Model</span><input class="settings-input" value={props.profile.provider.model}
                onInput={(event) => updatePanel((value) => ({ ...value, provider: { ...value.provider, model: event.currentTarget.value } }))} /></label>
            <label class="settings-field"><span class="settings-label">Base URL</span><input class="settings-input" value={props.profile.provider.base_url}
                onInput={(event) => updatePanel((value) => ({ ...value, provider: { ...value.provider, base_url: event.currentTarget.value } }))} /></label>
            <label class="settings-field"><span class="settings-label">Credential class</span><input class="settings-input" value={props.profile.provider.credential_class}
                onInput={(event) => updatePanel((value) => ({ ...value, provider: { ...value.provider, credential_class: event.currentTarget.value } }))} /></label>
        </div>

        <fieldset class="settings-field"><legend class="settings-label">Visitor input</legend>
            <label class="settings-checkbox"><input type="checkbox" checked disabled /> text</label>
            <small class="muted">The current public Session host admits text only.</small>
        </fieldset>

        <fieldset class="settings-field"><legend class="settings-label">Initial workspace</legend>
            <For each={props.profile.initial_workspace}>{(file) => <div class="member-row"><span>{file.path}</span><span class="member-id">{file.media_type} · {file.bytes.length} bytes</span>
                <button type="button" onClick={() => updatePanel((value) => ({ ...value, initial_workspace: value.initial_workspace.filter((candidate) => candidate.path !== file.path) }))}>remove</button></div>}</For>
            <div class="deployment-field-grid"><label class="settings-field"><span class="settings-label">Path</span><input class="settings-input" value={newFilePath()} onInput={(event) => setNewFilePath(event.currentTarget.value)} /></label>
                <label class="settings-field"><span class="settings-label">Media type</span><input class="settings-input" value={newFileMedia()} onInput={(event) => setNewFileMedia(event.currentTarget.value)} /></label></div>
            <textarea class="config-text" style={{ "min-height": "90px" }} value={newFileBody()} placeholder="Initial file contents" onInput={(event) => setNewFileBody(event.currentTarget.value)} />
            <button type="button" onClick={() => void addInitialFile()}>Add or replace file</button>
        </fieldset>

        <fieldset class="settings-field"><legend class="settings-label">Public retention ceiling</legend>
            <div class="deployment-field-grid"><label class="settings-field"><span class="settings-label">Idle seconds</span><input class="settings-input" type="number" min="1" value={props.profile.retention.idle_ttl_seconds}
                onInput={(event) => updatePanel((value) => ({ ...value, retention: { ...value.retention, idle_ttl_seconds: event.currentTarget.valueAsNumber } }))} /></label>
                <label class="settings-field"><span class="settings-label">Absolute seconds</span><input class="settings-input" type="number" min="1" value={props.profile.retention.absolute_ttl_seconds}
                    onInput={(event) => updatePanel((value) => ({ ...value, retention: { ...value.retention, absolute_ttl_seconds: event.currentTarget.valueAsNumber } }))} /></label></div>
            <label class="settings-checkbox"><input type="checkbox" checked={props.profile.retention.transcript_retained}
                onChange={(event) => updatePanel((value) => ({ ...value, retention: { ...value.retention, transcript_retained: event.currentTarget.checked } }))} /> Retain transcript</label>
            <label class="settings-checkbox"><input type="checkbox" checked={props.profile.retention.workspace_retained}
                onChange={(event) => updatePanel((value) => ({ ...value, retention: { ...value.retention, workspace_retained: event.currentTarget.checked } }))} /> Retain workspace</label>
        </fieldset>

        <fieldset class="settings-field"><legend class="settings-label">Project Inbox collection</legend>
            <label class="settings-checkbox"><input type="checkbox" checked={props.profile.collection !== null}
                onChange={(event) => updatePanel((value) => ({ ...value, collection: event.currentTarget.checked ? {
                    exportable_paths: ["outputs/**"], transcript_eligible: false, schema_ref: "gaugewright.panel-output/v1", recipient_class: "project", max_artifact_bytes: 1_048_576,
                } : null }))} /> Collect declared output after project deployment</label>
            <Show when={props.profile.collection}>{(collection) => <>
                <label class="settings-field"><span class="settings-label">Exportable paths, one per line</span><textarea class="config-text" style={{ "min-height": "72px" }} value={collection().exportable_paths.join("\n")}
                    onInput={(event) => updatePanel((value) => ({ ...value, collection: value.collection && { ...value.collection, exportable_paths: event.currentTarget.value.split("\n").map((line) => line.trim()).filter(Boolean) } }))} /></label>
                <div class="deployment-field-grid"><label class="settings-field"><span class="settings-label">Schema</span><input class="settings-input" value={collection().schema_ref}
                    onInput={(event) => updatePanel((value) => ({ ...value, collection: value.collection && { ...value.collection, schema_ref: event.currentTarget.value } }))} /></label>
                    <label class="settings-field"><span class="settings-label">Recipient class</span><input class="settings-input" value={collection().recipient_class}
                        onInput={(event) => updatePanel((value) => ({ ...value, collection: value.collection && { ...value.collection, recipient_class: event.currentTarget.value } }))} /></label>
                    <label class="settings-field"><span class="settings-label">Maximum artifact bytes</span><input class="settings-input" type="number" min="1" value={collection().max_artifact_bytes}
                        onInput={(event) => updatePanel((value) => ({ ...value, collection: value.collection && { ...value.collection, max_artifact_bytes: event.currentTarget.valueAsNumber } }))} /></label></div>
                <label class="settings-checkbox"><input type="checkbox" checked={collection().transcript_eligible}
                    onChange={(event) => updatePanel((value) => ({ ...value, collection: value.collection && { ...value.collection, transcript_eligible: event.currentTarget.checked } }))} /> Transcript may be collected</label>
            </>}</Show>
        </fieldset>
    </section>;
}
