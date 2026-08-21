/**
 * GaugeDesk-owned runtime selection for an archetype. Method behavior and tool
 * authority live in the authored WhippleScript package; this surface owns only
 * host/provider choices such as the preferred model.
 *
 * Round 5 (#5): the modal used to be a single raw `{}` JSON textarea labelled
 * "Advanced … leave it as {} to use the defaults" — so the one beginner
 * instruction the empty state gives ("set what this method does in settings")
 * dead-ended at a field that told the beginner not to touch it. There was nowhere
 * to express, in plain words, how the method should behave. We now lead with a
 * plain-language model field and demote raw provider settings to Advanced. The
 * package draft is edited in an edit chat and frozen by Publish.
 */

import { createEffect, createMemo, createResource, createSignal, For, onCleanup, Show } from "solid-js";
import {
    type AgentAbility,
    type AgentKind,
    type ArchetypeId,
    type PanelPublicProfile,
    type PublicPanelComponent,
} from "@gaugewright/control-plane-client";

/** Turn a raw parser error (often double-wrapped JSON with a line/column) into one
 *  plain sentence (#2). The raw JSON is only the Advanced surface now, so we tell
 *  the user *what's wrong* in their terms rather than leaking the parser's object. */
export function plainConfigError(raw: string): string {
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
    onClose: () => void;
}

export const AGENT_ABILITY_PRESETS: ReadonlyArray<{
    name: string;
    detail: string;
    value: AgentAbility[];
}> = [
    {
        name: "Chat only",
        detail: "Conversation and reasoning, with no workspace tools.",
        value: [],
    },
    {
        name: "Read workspace",
        detail: "Read, search, find, and list files.",
        value: ["workspace.read"],
    },
    {
        name: "Create artifacts",
        detail: "Read files, then write and edit artifacts.",
        value: ["workspace.read", "workspace.write"],
    },
    {
        name: "Run workspace commands",
        detail: "Create artifacts and run virtual bash. Commands are write-capable.",
        value: ["workspace.read", "workspace.write", "command.run"],
    },
];

export function AgentSettings(props: AgentSettingsProps) {
    const [loaded] = createResource(
        () => props.id,
        (id) => props.api.getArchetypeConfig(id),
    );
    const [loadedAbilities] = createResource(
        () => props.id,
        (id) => props.api.getArchetypeAbilities(id),
    );
    const [loadedPanel] = createResource(
        () => props.kind === "panel" ? props.id : null,
        (id) => props.api.getPanelProfile(id),
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
    const [newFilePath, setNewFilePath] = createSignal("welcome.md");
    const [newFileMedia, setNewFileMedia] = createSignal("text/markdown");
    const [newFileBody, setNewFileBody] = createSignal("");
    const text = () => raw() ?? loaded() ?? "{}";

    // Escape closes the modal (#6 round-5: it didn't, leaving the user to hunt for
    // "close" — a forgiveness/convention gap). A native listener: Solid delegates
    // events, so a synthetic keydown on the modal wouldn't catch a focused textarea.
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && props.onClose();
    document.addEventListener("keydown", onKey);
    onCleanup(() => document.removeEventListener("keydown", onKey));

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
        if (loadedProfile && panelDraft() === null) setPanelDraft(loadedProfile);
    });

    function updatePanel(update: (profile: PanelPublicProfile) => PanelPublicProfile) {
        const current = panel();
        if (current) setPanelDraft(update(current));
        setMsg("");
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
        if (!path) return setMsg("Initial content needs a path.");
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

    function updateForm(patch: Partial<FormConfig>) {
        const next = writeFormConfig(parsed() ?? {}, { ...form(), ...patch });
        setRaw(JSON.stringify(next, null, 2));
        setMsg("");
    }

    async function save() {
        try {
            if (props.kind === "panel") {
                const profile = panel();
                if (!profile) throw new Error("Panel profile is still loading.");
                await props.api.setPanelProfile(props.id, profile);
            }
            await props.api.setArchetypeAbilities(props.id, abilities());
            await props.api.setArchetypeConfig(props.id, text());
            setMsg("saved");
        } catch (e) {
            setMsg(plainConfigError(String(e)));
        }
    }

    return (
        <div class="modal embed-monitor" data-config-editor>
            <div class="modal-head">
                <h3>Settings · {props.name}</h3>
                <button onClick={props.onClose}>close</button>
            </div>
            <p class="status" style={{ margin: "0 0 10px" }}>
                {props.kind === "panel"
                    ? "Preview uses this public contract. Publishing freezes it into a version; deployments cannot redefine it."
                    : "These settings apply to test chats now and are frozen into the next published version."}
            </p>

            <Show
                when={
                    (loaded.state === "ready" || raw() !== null) &&
                    loadedAbilities.state === "ready"
                }
                fallback={<div class="status">loading…</div>}
            >
                <div class="settings-form" data-settings-form>
                    <Show when={props.kind === "panel" && panel()}>
                        {(profile) => <section class="admin-section" data-panel-public-profile>
                            <h3>Panel contract</h3>
                            <fieldset class="settings-field"><legend class="settings-label">Published panels</legend>
                                <For each={(["gw-chat", "gw-viewer", "gw-files", "gw-chats"] as PublicPanelComponent[])}>{(component) =>
                                    <label class="settings-checkbox"><input type="checkbox"
                                        checked={profile().panels.components.includes(component)}
                                        onChange={(event) => togglePanel(component, event.currentTarget.checked)} /> {component}</label>}
                                </For>
                                <label class="settings-field"><span class="settings-label">Default panel</span><select class="settings-input"
                                    value={profile().panels.default_component}
                                    onChange={(event) => updatePanel((value) => ({ ...value, panels: { ...value.panels, default_component: event.currentTarget.value as PublicPanelComponent } }))}>
                                    <For each={profile().panels.components}>{(component) => <option value={component}>{component}</option>}</For>
                                </select></label>
                                <label class="settings-checkbox"><input type="checkbox"
                                    checked={profile().panels.attribution === "white_label_eligible"}
                                    onChange={(event) => updatePanel((value) => ({ ...value, panels: { ...value.panels, attribution: event.currentTarget.checked ? "white_label_eligible" : "gauge_wright" } }))} /> Allow white-label branding</label>
                            </fieldset>

                            <fieldset class="settings-field"><legend class="settings-label">Public abilities</legend>
                                <p class="status">The deployed agent receives only this subset of its authored package abilities.</p>
                                <For each={(["workspace.read", "workspace.write", "command.run"] as AgentAbility[])}>{(ability) =>
                                    <label class="settings-checkbox"><input type="checkbox" checked={profile().public_abilities.includes(ability)}
                                        onChange={(event) => togglePublicAbility(ability, event.currentTarget.checked)} /> {ability}</label>}
                                </For>
                            </fieldset>

                            <div class="deployment-field-grid">
                                <label class="settings-field"><span class="settings-label">Provider</span><input class="settings-input" value={profile().provider.provider}
                                    onInput={(event) => updatePanel((value) => ({ ...value, provider: { ...value.provider, provider: event.currentTarget.value } }))} /></label>
                                <label class="settings-field"><span class="settings-label">Model</span><input class="settings-input" value={profile().provider.model}
                                    onInput={(event) => updatePanel((value) => ({ ...value, provider: { ...value.provider, model: event.currentTarget.value } }))} /></label>
                                <label class="settings-field"><span class="settings-label">Base URL</span><input class="settings-input" value={profile().provider.base_url}
                                    onInput={(event) => updatePanel((value) => ({ ...value, provider: { ...value.provider, base_url: event.currentTarget.value } }))} /></label>
                                <label class="settings-field"><span class="settings-label">Credential class</span><input class="settings-input" value={profile().provider.credential_class}
                                    onInput={(event) => updatePanel((value) => ({ ...value, provider: { ...value.provider, credential_class: event.currentTarget.value } }))} /></label>
                            </div>

                            <fieldset class="settings-field"><legend class="settings-label">Visitor input</legend>
                                <label class="settings-checkbox"><input type="checkbox" checked disabled /> text</label>
                                <small class="muted">The current public Session host admits text only.</small>
                            </fieldset>

                            <fieldset class="settings-field"><legend class="settings-label">Initial workspace</legend>
                                <For each={profile().initial_workspace}>{(file) => <div class="member-row"><span>{file.path}</span><span class="member-id">{file.media_type} · {file.bytes.length} bytes</span>
                                    <button type="button" onClick={() => updatePanel((value) => ({ ...value, initial_workspace: value.initial_workspace.filter((candidate) => candidate.path !== file.path) }))}>remove</button></div>}</For>
                                <div class="deployment-field-grid"><label class="settings-field"><span class="settings-label">Path</span><input class="settings-input" value={newFilePath()} onInput={(event) => setNewFilePath(event.currentTarget.value)} /></label>
                                    <label class="settings-field"><span class="settings-label">Media type</span><input class="settings-input" value={newFileMedia()} onInput={(event) => setNewFileMedia(event.currentTarget.value)} /></label></div>
                                <textarea class="config-text" style={{ "min-height": "90px" }} value={newFileBody()} placeholder="Initial file contents" onInput={(event) => setNewFileBody(event.currentTarget.value)} />
                                <button type="button" onClick={() => void addInitialFile()}>Add or replace file</button>
                            </fieldset>

                            <fieldset class="settings-field"><legend class="settings-label">Public retention ceiling</legend>
                                <div class="deployment-field-grid"><label class="settings-field"><span class="settings-label">Idle seconds</span><input class="settings-input" type="number" min="1" value={profile().retention.idle_ttl_seconds}
                                    onInput={(event) => updatePanel((value) => ({ ...value, retention: { ...value.retention, idle_ttl_seconds: event.currentTarget.valueAsNumber } }))} /></label>
                                    <label class="settings-field"><span class="settings-label">Absolute seconds</span><input class="settings-input" type="number" min="1" value={profile().retention.absolute_ttl_seconds}
                                        onInput={(event) => updatePanel((value) => ({ ...value, retention: { ...value.retention, absolute_ttl_seconds: event.currentTarget.valueAsNumber } }))} /></label></div>
                                <label class="settings-checkbox"><input type="checkbox" checked={profile().retention.transcript_retained}
                                    onChange={(event) => updatePanel((value) => ({ ...value, retention: { ...value.retention, transcript_retained: event.currentTarget.checked } }))} /> Retain transcript</label>
                                <label class="settings-checkbox"><input type="checkbox" checked={profile().retention.workspace_retained}
                                    onChange={(event) => updatePanel((value) => ({ ...value, retention: { ...value.retention, workspace_retained: event.currentTarget.checked } }))} /> Retain workspace</label>
                            </fieldset>

                            <fieldset class="settings-field"><legend class="settings-label">Project Inbox collection</legend>
                                <label class="settings-checkbox"><input type="checkbox" checked={profile().collection !== null}
                                    onChange={(event) => updatePanel((value) => ({ ...value, collection: event.currentTarget.checked ? {
                                        exportable_paths: ["outputs/**"], transcript_eligible: false, schema_ref: "gaugewright.panel-output/v1", recipient_class: "project", max_artifact_bytes: 1_048_576,
                                    } : null }))} /> Collect declared output after project deployment</label>
                                <Show when={profile().collection}>{(collection) => <>
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
                        </section>}
                    </Show>

                    <label class="settings-field">
                        <span class="settings-label">Preferred model</span>
                        <input
                            class="settings-input"
                            data-settings-model
                            placeholder="leave blank to use the default"
                            value={form().model}
                            onInput={(e) => updateForm({ model: e.currentTarget.value })}
                        />
                    </label>

                    <fieldset class="settings-field" data-settings-abilities>
                        <legend class="settings-label">Abilities</legend>
                        <p class="status" style={{ margin: "2px 0 8px" }}>
                            Choose the maximum workspace access this agent receives.
                        </p>
                        {AGENT_ABILITY_PRESETS.map((preset) => {
                            const checked = () =>
                                JSON.stringify([...abilities()].sort()) ===
                                JSON.stringify([...preset.value].sort());
                            return (
                                <label
                                    style={{
                                        display: "grid",
                                        "grid-template-columns": "auto 1fr",
                                        gap: "2px 8px",
                                        padding: "7px 0",
                                        cursor: "pointer",
                                    }}
                                >
                                    <input
                                        type="radio"
                                        name="agent-abilities"
                                        checked={checked()}
                                        onChange={() => {
                                            setSelectedAbilities(preset.value);
                                            setMsg("");
                                        }}
                                    />
                                    <span>
                                        <span style={{ display: "block" }}>{preset.name}</span>
                                        <span class="status">{preset.detail}</span>
                                    </span>
                                </label>
                            );
                        })}
                    </fieldset>

                </div>

                {/* The raw JSON is now a collapsed power-user surface, not the only
                    way in (#5). It edits the same document the form does. */}
                <button
                    type="button"
                    class="settings-advanced-toggle"
                    data-settings-advanced-toggle
                    onClick={() => setShowAdvanced((v) => !v)}
                >
                    {showAdvanced() ? "▾" : "▸"} Advanced (raw settings)
                </button>
                <Show when={showAdvanced()}>
                    <p class="status" style={{ margin: "4px 0 6px" }}>
                        The exact settings text. Leave it as <code>{"{}"}</code> to use the defaults.
                    </p>
                    <textarea
                        class="config-text"
                        data-config-text
                        spellcheck={false}
                        value={text()}
                        onInput={(e) => { setRaw(e.currentTarget.value); setMsg(""); }}
                    />
                    <Show when={!rawIsValid()}>
                        <div class="status" data-config-status>That isn't valid settings text — check for a stray character or a missing comma, bracket, or quote.</div>
                    </Show>
                </Show>
            </Show>

            <div class="bar">
                <button data-settings-save onClick={save}>save</button>
                <span class="status" data-config-status>{msg()}</span>
            </div>
        </div>
    );
}
