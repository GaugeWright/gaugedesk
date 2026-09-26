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
    onClose: () => void;
    onSaved?: () => void;
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
            if (props.kind === "panel") {
                const profile = panel();
                if (!profile) throw new Error("Panel profile is still loading.");
                await props.api.setPanelProfile(props.id, profile);
            }
            await props.api.setArchetypeAbilities(props.id, abilities());
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
        <main class="agent-settings-content" data-config-editor>
            <article class="agent-settings-page">
            <header class="agent-settings-page-head">
                <div><span>Agent settings</span><h1>{props.name}</h1></div>
                <button type="button" onClick={props.onClose}>Close</button>
            </header>
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
                        {(profile) => <PanelContractEditor
                            profile={profile()}
                            onChange={(next) => { setPanelDraft(next); setPanelDirty(true); setMsg(""); }}
                            onNotice={setMsg} />}
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
                            Choose the workspace and task abilities this agent receives.
                        </p>
                        {AGENT_ABILITY_PRESETS.map((preset) => {
                            const checked = () =>
                                JSON.stringify(abilities().filter((ability) => ability !== "tracker.file").sort()) ===
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
                                            setSelectedAbilities(abilities().includes("tracker.file")
                                                ? [...preset.value, "tracker.file"] : preset.value);
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
                        <label style={{ display: "flex", gap: "8px", "align-items": "start", margin: "10px 0 0" }}>
                            <input type="checkbox" checked={abilities().includes("tracker.file")}
                                onChange={(event) => {
                                    setSelectedAbilities(event.currentTarget.checked
                                        ? [...abilities(), "tracker.file"]
                                        : abilities().filter((ability) => ability !== "tracker.file"));
                                    setMsg("");
                                }} />
                            <span>File project tasks <small class="status" style={{ display: "block" }}>Allows this agent to create real items in the current project’s task bar. Publish the draft to make this available to placed Agents.</small></span>
                        </label>
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
            </article>
        </main>
    );
}
