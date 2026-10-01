/**
 * How a Panel agent's contract and deployment read to its owner (PANEL-12).
 *
 * The wire names — `gw-chat`, `workspace.write`, seconds, cents, bytes — are the
 * contract's, and they stay on the wire. The owner reads plain names and the
 * units they think in. Every translation between the two lives here, as pure
 * functions, so a UI rewrite cannot quietly change what a label means or what
 * a number publishes as, and so each is pinned by a test.
 *
 * Nothing here decides what the Home or the edge admits. Where a rule is
 * mirrored (a collection path), it is mirrored only to say what is wrong before
 * the owner saves; the authority's own refusal still stands.
 */

import type { AgentAbility, PanelPublicProfile, PublicPanelComponent } from "@gaugewright/control-plane-client";
import { isDefaultVisible, pickableModels } from "./model-picker";

export interface Choice<T> {
    readonly value: T;
    readonly name: string;
    readonly detail: string;
}

/** The public panels a Panel agent may publish, in the order the owner reads them. */
export const PANEL_CHOICES: readonly Choice<PublicPanelComponent>[] = [
    { value: "gw-chat", name: "Chat", detail: "Visitors talk with the agent." },
    { value: "gw-viewer", name: "Viewer", detail: "Shows the file the agent is working on." },
    { value: "gw-files", name: "Files", detail: "Visitors browse and download the session's files." },
    { value: "gw-chats", name: "Conversations", detail: "Visitors return to their earlier conversations." },
];

/** The abilities a Panel agent may offer the public, in plain words. */
export const PUBLIC_ABILITY_CHOICES: readonly Choice<AgentAbility>[] = [
    { value: "workspace.read", name: "Read files", detail: "Read and search the files in the visitor's session." },
    { value: "workspace.write", name: "Create and edit files", detail: "Write documents and other results into the session." },
    { value: "command.run", name: "Run commands", detail: "Run commands in the session's sandbox. Commands can write files." },
    { value: "question.ask", name: "Ask questions", detail: "Ask the visitor short multiple-choice questions." },
];

export interface ProviderChoice {
    readonly value: string;
    readonly name: string;
    readonly credentialClass: string;
}

/** Providers the public session host calls directly. The base URL is the
 *  provider's origin: the native clients append their own API paths. */
/** The providers whose keys can pay for a deployment. A key is stored under its
 *  provider's class, and a deployment it funds runs on that provider (DR-0272). */
export const KEY_PROVIDERS: readonly ProviderChoice[] = [
    { value: "openai", name: "OpenAI", credentialClass: "openai-api-key" },
    { value: "anthropic", name: "Anthropic", credentialClass: "anthropic-api-key" },
];

export function providerName(provider: string): string {
    return KEY_PROVIDERS.find((choice) => choice.value === provider)?.name ?? provider;
}

/** The value the model choice holds for "no pin". */
export const WORK_CHAT_DEFAULT_MODEL = "";

/** The models a Panel version can pin, from GaugeDesk's shipped model catalog:
 *  the set the chat picker shows by default across the providers that can serve
 *  a deployment, so the two never list different models (WS-597). The first
 *  choice pins nothing, so a deployment uses the publisher's work-chat default.
 *
 *  A model the profile already pins stays listed when the catalog does not
 *  carry it, so opening the editor never changes what a published version
 *  runs. */
export function panelModelChoices(current = ""): readonly Choice<string>[] {
    const models: Choice<string>[] = [{
        value: WORK_CHAT_DEFAULT_MODEL,
        name: "Your work-chat default",
        detail: "Whatever model your work chats use when you deploy.",
    }];
    for (const model of pickableModels(KEY_PROVIDERS.map((provider) => provider.value)).filter(isDefaultVisible)) {
        models.push({ value: model.id, name: model.name, detail: model.id });
    }
    if (current && !models.some((model) => model.value === current)) {
        models.push({ value: current, name: current, detail: "Not in GaugeDesk's model catalog." });
    }
    return models;
}

/** The profile with `model` pinned, or unpinned for the work-chat default. */
export function withPinnedModel(profile: PanelPublicProfile, model: string): PanelPublicProfile {
    const pinned = model.trim();
    const { pinned: _previous, ...ceilings } = profile.model;
    return { ...profile, model: pinned ? { ...ceilings, pinned } : ceilings };
}

// --- money ------------------------------------------------------------------

/** "$12.84" for 1284 cents. */
export function formatCents(cents: number): string {
    return `$${(cents / 100).toFixed(2)}`;
}

/** The dollars an input shows for a cents value: no trailing ".00" noise. */
export function dollarsFromCents(cents: number): string {
    const dollars = cents / 100;
    return Number.isInteger(dollars) ? String(dollars) : dollars.toFixed(2);
}

/** Cents to publish for what the owner typed, or null when it is not an amount. */
export function centsFromDollars(input: string): number | null {
    const trimmed = input.trim().replace(/^\$/, "");
    if (!/^\d+(\.\d{0,2})?$|^\.\d{1,2}$/.test(trimmed)) return null;
    return Math.round(Number(trimmed) * 100);
}

// --- durations --------------------------------------------------------------

export type DurationUnit = "hours" | "days";

const UNIT_SECONDS: Record<DurationUnit, number> = { hours: 3_600, days: 86_400 };

/** The unit a duration reads in: whole days when it is whole days, else hours. */
export function durationParts(seconds: number): { value: number; unit: DurationUnit } {
    if (seconds >= UNIT_SECONDS.days && seconds % UNIT_SECONDS.days === 0) {
        return { value: seconds / UNIT_SECONDS.days, unit: "days" };
    }
    return { value: Math.max(1, Math.round(seconds / UNIT_SECONDS.hours)), unit: "hours" };
}

export function secondsFrom(value: number, unit: DurationUnit): number {
    return Math.round(value * UNIT_SECONDS[unit]);
}

/** "1 day", "30 days", "12 hours", "45 minutes". */
export function formatDuration(seconds: number): string {
    const plural = (count: number, word: string) => `${count} ${word}${count === 1 ? "" : "s"}`;
    if (seconds >= UNIT_SECONDS.days && seconds % UNIT_SECONDS.days === 0) return plural(seconds / UNIT_SECONDS.days, "day");
    if (seconds >= UNIT_SECONDS.hours && seconds % UNIT_SECONDS.hours === 0) return plural(seconds / UNIT_SECONDS.hours, "hour");
    return plural(Math.max(1, Math.round(seconds / 60)), "minute");
}

/** "2 hours ago", "3 days ago": how long since a moment, for a list of sessions. */
export function formatAge(thenMs: number, nowMs: number): string {
    const minutes = Math.max(0, Math.floor((nowMs - thenMs) / 60_000));
    if (minutes < 1) return "just now";
    if (minutes < 60) return `${minutes} min ago`;
    const hours = Math.floor(minutes / 60);
    if (hours < 24) return `${hours} h ago`;
    const days = Math.floor(hours / 24);
    return `${days} day${days === 1 ? "" : "s"} ago`;
}

// --- collection -------------------------------------------------------------

/** The largest single collected file the Home admits (`MAX_COLLECTION_ARTIFACT_BYTES`). */
export const MAX_COLLECTED_FILE_MB = 8;

/** The collection selector a new collecting contract starts with: every file the
 *  agent leaves directly in `artifacts/`. */
export const DEFAULT_COLLECTED_PATH = "artifacts/*";

/** Why a collection path would be refused, in the owner's terms, or "" when it is
 *  a bounded selector inside `artifacts/` (`library_state.rs`, `validate_panel_profile`). */
export function collectionPathProblem(path: string): string {
    const selector = path.endsWith("/*") ? path.slice(0, -2) : path;
    if (!path.startsWith("artifacts/")) return `“${path}” must be inside artifacts/.`;
    if (path.includes("**")) return `“${path}” can't use **. Name a file, or a folder followed by /*.`;
    if (!selector || selector.startsWith("/") || selector.includes("\\")
        || selector.split("/").some((part) => !part || part === "." || part === "..")) {
        return `“${path}” isn't a file or folder path.`;
    }
    return "";
}

// --- the contract, read back ------------------------------------------------

export interface ContractFact {
    readonly label: string;
    readonly value: string;
}

function list(values: readonly string[]): string {
    if (values.length <= 1) return values[0] ?? "";
    return `${values.slice(0, -1).join(", ")} and ${values[values.length - 1]}`;
}

/** The frozen contract in the owner's words: what a deployment of it gives visitors. */
export function contractFacts(profile: PanelPublicProfile): ContractFact[] {
    const panels = PANEL_CHOICES.filter((choice) => profile.panels.components.includes(choice.value))
        .map((choice) => choice.name);
    const abilities = PUBLIC_ABILITY_CHOICES.filter((choice) => profile.public_abilities.includes(choice.value))
        .map((choice) => choice.name.toLowerCase());
    const files = profile.initial_workspace.map((file) => file.path);
    const kept = [
        profile.retention.transcript_retained ? "transcript" : "",
        profile.retention.workspace_retained ? "files" : "",
    ].filter(Boolean);
    const collection = profile.collection;
    return [
        { label: "Visitors see", value: list(panels) },
        // Commas, not "and": "create and edit files" already has one.
        { label: "The agent can", value: abilities.length ? abilities.join(", ") : "only chat" },
        { label: "Model", value: profile.model.pinned ?? "Your work-chat default when deployed" },
        { label: "Starting files", value: files.length ? list(files) : "None" },
        {
            label: "History",
            value: `Resumable for ${formatDuration(profile.retention.idle_ttl_seconds)} after the last message, `
                + `deleted after at most ${formatDuration(profile.retention.absolute_ttl_seconds)}`
                + (kept.length ? `; keeps the ${list(kept)}` : "; keeps nothing"),
        },
        {
            label: "Results",
            value: collection
                ? `Sent to the project Inbox: ${list([...collection.exportable_paths, ...(collection.transcript_eligible ? ["the transcript"] : [])])}`
                : "Not collected",
        },
    ];
}
