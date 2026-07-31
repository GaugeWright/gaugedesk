/**
 * The composer **model picker**, derived from GaugeDesk's model catalog
 * (`model-catalog.generated.ts`) and the operator's **linked accounts** (LLM-1,
 * [ADR 0062](../../specs/decisions/0062-llm-access-byok-and-managed-with-per-project-credentials.md)).
 *
 * The catalog is product truth for *what exists* (provider plus supported
 * reasoning levels); linked accounts decide *what
 * is reachable*. We never call provider `/v1/models` at run time: the catalog is what the
 * runtime actually resolves, it carries the per-model thinking levels no listing reports,
 * and it works for `openai-codex` OAuth, which has no listing endpoint.
 *
 * Each linked account maps to one or more catalog providers, split into **primary** (the
 * account's own set — e.g. codex's GPT-5.x line) and **secondary** (extra sets the account
 * can also serve — codex can run the regular OpenAI catalog too). Primary models populate
 * the picker by default; secondary ones are reachable through the model-management setting.
 * Whatever the source, the chat config pins `(model, provider)` to the **account** provider
 * (so the engine authenticates against the right endpoint).
 */
import { MODEL_CATALOG, type CatalogModel } from "./model-catalog.generated";

/** How a linked account provider sources catalog models. `pin` is the provider written
 *  into the chat config (the engine's auth axis); `primary`/`secondary` are catalog
 *  provider keys the account can serve. */
interface AccountSource {
    readonly pin: string;
    readonly primary: readonly string[];
    readonly secondary: readonly string[];
}

const ACCOUNT_SOURCES: Record<string, AccountSource> = {
    // Codex runs its own GPT-5.x line (primary) and can also serve the regular OpenAI
    // catalog (secondary) — both pinned to `openai-codex` so the governed
    // provider binding uses the OAuth endpoint.
    "openai-codex": { pin: "openai-codex", primary: ["openai-codex"], secondary: ["openai"] },
    openai: { pin: "openai", primary: ["openai"], secondary: [] },
    anthropic: { pin: "anthropic", primary: ["anthropic"], secondary: [] },
    // openai-generic (ADR 0083) points at a user-configured endpoint whose model set
    // GaugeDesk cannot enumerate — there is no catalog, so no primary/secondary. Its
    // models come from a free-text entry the user types (see `providerTakesCustomModel`).
    "openai-generic": { pin: "openai-generic", primary: [], secondary: [] },
};

/** A friendly provider name for the `(provider)` disambiguator suffix. */
const PROVIDER_LABEL: Record<string, string> = {
    "openai-codex": "Codex",
    openai: "OpenAI",
    anthropic: "Anthropic",
    "openai-generic": "OpenAI-compatible",
};

/** Providers whose model id is entered free-text rather than picked from the catalog
 *  (the endpoint-configurable `openai-generic`, ADR 0083 — GaugeDesk cannot list its
 *  models). The composer offers a text field for these instead of catalog rows. */
export function providerTakesCustomModel(provider: string): boolean {
    return provider === "openai-generic";
}

/** A model reachable through the linked accounts. `provider` is the config pin; `primary`
 *  marks the account's native set (shown by default vs. settings-only). */
export interface PickableModel {
    readonly id: string;
    readonly provider: string;
    readonly name: string;
    /** Display label — the name, plus a `(provider)` suffix when more than one linked
     *  account can serve a model of the same name. */
    readonly label: string;
    readonly thinking: readonly string[];
    readonly reasoning: boolean;
    readonly primary: boolean;
}

/** A stable key for a pickable model / an enabled-set entry: `provider:id`. */
export function modelKey(m: { id: string; provider: string }): string {
    return `${m.provider}:${m.id}`;
}

/** Every model reachable through the linked accounts (primary + secondary), deduped on
 *  `provider:id` (primary wins), with `(provider)` suffixes applied to names that more than
 *  one linked account can serve. Order: catalog order, primary entries first. */
export function pickableModels(
    linkedAccountProviders: readonly string[],
    catalog: readonly CatalogModel[] = MODEL_CATALOG,
): PickableModel[] {
    const seen = new Set<string>();
    const entries: Array<Omit<PickableModel, "label">> = [];

    const take = (accounts: readonly string[], tier: "primary" | "secondary") => {
        for (const acct of accounts) {
            const src = ACCOUNT_SOURCES[acct];
            if (!src) continue;
            const catProviders = tier === "primary" ? src.primary : src.secondary;
            for (const m of catalog) {
                if (!catProviders.includes(m.provider)) continue;
                const key = `${src.pin}:${m.id}`;
                if (seen.has(key)) continue; // primary pass already claimed it
                seen.add(key);
                entries.push({
                    id: m.id,
                    provider: src.pin,
                    name: m.name,
                    thinking: m.thinking,
                    reasoning: m.reasoning,
                    primary: tier === "primary",
                });
            }
        }
    };
    // Primary first so it wins dedup over a secondary source of the same id.
    take(linkedAccountProviders, "primary");
    take(linkedAccountProviders, "secondary");

    // A name served by >1 distinct config provider gets a `(provider)` suffix so the two
    // are distinguishable (e.g. the same model via Codex and via an OpenAI key).
    const providersByName = new Map<string, Set<string>>();
    for (const e of entries) {
        if (!providersByName.has(e.name)) providersByName.set(e.name, new Set());
        providersByName.get(e.name)!.add(e.provider);
    }
    return entries.map((e) => ({
        ...e,
        label:
            (providersByName.get(e.name)?.size ?? 0) > 1
                ? `${e.name} (${PROVIDER_LABEL[e.provider] ?? e.provider})`
                : e.name,
    }));
}

/** Date-pinned snapshot ids (e.g. `…-20241022`, `…-2024-05-13`) — hidden by default in
 *  favour of the moving aliases; still reachable through the model-management setting. */
const SNAPSHOT = /\d{6,8}|\d{4}-\d{2}-\d{2}/;

/** The default-visible set when the operator hasn't curated their models: the account's
 *  **primary**, reasoning-capable, non-snapshot models — the modern, agent-suitable ones. */
export function isDefaultVisible(m: PickableModel): boolean {
    return m.primary && m.reasoning && !SNAPSHOT.test(m.id);
}

/** A picker option (the `<option>`): `id`/`provider` are the config pin (empty = no
 *  override), `thinking` drives the reasoning-effort toggle's choices. */
export interface ModelOption {
    readonly id: string;
    readonly provider: string;
    readonly label: string;
    readonly thinking: readonly string[];
}

/** The "Default" (no per-chat override) option — always first. */
export const DEFAULT_OPTION: ModelOption = { id: "", provider: "", label: "Default", thinking: ["off"] };

/** The engine's resolved no-pin default, as reported by `/account/default-model`. */
export interface ResolvedDefault {
    readonly provider: string;
    readonly model: string | null;
}

/** The picker's first row. When the engine's resolved no-pin default is known,
 *  name it — "GPT-5.5 (default)" — so the row says what will actually run; a
 *  blind "Default" is only the fallback while that's unknown (or the resolved
 *  provider has no default model). The value stays empty: picking it still
 *  means "no per-chat override", not a pin. */
export function defaultOption(
    resolvedDefault?: ResolvedDefault | null,
    catalog: readonly CatalogModel[] = MODEL_CATALOG,
): ModelOption {
    const id = resolvedDefault?.model;
    if (!id) return DEFAULT_OPTION;
    const m = catalog.find((c) => c.provider === resolvedDefault?.provider && c.id === id);
    return { ...DEFAULT_OPTION, label: `${m?.name ?? id} (default)` };
}

/**
 * The picker options for the linked accounts and the operator's enabled-set preference:
 * `enabled` null/empty → the default-visible subset; otherwise exactly the enabled models.
 * Always leads with the default row (named when `resolvedDefault` is known), and keeps a
 * `pinned` model present even if it's filtered out
 * (so the `<select>` reflects the chat's real config rather than snapping to the first row).
 */
export function modelOptions(
    linkedAccountProviders: readonly string[],
    enabled: ReadonlySet<string> | null,
    pinned?: { id: string; provider: string },
    catalog: readonly CatalogModel[] = MODEL_CATALOG,
    resolvedDefault?: ResolvedDefault | null,
): ModelOption[] {
    const all = pickableModels(linkedAccountProviders, catalog);
    // `null` = never curated → the default-visible subset. A present set (even empty) is
    // the operator's explicit choice and is honoured exactly (empty → only "Default").
    const visible = all.filter((m) => (enabled !== null ? enabled.has(modelKey(m)) : isDefaultVisible(m)));

    if (pinned?.id && !visible.some((m) => m.id === pinned.id && m.provider === pinned.provider)) {
        const found = all.find((m) => m.id === pinned.id && m.provider === pinned.provider);
        if (found) visible.push(found);
        else if (providerTakesCustomModel(pinned.provider)) {
            // A custom openai-generic model has no catalog entry; keep the pin visible so
            // the `<select>` reflects the chat's real config rather than snapping away.
            visible.push({
                id: pinned.id,
                provider: pinned.provider,
                name: pinned.id,
                label: pinned.id,
                thinking: ["off"],
                reasoning: false,
                primary: true,
            });
        }
    }

    return [
        defaultOption(resolvedDefault, catalog),
        ...visible.map((m) => ({ id: m.id, provider: m.provider, label: m.label, thinking: m.thinking })),
    ];
}

// --- the operator's "which models show in the picker" preference (managed in the
//     Account panel, persisted in the account settings KV) ---------------------------

/** The account-settings key holding the enabled-model set (a JSON array of `provider:id`). */
export const ENABLED_MODELS_SETTING = "model_picker.enabled";

/** Parse the stored enabled set. Absent/blank/malformed → `null` (= use the default-visible
 *  subset). A present value (including `[]`, meaning "the operator disabled everything") →
 *  the exact set. */
export function parseEnabledModels(raw: string | null | undefined): Set<string> | null {
    if (!raw) return null;
    try {
        const arr = JSON.parse(raw);
        if (Array.isArray(arr) && arr.every((x) => typeof x === "string")) return new Set(arr);
    } catch {
        /* fall through */
    }
    return null;
}

/** Serialize an enabled set for the account-settings store (sorted → stable persistence). */
export function serializeEnabledModels(enabled: ReadonlySet<string>): string {
    return JSON.stringify([...enabled].sort());
}

/** The `provider:id` keys of the default-visible models — the checklist's initial state when
 *  the operator hasn't curated yet (so the settings UI reflects what the picker shows). */
export function defaultVisibleKeys(
    linkedAccountProviders: readonly string[],
    catalog: readonly CatalogModel[] = MODEL_CATALOG,
): Set<string> {
    return new Set(pickableModels(linkedAccountProviders, catalog).filter(isDefaultVisible).map(modelKey));
}

/** The reasoning-effort (`--thinking`) levels offered for a pinned model under the linked
 *  accounts — the toggle's options. `["off"]` for Default / an unknown model. */
export function thinkingLevelsFor(
    linkedAccountProviders: readonly string[],
    modelId: string,
    provider: string,
    catalog: readonly CatalogModel[] = MODEL_CATALOG,
): readonly string[] {
    if (!modelId) return ["off"];
    const m = pickableModels(linkedAccountProviders, catalog).find((x) => x.id === modelId && x.provider === provider);
    return m?.thinking ?? ["off"];
}

/**
 * Whether a chat's selected model accepts image input (UX-14 vision pre-check). Looks the
 * model up in the catalog by (provider, id) and reads its `input` modalities. **Permissive
 * on the unknown:** the default model (no pin) or a model absent from the catalog returns
 * `true` — we never *claim* a model can't see images unless the catalog says so, so the
 * composer only blocks an image attach on a **known non-vision** model rather than
 * second-guessing the provider binding's default resolution.
 */
export function modelAcceptsImages(
    pinned: { id: string; provider: string } | null | undefined,
    catalog: readonly CatalogModel[] = MODEL_CATALOG,
): boolean {
    if (!pinned?.id) return true; // default model — take the runtime's word
    const m = catalog.find((c) => c.id === pinned.id && c.provider === pinned.provider);
    if (!m) return true; // unknown to the catalog — don't pre-block
    return m.input.includes("image");
}
