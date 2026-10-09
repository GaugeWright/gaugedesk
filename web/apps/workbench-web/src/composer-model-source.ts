/**
 * Where the composer's model picker reads what it may offer (WS-1026).
 *
 * A chat in the person's own work offers the models their account reaches:
 * its linked credentials, a Codex sign-in, the endpoint models they declared,
 * their curation of the picker, and the default their account resolves.
 *
 * A chat in a project someone shared with them runs on that project's own
 * credentials, at the Home that holds it (DR-0451, DR-0453 §5), and that Home
 * keeps none of the person's own. So it offers what that Home answers for the
 * project — `WorkbenchControlPlane.sharedProjectModels`: the project's own
 * keys, with the models the owner declared for any that ship no catalog —
 * and nothing of the person's own account: their own keys are not what a
 * turn there spends, and their curation of their own models would hide the
 * project's. A member never falls back to the owner's own account key, so a
 * project with no key of its own says so rather than offering nothing
 * (DR-0476). While that answer is outstanding it offers nothing, rather than
 * the person's own models, which no turn there could run.
 */
import type { LinkedProvider, ProjectModels } from "@gaugewright/control-plane-client";
import {
    ENABLED_MODELS_SETTING,
    ENDPOINT_MODELS_SETTING,
    catalogWithEndpointModels,
    parseEnabledModels,
    parseEndpointModels,
    pickableModels,
    type ResolvedDefault,
} from "@gaugewright/workbench-ui";

/** What the person's own account answered for the picker. */
export interface OwnModelAccess {
    readonly credentials: readonly LinkedProvider[] | undefined;
    readonly codexLinked: boolean;
    readonly settings: Readonly<Record<string, string>> | undefined;
    readonly resolvedDefault: ResolvedDefault | null;
}

/** A shared project whose Home could not say what it runs: nothing is offered,
 * rather than the person's own models, which no turn there could run. */
export const NO_PROJECT_MODELS: ProjectModels = {
    providers: [],
    endpointModels: {},
    defaultModel: { provider: null, model: null },
};

/** The inputs `modelOptions` takes. */
export interface ComposerModelSource {
    readonly providers: readonly string[];
    readonly enabled: ReadonlySet<string> | null;
    readonly catalog: ReturnType<typeof catalogWithEndpointModels>;
    readonly resolvedDefault: ResolvedDefault | null;
    /** Why a shared project's chat has no model to offer, said in the picker
     * and the composer instead of an empty list (DR-0476 §2). */
    readonly unavailable?: string;
}

/** A shared project whose owner linked no key of the project's own. A
 * member's turns never fall back to the owner's own account key (DR-0476 §2),
 * so there is nothing to offer until the owner links one. */
export const NO_PROJECT_KEY = "The owner hasn't linked a model key to this project.";

/** A shared project whose own key ships no catalog and for which the owner
 * declared no model (DR-0476 §1). */
export const NO_DECLARED_MODEL = "The owner hasn't named a model for this project's key.";

/**
 * `shared` is the shared project's answer, `undefined` while it is being
 * read, and `null` when the chat is not in a project shared with the person.
 */
export function composerModelSource(
    shared: ProjectModels | null | undefined,
    own: OwnModelAccess,
): ComposerModelSource {
    if (shared !== null) {
        const providers = [...(shared?.providers ?? [])];
        const catalog = catalogWithEndpointModels(shared?.endpointModels ?? {});
        const resolvedDefault = shared?.defaultModel ?? null;
        // The project's own keys, with the models its owner declared for any
        // that ship no catalog (DR-0476 §1). Said, not left empty, when there
        // is nothing: no key of the project's own, or a key with no model.
        const unavailable = shared === undefined
            ? undefined
            : providers.length === 0
                ? NO_PROJECT_KEY
                : pickableModels(providers, catalog).length === 0 && !resolvedDefault?.model
                    ? NO_DECLARED_MODEL
                    : undefined;
        return {
            providers,
            // Uncurated: the default-visible subset of what the project runs.
            enabled: null,
            catalog,
            resolvedDefault,
            ...(unavailable ? { unavailable } : {}),
        };
    }
    const providers = (own.credentials ?? []).filter((c) => c.linked).map((c) => c.provider);
    if (own.codexLinked) providers.push("openai-codex");
    return {
        providers,
        enabled: parseEnabledModels(own.settings?.[ENABLED_MODELS_SETTING]),
        // The providers GaugeDesk ships no catalog for — an OpenAI-compatible endpoint
        // with no listing (ADR 0083), OpenRouter with one too large and too short-lived
        // to snapshot (ADR 0148) — contribute the models the operator declared in
        // Settings. They join the catalog here rather than at each call, so the picker,
        // the effort toggle and the vision check all see one set.
        catalog: catalogWithEndpointModels(parseEndpointModels(own.settings?.[ENDPOINT_MODELS_SETTING])),
        resolvedDefault: own.resolvedDefault,
    };
}
