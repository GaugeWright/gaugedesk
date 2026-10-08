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
 * project — `WorkbenchControlPlane.sharedProjectModels` — and nothing of the
 * person's own account: their own keys are not what a turn there spends, and
 * their curation of their own models would hide the project's. While that
 * answer is outstanding it offers nothing, rather than the person's own
 * models, which no turn there could run.
 */
import type { LinkedProvider, ProjectModels } from "@gaugewright/control-plane-client";
import {
    ENABLED_MODELS_SETTING,
    ENDPOINT_MODELS_SETTING,
    catalogWithEndpointModels,
    parseEnabledModels,
    parseEndpointModels,
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
}

/**
 * `shared` is the shared project's answer, `undefined` while it is being
 * read, and `null` when the chat is not in a project shared with the person.
 */
export function composerModelSource(
    shared: ProjectModels | null | undefined,
    own: OwnModelAccess,
): ComposerModelSource {
    if (shared !== null) {
        return {
            providers: [...(shared?.providers ?? [])],
            // Uncurated: the default-visible subset of what the project runs.
            enabled: null,
            catalog: catalogWithEndpointModels(shared?.endpointModels ?? {}),
            resolvedDefault: shared?.defaultModel ?? null,
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
