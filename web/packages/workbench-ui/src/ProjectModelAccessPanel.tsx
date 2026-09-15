/**
 * **Project model access** (`LLM-2`, [ADR 0062]): a per-project LLM-access settings
 * surface. A project may pin its own BYOK provider credential in its coordination scope,
 * overriding the account default for chats in that project (nearest-scope-wins at run
 * time — see `account::resolved_credential_envs`). Opened from a project node's "model
 * access…" menu; the project id comes from context, never typed.
 *
 * A thin renderer over `/projects/:id/credentials`. Same write-only discipline as the
 * account credential surface: the token is sealed server-side (`SEC-4`) and never read
 * back — the panel lists provider names + a linked flag, never the secret.
 */

import { createEffect, createResource, createSignal, For, Show, type JSX } from "solid-js";
import type {
    LinkedProvider,
    OrganizationModelAuthorityBinding,
    ProjectOrganizationModelOptions,
    ProjectOrganizationModelSelection,
} from "@gaugewright/control-plane-client";
import { providerTakesEndpoint } from "./model-picker";

const PROVIDERS = ["openai", "anthropic", "xai", "openrouter", "openai-generic"];

export interface ProjectModelAccessApi {
    projectCredentials(project: string): Promise<LinkedProvider[]>;
    linkProjectCredential(
        project: string,
        provider: string,
        token: string,
        baseUrl?: string,
    ): Promise<void>;
    unlinkProjectCredential(project: string, provider: string): Promise<void>;
    projectOrganizationModelOptions(project: string): Promise<ProjectOrganizationModelOptions>;
    projectOrganizationModelSelection(project: string): Promise<ProjectOrganizationModelSelection | null>;
    selectProjectOrganizationModel(
        project: string,
        input: {
            readonly binding: OrganizationModelAuthorityBinding;
            readonly connection: string;
            readonly model: string;
            readonly privateBroker: string;
            readonly admitPrivatePlaintext: true;
        },
    ): Promise<ProjectOrganizationModelSelection>;
    clearProjectOrganizationModelSelection(project: string): Promise<void>;
}

export function ProjectModelAccessContent(props: {
    api: ProjectModelAccessApi;
    project: string;
    projectName: string;
}): JSX.Element {
    const [tick, setTick] = createSignal(0);
    const refresh = () => setTick((t) => t + 1);
    const [status, setStatus] = createSignal("");
    const [credentials] = createResource(tick, () => props.api.projectCredentials(props.project));
    const [organizationOptions] = createResource(tick, () =>
        props.api.projectOrganizationModelOptions(props.project),
    );
    const [organizationSelection] = createResource(tick, () =>
        props.api.projectOrganizationModelSelection(props.project),
    );

    const [provider, setProvider] = createSignal("openai");
    const [token, setToken] = createSignal("");
    // The OpenAI-compatible endpoint, shown + required only for openai-generic (ADR 0083).
    const [endpoint, setEndpoint] = createSignal("");
    const needsEndpoint = () => providerTakesEndpoint(provider());
    const isLinked = (p: string) => (credentials() ?? []).some((c) => c.provider === p && c.linked);
    const [organizationConnection, setOrganizationConnection] = createSignal("");
    const [organizationModel, setOrganizationModel] = createSignal("");
    const [admittedPrivateBroker, setAdmittedPrivateBroker] = createSignal("");
    const selectedOption = () =>
        organizationOptions()?.options.find((option) => option.connection === organizationConnection());

    createEffect(() => {
        const options = organizationOptions()?.options ?? [];
        const current = organizationSelection();
        const currentOption = current
            ? options.find((option) => option.connection === current.connection)
            : undefined;
        const option =
            options.find((candidate) => candidate.connection === organizationConnection()) ??
            currentOption ??
            options[0];
        if (!option) {
            setOrganizationConnection("");
            setOrganizationModel("");
            return;
        }
        if (organizationConnection() !== option.connection) {
            setOrganizationConnection(option.connection);
        }
        const currentModel = organizationModel();
        const nextModel =
            option.models.includes(currentModel)
                ? currentModel
                : currentOption === option && current && option.models.includes(current.model)
                  ? current.model
                  : option.organizationDefault ?? option.models[0] ?? "";
        if (organizationModel() !== nextModel) setOrganizationModel(nextModel);
    });

    const link = async () => {
        if (!token()) {
            setStatus("paste a token first");
            return;
        }
        if (needsEndpoint() && !endpoint().trim()) {
            setStatus("enter the endpoint URL first");
            return;
        }
        try {
            await props.api.linkProjectCredential(
                props.project,
                provider(),
                token(),
                needsEndpoint() ? endpoint().trim() : undefined,
            );
            setToken("");
            setEndpoint("");
            setStatus(`pinned ${provider()} for this project ✓`);
            refresh();
        } catch (e) {
            setStatus(`could not pin: ${e instanceof Error ? e.message : String(e)}`);
        }
    };
    const unlink = async (p: string) => {
        try {
            await props.api.unlinkProjectCredential(props.project, p);
            setStatus(`removed the ${p} key from this project`);
            refresh();
        } catch (e) {
            setStatus(`could not remove key: ${e instanceof Error ? e.message : String(e)}`);
        }
    };
    const chooseOrganizationModel = async () => {
        const options = organizationOptions();
        const option = selectedOption();
        if (!options || !option || !organizationModel()) {
            setStatus("choose an available organization connection and model");
            return;
        }
        if (admittedPrivateBroker() !== option.privateBroker.authority) {
            setStatus(`confirm that ${option.privateBroker.name} may receive model input and output`);
            return;
        }
        try {
            await props.api.selectProjectOrganizationModel(props.project, {
                binding: options.binding,
                connection: option.connection,
                model: organizationModel(),
                privateBroker: option.privateBroker.authority,
                admitPrivatePlaintext: true,
            });
            setAdmittedPrivateBroker("");
            setStatus(`using ${option.name} · ${organizationModel()} for this project ✓`);
            refresh();
        } catch (error) {
            setStatus(`could not select: ${error instanceof Error ? error.message : String(error)}`);
        }
    };
    const clearOrganizationModel = async () => {
        try {
            await props.api.clearProjectOrganizationModelSelection(props.project);
            setStatus("organization model selection removed");
            refresh();
        } catch (error) {
            setStatus(`could not remove: ${error instanceof Error ? error.message : String(error)}`);
        }
    };

    return (
            <div class="project-model-access-content" data-project-model-access={props.project}>

                <section class="admin-section">
                    <h4>Organization-managed access</h4>
                    <Show
                        when={(organizationOptions()?.options.length ?? 0) > 0}
                        fallback={
                            <p class="muted" data-organization-model-empty>
                                {organizationOptions.error
                                    ? "Organization model access is unavailable right now."
                                    : "No organization connection is available to this project."}
                            </p>
                        }
                    >
                        <Show when={organizationSelection()}>
                            {(selection) => {
                                const current = () =>
                                    organizationOptions()?.options.find(
                                        (option) => option.connection === selection().connection,
                                    );
                                return (
                                    <p class="muted" data-organization-model-current>
                                        {current()
                                            ? `Current: ${current()!.name} · ${selection().model} via ${selection().privateBroker.name}`
                                            : "The previous organization selection is no longer available."}
                                    </p>
                                );
                            }}
                        </Show>
                        <div class="admin-invite" data-organization-model-picker>
                            <select
                                aria-label="organization connection"
                                value={organizationConnection()}
                                onChange={(event) => setOrganizationConnection(event.currentTarget.value)}
                            >
                                <For each={organizationOptions()?.options ?? []}>
                                    {(option) => <option value={option.connection}>{option.name}</option>}
                                </For>
                            </select>
                            <select
                                aria-label="organization model"
                                value={organizationModel()}
                                onChange={(event) => setOrganizationModel(event.currentTarget.value)}
                            >
                                <For each={selectedOption()?.models ?? []}>
                                    {(model) => <option value={model}>{model}</option>}
                                </For>
                            </select>
                            <button type="button" class="tree-action" onClick={() => void chooseOrganizationModel()}>
                                Use
                            </button>
                            <Show when={organizationSelection()}>
                                <button type="button" class="tree-action" onClick={() => void clearOrganizationModel()}>
                                    Remove
                                </button>
                            </Show>
                        </div>
                        <Show when={selectedOption()}>
                            {(option) => (
                                <label class="settings-toggle-row" data-private-model-broker-admission>
                                    <input
                                        type="checkbox"
                                        checked={admittedPrivateBroker() === option().privateBroker.authority}
                                        onChange={(event) => setAdmittedPrivateBroker(
                                            event.currentTarget.checked ? option().privateBroker.authority : "",
                                        )}
                                    />
                                    <span>
                                        Allow {option().privateBroker.name}, operated by {option().privateBroker.operator},
                                        to receive this project's model input and output while making these calls.
                                    </span>
                                </label>
                            )}
                        </Show>
                    </Show>
                </section>

                <section class="admin-section">
                    <h4>Project-owned connection</h4>
                    <p class="muted">
                        Keep a key inside this project Home. The token is sealed and never shown again.
                    </p>
                    <ul class="member-list">
                        <For
                            each={credentials()}
                            fallback={<li class="muted">No project-owned key.</li>}
                        >
                            {(c) => (
                                <li class="member-row" data-pinned={c.provider}>
                                    <span class="member-id">{c.provider}</span>
                                    <span class="badge">pinned</span>
                                    <button
                                        type="button"
                                        class="tree-action"
                                        onClick={() => void unlink(c.provider)}
                                    >
                                        Remove key
                                    </button>
                                </li>
                            )}
                        </For>
                    </ul>
                    <div class="admin-invite">
                        <select value={provider()} onChange={(e) => setProvider(e.currentTarget.value)}>
                            <For each={PROVIDERS}>
                                {(p) => (
                                    <option value={p}>
                                        {p}
                                        {isLinked(p) ? " (pinned)" : ""}
                                    </option>
                                )}
                            </For>
                        </select>
                        <Show when={needsEndpoint()}>
                            <input
                                data-project-credential-endpoint
                                type="url"
                                value={endpoint()}
                                onInput={(e) => setEndpoint(e.currentTarget.value)}
                                placeholder="endpoint URL (e.g. https://api.together.xyz/v1)"
                            />
                        </Show>
                        <input
                            data-project-credential-token
                            type="password"
                            value={token()}
                            onInput={(e) => setToken(e.currentTarget.value)}
                            placeholder="paste API key / token"
                        />
                        <button type="button" class="tree-action" onClick={() => void link()}>
                            Add key
                        </button>
                    </div>
                </section>

                <p class="status" data-project-model-access-status>
                    {status()}
                </p>
            </div>
    );
}

export function ProjectModelAccessPanel(props: {
    api: ProjectModelAccessApi;
    project: string;
    projectName: string;
    onClose: () => void;
}): JSX.Element {
    return (
        <div class="modal-overlay" onClick={() => props.onClose()}>
            <div
                class="modal project-model-access"
                role="dialog"
                aria-label={`model access for ${props.projectName}`}
                onClick={(event) => event.stopPropagation()}
                onKeyDown={(event) => event.key === "Escape" && props.onClose()}
            >
                <div class="modal-head">
                    <h3>Model access — {props.projectName}</h3>
                    <button type="button" onClick={() => props.onClose()}>×</button>
                </div>
                <ProjectModelAccessContent
                    api={props.api}
                    project={props.project}
                    projectName={props.projectName}
                />
            </div>
        </div>
    );
}
