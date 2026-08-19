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

import { createResource, createSignal, For, Show, type JSX } from "solid-js";
import type { LinkedProvider } from "@gaugewright/control-plane-client";
import { providerTakesCustomModel } from "./model-picker";

const PROVIDERS = ["openai", "anthropic", "xai", "openai-generic"];

export interface ProjectModelAccessApi {
    projectCredentials(project: string): Promise<LinkedProvider[]>;
    linkProjectCredential(
        project: string,
        provider: string,
        token: string,
        baseUrl?: string,
    ): Promise<void>;
    unlinkProjectCredential(project: string, provider: string): Promise<void>;
}

export function ProjectModelAccessPanel(props: {
    api: ProjectModelAccessApi;
    project: string;
    projectName: string;
    onClose: () => void;
}): JSX.Element {
    const [tick, setTick] = createSignal(0);
    const refresh = () => setTick((t) => t + 1);
    const [status, setStatus] = createSignal("");
    const [credentials] = createResource(tick, () => props.api.projectCredentials(props.project));

    const [provider, setProvider] = createSignal("openai");
    const [token, setToken] = createSignal("");
    // The OpenAI-compatible endpoint, shown + required only for openai-generic (ADR 0083).
    const [endpoint, setEndpoint] = createSignal("");
    const needsEndpoint = () => providerTakesCustomModel(provider());
    const isLinked = (p: string) => (credentials() ?? []).some((c) => c.provider === p && c.linked);

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
            setStatus(`unpinned ${p} — falls back to the account default`);
            refresh();
        } catch (e) {
            setStatus(`could not unpin: ${e instanceof Error ? e.message : String(e)}`);
        }
    };

    return (
        <div class="modal-overlay" onClick={() => props.onClose()}>
            <div
                class="modal project-model-access"
                data-project-model-access={props.project}
                role="dialog"
                aria-label={`model access for ${props.projectName}`}
                onClick={(e) => e.stopPropagation()}
                onKeyDown={(e) => e.key === "Escape" && props.onClose()}
            >
                <div class="modal-head">
                    <h3>Model access — {props.projectName}</h3>
                    <button type="button" onClick={() => props.onClose()}>
                        ×
                    </button>
                </div>

                <section class="admin-section">
                    <p class="muted">
                        Pin a provider key for this project. Chats here use the pinned key,
                        overriding your account default; unpin to fall back. The token is sealed —
                        it is never shown again.
                    </p>
                    <ul class="member-list">
                        <For
                            each={credentials()}
                            fallback={<li class="muted">No project pin — using the account default.</li>}
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
                                        unpin
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
                            pin
                        </button>
                    </div>
                </section>

                <p class="status" data-project-model-access-status>
                    {status()}
                </p>
            </div>
        </div>
    );
}
