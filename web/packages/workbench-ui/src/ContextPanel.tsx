/**
 * The **context-sources panel** (RF-E1 / m0-gate O-1): a listing of the durable
 * resources the chat works *from* — its attached context and its method — read
 * from the `GET /chats/:id/resources` projection (`control-plane.ts`). Until now
 * the backend served this projection but no UI read it: a user could attach a
 * folder and have no surface confirming what context the agent actually holds.
 *
 * It is a thin renderer: the "which resources belong here?", "is this available?",
 * "what does its access read as?" decisions are the pure helpers in
 * `resource-catalog.ts`. The panel only paints each source with its kind,
 * availability, and tombstone state — handle + metadata only, never payload
 * (`INV-10`). Mounted near the "add files" affordance in the chat header.
 */

import { createResource, createSignal, For, Show } from "solid-js";
import type { EngagementId, ResourceView } from "@gaugewright/control-plane-client";
import {
    availabilityLabel,
    availabilityOf,
    contextSources,
    kindLabel,
    resourceTitle,
} from "./resource-catalog";
import { LoadError } from "./LoadError";

export interface ContextResourceApi {
    getResources(id: EngagementId): Promise<ResourceView[]>;
    requestResourceAccess(id: EngagementId, resource: string): Promise<unknown>;
    approveResourceAccess(id: EngagementId, resource: string): Promise<unknown>;
}

export function ContextPanel(props: {
    api: ContextResourceApi;
    id: EngagementId;
    onClose: () => void;
    /** Bumped by the host on ingest so the listing refreshes when a folder is added. */
    refreshKey?: unknown;
}) {
    const [resources, { refetch }] = createResource(
        () => [props.id, props.refreshKey] as const,
        ([id]) => props.api.getResources(id),
    );
    const sources = () => contextSources(resources() ?? []);
    const [acting, setActing] = createSignal<string | null>(null);
    const [actionError, setActionError] = createSignal("");
    const act = async (resource: ResourceView, action: "request" | "approve") => {
        setActing(resource.id);
        setActionError("");
        try {
            if (action === "request") {
                await props.api.requestResourceAccess(props.id, resource.id);
            } else {
                await props.api.approveResourceAccess(props.id, resource.id);
            }
            await refetch();
        } catch (error) {
            setActionError(error instanceof Error ? error.message : "resource access failed");
        } finally {
            setActing(null);
        }
    };

    return (
        <div class="drawer-overlay" data-context-overlay onClick={props.onClose}>
            <div class="drawer context-drawer" onClick={(e) => e.stopPropagation()}>
                <div class="modal-head">
                    <h3 style={{ margin: 0 }}>Context sources</h3>
                    <button onClick={props.onClose}>close</button>
                </div>
                <Show when={!resources.error} fallback={<LoadError what="the context sources" onRetry={() => void refetch()} />}>
                <Show when={resources()} fallback={<div class="status">loading…</div>}>
                    <Show
                        when={sources().length}
                        fallback={
                            <div class="status">
                                No context attached yet. Use "add files" to give the agent reference material.
                            </div>
                        }
                    >
                        <div class="resource-list" data-context-list>
                            <For each={sources()}>
                                {(r) => {
                                    const avail = availabilityOf(r);
                                    return (
                                        <div
                                            class="resource-row"
                                            data-context-source={r.id}
                                            data-kind={r.kind}
                                            data-availability={avail}
                                            classList={{ erased: avail === "erased" }}
                                        >
                                            <span class="resource-kind" data-resource-kind>{kindLabel(r.kind)}</span>
                                            <span class="resource-title">{resourceTitle(r)}</span>
                                            <span
                                                class="resource-availability"
                                                data-availability={avail}
                                                title={`access: ${r.access}`}
                                            >
                                                {availabilityLabel(avail)}
                                            </span>
                                            <Show when={r.access === "Init" || r.access === "Revoked"}>
                                                <button
                                                    type="button"
                                                    class="link-btn"
                                                    data-resource-access-request={r.id}
                                                    disabled={acting() === r.id}
                                                    onClick={() => void act(r, "request")}
                                                >request access</button>
                                            </Show>
                                            <Show when={r.access === "Requested"}>
                                                <button
                                                    type="button"
                                                    class="link-btn"
                                                    data-resource-access-approve={r.id}
                                                    disabled={acting() === r.id}
                                                    onClick={() => void act(r, "approve")}
                                                >approve access</button>
                                            </Show>
                                            <Show when={r.tombstoned}>
                                                <span class="resource-tombstone" data-tombstoned title="payload erased">
                                                    erased
                                                </span>
                                            </Show>
                                        </div>
                                    );
                                }}
                            </For>
                        </div>
                    </Show>
                    <Show when={actionError()}>
                        <div class="status error" data-resource-access-error>{actionError()}</div>
                    </Show>
                </Show>
                </Show>
            </div>
        </div>
    );
}
