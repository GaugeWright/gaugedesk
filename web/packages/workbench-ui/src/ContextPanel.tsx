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
import type { ContextInspectionStatus, EngagementId, ResourceView } from "@gaugewright/control-plane-client";
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
    getContextInspection(id: EngagementId, resource: string): Promise<ContextInspectionStatus>;
    requestContextInspection(id: EngagementId, resource: string): Promise<ContextInspectionStatus>;
    getContextInspectionRequests(id: EngagementId, resource: string): Promise<{readers: string[]; granted: string[]}>;
    approveContextInspection(id: EngagementId, resource: string, reader: string): Promise<void>;
    revokeContextInspection(id: EngagementId, resource: string, reader: string): Promise<void>;
    revokeOwnContextInspection(id: EngagementId, resource: string): Promise<ContextInspectionStatus>;
}

function SourceInspection(props: { api: ContextResourceApi; id: EngagementId; resource: string }) {
    const [status, { refetch }] = createResource(
        () => [props.id, props.resource] as const,
        ([id, resource]) => props.api.getContextInspection(id, resource),
    );
    const [requests, { refetch: refetchRequests }] = createResource(
        () => [props.id, props.resource] as const,
        ([id, resource]) => props.api.getContextInspectionRequests(id, resource).catch(() => ({readers: [], granted: []})),
    );
    const [busy, setBusy] = createSignal(false);
    const [error, setError] = createSignal("");
    const request = async () => {
        setBusy(true);
        setError("");
        try {
            await props.api.requestContextInspection(props.id, props.resource);
            await refetch();
            await refetchRequests();
        } catch (reason) {
            setError(reason instanceof Error ? reason.message : "source request failed");
        } finally {
            setBusy(false);
        }
    };
    const approve = async (reader: string) => {
        setBusy(true);
        setError("");
        try {
            await props.api.approveContextInspection(props.id, props.resource, reader);
            await refetchRequests();
            await refetch();
        } catch (reason) {
            setError(reason instanceof Error ? reason.message : "source approval failed");
        } finally {
            setBusy(false);
        }
    };
    const revoke = async (reader: string) => {
        setBusy(true);
        setError("");
        try {
            await props.api.revokeContextInspection(props.id, props.resource, reader);
            await refetchRequests();
            await refetch();
        } catch (reason) {
            setError(reason instanceof Error ? reason.message : "source revocation failed");
        } finally {
            setBusy(false);
        }
    };
    const revokeOwn = async () => {
        setBusy(true);
        setError("");
        try {
            await props.api.revokeOwnContextInspection(props.id, props.resource);
            await refetchRequests();
            await refetch();
        } catch (reason) {
            setError(reason instanceof Error ? reason.message : "source revocation failed");
        } finally {
            setBusy(false);
        }
    };
    return <>
        <Show when={status()?.phase === "init"}>
            <button type="button" class="link-btn" disabled={busy()} onClick={() => void request()}>
                request inspection
            </button>
        </Show>
        <Show when={status()?.phase === "requested"}>
            <span class="resource-availability">inspection awaiting source approval</span>
        </Show>
        <Show when={status()?.phase === "granted"}>
            <span class="resource-availability">inspection granted</span>
            <button type="button" class="link-btn" disabled={busy()} onClick={() => void revokeOwn()}>
                revoke my inspection
            </button>
        </Show>
        <Show when={status()?.phase === "revoked"}>
            <span class="resource-availability">inspection revoked</span>
        </Show>
        <For each={requests()?.readers ?? []}>{(reader) =>
            <button type="button" class="link-btn" disabled={busy()} onClick={() => void approve(reader)}>
                approve inspection for {reader}
            </button>
        }</For>
        <For each={requests()?.granted ?? []}>{(reader) =>
            <button type="button" class="link-btn" disabled={busy()} onClick={() => void revoke(reader)}>
                revoke inspection for {reader}
            </button>
        }</For>
        <Show when={error()}><span class="status error">{error()}</span></Show>
    </>;
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
                                            <Show when={r.kind === "context" && !r.tombstoned}>
                                                <SourceInspection api={props.api} id={props.id} resource={r.id} />
                                            </Show>
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
