/**
 * The review surface (ADR 0110 §7, GATE-6): what inbound material has arrived,
 * what the gate ruled, and one item at a time.
 *
 * An **index**, not a document. Nothing here concatenates the corpus into one
 * page — that would hand a reviewer a wall of attacker-authored text and ask
 * them to notice one line of it. Provenance leads; a payload is read only when a
 * person deliberately opens it.
 *
 * The verdict buttons carry an answer; they never decide. `reviewQuarantinedItem`
 * hands it to the project's gate, which is the only producer of a verdict
 * (ADR 0117 §1). A `flag` escalates rather than discarding (ADR 0110 §6), so the
 * copy says "flag", never "delete".
 *
 * A thin renderer (`INV-5`): it shows a projection and submits a command.
 */

import { createResource, createSignal, For, Show } from "solid-js";
import type { QuarantinedItem } from "@gaugewright/control-plane-client";
import { useSession } from "./session-context";

/** Bytes, in the units a reviewer can judge at a glance. */
export function quarantineSize(bytes: number): string {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${Math.round(bytes / 102.4) / 10} KB`;
    return `${Math.round(bytes / 104857.6) / 10} MB`;
}

/** Arrival time, local. Absolute rather than relative: "3 days ago" is worse than
 *  a date when the question is whether this is the batch you were expecting. */
function arrived(unixMs: number): string {
    if (!Number.isFinite(unixMs) || unixMs <= 0) return "unknown";
    return new Date(unixMs).toLocaleString();
}

/** What the gate has said about an item, in the reviewer's words. */
export function quarantineStatusCopy(status: string): { label: string; tone: string } {
    switch (status) {
        case "Approved":
            return { label: "approved", tone: "ok" };
        case "Rejected":
            return { label: "flagged", tone: "warn" };
        default:
            return { label: "awaiting review", tone: "pending" };
    }
}

export function QuarantineIndex(props: { readonly project: string }) {
    const session = useSession();
    const [refreshKey, setRefreshKey] = createSignal(0);
    const [open, setOpen] = createSignal<string | null>(null);
    const [msg, setMsg] = createSignal("");

    const [index] = createResource(
        () => [props.project, refreshKey()] as const,
        async ([project]) => session.api.listQuarantine?.(project) ?? null,
    );

    // The opened item's bytes, fetched only when a person asks for them.
    const [body] = createResource(
        () => {
            const item = open();
            return item ? ([props.project, item] as const) : null;
        },
        async ([project, item]) => session.api.readQuarantinedItem?.(project, item) ?? "",
    );

    async function rule(item: string, verdict: "keep" | "flag") {
        const chat = session.engagementId();
        if (!chat) {
            setMsg("open a chat first — a review is acted from one");
            return;
        }
        if (!session.api.reviewQuarantinedItem) {
            setMsg("this session cannot review inbound material");
            return;
        }
        setMsg("");
        try {
            const ruled = await session.api.reviewQuarantinedItem(
                props.project,
                item,
                chat,
                verdict,
            );
            setOpen(null);
            setRefreshKey((n) => n + 1);
            // A gate that parks rather than ruling is not a failure — a composed
            // gate escalates — but it is also not the approval the button
            // implies, and saying nothing made the two identical. The item stayed
            // in the list "awaiting review" with no account of why, which is
            // exactly what a reviewer cannot act on.
            if (!ruled.workspacePath) {
                setMsg(
                    "The gate has not settled this yet — it escalated rather than ruling. "
                        + "The item stays in quarantine.",
                );
            }
        } catch (error) {
            setMsg(error instanceof Error ? error.message : "the verdict did not reach the gate");
        }
    }

    return (
        <div class="quarantine" data-testid="quarantine-index">
            <div class="quarantine-head">
                <span class="quarantine-title">inbound</span>
                <span class="status">
                    {index()
                        ? `${index()!.items.length} item(s) · ${index()!.pending} awaiting the gate`
                        : "reading…"}
                </span>
                <button class="ghost" onClick={() => setRefreshKey((n) => n + 1)}>refresh</button>
            </div>
            <Show when={msg()}>
                <p class="status warn" data-quarantine-msg>{msg()}</p>
            </Show>
            <Show
                when={(index()?.items.length ?? 0) > 0}
                fallback={<p class="status">Nothing has arrived for this project.</p>}
            >
                <ul class="quarantine-list">
                    <For each={index()!.items}>
                        {(item: QuarantinedItem) => {
                            const state = quarantineStatusCopy(item.status);
                            const showing = () => open() === item.item_id;
                            return (
                                <li
                                    class="quarantine-item"
                                    classList={{ open: showing() }}
                                    data-quarantine-item={item.item_id}
                                >
                                    <button
                                        class="quarantine-row"
                                        aria-expanded={showing()}
                                        onClick={() => setOpen(showing() ? null : item.item_id)}
                                    >
                                        <span class="quarantine-source" title={item.source_id}>
                                            {item.source_id}
                                        </span>
                                        <span class="quarantine-schema">{item.schema_ref}</span>
                                        <span class="quarantine-when">{arrived(item.arrived_at_unix_ms)}</span>
                                        <span class="quarantine-size">{quarantineSize(item.byte_len)}</span>
                                        <span class={`quarantine-status ${state.tone}`}>{state.label}</span>
                                    </button>
                                    <Show when={showing()}>
                                        <div class="quarantine-body">
                                            {/* The payload, read deliberately. This is the
                                                reviewer's path — no agent file store root
                                                resolves into quarantine, so these bytes
                                                are unreachable from a turn. */}
                                            <pre class="quarantine-payload">{body() ?? "reading…"}</pre>
                                            <Show when={item.status === "Pending"}>
                                                <div class="quarantine-actions">
                                                    <button
                                                        class="primary"
                                                        data-quarantine-keep
                                                        title="Keep this into the workspace, where an agent can read it"
                                                        onClick={() => rule(item.item_id, "keep")}
                                                    >
                                                        keep
                                                    </button>
                                                    <button
                                                        class="ghost"
                                                        data-quarantine-flag
                                                        title="Flag it — it stays here for another look and never reaches the workspace"
                                                        onClick={() => rule(item.item_id, "flag")}
                                                    >
                                                        flag
                                                    </button>
                                                </div>
                                            </Show>
                                            <Show when={item.workspace_path}>
                                                <p class="status">Kept at {item.workspace_path}</p>
                                            </Show>
                                        </div>
                                    </Show>
                                </li>
                            );
                        }}
                    </For>
                </ul>
            </Show>
        </div>
    );
}
