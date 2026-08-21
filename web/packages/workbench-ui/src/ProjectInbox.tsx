import { createResource, createSignal, For, Show, type JSX } from "solid-js";
import type { QuarantineIndex, QuarantinedItem } from "@gaugewright/control-plane-client";
import { quarantineSize, quarantineStatusCopy } from "./QuarantineIndex";

export interface ProjectInboxApi {
    listQuarantine(project: string): Promise<QuarantineIndex>;
    readQuarantinedItem(project: string, item: string): Promise<string>;
    reviewQuarantinedItem(project: string, item: string, verdict: "keep" | "flag"): Promise<{ workspacePath: string | null }>;
}

function arrived(unixMs: number): string {
    return Number.isFinite(unixMs) && unixMs > 0 ? new Date(unixMs).toLocaleString() : "unknown";
}

export function ProjectInbox(props: {
    api: ProjectInboxApi;
    project: string;
    projectName: string;
    onClose: () => void;
}): JSX.Element {
    const [refreshKey, setRefreshKey] = createSignal(0);
    const [open, setOpen] = createSignal<string | null>(null);
    const [message, setMessage] = createSignal("");
    const [busy, setBusy] = createSignal(false);
    const [index] = createResource(
        () => [props.project, refreshKey()] as const,
        ([project]) => props.api.listQuarantine(project),
    );
    const [body] = createResource(
        () => open() ? [props.project, open()!] as const : null,
        ([project, item]) => props.api.readQuarantinedItem(project, item),
    );

    async function review(item: string, verdict: "keep" | "flag") {
        setBusy(true);
        setMessage("");
        try {
            const result = await props.api.reviewQuarantinedItem(props.project, item, verdict);
            setOpen(null);
            setRefreshKey((value) => value + 1);
            setMessage(result.workspacePath
                ? `The project gate kept this at ${result.workspacePath}.`
                : "The project gate escalated this item. It remains isolated in Inbox.");
        } catch (reason) {
            setMessage(String(reason));
        } finally {
            setBusy(false);
        }
    }

    return <div class="modal-overlay" role="presentation" onClick={(event) => {
        if (event.target === event.currentTarget) props.onClose();
    }}><section class="modal embed-monitor" role="dialog" aria-modal="true" aria-label={`${props.projectName} Inbox`}>
        <header class="modal-head"><div><strong>{props.projectName} · Inbox</strong>
            <div class="muted">Collected Panel-agent data stays isolated until this project’s gate admits it.</div></div>
            <button type="button" class="icon-button" aria-label="Close" onClick={props.onClose}>×</button></header>
        <div class="quarantine" data-testid="project-inbox">
            <div class="quarantine-head"><span class="quarantine-title">inbound</span>
                <span class="status">{index() ? `${index()!.items.length} item(s) · ${index()!.pending} awaiting the gate` : "reading…"}</span>
                <button type="button" class="ghost" onClick={() => setRefreshKey((value) => value + 1)}>refresh</button></div>
            <Show when={message()}><p class="status warn">{message()}</p></Show>
            <Show when={(index()?.items.length ?? 0) > 0} fallback={<p class="status">Nothing has arrived for this project.</p>}>
                <ul class="quarantine-list"><For each={index()!.items}>{(item: QuarantinedItem) => {
                    const state = quarantineStatusCopy(item.status);
                    const showing = () => open() === item.item_id;
                    return <li class="quarantine-item" classList={{ open: showing() }}>
                        <button type="button" class="quarantine-row" aria-expanded={showing()} onClick={() => setOpen(showing() ? null : item.item_id)}>
                            <span class="quarantine-source" title={item.source_id}>{item.source_id}</span>
                            <span class="quarantine-schema">{item.schema_ref}</span>
                            <span class="quarantine-when">{arrived(item.arrived_at_unix_ms)}</span>
                            <span class="quarantine-size">{quarantineSize(item.byte_len)}</span>
                            <span class={`quarantine-status ${state.tone}`}>{state.label}</span>
                        </button>
                        <Show when={showing()}><div class="quarantine-body"><pre class="quarantine-payload">{body() ?? "reading…"}</pre>
                            <Show when={item.status === "Pending"}><div class="quarantine-actions">
                                <button type="button" class="primary" disabled={busy()} onClick={() => void review(item.item_id, "keep")}>keep</button>
                                <button type="button" class="ghost" disabled={busy()} onClick={() => void review(item.item_id, "flag")}>flag</button>
                            </div></Show>
                            <Show when={item.workspace_path}><p class="status">Kept at {item.workspace_path}</p></Show>
                        </div></Show>
                    </li>;
                }}</For></ul>
            </Show>
        </div>
    </section></div>;
}
