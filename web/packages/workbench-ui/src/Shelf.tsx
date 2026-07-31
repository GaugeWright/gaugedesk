/**
 * The history shelf (round-6 #1): opened as a right-side drawer from the chat
 * header. For a layperson it shows one thing — the plain-language **activity**
 * list of what happened in this chat (the Timeline tab).
 *
 * Raw reducer controls are intentionally absent. Review and export decisions
 * live on concrete outputs in the user-facing Outputs tab.
 */

import { createSignal, For, Show } from "solid-js";
import type { EngagementId, ScopeId } from "@gaugewright/control-plane-client";
import { AuditTimeline, type AuditTimelineApi } from "./AuditTimeline";
import { OutputCatalog, type OutputCatalogApi } from "./OutputCatalog";

type Tab = "audit" | "outputs";
const TAB_LABEL: Record<Tab, string> = { audit: "Activity", outputs: "Outputs" };

export type ShelfApi = AuditTimelineApi & OutputCatalogApi;

export function Shelf(props: {
    api: ShelfApi;
    /** The chat's scope (scope-keyed surfaces: activity timeline, review driver). */
    scope: ScopeId;
    /** The same chat as an engagement id (the engagement-keyed outputs route). The
     *  owner (`App`) mints both brands; the shelf never launders one into the other. */
    id: EngagementId;
    onSaveOutputToDisk?: (resourceId: string) => Promise<{ exported: string[]; dest: string } | null>;
    onClose: () => void;
}) {
    const [tab, setTab] = createSignal<Tab>("audit");
    const tabs = (): Tab[] => ["audit", "outputs"];
    return (
        // A right-side drawer (#6) rather than a thin bar floating mid-screen: it
        // sits against the chat lane it describes; the dimmed backdrop still closes it.
        <div class="drawer-overlay" data-history-overlay onClick={props.onClose}>
            <div class="drawer shelf-drawer" onClick={(e) => e.stopPropagation()}>
                <div class="modal-head">
                    <div class="tabs" style={{ border: "none", margin: 0 }}>
                        <For each={tabs()}>
                            {(t) => (
                                <span class="tab" data-tab={t} classList={{ active: tab() === t }} onClick={() => setTab(t)}>
                                    {TAB_LABEL[t]}
                                </span>
                            )}
                        </For>
                    </div>
                    <button onClick={props.onClose}>close</button>
                </div>
                <Show when={tab() === "audit"}>
                    <AuditTimeline api={props.api} scope={props.scope} />
                </Show>
                <Show when={tab() === "outputs"}>
                    <OutputCatalog api={props.api} id={props.id} onSaveToDisk={props.onSaveOutputToDisk} />
                </Show>
            </div>
        </div>
    );
}
