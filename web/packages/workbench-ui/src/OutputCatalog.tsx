/**
 * The **output catalog** (RF-E1 / m0-gate O-4): a listing of the produced
 * `output`-kind resources an engagement holds, read from the
 * `GET /chats/:id/resources` projection and filtered to outputs. It is the
 * production surface for a finished deliverable and its protection state.
 *
 * Each output is shown with its availability/tombstone state and its review +
 * export **phase** (the protection gating it must pass before it can leave). The
 * decisions are the pure helpers in `workbench-ui/resource-catalog.ts` (re-exported
 * through the transitional `state/resource-catalog.ts` path); this component only
 * paints them and reads the review/export projections per output (handle +
 * metadata only, `INV-10`). It is mounted as a tab in the history `Shelf`.
 */

import { createResource, createSignal, For, Show } from "solid-js";
import {
    type EngagementId,
    type ResourceExportAction,
    type ResourceReviewAction,
    type ExportState,
    type ResourceView,
    type ReviewState,
} from "@gaugewright/control-plane-client";
import {
    availabilityLabel,
    availabilityOf,
    outputProtectionLabel,
    outputs,
    resourceTitle,
} from "./resource-catalog";
import { LoadError } from "./LoadError";

export interface OutputCatalogApi {
    getResources(id: EngagementId): Promise<ResourceView[]>;
    getResourceReview(id: EngagementId, resource: string): Promise<ReviewState>;
    getResourceExport(id: EngagementId, resource: string): Promise<ExportState>;
    proposeResourceReview(id: EngagementId, resource: string): Promise<{ scope: string; state: ReviewState }>;
    proposeResourceExport(id: EngagementId, resource: string): Promise<{ scope: string; state: ExportState }>;
    resourceReviewCommand(id: EngagementId, resource: string, action: ResourceReviewAction): Promise<ReviewState>;
    resourceExportCommand(id: EngagementId, resource: string, action: ResourceExportAction): Promise<ExportState>;
}

export function OutputCatalog(props: {
    api: OutputCatalogApi;
    /** The engagement whose outputs to catalog (the resource route is engagement-keyed). */
    id: EngagementId;
    refreshKey?: unknown;
    /** Desktop-only final egress hop. Absent in browser/enterprise surfaces. */
    onSaveToDisk?: (resourceId: string) => Promise<{ exported: string[]; dest: string } | null>;
}) {
    const [resources, { refetch }] = createResource(
        () => [props.id, props.refreshKey] as const,
        ([id]) => props.api.getResources(id),
    );
    const produced = () => outputs(resources() ?? []);

    return (
        <div class="output-catalog" data-output-catalog>
            <Show when={!resources.error} fallback={<LoadError what="the outputs" onRetry={() => void refetch()} />}>
            <Show when={resources()} fallback={<div class="status">loading…</div>}>
                <Show
                    when={produced().length}
                    fallback={
                        <div class="status">
                            No outputs yet. When the agent produces a deliverable it shows here with its review status.
                        </div>
                    }
                >
                    <div class="resource-list">
                        <For each={produced()}>
                            {(r) => <OutputRow api={props.api} engagement={props.id} resourceId={r.id} avail={availabilityOf(r)} title={resourceTitle(r)} tombstoned={r.tombstoned} onSaveToDisk={props.onSaveToDisk} />}
                        </For>
                    </div>
                </Show>
            </Show>
            </Show>
        </div>
    );
}

/** One output row: its availability plus the review/export phases that gate it.
 *  The lifecycle scopes are minted lazily (an output that was never proposed reads
 *  as `Init`), so a failed read just shows a dash rather than breaking the row. */
function OutputRow(props: {
    api: OutputCatalogApi;
    engagement: EngagementId;
    resourceId: string;
    avail: ReturnType<typeof availabilityOf>;
    title: string;
    tombstoned: boolean;
    onSaveToDisk?: (resourceId: string) => Promise<{ exported: string[]; dest: string } | null>;
}) {
    const [saveStatus, setSaveStatus] = createSignal<string | null>(null);
    const [decisionError, setDecisionError] = createSignal<string | null>(null);
    const [review, { mutate: setReview, refetch: refetchReview }] = createResource(
        () => props.resourceId,
        async (rid) => {
            try {
                return await props.api.getResourceReview(props.engagement, rid);
            } catch {
                return null;
            }
        },
    );
    const proposeReview = async () => {
        try {
            const proposal = await props.api.proposeResourceReview(props.engagement, props.resourceId);
            setReview(proposal.state);
            setDecisionError(null);
        } catch {
            setDecisionError("couldn't request review");
            await refetchReview();
        }
    };
    const reviewAction = async (action: ResourceReviewAction) => {
        try {
            setReview(await props.api.resourceReviewCommand(props.engagement, props.resourceId, action));
            setDecisionError(null);
        } catch {
            setDecisionError("that review decision wasn't admitted");
            await refetchReview();
        }
    };
    const [exp, { mutate: setExport, refetch: refetchExport }] = createResource(
        () => props.resourceId,
        async (rid) => {
            try {
                return await props.api.getResourceExport(props.engagement, rid);
            } catch {
                return null;
            }
        },
    );
    const proposeExport = async () => {
        try {
            const proposal = await props.api.proposeResourceExport(props.engagement, props.resourceId);
            setExport(proposal.state);
            setDecisionError(null);
        } catch {
            setDecisionError("couldn't prepare the export");
            await refetchExport();
        }
    };
    const exportAction = async (action: ResourceExportAction) => {
        try {
            setExport(await props.api.resourceExportCommand(props.engagement, props.resourceId, action));
            setDecisionError(null);
        } catch {
            setDecisionError("that export decision wasn't admitted");
            await refetchExport();
        }
    };
    const sourceComplete = () => {
        const state = exp();
        return state?.phase === "Requested"
            && state.source_required.every((party) => state.source_consented.includes(party));
    };
    const saveToDisk = async () => {
        if (!props.onSaveToDisk) return;
        setSaveStatus("saving…");
        try {
            const result = await props.onSaveToDisk(props.resourceId);
            setSaveStatus(result ? `saved ${result.exported.length} file(s)` : null);
            if (result) await refetchExport();
        } catch {
            setSaveStatus("couldn't save");
        }
    };

    return (
        <div
            class="resource-row output-row"
            data-output={props.resourceId}
            data-availability={props.avail}
            classList={{ erased: props.tombstoned }}
        >
            <span class="resource-kind" data-resource-kind>output</span>
            <span class="resource-title">{props.title}</span>
            <span class="resource-availability" data-availability={props.avail} title="whether this output's contents are available to you">
                {availabilityLabel(props.avail)}
            </span>
            {/* Plain-language protection status — never raw "review: Init / export:
                Init" tokens (round-12 A). Hidden entirely until something happens;
                the raw phases stay on data- attributes for tests/automation. */}
            <Show when={outputProtectionLabel(review()?.phase, exp()?.phase)}>
                {(label) => (
                    <span
                        class="output-status"
                        data-output-review={review()?.phase ?? "—"}
                        data-output-export={exp()?.phase ?? "—"}
                        title="review &amp; sharing status"
                    >
                        {label()}
                    </span>
                )}
            </Show>
            <Show when={props.tombstoned}>
                <span class="resource-tombstone" data-tombstoned title="payload erased">erased</span>
            </Show>
            <Show when={review()?.phase === "Released"}>
                <span class="badge released" data-output-released title="every stakeholder consented — this output can leave">released</span>
            </Show>
            <Show when={!props.tombstoned && (sourceComplete() || exp()?.phase === "Cleared") && props.onSaveToDisk}>
                <button
                    type="button"
                    class="link-btn"
                    data-save-output={props.resourceId}
                    onClick={() => void saveToDisk()}
                >
                    save to folder
                </button>
            </Show>
            <Show when={saveStatus()}>{(message) => <span class="status" data-save-output-status>{message()}</span>}</Show>
            <Show when={!props.tombstoned && review()?.phase === "Init"}>
                <button type="button" class="link-btn" data-propose-review onClick={() => void proposeReview()}>
                    request review
                </button>
            </Show>
            {/* UX-11: all stakeholders consented — the output is cleared and can be released. */}
            <Show when={review()?.phase === "Cleared"}>
                <div class="output-review-cleared" data-output-review-cleared={props.resourceId}>
                    <span class="hold-note">All stakeholders consented — ready to release</span>
                    <button type="button" class="link-btn" data-release onClick={() => void reviewAction("release")}>
                        release
                    </button>
                </div>
            </Show>
            {/* UX-11: a held output awaiting cross-party review. Show the stakeholder parties
                (its provenance — whose data it derives from) and each party's consent, with a
                consent-to-release affordance. Content stays gated until all consent. */}
            <Show when={review()?.phase === "Proposed"}>
                <div class="output-review-hold" data-output-review-hold={props.resourceId}>
                    <span class="hold-note" title="this output derives from other parties' data and is held until they consent to release">
                        Held for review — stakeholders must consent to release
                    </span>
                    <ul class="review-parties">
                        <For each={review()!.required}>
                            {(party) => {
                                const consented = () => (review()?.consented ?? []).includes(party);
                                return (
                                    <li class="review-party" data-review-party={party} classList={{ consented: consented() }}>
                                        <span class="party-id">{party}</span>
                                        <Show
                                            when={consented()}
                                            fallback={
                                                <span>awaiting consent</span>
                                            }
                                        >
                                            <span class="badge" data-consented={party}>consented ✓</span>
                                        </Show>
                                    </li>
                                );
                            }}
                        </For>
                    </ul>
                    <button
                        type="button"
                        class="link-btn"
                        data-consent-self
                        onClick={() => void reviewAction("consent")}
                    >
                        consent as me
                    </button>
                </div>
            </Show>
            <Show when={!props.tombstoned && review()?.phase === "Released" && exp()?.phase === "Init"}>
                <button type="button" class="link-btn" data-propose-export onClick={() => void proposeExport()}>
                    prepare export
                </button>
            </Show>
            <Show when={!props.tombstoned && exp()?.phase === "Requested" && !sourceComplete()}>
                <div class="output-export-hold" data-output-export-hold={props.resourceId}>
                    <span class="hold-note">Export is waiting for its source stakeholders</span>
                    <button
                        type="button"
                        class="link-btn"
                        data-export-consent-self
                        onClick={() => void exportAction("consent")}
                    >
                        consent to export as me
                    </button>
                </div>
            </Show>
            <Show when={!props.tombstoned && sourceComplete() && !props.onSaveToDisk}>
                <span class="hold-note" data-export-source-ready>
                    Source approved — waiting for target admission
                </span>
            </Show>
            <Show when={decisionError()}>{(message) => <span class="status" data-output-decision-error>{message()}</span>}</Show>
        </div>
    );
}
