/**
 * **Project Home** (`UX-2`, `mvp-workbench.md` "Project Home"): the per-project summary
 * panel — recent runs, live outputs/reviews, and an audit rollup — all derived **from
 * data** server-side (`INV-5`; `GET /projects/:id/home`) and rendered here. Opened from a
 * project node's "project home…" menu; the id comes from context, never typed.
 *
 * A thin, total renderer over the parsed {@link ProjectHome}: a partial/empty rollup
 * degrades to empty lists + zero counts (the parser never throws), so the panel always
 * renders.
 */

import { programsFromV1, projectWhipFor } from "./whip-view";
import { createResource, For, Show, type JSX } from "solid-js";
import type { ProjectHome, ProjectWhips } from "@gaugewright/control-plane-client";

export interface ProjectHomeApi {
    projectHome(project: string): Promise<ProjectHome>;
    /** The project's whip programs and instances. Optional: a session
     *  that cannot list them shows the section empty rather than absent. */
    listWhips?(project: string): Promise<ProjectWhips>;
}

export function ProjectHomePanel(props: {
    api: ProjectHomeApi;
    project: string;
    projectName: string;
    onOpenChat?: (chat: string) => void;
    /** Open a whip program's file, which is where its views live. */
    onOpenWhip?: (path: string) => void;
    onClose: () => void;
}): JSX.Element {
    const [home] = createResource(() => props.project, (p) => props.api.projectHome(p));
    // Every project runs at least the inbound gate, so this is never a section
    // the reader has to go looking for. Rolled up from the same instance views
    // the file's Instances tab renders, so the two cannot disagree.
    const [programs] = createResource(
        () => props.project,
        async (p) => (props.api.listWhips ? programsFromV1(await props.api.listWhips(p)) : []),
    );
    const whips = () =>
        (programs() ?? []).flatMap((program) =>
            program.instances.map((view) => projectWhipFor(program.path ?? program.program, view)),
        );

    return (
        <div class="modal-overlay" onClick={() => props.onClose()}>
            <div
                class="modal project-home-panel"
                data-project-home-panel={props.project}
                role="dialog"
                aria-label={`project home for ${props.projectName}`}
                onClick={(e) => e.stopPropagation()}
                onKeyDown={(e) => e.key === "Escape" && props.onClose()}
            >
                <div class="modal-head">
                    <h3>{props.projectName}</h3>
                    <button type="button" onClick={() => props.onClose()}>
                        ×
                    </button>
                </div>

                <section class="admin-section" data-project-home-audit>
                    <h4>At a glance</h4>
                    <ul class="member-list">
                        <li class="member-row">
                            <span class="member-id">placements</span>
                            <span class="badge" data-audit-placements>{home()?.audit.placements ?? 0}</span>
                        </li>
                        <li class="member-row">
                            <span class="member-id">chats</span>
                            <span class="badge" data-audit-chats>{home()?.audit.chats ?? 0}</span>
                        </li>
                        <li class="member-row">
                            <span class="member-id">events</span>
                            <span class="badge" data-audit-events>{home()?.audit.events ?? 0}</span>
                        </li>
                    </ul>
                </section>

                <section class="admin-section" data-project-home-runs>
                    <h4>Recent runs</h4>
                    <ul class="member-list">
                        <For
                            each={home()?.recentRuns ?? []}
                            fallback={<li class="muted">No runs in this project yet.</li>}
                        >
                            {(r) => (
                                <li
                                    class="member-row"
                                    data-run-chat={r.chat}
                                    onClick={() => props.onOpenChat?.(r.chat)}
                                >
                                    <span class="member-id">{r.title || "untitled chat"}</span>
                                    <span class="member-status">{r.phase}</span>
                                    <Show when={r.ran}>
                                        <span class="badge">ran</span>
                                    </Show>
                                </li>
                            )}
                        </For>
                    </ul>
                </section>

                <section class="admin-section" data-project-home-whips>
                    <h4>Whips running</h4>
                    <ul class="member-list">
                        <For
                            each={whips()}
                            fallback={<li class="muted">No whip is running in this project.</li>}
                        >
                            {(whip) => (
                                <li
                                    class="member-row"
                                    data-whip-instance={whip.instanceId}
                                    onClick={() => props.onOpenWhip?.(whip.path)}
                                >
                                    <span class="member-id">{whip.workflow}</span>
                                    <span class="member-status">{whip.status}</span>
                                    {/* Typed reasons, so "why is nothing happening"
                                        is a lookup rather than an investigation. */}
                                    <Show when={whip.blocked > 0}>
                                        <span class="badge" data-whip-blocked>
                                            {whip.blocked} blocked
                                        </span>
                                    </Show>
                                    {/* The count no log can produce. */}
                                    <Show when={whip.neverRequested > 0}>
                                        <span class="badge" data-whip-absent>
                                            {whip.neverRequested} never requested
                                        </span>
                                    </Show>
                                </li>
                            )}
                        </For>
                    </ul>
                </section>

                <section class="admin-section" data-project-home-outputs>
                    <h4>Outputs under review</h4>
                    <ul class="member-list">
                        <For
                            each={home()?.outputs ?? []}
                            fallback={<li class="muted">No outputs awaiting review.</li>}
                        >
                            {(o) => (
                                <li
                                    class="member-row"
                                    data-output-chat={o.chat}
                                    onClick={() => props.onOpenChat?.(o.chat)}
                                >
                                    <span class="member-id">{o.title || "untitled chat"}</span>
                                    <span class="member-status">{o.phase}</span>
                                </li>
                            )}
                        </For>
                    </ul>
                </section>
            </div>
        </div>
    );
}
