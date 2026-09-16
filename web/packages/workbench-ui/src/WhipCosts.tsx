/**
 * **What a project's whips have cost** (`COST-3`), on the page that already
 * answers which models a project may use.
 *
 * The figure and the reason it is missing are the same element, never two. A
 * total appears only when there is one; when there is not, its place is taken
 * by the word for its absence and the list of things to fix. The recorded
 * figure is labelled as recorded and sits UNDER the gaps, so a reader skimming
 * the section cannot mistake it for the total — which is the failure the whole
 * stack beneath this is shaped to prevent.
 */

import { createResource, For, Show, type JSX } from "solid-js";
import type { ProjectWhipCosts } from "@gaugewright/control-plane-client";

import { costReadingFrom } from "./whip-cost";

export interface WhipCostsApi {
    /** Optional: a session that cannot read them shows no section rather than
     *  an empty one, because "no section" and "nothing spent" are different
     *  claims and only one of them is true. */
    listWhipCosts?(project: string): Promise<ProjectWhipCosts>;
}

export function WhipCostsSection(props: {
    api: WhipCostsApi;
    project: string;
}): JSX.Element {
    const [costs] = createResource(
        () => props.project,
        async (p) => (props.api.listWhipCosts ? costReadingFrom(await props.api.listWhipCosts(p)) : null),
    );

    return (
        <Show when={costs()}>
            {(reading) => (
                <section class="project-settings-section" data-project-whip-costs>
                    <h3>What its whips have cost</h3>
                    <ul class="member-list">
                        <li class="member-row">
                            <span class="member-id">total</span>
                            <Show
                                when={reading().total}
                                fallback={
                                    <span class="member-status" data-cost-unavailable>
                                        not available
                                    </span>
                                }
                            >
                                <span class="badge" data-cost-total>{reading().total}</span>
                            </Show>
                        </li>

                        {/* A store that would not open has no gap to name: the
                            desk does not know what it could not see. Saying
                            nothing here would leave a missing total looking
                            like a fault in this page. */}
                        <Show when={reading().unread}>
                            <li class="member-row" data-cost-unread>
                                <span class="member-id muted">
                                    a runtime store could not be read, so what it holds is in no
                                    figure here
                                </span>
                            </li>
                        </Show>

                        <For each={reading().gaps}>
                            {(gap) => (
                                <li class="member-row" data-cost-gap={gap.key}>
                                    <span class="member-id muted">{gap.label}</span>
                                </li>
                            )}
                        </For>

                        <Show when={!reading().complete}>
                            <li class="member-row">
                                <span class="member-id muted">recorded so far</span>
                                <span class="member-status" data-cost-recorded>
                                    {reading().recorded}
                                </span>
                            </li>
                        </Show>

                        <Show when={reading().card}>
                            <li class="member-row">
                                <span class="member-id muted">priced under</span>
                                <span class="member-status" data-cost-card>{reading().card}</span>
                            </li>
                        </Show>
                    </ul>
                </section>
            )}
        </Show>
    );
}
