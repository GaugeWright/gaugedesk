/**
 * A frozen Panel-agent contract, read back in the owner's words (PANEL-12).
 *
 * Where the contract cannot be changed — a placement pinned to a version, and
 * the deploy dialog, which operates a version but never redefines it — it is
 * shown, not edited. The facts come from `contractFacts`, so this and the
 * editor name every setting the same way.
 */

import { For, type JSX } from "solid-js";
import type { PanelPublicProfile } from "@gaugewright/control-plane-client";
import { contractFacts } from "./panel-agent-presentation";
import "./panel-agent.css";

export function PanelContractSummary(props: { profile: PanelPublicProfile }): JSX.Element {
    return <dl class="pa-facts" data-panel-contract-summary>
        <For each={contractFacts(props.profile)}>{(fact) => <>
            <dt>{fact.label}</dt><dd>{fact.value}</dd>
        </>}</For>
    </dl>;
}
