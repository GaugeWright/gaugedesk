/**
 * Bench for the Structure figure a `.whip` file gets in the content viewer.
 *
 * It runs the real `WhipStructureView` against the real stylesheet and the real
 * projection output, so what is agreed here is what ships. The figure has no
 * other bench: it is drawn from a compiled program joined to runtime state, so
 * seeing it in the app means a running control plane with a program that has
 * actually fired, and a change to how a rule box reads should not need that.
 *
 * Served in development only (`/whip-lab.html`); no shipped bundle names this
 * entry.
 */
import { For } from "solid-js";
import { WhipStructureView } from "@gaugewright/workbench-ui/WhipViews";
import { structureFromV0 } from "@gaugewright/workbench-ui/whip-view";
import "@gaugewright/workbench-ui/styles.css";
import { render } from "solid-js/web";
import { LAB_PROGRAMS } from "./whip-lab-programs";

function Lab() {
    return (
        <div class="lab">
            <div class="lab-head">
                <h1>Whip structure figures</h1>
                <p>
                    Three real programs, each drawn from the exact projection the runtime sends.
                    What to look at: every effect is named by the verb its author wrote, with
                    their own binding under it; a <code>where</code> guard sits on its own line
                    and is elided rather than setting the width of the page; and a{" "}
                    <code>table</code> declaration is drawn as the data it is rather than as one
                    more rule.
                </p>
            </div>
            <For each={LAB_PROGRAMS}>
                {(program) => (
                    <section class="lab-case">
                        <h2>{program.name}</h2>
                        <WhipStructureView structure={structureFromV0(program.structure)} />
                    </section>
                )}
            </For>
        </div>
    );
}

render(() => <Lab />, document.getElementById("root")!);
