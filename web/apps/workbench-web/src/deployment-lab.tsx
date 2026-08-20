/**
 * Front-end-only prototype for the public-panel deployment journey. It mounts
 * the real reusable Solid component against the real workbench stylesheet, but
 * deliberately owns all state in memory so product decisions can settle before
 * the existing publisher API is connected.
 */
import { render } from "solid-js/web";
import { DeploymentStudio } from "@gaugewright/workbench-ui";
import "@gaugewright/workbench-ui/styles.css";

const root = document.getElementById("root");
if (!root) throw new Error("missing #root");

render(() => (
    <DeploymentStudio
        selection={{
            projectName: "Theory A website",
            archetypeName: "Reader guide",
            version: 12,
            abilities: ["Chat", "Read published references", "Create structured responses"],
        }}
    />
), root);
