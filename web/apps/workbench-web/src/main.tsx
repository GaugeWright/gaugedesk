/* @refresh reload */
import { render } from "solid-js/web";
import { App } from "./App";
import "@gaugewright/workbench-ui/styles.css";
import { installTooltips } from "@gaugewright/workbench-ui/tooltips";

const root = document.getElementById("root");
if (!root) throw new Error("missing #root");
installTooltips(document);
render(() => <App />, root);
