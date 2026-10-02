/* @refresh reload */
import { render } from "solid-js/web";
import "@gaugewright/workbench-ui/styles.css";
import { installTooltips } from "@gaugewright/workbench-ui/tooltips";
import { EnterpriseWorkbench } from "./EnterpriseWorkbench";

const root = document.getElementById("root");
if (!root) throw new Error("missing #root");
installTooltips(document);
render(() => <EnterpriseWorkbench />, root);
