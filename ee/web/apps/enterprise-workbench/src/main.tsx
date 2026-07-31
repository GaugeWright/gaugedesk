/* @refresh reload */
import { render } from "solid-js/web";
import "@gaugewright/workbench-ui/styles.css";
import { EnterpriseWorkbench } from "./EnterpriseWorkbench";

const root = document.getElementById("root");
if (!root) throw new Error("missing #root");
render(() => <EnterpriseWorkbench />, root);
