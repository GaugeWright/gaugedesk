/* @refresh reload */
import { render } from "solid-js/web";
import { App } from "./App";
import "@gaugewright/workbench-ui/styles.css";

const root = document.getElementById("root");
if (!root) throw new Error("missing #root");
render(() => <App />, root);
