/* @refresh reload */
import { render } from "solid-js/web";
import { setTunnelModuleLoader } from "@gaugewright/control-plane-client";
import { App } from "./App";
import "@gaugewright/workbench-ui/styles.css";

// A Home behind NAT is reachable only through the relay, and only if this build
// can open a pinned tunnel (DESK-7, ADR 0130). Registering the loader here —
// rather than importing the module — keeps it out of the initial bundle: nothing
// is fetched until someone opens a project whose Home is relay-only, so a person
// whose Homes are all directly addressable never downloads it.
setTunnelModuleLoader(async () => {
    const module = await import("@gaugewright/control-plane-client/generated/tunnel.js");
    await module.default();
    return module;
});

const root = document.getElementById("root");
if (!root) throw new Error("missing #root");
render(() => <App />, root);
