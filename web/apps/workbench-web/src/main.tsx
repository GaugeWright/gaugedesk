/* @refresh reload */
import { render } from "solid-js/web";
import {
    setDirectoryModuleLoader,
    setTunnelModuleLoader,
} from "@gaugewright/control-plane-client";
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

// The signature verifier for the root-signed route record (DESK-5g, ADR 0133).
// Lazy for the same reason as the tunnel, but on a different trigger: it is
// fetched on the first signed-in route read, not on the first relay-only Home,
// because without it no record can be verified and every account silently falls
// back to endpoint-only reachability.
setDirectoryModuleLoader(async () => {
    const module = await import("@gaugewright/control-plane-client/generated/directory.js");
    await module.default();
    return module;
});

const root = document.getElementById("root");
if (!root) throw new Error("missing #root");
render(() => <App />, root);
