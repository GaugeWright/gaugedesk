/**
 * Register this build's wasm modules, for **every** host that renders `App`.
 *
 * This lived in `main.tsx` and was therefore dead on the surface that needs it
 * most. `main.tsx` is only the standalone entry; `desk.gaugewright.com` serves
 * the enterprise composition (ADR 0098), whose own entry renders `App` directly
 * and never executed a line of it. So the deployed desk registered no tunnel and
 * no verifier — a relay-only Home read as *no usable route*, and every signed
 * record went unverified, with nothing in either build to say so.
 *
 * Registration belongs with the app, not with one host's entry file. `App`
 * imports this for its side effect, so any composition that renders the
 * workbench gets both loaders by construction rather than by remembering.
 *
 * Both are **lazy**, and on different triggers. The tunnel is fetched only when
 * someone opens a relay-only Home, so a person whose Homes are all directly
 * addressable never downloads it. The verifier is fetched on the first
 * signed-in route read, because without it no record can be verified and the
 * account silently falls back to endpoint-only reachability.
 */

import {
    setDirectoryModuleLoader,
    setTunnelModuleLoader,
} from "@gaugewright/control-plane-client";

setTunnelModuleLoader(async () => {
    const module = await import("@gaugewright/control-plane-client/generated/tunnel.js");
    await module.default();
    return module;
});

setDirectoryModuleLoader(async () => {
    const module = await import("@gaugewright/control-plane-client/generated/directory.js");
    await module.default();
    return module;
});
