/**
 * Register the directory verifier wherever MobileApp renders (WS-746, ADR 0133 §5).
 *
 * Without it `resolveHomeRoutes` can verify no signed record, so every account
 * degrades to the hub's endpoints and a relay-only Home — whose route exists
 * only in that record — is unreachable from the phone.
 *
 * The native app's bundle is the enterprise composition, whose `App` already
 * registers it through workbench-web's `wasm-modules.ts` before rendering
 * `MobileApp`. This covers every other host of `MobileApp` — its own entry in
 * the open apps build among them — so the signed read never depends on which
 * composition happened to render it. Registering the same loader twice is
 * harmless: it is a pure function of the generated module.
 *
 * Only the verifier. Mobile carries its relay sessions natively
 * (`ensure_relay_route`), so it never needs the browser tunnel.
 */

import { setDirectoryModuleLoader } from "@gaugewright/control-plane-client";

setDirectoryModuleLoader(async () => {
    const module = await import("@gaugewright/control-plane-client/generated/directory.js");
    await module.default();
    return module;
});
