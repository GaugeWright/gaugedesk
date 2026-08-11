import { fileURLToPath } from "node:url";
import { defineConfig } from "vite";

// A page of its own, deliberately outside the workbench's config: this lane
// tests the transport seam, so it must not inherit the app's proxies, plugins,
// or control-plane origin. The one thing it needs from the workspace is the
// sources under `web/packages`, which sit above this root.
const repositoryRoot = fileURLToPath(new URL("../../..", import.meta.url));

export default defineConfig({
    root: fileURLToPath(new URL(".", import.meta.url)),
    server: {
        host: "127.0.0.1",
        // Vite refuses to serve files above the root by default. The imports
        // here resolve into `web/packages/control-plane-client/src`, including
        // the generated wasm, so the checkout is the boundary.
        fs: { allow: [repositoryRoot] },
    },
    // The generated binding is an artifact with its own `new URL(..., import.meta.url)`
    // wasm reference; pre-bundling rewrites that into something dev cannot serve.
    optimizeDeps: { exclude: ["@gaugewright/control-plane-client"] },
});
