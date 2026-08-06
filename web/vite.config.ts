import { defineConfig } from "vite";
import solid from "vite-plugin-solid";
// The control-plane base for this run (default :7878; the e2e harness shifts it per run for
// concurrency-safety — see e2e/ports.mjs). The browser opens streams same-origin and the
// preview/dev server proxies them to this backend, so the proxy target must track the CP port.
import { aliceCP, ports } from "./e2e/ports.mjs";

// The workbench is a client-owned Solid island served by Vite; Tauri wraps this
// same build for desktop (`app-stack.md`). The control plane runs separately on
// loopback (default :7878) — the dev/preview server proxies stream calls to it.
// Under the fabric the control plane's port is chosen by the orchestrator, so
// the proxy target follows it rather than the harness's fixed default.
const controlPlane = process.env.GAUGEDESK_DEV_CONTROL_PLANE_TARGET ?? aliceCP;
const proxy = {
    "/scopes": controlPlane,
    "/engagements": controlPlane,
};

// The cross-surface development fabric terminates TLS for every surface behind
// one router and serves this client at the `desk` origin. Under it this server
// binds loopback HTTP and answers to that name; run directly, it keeps the
// canonical loopback origins the control plane's CORS allowlist blesses.
const underFabric = process.env.GAUGEDESK_DEV_FABRIC === "1";
const fabricPort = Number(process.env.GAUGEDESK_DEV_PORT ?? "7443");
const fabricServer = underFabric
    ? {
        host: "127.0.0.1",
        allowedHosts: ["desk.gw.localhost", "127.0.0.1"],
        hmr: { protocol: "wss", host: "desk.gw.localhost", clientPort: fabricPort },
    }
    : {};

export default defineConfig({
    plugins: [solid()],
    build: {
        // Multi-page: the workbench (index.html) plus the embed demo page
        // (embed-example.html) that mounts the EMBED-2 custom elements.
        rollupOptions: {
            input: {
                main: "index.html",
                "embed-example": "embed-example.html",
            },
        },
    },
    server: {
        // Pin the dev port. The control plane's CORS allowlist only blesses the
        // canonical web origins (5173 dev, 4173 preview) — so Vite's default
        // behaviour of silently auto-incrementing to 5174 when 5173 is busy lands
        // the app on an origin the backend rejects ("Failed to fetch", with nothing
        // obviously wrong). `strictPort` makes a port clash a loud, immediate
        // failure instead, so you fix the real problem (a stray dev server) rather
        // than chase a phantom CORS bug.
        port: 5173,
        strictPort: true,
        proxy,
        ...fabricServer,
    },
    // The e2e harness drives `vite preview`; its port (passed via --port) and proxy track
    // this run's resolved ports so concurrent runs don't collide.
    preview: {
        port: ports.preview,
        strictPort: true,
        proxy,
    },
});
