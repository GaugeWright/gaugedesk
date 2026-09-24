import { defineConfig, type Plugin } from "vite";
import solid from "vite-plugin-solid";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const appRoot = fileURLToPath(new URL(".", import.meta.url));
const distRoot = fileURLToPath(
    new URL("../../dist-enterprise-workbench", import.meta.url),
);

// Desktop development serves the same enterprise composition that Tauri and
// the hosted release package. The browser addresses the control plane through
// the Desk origin, so Vite must carry every product route to the co-resident
// server instead of answering an XHR with the SPA fallback. A production build
// does not use this proxy; VITE_CP_BASE points it at the hosted account plane.
const controlPlane = process.env.GAUGEDESK_DEV_CONTROL_PLANE_TARGET ?? "http://127.0.0.1:7878";
const controlPlanePrefixes = [
    "/account",
    "/admin",
    "/archetypes",
    "/auth",
    "/background",
    "/boundaries",
    "/chats",
    "/collection-recipients",
    "/commercial",
    "/console",
    "/engagements",
    "/environments",
    "/federation",
    "/file",
    "/fork-tree",
    "/gaugeapps",
    "/health",
    "/home",
    "/mobile",
    "/organization-invitations",
    "/pairing-requests",
    "/pairing-status",
    "/panel-previews",
    "/placements",
    "/projections",
    "/projects",
    "/public-deployments",
    "/roster",
    "/saml",
    "/scim",
    "/scopes",
    "/search",
    "/target-settlements",
    "/targets",
    "/tasks",
    "/work-items",
    "/workspace",
    "/workstreams",
];
const proxy = Object.fromEntries(
    controlPlanePrefixes.map((prefix) => [prefix, controlPlane]),
);
// The browser tab shows the same icon as the desktop app. /favicon.ico is the
// path clients ask for when they do not read the page's <link rel="icon">, and
// without a file there the hosted origin answers it with the SPA fallback.
const favicon = readFileSync(
    fileURLToPath(new URL("../../../../src-tauri/icons/icon.ico", import.meta.url)),
);
const faviconPlugin: Plugin = {
    name: "gaugedesk-favicon",
    configureServer(server) {
        server.middlewares.use("/favicon.ico", (_req, res) => {
            res.setHeader("Content-Type", "image/x-icon");
            res.end(favicon);
        });
    },
    generateBundle() {
        this.emitFile({ type: "asset", fileName: "favicon.ico", source: favicon });
    },
};

const underFabric = process.env.GAUGEDESK_DEV_FABRIC === "1";
const fabricPort = Number(process.env.GAUGEDESK_DEV_PORT ?? "7443");

export default defineConfig({
    root: appRoot,
    plugins: [solid(), faviconPlugin],
    // Shared workbench packages live outside this workspace. Force one Solid
    // runtime so a signal created by the enterprise host updates shared panels.
    resolve: { dedupe: ["solid-js"] },
    server: {
        port: 5173,
        strictPort: true,
        proxy,
        ...(underFabric ? {
            host: "127.0.0.1",
            allowedHosts: ["desk.gw.localhost", "127.0.0.1"],
            hmr: { protocol: "wss", host: "desk.gw.localhost", clientPort: fabricPort },
            // Concurrent worktrees can exhaust Linux's per-user inotify
            // allowance. Keep fabric instances independent of that shared
            // limit; standalone Vite retains its native watcher.
            watch: { usePolling: true, interval: 500 },
        } : {}),
    },
    build: {
        outDir: distRoot,
        emptyOutDir: true,
        rollupOptions: {
            input: {
                workbench: fileURLToPath(new URL("index.html", import.meta.url)),
            },
        },
    },
});
