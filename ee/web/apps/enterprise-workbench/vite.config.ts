import { defineConfig } from "vite";
import solid from "vite-plugin-solid";
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
const underFabric = process.env.GAUGEDESK_DEV_FABRIC === "1";
const fabricPort = Number(process.env.GAUGEDESK_DEV_PORT ?? "7443");

export default defineConfig({
    root: appRoot,
    plugins: [solid()],
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
