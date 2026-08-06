import { defineConfig } from "@playwright/test";
import { defineBddConfig } from "playwright-bdd";
// Single source of truth for the harness ports (concurrency-safety). `e2e/run.mjs`
// resolves a free set per run and exports them; here we just read the resolved values.
import {
    enterpriseAppURL,
    aliceState,
    bobState,
    brokerAddr,
    enterpriseCP,
    enterpriseState,
    ports,
    previewURL,
} from "./e2e/ports.mjs";

// Gherkin .feature files → generated Playwright specs (the "pickle" pipeline).
// Enterprise features live with their owning workspace (ee/web); this harness stays
// the one repo-wide runner until that package runs independently, so its discovery
// spans both roots (featuresRoot = the repo root).
// Which composition the browser drives at the preview origin: the open
// workbench (default) or the combined enterprise workbench
// (`GW_E2E_COMPOSITION=enterprise`). Every shipped surface — desktop packaging
// and the hosted desk — runs the enterprise composition (ADR 0098), so the
// full suite must be runnable against it; the open dev loop alone let an
// enterprise-only crash ship (the Devices modal, 2026-07-31). Features that
// exist only in the open bundle are tagged @open-only and skipped by the lane.
const enterpriseLane = process.env.GW_E2E_COMPOSITION === "enterprise";

const testDir = defineBddConfig({
    features: [
        "e2e/features/**/*.feature",
        "../ee/web/e2e/features/**/*.feature",
    ],
    featuresRoot: "..",
    steps: "e2e/steps/**/*.ts",
});

export default defineConfig({
    testDir,
    fullyParallel: false, // one shared control plane; scenarios share its state
    workers: 1,
    timeout: 60_000, // generous enough for an @live real-model WhippleScript turn
    expect: { timeout: 8_000 },
    reporter: [["list"]],
    use: {
        baseURL: previewURL,
        channel: "chrome", // system Google Chrome — no browser download
        headless: true,
        trace: "retain-on-failure",
    },
    webServer: [
        // The hermetic WSS relay both authorities dial out to (M8 federation).
        {
            command: "bash e2e/broker.sh",
            port: ports.broker,
            reuseExistingServer: false,
            timeout: 30_000,
            env: { BROKER_PORT: String(ports.broker) },
        },
        // The stand-in Hub the desktop account handoff redeems against
        // (LOGIN-5, ADR 0123): exchange, device-bound refresh, revocation.
        {
            command: "bash e2e/account-hub.sh",
            url: `http://127.0.0.1:${ports.hub}/health`,
            reuseExistingServer: false,
            timeout: 30_000,
            env: { HUB_PORT: String(ports.hub) },
        },
        // The primary control plane (alice / `local-user`) — the one the existing
        // single-instance suite drives. Port-scoped launcher so the peer instance
        // survives (no blanket pkill). Its CORS allowlist blesses THIS run's preview
        // origin so the cross-origin client calls are admitted (FED-2).
        {
            command: "bash e2e/fed-control-plane.sh",
            url: `http://127.0.0.1:${ports.alice}/chats`,
            reuseExistingServer: false,
            timeout: 30_000,
            env: {
                FED_PORT: String(ports.alice),
                GAUGEDESK_RELAY_ENDPOINT: brokerAddr,
                GAUGEDESK_E2E_STATE: aliceState,
                GAUGEDESK_ALLOWED_ORIGINS: previewURL,
                // The desktop account handoff redeems at THIS run's stand-in
                // Hub (LOGIN-5), never the production default.
                GAUGEDESK_ACCOUNT_HUB_URL: `http://127.0.0.1:${ports.hub}`,
            },
        },
        // The federation peer (authority `bob`) — only the cross-machine scenarios use
        // it; it sits idle for the rest.
        {
            command: "bash e2e/fed-control-plane.sh",
            url: `http://127.0.0.1:${ports.bob}/chats`,
            reuseExistingServer: false,
            timeout: 30_000,
            env: {
                FED_PORT: String(ports.bob),
                GAUGEDESK_AUTHORITY: "bob",
                GAUGEDESK_RELAY_ENDPOINT: brokerAddr,
                GAUGEDESK_E2E_STATE: bobState,
                GAUGEDESK_ALLOWED_ORIGINS: previewURL,
            },
        },
        // The composition under test at the preview origin. Both bundles bake
        // this run's `VITE_CP_BASE`, so either one drives the alice control
        // plane; the enterprise dist serves its workbench at `/` with SPA
        // fallback, so the suite's relative navigation works unchanged.
        enterpriseLane
            ? {
                command: `npx vite preview --config apps/enterprise-workbench/vite.config.ts --port ${ports.preview} --strictPort`,
                cwd: "../ee/web",
                url: previewURL,
                reuseExistingServer: false,
                timeout: 30_000,
            }
            : {
                command: `npm run preview -- --port ${ports.preview} --strictPort`,
                url: previewURL,
                reuseExistingServer: false,
                timeout: 30_000,
            },
        // The SELF-HOSTED enterprise composition (`gaugedesk-enterprise-server`,
        // ee/): the /admin/* + SSO surface without the managed planes. The
        // combined enterprise-workbench scenarios point at it via `?cp=` — enterprise
        // coverage runs against ee code only, never the private cloud repo.
        {
            command: "bash e2e/enterprise-control-plane.sh",
            url: `${enterpriseCP}/chats`,
            reuseExistingServer: false,
            timeout: 30_000,
            env: {
                ENTERPRISE_PORT: String(ports.enterprise),
                GAUGEDESK_E2E_STATE: enterpriseState,
                GAUGEDESK_ALLOWED_ORIGINS: [
                    previewURL,
                    new URL(enterpriseAppURL).origin,
                ].join(","),
            },
        },
        // Static preview of the combined enterprise workbench, built by e2e/run.mjs
        // in its owning workspace. The preview serves the whole dist.
        {
            command: `npx vite preview --config apps/enterprise-workbench/vite.config.ts --port ${ports.enterpriseApp} --strictPort`,
            cwd: "../ee/web",
            url: enterpriseAppURL,
            reuseExistingServer: false,
            timeout: 30_000,
        },
    ],
});
