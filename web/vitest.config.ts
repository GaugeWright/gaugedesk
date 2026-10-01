import { defineConfig } from "vitest/config";
import solid from "vite-plugin-solid";

// The doctrine-bearing logic (transcript reduction, projection parsing) is
// framework-agnostic TS — tested without the Solid JSX plugin. Mounted component
// tests have their own DOM environment and the production Solid JSX transform.
//
// `resolve.conditions` picks Solid's **client** reactive build (`dist/dev.js`)
// over its SSR build, so reactive-but-DOM-free units — the remote Session's
// signals/resources (EMBED-2) — run under `createRoot`. Full browser journeys
// still qualify browser-specific behavior separately.
export default defineConfig({
    test: {
        projects: [
            {
                extends: true,
                test: {
                    name: "logic",
                    include: ["packages/**/*.test.ts", "apps/**/*.test.ts", "e2e/**/*.test.ts"],
                    exclude: ["**/*.component.test.ts"],
                },
            },
            {
                extends: true,
                plugins: [solid()],
                test: {
                    name: "components",
                    environment: "happy-dom",
                    include: ["packages/**/*.component.test.ts", "apps/**/*.component.test.ts"],
                },
            },
        ],
    },
    // Logic tests import `.tsx` modules only for their pure exports, so their JSX
    // only needs to compile to valid-but-unexecuted JS. The components project
    // overrides this through the Solid plugin when it mounts those components.
    // The root tsconfig's `jsx: "preserve"` now covers the app/package sources
    // (it drives `npm run typecheck`), so pin the classic JSX transform here —
    // otherwise the transformer inherits `preserve` and import analysis chokes
    // on raw JSX, exactly what didn't happen while these sources sat outside
    // the root tsconfig's include.
    oxc: {
        jsx: { runtime: "classic" },
    },
    resolve: {
        alias: [{ find: /^solid-js$/, replacement: "solid-js/dist/dev.js" }],
        conditions: ["development", "browser"],
    },
});
