import { defineConfig } from "vitest/config";

// The doctrine-bearing logic (transcript reduction, projection parsing) is
// framework-agnostic TS — tested without the Solid JSX plugin.
//
// `resolve.conditions` picks Solid's **client** reactive build (`dist/dev.js`)
// over its SSR build, so reactive-but-DOM-free units — the remote Session's
// signals/resources (EMBED-2) — run under `createRoot`. (DOM-bound code, e.g.
// the embed custom elements, is exercised in a real browser via e2e instead.)
export default defineConfig({
    test: {
        include: ["packages/**/*.test.ts", "apps/**/*.test.ts", "e2e/**/*.test.ts"],
    },
    // Tests import `.tsx` modules only for their pure exports (the components are
    // never invoked), so JSX just needs to compile to valid-but-unexecuted JS.
    // The root tsconfig's `jsx: "preserve"` now covers the app/package sources
    // (it drives `npm run typecheck`), so pin the classic JSX transform here —
    // otherwise the transformer inherits `preserve` and import analysis chokes
    // on raw JSX, exactly what didn't happen while these sources sat outside
    // the root tsconfig's include.
    oxc: {
        jsx: { runtime: "classic" },
    },
    resolve: {
        alias: {
            "solid-js": "solid-js/dist/dev.js",
        },
        conditions: ["development", "browser"],
    },
});
