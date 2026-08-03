import { defineConfig } from "vite";
import solid from "vite-plugin-solid";
import { fileURLToPath } from "node:url";

// The standalone **embed bundle** (EMBED-2): builds
// `packages/gw-embed/src/index.ts` into a self-registering `embed.js` a
// consultant drops onto their page with
// `<script type="module" src="…/embed.js">`. The complete default styles ride
// inside the bundle (imported via `?inline` and injected per shadow root), so a
// stylesheet is never required. `packages/gw-embed/public/embed.css` is copied
// beside the bundle as a readable, optional customization starter. The diff
// viewer stays a lazy chunk (loaded only when a viewer's Diff tab opens).
// Building the artifact is local; **publishing it to a CDN is needs-infra
// (`D-HOST`).**
const webRoot = fileURLToPath(new URL(".", import.meta.url));

export default defineConfig({
    root: webRoot,
    publicDir: "packages/gw-embed/public",
    plugins: [solid()],
    build: {
        outDir: "dist-embed",
        emptyOutDir: true,
        lib: {
            entry: "packages/gw-embed/src/index.ts",
            formats: ["es"],
            fileName: () => "embed.js",
        },
    },
});
