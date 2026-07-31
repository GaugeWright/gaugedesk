import { defineConfig } from "vite";
import solid from "vite-plugin-solid";
import { fileURLToPath } from "node:url";

const webRoot = fileURLToPath(new URL("../../", import.meta.url));

export default defineConfig({
    root: webRoot,
    plugins: [solid()],
    // Shared workbench packages live outside this workspace. Force one Solid
    // runtime so a signal created by the enterprise host updates shared panels.
    resolve: { dedupe: ["solid-js"] },
    build: {
        outDir: "dist-enterprise-workbench",
        emptyOutDir: true,
        rollupOptions: {
            input: {
                workbench: fileURLToPath(new URL("index.html", import.meta.url)),
            },
        },
    },
});
