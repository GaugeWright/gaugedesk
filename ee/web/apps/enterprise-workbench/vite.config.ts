import { defineConfig } from "vite";
import solid from "vite-plugin-solid";
import { fileURLToPath } from "node:url";

const appRoot = fileURLToPath(new URL(".", import.meta.url));
const distRoot = fileURLToPath(
    new URL("../../dist-enterprise-workbench", import.meta.url),
);

export default defineConfig({
    root: appRoot,
    plugins: [solid()],
    // Shared workbench packages live outside this workspace. Force one Solid
    // runtime so a signal created by the enterprise host updates shared panels.
    resolve: { dedupe: ["solid-js"] },
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
