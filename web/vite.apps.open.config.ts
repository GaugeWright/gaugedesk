import { defineConfig } from "vite";
import solid from "vite-plugin-solid";
import { fileURLToPath } from "node:url";

const webRoot = fileURLToPath(new URL(".", import.meta.url));

export default defineConfig({
    root: webRoot,
    plugins: [solid()],
    build: {
        outDir: "dist-apps-open",
        emptyOutDir: true,
        rollupOptions: {
            input: {
                workbench: fileURLToPath(new URL("index.html", import.meta.url)),
                mobile: fileURLToPath(
                    new URL("apps/mobile-web/index.html", import.meta.url),
                ),
            },
        },
    },
});
