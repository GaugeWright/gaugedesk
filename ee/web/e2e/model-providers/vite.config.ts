import { defineConfig } from "vite";
import solid from "vite-plugin-solid";
import { fileURLToPath } from "node:url";
// Isolated component evidence, never a production entrypoint or auth bypass.
export default defineConfig({
    root: fileURLToPath(new URL(".", import.meta.url)),
    plugins: [solid()], resolve: { dedupe: ["solid-js"] },
    server: { host: "127.0.0.1", port: 7661, strictPort: true, fs: { allow: [fileURLToPath(new URL("../../../..", import.meta.url))] } },
});
