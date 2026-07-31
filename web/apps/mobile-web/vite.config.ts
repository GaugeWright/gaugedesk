import { defineConfig } from "vite";
import solid from "vite-plugin-solid";
import { fileURLToPath } from "node:url";

const mobileRoot = fileURLToPath(new URL(".", import.meta.url));
const tauriHost = process.env.TAURI_DEV_HOST;

export default defineConfig({
    root: mobileRoot,
    base: "./",
    plugins: [solid()],
    clearScreen: false,
    server: {
        host: tauriHost || "127.0.0.1",
        port: 5174,
        strictPort: true,
        hmr: tauriHost
            ? {
                  protocol: "ws",
                  host: tauriHost,
                  port: 5175,
              }
            : undefined,
        watch: {
            ignored: ["**/src-tauri-mobile/**"],
        },
    },
    build: {
        outDir: "../../dist-app-mobile-web",
        emptyOutDir: true,
        rollupOptions: {
            input: {
                mobile: fileURLToPath(new URL("index.html", import.meta.url)),
            },
        },
    },
});
