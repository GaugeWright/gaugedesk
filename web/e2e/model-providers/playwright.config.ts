import { defineConfig } from "@playwright/test";
import { fileURLToPath } from "node:url";
export default defineConfig({
    testDir: ".", testMatch: "*.spec.ts", workers: 1, fullyParallel: false,
    use: { baseURL: "http://127.0.0.1:7661", channel: "chrome", headless: true, viewport: { width: 1100, height: 900 }, trace: "retain-on-failure" },
    webServer: { command: "node_modules/.bin/vite --config e2e/model-providers/vite.config.ts", cwd: fileURLToPath(new URL("../../../ee/web", import.meta.url)), url: "http://127.0.0.1:7661", reuseExistingServer: false },
    outputDir: "../../test-results/model-providers",
});
