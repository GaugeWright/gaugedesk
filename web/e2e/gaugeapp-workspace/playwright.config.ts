import { defineConfig } from "@playwright/test";
import { fileURLToPath } from "node:url";
// The fixture server binds its port strictly and is never reused, so a second
// checkout running this suite — or one's server left behind — refuses the run
// outright. GAUGEDESK_GAUGEAPP_WORKSPACE_PORT moves this run to a free port.
const port = Number(process.env.GAUGEDESK_GAUGEAPP_WORKSPACE_PORT ?? "7662");
export default defineConfig({
    testDir: ".", testMatch: "*.spec.ts", workers: 1,
    use: { baseURL: `http://127.0.0.1:${port}`, channel: "chrome", headless: true, viewport: { width: 1100, height: 900 }, trace: "retain-on-failure" },
    webServer: { command: `node_modules/.bin/vite --config e2e/gaugeapp-workspace/vite.config.ts --port ${port}`, cwd: fileURLToPath(new URL("../../../ee/web", import.meta.url)), url: `http://127.0.0.1:${port}`, reuseExistingServer: false },
    outputDir: "../../test-results/gaugeapp-workspace",
});
