/**
 * Run DESK-7's joined lane: serve `e2e/relay-pool/` and drive it in a browser.
 *
 * The page is the test (`relay-pool/journey.ts`); this only stands up an origin
 * for it and reports what it found. Kept out of the Playwright BDD harness on
 * purpose — that harness boots two control planes, a broker, a stand-in Hub and
 * two previews to exercise the workbench, and none of it has anything to say
 * about whether the pool can reach a Home through a relay.
 *
 * `scripts/browser-journey.sh` starts the hermetic harness first and refuses to
 * continue until it answers, so an absent harness is a failure here rather than
 * a skip: by the time this runs, its fixture has already been proved present.
 */

import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";

const CONFIG_URL = "http://127.0.0.1:7908/";

export async function runRelayPoolJourney() {
    const [{ createServer }, { chromium }] = await Promise.all([
        import("vite"),
        import("playwright"),
    ]);

    // Vite steps to the next free port when its default is taken, so a second
    // worktree running this at the same time gets its own origin.
    const server = await createServer({
        configFile: fileURLToPath(new URL("./relay-pool/vite.config.ts", import.meta.url)),
    });
    await server.listen();
    const address = server.httpServer?.address();
    assert(address && typeof address === "object", "the journey server bound no port");
    const origin = `http://127.0.0.1:${address.port}/`;

    const browser = await chromium.launch({ headless: true });
    let context;
    try {
        context = await browser.newContext();
        const page = await context.newPage();
        // Everything the page says, said here too. A wasm module that fails to
        // instantiate reports it to the console and nowhere else, and a silent
        // timeout would send a reader looking at the relay instead.
        page.on("console", (message) => console.log(`[page:${message.type()}] ${message.text()}`));
        page.on("pageerror", (error) => console.log(`[page:error] ${String(error)}`));

        await page.goto(origin, { waitUntil: "domcontentloaded" });
        // Generous: a cold wasm instantiation plus a relay splice plus two TLS
        // handshakes. Bounded, because a hang must fail rather than sit.
        await page.waitForFunction(() => window.__relayPoolJourney !== undefined, null, {
            timeout: 60_000,
        });
        const outcome = await page.evaluate(() => window.__relayPoolJourney);
        assert(outcome, "the page produced no outcome");
        assert(outcome.ok, `the joined lane failed: ${outcome.ok ? "" : outcome.error}`);
        console.log(
            `the pool admitted ${outcome.result.homeId} over the tunnel (${outcome.result.state}),`
                + ` reached it again by id alone (${outcome.result.byHome}), and refused a route`
                + ` naming another Home: ${outcome.result.mismatch}`,
        );
        return outcome.result;
    } finally {
        await context?.close().catch(() => undefined);
        await browser.close().catch(() => undefined);
        await server.close().catch(() => undefined);
    }
}

if (import.meta.url === `file://${process.argv[1]}`) {
    // The harness answers on loopback, on a port this process started itself;
    // there is no transport to encrypt and no name to authenticate.
    // nosemgrep: typescript.react.security.react-insecure-request.react-insecure-request
    const probe = await fetch(CONFIG_URL).catch(() => null);
    assert(
        probe?.ok,
        `the hermetic harness is not answering at ${CONFIG_URL}`
            + " — run this through scripts/browser-journey.sh, which starts it",
    );
    await runRelayPoolJourney();
}
