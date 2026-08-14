import assert from "node:assert/strict";
import test from "node:test";
import { spawn } from "node:child_process";
import { createServer } from "node:http";
import { createInterface } from "node:readline";
import { fileURLToPath } from "node:url";

// The helper binds one fixed loopback port, which is registered with OpenAI and
// so cannot be per-process. That makes every way it can fail to let go of the
// port a way to break the *next* sign-in, which is what these cover: an
// abandoned browser tab, a GaugeDesk that exited while the tab was open, and a
// port some other process is already holding.
//
// Observed 2026-08-14: a helper spawned at 11:02 was still holding 127.0.0.1:1455
// hours later, its parent long gone, and every sign-in attempt after it failed
// with `EADDRINUSE`.

const HELPER = fileURLToPath(new URL("./codex-oauth-login.mjs", import.meta.url));

/** A port nothing is listening on. Bind-then-release rather than a fixed number,
 *  so a developer's real helper on 1455 neither fails these nor is killed by them. */
const freePort = () => new Promise((resolve, reject) => {
    const probe = createServer();
    probe.once("error", reject);
    probe.listen(0, "127.0.0.1", () => {
        const { port } = probe.address();
        probe.close(() => resolve(port));
    });
});

const holdPort = (port) => new Promise((resolve, reject) => {
    const server = createServer();
    server.once("error", reject);
    server.listen(port, "127.0.0.1", () => resolve(server));
});

const portIsFree = async (port) => {
    try {
        const server = await holdPort(port);
        await new Promise((resolve) => server.close(resolve));
        return true;
    } catch {
        return false;
    }
};

/** Run the helper as the app does — its private stdout pipe carries one JSON
 *  event per line — and expose those events as an async iterator. */
function runHelper(env) {
    const child = spawn(process.execPath, [HELPER], {
        env: { ...process.env, ...env },
        stdio: ["ignore", "pipe", "pipe"],
    });
    const lines = createInterface({ input: child.stdout })[Symbol.asyncIterator]();
    return {
        child,
        async event() {
            const { value, done } = await lines.next();
            assert.ok(!done, "helper closed its pipe without emitting an event");
            return JSON.parse(value);
        },
        exit: new Promise((resolve) => child.once("exit", (code) => resolve(code))),
    };
}

test("a sign-in nobody finishes releases the callback port", async () => {
    const port = await freePort();
    const helper = runHelper({
        GAUGEDESK_OAUTH_CALLBACK_PORT: String(port),
        GAUGEDESK_OAUTH_CALLBACK_TIMEOUT_MS: "250",
    });

    const started = await helper.event();
    assert.equal(started.event, "auth_url");
    // The authorize request and the listener must name the same place, or the
    // browser comes back to a port nothing is waiting on.
    assert.match(started.url, new RegExp(`redirect_uri=http%3A%2F%2Flocalhost%3A${port}%2F`));

    const ended = await helper.event();
    assert.equal(ended.event, "error");
    assert.match(ended.message, /not completed in time/);
    assert.equal(await helper.exit, 1);
    assert.ok(await portIsFree(port), "the abandoned helper kept the callback port");
});

test("a helper outliving GaugeDesk exits instead of holding the port", async () => {
    const port = await freePort();
    // An intermediate parent that spawns the helper, waits for it to be listening,
    // then exits — exactly the orphaning a crashed or restarted app performs.
    const orphaner = spawn(process.execPath, ["-e", `
        const { spawn } = require("node:child_process");
        const child = spawn(process.execPath, [process.argv[1]], {
            env: process.env,
            stdio: ["ignore", "pipe", "ignore"],
        });
        child.stdout.once("data", () => {
            process.stdout.write(String(child.pid) + "\\n");
            process.exit(0);
        });
    `, HELPER], {
        env: {
            ...process.env,
            GAUGEDESK_OAUTH_CALLBACK_PORT: String(port),
            // Long enough that only the orphan watchdog can end this one.
            GAUGEDESK_OAUTH_CALLBACK_TIMEOUT_MS: "600000",
        },
        stdio: ["ignore", "pipe", "ignore"],
    });
    const reported = await createInterface({ input: orphaner.stdout })[Symbol.asyncIterator]()
        .next()
        .then(({ value }) => Number(String(value).trim()));
    assert.ok(Number.isInteger(reported), "the orphaning parent reported no helper pid");

    const deadline = Date.now() + 10_000;
    let alive = true;
    while (alive && Date.now() < deadline) {
        try {
            process.kill(reported, 0);
            await new Promise((resolve) => setTimeout(resolve, 50));
        } catch {
            alive = false;
        }
    }
    assert.equal(alive, false, "the orphaned helper outlived the process it reports to");
    assert.ok(await portIsFree(port), "the orphaned helper kept the callback port");
});

test("a port someone else holds is reported as that, not as a bare listen error", async () => {
    const port = await freePort();
    const squatter = await holdPort(port);
    try {
        const helper = runHelper({ GAUGEDESK_OAUTH_CALLBACK_PORT: String(port) });
        const failed = await helper.event();
        assert.equal(failed.event, "error");
        // `EADDRINUSE 127.0.0.1:1455` is a true statement that tells the person
        // reading it nothing about what to do.
        assert.match(failed.message, new RegExp(`callback port ${port} is already held`));
        assert.equal(await helper.exit, 1);
    } finally {
        await new Promise((resolve) => squatter.close(resolve));
    }
});
