/** Browser acceptance for two retained accounts against a real Hub listener. */
import { spawn } from "node:child_process";
import { createServer } from "node:http";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { createServer as createTcpServer } from "node:net";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { chromium } from "playwright";
import {
    attachVirtualAuthenticator,
    beginEmailProof,
    completePasskeyAccount,
} from "./passkey-account-door.mjs";

const root = resolve(import.meta.dirname, "../..");
const stateRoot = await mkdtemp(resolve(tmpdir(), "gaugedesk-browser-accounts-"));
const outbox = resolve(stateRoot, "account-auth-email.json");

async function freePort() {
    const listener = createTcpServer();
    await new Promise((resolveReady) => listener.listen(0, "127.0.0.1", resolveReady));
    const port = listener.address().port;
    await new Promise((resolveClosed) => listener.close(resolveClosed));
    return port;
}

const apiPort = await freePort();
const pagePort = await freePort();
const apiOrigin = `http://localhost:${apiPort}`;
const pageOrigin = `http://localhost:${pagePort}`;
const pageServer = createServer((_request, response) => {
    response.writeHead(200, { "content-type": "text/html" });
    response.end("<!doctype html><title>Account switching acceptance</title>");
});
await new Promise((resolveReady) => pageServer.listen(pagePort, "127.0.0.1", resolveReady));

const hub = spawn(resolve(root, "target/debug/gaugedesk-enterprise-server"), [], {
    cwd: stateRoot,
    env: {
        ...process.env,
        GAUGEDESK_ADDR: `127.0.0.1:${apiPort}`,
        GAUGEDESK_ROOT: stateRoot,
        GAUGEDESK_WEB_ACCOUNT: "1",
        GAUGEDESK_TEST_RESET: "1",
        GAUGEDESK_ACCOUNT_RP_ID: "localhost",
        GAUGEDESK_ACCOUNT_ORIGIN: pageOrigin,
        GAUGEDESK_TEST_AUTH_EMAIL_OUTBOX: outbox,
        GAUGEDESK_SESSION_COOKIE_INSECURE: "1",
        GAUGEDESK_ALLOWED_ORIGINS: pageOrigin,
    },
    stdio: ["ignore", "pipe", "pipe"],
});
let hubOutput = "";
hub.stdout.on("data", (chunk) => { hubOutput += chunk.toString(); });
hub.stderr.on("data", (chunk) => { hubOutput += chunk.toString(); });

let browser;
try {
    for (let attempt = 0; attempt < 300; attempt++) {
        if (hub.exitCode !== null) throw new Error(`Hub exited: ${hubOutput}`);
        try {
            if ((await fetch(`${apiOrigin}/health`)).ok) break;
        } catch { /* listener is starting */ }
        if (attempt === 299) throw new Error(`Hub did not start: ${hubOutput}`);
        await new Promise((resolveWait) => setTimeout(resolveWait, 100));
    }

    browser = await chromium.launch({ channel: "chrome", headless: true });
    const context = await browser.newContext();
    const page = await context.newPage();
    await page.goto(pageOrigin);
    const detach = await attachVirtualAuthenticator(context, page);
    const call = (path, init = {}) => page.evaluate(async ([origin, route, options]) => {
        const response = await fetch(`${origin}${route}`, { credentials: "include", ...options });
        return { status: response.status, body: await response.json().catch(() => null) };
    }, [apiOrigin, path, init]);
    const enroll = async (name) => {
        const email = `${name}@example.test`;
        const challengeId = await beginEmailProof(page, apiOrigin, email);
        const posted = JSON.parse(await readFile(outbox, "utf8"));
        if (posted.email !== email || posted.purpose !== "verification") {
            throw new Error(`unexpected verification mail for ${name}`);
        }
        return completePasskeyAccount(page, apiOrigin, {
            challengeId, code: posted.code, displayName: name,
        });
    };
    const alice = await enroll("alice");
    const aliceTenants = await call("/account/tenants");
    if (aliceTenants.status !== 200) throw new Error("Alice's account data is unavailable");
    const firstWallet = (await context.cookies(apiOrigin)).find((cookie) => cookie.name === "gw_account_wallet");
    if (!firstWallet?.httpOnly) throw new Error("first wallet cookie is not HttpOnly");
    const bob = await enroll("bob");
    const bobTenants = await call("/account/tenants");
    if (bobTenants.status !== 200 || JSON.stringify(bobTenants.body) === JSON.stringify(aliceTenants.body)) {
        throw new Error("account selection did not isolate the tenants projection");
    }
    const roster = await call("/auth/browser-accounts");
    if (roster.status !== 200 || roster.body.selected !== bob
        || roster.body.accounts.length !== 2
        || !roster.body.accounts.some((account) => account.person === alice && !account.expired)) {
        throw new Error(`two-account roster is wrong: ${JSON.stringify(roster)}`);
    }
    const oldHandle = await fetch(`${apiOrigin}/auth/browser-accounts/select`, {
        method: "POST",
        headers: {
            "content-type": "application/json",
            Cookie: `gw_account_wallet=${firstWallet.value}`,
        },
        body: JSON.stringify({ person: alice }),
    });
    if (oldHandle.status !== 409) throw new Error("retired wallet handle still selects an account");
    const selectedAlice = await call("/auth/browser-accounts/select", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ person: alice }),
    });
    if (selectedAlice.status !== 204) throw new Error(`could not select Alice: ${JSON.stringify(selectedAlice)}`);
    await page.reload();
    const switched = await call("/auth/browser-accounts");
    if (switched.body.selected !== alice || switched.body.accounts.length !== 2) {
        throw new Error(`reload lost account selection: ${JSON.stringify(switched)}`);
    }
    const restoredTenants = await call("/account/tenants");
    if (JSON.stringify(restoredTenants.body) !== JSON.stringify(aliceTenants.body)) {
        throw new Error("switching back did not restore Alice's account data");
    }
    const signedOut = await call("/auth/logout", { method: "POST" });
    if (signedOut.status !== 204) throw new Error(`sign-out failed: ${JSON.stringify(signedOut)}`);
    const remaining = await call("/auth/browser-accounts");
    if (remaining.body.selected !== null || remaining.body.accounts.length !== 1
        || remaining.body.accounts[0].person !== bob) {
        throw new Error(`sign-out affected the wrong account: ${JSON.stringify(remaining)}`);
    }
    const selectedBob = await call("/auth/browser-accounts/select", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ person: bob }),
    });
    if (selectedBob.status !== 204) throw new Error("remaining account cannot be selected");
    if ((await call("/auth/browser-accounts")).body.selected !== bob) {
        throw new Error("remaining account did not become active");
    }
    await detach();
    console.log("retained browser accounts: two logins, switch, reload, exact sign-out, handle retirement passed");
} finally {
    await browser?.close();
    if (hub.exitCode === null) {
        hub.kill("SIGTERM");
        await new Promise((resolveExit) => hub.once("exit", resolveExit));
    }
    await new Promise((resolveClosed) => pageServer.close(resolveClosed));
    await rm(stateRoot, { recursive: true, force: true });
}
