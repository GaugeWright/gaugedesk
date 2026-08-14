#!/usr/bin/env node
/** GaugeDesk-owned OpenAI Codex OAuth helper.
 *
 * Runs PKCE + the loopback callback and emits the resulting credential bundle
 * only over its private stdout pipe to the GaugeDesk control plane. GaugeDesk
 * seals and stores it; this helper never writes Pi, Codex, or WhippleScript
 * configuration files.
 */

import { createHash, randomBytes } from "node:crypto";
import { createServer } from "node:http";

const CLIENT_ID = "app_EMoamEEZ73f0CkXaXp7hrann";
const AUTHORIZE_URL = "https://auth.openai.com/oauth/authorize";
const TOKEN_URL = "https://auth.openai.com/oauth/token";
const SCOPE = "openid profile email offline_access";
const JWT_CLAIM = "https://api.openai.com/auth";

/** The loopback callback address. Both halves are overridable so the test suite
 *  can run this helper without contending for the real port, and the redirect is
 *  derived from them so the authorize request and the listener can never name
 *  different places. OpenAI has 1455 registered for this client, so overriding
 *  the port in production only breaks that client's own sign-in. */
const CALLBACK_PORT = Number(process.env.GAUGEDESK_OAUTH_CALLBACK_PORT || 1455);
const CALLBACK_HOST = process.env.GAUGEDESK_OAUTH_CALLBACK_HOST || "127.0.0.1";
const REDIRECT_URI = `http://localhost:${CALLBACK_PORT}/auth/callback`;

/** How long the listener waits for the browser to come back. The port is fixed,
 *  so exactly one helper can hold it: a sign-in someone abandons in the browser
 *  must not keep it until the app is restarted, which is what made the next
 *  attempt fail with EADDRINUSE. */
const CALLBACK_TIMEOUT_MS = Number(process.env.GAUGEDESK_OAUTH_CALLBACK_TIMEOUT_MS || 600_000);

/** GaugeDesk reads the credential bundle over this helper's private stdout pipe.
 *  Once that process is gone the bundle has nowhere to land, so continuing to
 *  wait only holds the port against the next attempt — the state a crashed or
 *  restarted app left behind. Reparenting is the portable signal: the kernel
 *  hands an orphan to init or to the session's subreaper. */
const PARENT_POLL_MS = 500;

const emit = (value) => process.stdout.write(`${JSON.stringify(value)}\n`);
// Writing to a pipe whose reader has exited is not a crash worth a stack trace:
// there is no longer anyone to tell, so leave.
process.stdout.on("error", () => process.exit(1));
const fail = (error) => {
    emit({ event: "error", message: String(error?.message || error) });
    process.exit(1);
};
const base64url = (bytes) => Buffer.from(bytes).toString("base64url");

function accountId(access) {
    try {
        const payload = JSON.parse(Buffer.from(access.split(".")[1], "base64url").toString("utf8"));
        const value = payload?.[JWT_CLAIM]?.chatgpt_account_id;
        return typeof value === "string" && value ? value : null;
    } catch {
        return null;
    }
}

async function exchange(code, verifier) {
    const response = await fetch(TOKEN_URL, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
            grant_type: "authorization_code",
            client_id: CLIENT_ID,
            code,
            code_verifier: verifier,
            redirect_uri: REDIRECT_URI,
        }),
    });
    const body = await response.json().catch(() => ({}));
    if (!response.ok || !body.access_token || !body.refresh_token || typeof body.expires_in !== "number") {
        throw new Error(`OpenAI Codex token exchange failed (${response.status})`);
    }
    const account = accountId(body.access_token);
    if (!account) throw new Error("OpenAI Codex access token has no account id");
    return {
        access: body.access_token,
        refresh: body.refresh_token,
        expires: Date.now() + body.expires_in * 1000,
        accountId: account,
    };
}

try {
    const verifier = base64url(randomBytes(32));
    const challenge = base64url(createHash("sha256").update(verifier).digest());
    const state = randomBytes(16).toString("hex");
    const authorize = new URL(AUTHORIZE_URL);
    for (const [key, value] of Object.entries({
        response_type: "code",
        client_id: CLIENT_ID,
        redirect_uri: REDIRECT_URI,
        scope: SCOPE,
        code_challenge: challenge,
        code_challenge_method: "S256",
        state,
        id_token_add_organizations: "true",
        codex_cli_simplified_flow: "true",
        originator: "gaugedesk",
    })) authorize.searchParams.set(key, value);

    const code = await new Promise((resolve, reject) => {
        const server = createServer((request, response) => {
            const url = new URL(request.url || "", "http://localhost");
            if (url.pathname !== "/auth/callback" || url.searchParams.get("state") !== state) {
                response.writeHead(400, { "content-type": "text/plain; charset=utf-8" });
                response.end("GaugeDesk authentication failed: invalid callback.");
                return;
            }
            const value = url.searchParams.get("code");
            if (!value) {
                response.writeHead(400, { "content-type": "text/plain; charset=utf-8" });
                response.end("GaugeDesk authentication failed: missing code.");
                return;
            }
            response.writeHead(200, { "content-type": "text/plain; charset=utf-8" });
            response.end("GaugeDesk authentication completed. You can close this window.");
            release();
            resolve(value);
        });
        let timeout;
        let watchdog;
        // Every exit from the wait runs through here, so the port is released at
        // the moment the wait ends rather than whenever the process happens to.
        const release = () => {
            clearTimeout(timeout);
            clearInterval(watchdog);
            server.close();
        };
        const abandon = (message) => {
            release();
            reject(new Error(message));
        };
        server.once("error", (error) => {
            release();
            reject(
                error?.code === "EADDRINUSE"
                    ? new Error(
                        `the sign-in callback port ${CALLBACK_PORT} is already held by another `
                        + "process — an earlier sign-in is still waiting for its browser",
                    )
                    : error,
            );
        });
        server.listen(CALLBACK_PORT, CALLBACK_HOST, () => {
            const parent = process.ppid;
            timeout = setTimeout(
                () => abandon("the browser sign-in was not completed in time"),
                CALLBACK_TIMEOUT_MS,
            );
            watchdog = setInterval(() => {
                if (process.ppid !== parent) {
                    abandon("GaugeDesk exited before the sign-in completed");
                }
            }, PARENT_POLL_MS);
            emit({ event: "auth_url", url: authorize.toString() });
        });
    });
    emit({ event: "linked", ...(await exchange(code, verifier)) });
} catch (error) {
    fail(error);
}
