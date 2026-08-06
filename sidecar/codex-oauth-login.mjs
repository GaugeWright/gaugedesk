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
const REDIRECT_URI = "http://localhost:1455/auth/callback";
const SCOPE = "openid profile email offline_access";
const JWT_CLAIM = "https://api.openai.com/auth";

const emit = (value) => process.stdout.write(`${JSON.stringify(value)}\n`);
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
            server.close();
            resolve(value);
        });
        server.once("error", reject);
        server.listen(1455, process.env.GAUGEDESK_OAUTH_CALLBACK_HOST || "127.0.0.1", () => {
            emit({ event: "auth_url", url: authorize.toString() });
        });
    });
    emit({ event: "linked", ...(await exchange(code, verifier)) });
} catch (error) {
    fail(error);
}
