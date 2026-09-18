/**
 * The check that was short: pressing a provider button with an EMPTY account
 * store.
 *
 * `authenticated-account-session.mjs` creates the account with an email code and
 * a passkey, links the provider, and only then drives `/auth/login` — so every
 * provider sign-in it has ever run was a sign-in by an already-linked account.
 * Nothing exercised the first-time case, and the refusal that stood there for a
 * first-time person appeared exactly once in the repository with no test on it
 * at all. That is how a hosted deployment shipped with no working entrance:
 * Google refused, and (on a packaged desktop) the passkey routes 404.
 *
 * This runs against its own state root, so `external_subjects` really is empty
 * and the person really is new. It reuses port 1421 because the realm's client
 * pins that redirect URI, which also means it runs after, not beside, the
 * session-wiring lane.
 *
 * What it proves, in order:
 *   1. A first-time Google callback does not refuse. It redirects to the
 *      WebAuthn origin with a signup ticket in the FRAGMENT.
 *   2. That ticket projects the address Google verified, without being spent.
 *   3. The ceremony creates a real passkey on a virtual authenticator, and the
 *      response carries recovery codes — which is the ADR 0146 §2 property that
 *      makes the account recoverable at all.
 *   4. The session it mints reports `passkey`, because a passkey is what was
 *      just proved.
 *   5. A SUBSEQUENT `/auth/login` round trip in a fresh browser context resolves
 *      through the link and reports `google`. This is the assertion that proves
 *      the subject was actually written onto the account rather than the signup
 *      merely having appeared to work.
 *   6. The ticket is single-use: replaying it creates no second account.
 */

import { spawn } from "node:child_process";
import { createServer } from "node:http";
import { mkdtemp, rm, stat } from "node:fs/promises";
import { createServer as createTcpServer } from "node:net";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { chromium } from "playwright";
import { attachVirtualAuthenticator } from "./passkey-account-door.mjs";

const repositoryRoot = resolve(import.meta.dirname, "../..");
const serverBinary = resolve(
    repositoryRoot,
    "target/debug/gaugedesk-enterprise-server",
);
const apiOrigin = "http://localhost:1421";
const issuer = process.env.OIDC_ISSUER;
const clientId = process.env.OIDC_CLIENT_ID ?? "gaugedesk-app";
const username = process.env.OIDC_USERNAME ?? "testuser";
const password = process.env.OIDC_PASSWORD ?? "Passw0rd!";
// The realm marks this address `emailVerified`, which is exactly the claim the
// signup path admits as ADR 0146 §1 step 1. Keycloak stands in for Google here.
const providerEmail = process.env.OIDC_EMAIL ?? "testuser@gaugewright.test";
if (!issuer) throw new Error("OIDC_ISSUER is required");
await stat(serverBinary);

async function freePort() {
    return new Promise((resolveReady, reject) => {
        const probe = createTcpServer();
        probe.once("error", reject);
        probe.listen(0, "127.0.0.1", () => {
            const { port } = probe.address();
            probe.close(() => resolveReady(port));
        });
    });
}

async function waitForHealth(child) {
    const deadline = Date.now() + 30_000;
    while (Date.now() < deadline) {
        if (child.exitCode !== null) {
            throw new Error(`server exited before readiness (${child.exitCode})`);
        }
        try {
            const response = await fetch(`${apiOrigin}/health`);
            if (response.ok) return;
        } catch {
            // Startup is still in progress.
        }
        await new Promise((wait) => setTimeout(wait, 100));
    }
    throw new Error("server did not become ready");
}

/** Sign in at the provider and return where the callback sent the browser. */
async function providerRoundTrip(context, loginUrl) {
    const page = await context.newPage();
    await page.goto(loginUrl, { waitUntil: "domcontentloaded" });
    await page.locator("#username").fill(username);
    await page.locator("#password").fill(password);
    await Promise.all([
        page.waitForURL((url) => url.origin !== new URL(issuer).origin),
        page.locator("#kc-login").click(),
    ]);
    return page;
}

/**
 * The signup ceremony as the shipped client runs it: claim, register/start,
 * a real credential from the virtual authenticator, then the SAME
 * `passkey/register/finish` the email entrance uses.
 */
async function completeSignup(page, ticket, displayName) {
    return page.evaluate(async ([api, signupTicket, name]) => {
        const b64urlToBytes = (value) => {
            const padded = value.replace(/-/g, "+").replace(/_/g, "/");
            const binary = atob(padded + "=".repeat((4 - (padded.length % 4)) % 4));
            return Uint8Array.from(binary, (character) => character.charCodeAt(0));
        };
        const bytesToB64url = (buffer) =>
            btoa(String.fromCharCode(...new Uint8Array(buffer)))
                .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
        const post = async (path, body) => {
            const response = await fetch(`${api}${path}`, {
                method: "POST",
                credentials: "include",
                headers: { "content-type": "application/json" },
                body: JSON.stringify(body),
            });
            const parsed = await response.json().catch(() => null);
            return { status: response.status, body: parsed };
        };

        const claimed = await post("/auth/account/consumer-signup/claim", {
            ticket: signupTicket,
        });
        if (claimed.status !== 200) {
            throw new Error(`claim returned ${claimed.status}`);
        }
        const started = await post("/auth/account/consumer-signup/register/start", {
            ticket: signupTicket,
            display_name: name,
        });
        if (started.status !== 200) {
            throw new Error(`register/start returned ${started.status}`);
        }
        const options = started.body.public_key?.publicKey ?? started.body.public_key;
        const credential = await navigator.credentials.create({
            publicKey: {
                ...options,
                challenge: b64urlToBytes(options.challenge),
                user: { ...options.user, id: b64urlToBytes(options.user.id) },
                excludeCredentials: (options.excludeCredentials ?? []).map((descriptor) => ({
                    ...descriptor,
                    id: b64urlToBytes(descriptor.id),
                })),
            },
        });
        if (!credential || credential.type !== "public-key") {
            throw new Error("the authenticator created no credential");
        }
        const finished = await post("/auth/account/passkey/register/finish", {
            ceremony_id: started.body.ceremony_id,
            label: "Passkey",
            credential: {
                id: bytesToB64url(credential.rawId),
                transports: credential.response.getTransports?.() ?? [],
                attestationObject: bytesToB64url(credential.response.attestationObject),
                clientDataJSON: bytesToB64url(credential.response.clientDataJSON),
            },
        });
        // A second use of the same ticket must find nothing — it is a bearer for
        // one verified email and one provider subject.
        const replayed = await post("/auth/account/consumer-signup/register/start", {
            ticket: signupTicket,
            display_name: name,
        });
        return { claimed: claimed.body, finished, replayed: replayed.status };
    }, [apiOrigin, ticket, displayName]);
}

const stateRoot = await mkdtemp(resolve(tmpdir(), "gw-google-first-signup-"));
const staticPort = await freePort();
const staticOrigin = `http://localhost:${staticPort}`;

const staticServer = createServer((_request, response) => {
    response.writeHead(200, {
        "cache-control": "no-store",
        "content-type": "text/html; charset=utf-8",
    });
    response.end("<!doctype html><title>Google-first account signup</title>");
});
await new Promise((ready, reject) => {
    staticServer.once("error", reject);
    staticServer.listen(staticPort, "127.0.0.1", ready);
});

let serverOutput = "";
let progress = "server startup";
const server = spawn(serverBinary, [], {
    cwd: stateRoot,
    env: {
        ...process.env,
        GAUGEDESK_ADDR: "127.0.0.1:1421",
        GAUGEDESK_ROOT: stateRoot,
        GAUGEDESK_TEST_RESET: "1",
        GAUGEDESK_WEB_ACCOUNT: "1",
        GAUGEDESK_GOOGLE_CLIENT_ID: clientId,
        GAUGEDESK_OIDC_ISSUER: issuer,
        GAUGEDESK_OIDC_REDIRECT_URI: `${apiOrigin}/auth/callback`,
        GAUGEDESK_OIDC_POST_LOGIN_URL: `${staticOrigin}/`,
        GAUGEDESK_SESSION_COOKIE_INSECURE: "1",
        GAUGEDESK_ALLOWED_ORIGINS: staticOrigin,
        GAUGEDESK_ACCOUNT_RP_ID: "localhost",
        // The one origin WebAuthn will accept, and therefore the one the
        // callback may send a signup to. The failure this pins down is quiet:
        // redirect anywhere else and the person meets the authenticator, gives
        // a fingerprint, and only then gets a 401 from `finish_registration`.
        GAUGEDESK_ACCOUNT_ORIGIN: staticOrigin,
        GAUGEDESK_TEST_AUTH_EMAIL_OUTBOX: resolve(stateRoot, "outbox.json"),
    },
    stdio: ["ignore", "pipe", "pipe"],
});
server.stdout.on("data", (chunk) => { serverOutput += chunk.toString(); });
server.stderr.on("data", (chunk) => { serverOutput += chunk.toString(); });

let browser;
try {
    await waitForHealth(server);
    browser = await chromium.launch({ channel: "chrome", headless: true });

    // google-first-signup-callback
    progress = "first-time provider callback";
    const signupContext = await browser.newContext();
    const page = await providerRoundTrip(signupContext, `${apiOrigin}/auth/login`);
    const landed = new URL(page.url());
    if (landed.origin !== staticOrigin) {
        throw new Error(
            `a first-time Google callback landed on ${landed.origin}, not the WebAuthn origin`,
        );
    }
    const ticket = new URLSearchParams(landed.hash.slice(1)).get("account_signup");
    if (!ticket) {
        throw new Error(`no signup ticket in the fragment: ${page.url()}`);
    }
    // In the fragment, never the query: a bearer for a verified identity must
    // not reach browser history, a Referer, or a server access log.
    if (landed.search.includes("account_signup")) {
        throw new Error("the signup ticket rode a query parameter");
    }

    // google-first-signup-ceremony
    progress = "passkey ceremony and recovery codes";
    const detachAuthenticator = await attachVirtualAuthenticator(signupContext, page);
    const result = await completeSignup(page, ticket, "Google First");
    if (result.claimed?.email !== providerEmail) {
        throw new Error(`claim projected ${JSON.stringify(result.claimed)}`);
    }
    if (result.finished.status !== 200) {
        throw new Error(`register/finish returned ${result.finished.status}`);
    }
    const codes = result.finished.body?.recovery_codes;
    if (!Array.isArray(codes) || codes.length === 0) {
        throw new Error(
            "the account was created with no recovery codes — ADR 0146 §2 recovery "
            + "needs a verified email AND an unused code, so this account is unrecoverable",
        );
    }
    const accountId = result.finished.body?.account_id;
    if (typeof accountId !== "string" || !accountId) {
        throw new Error("register/finish returned no account id");
    }
    if (result.replayed !== 401) {
        throw new Error(`a replayed signup ticket returned ${result.replayed}`);
    }

    // google-first-signup-session-method
    progress = "signup session method";
    const session = await page.evaluate(async (api) => {
        const response = await fetch(`${api}/auth/session`, { credentials: "include" });
        return response.json();
    }, apiOrigin);
    // The person did just prove a passkey, and only a passkey-or-recovery
    // session may link a further provider. Reporting the provider here would
    // lock them out of Account Settings with the credential in their hand.
    if (session?.method !== "passkey") {
        throw new Error(`signup session reported ${JSON.stringify(session)}`);
    }
    await detachAuthenticator();
    await signupContext.close();

    // google-first-signup-link-resolves
    progress = "subsequent provider sign-in resolves the link";
    // A fresh context, because the first one holds a provider session that
    // would wave the form through — and, more to the point, a browser that has
    // never met this account is how the second sign-in actually happens.
    const returning = await browser.newContext();
    const returningPage = await providerRoundTrip(returning, `${apiOrigin}/auth/login`);
    if (new URL(returningPage.url()).hash.includes("account_signup")) {
        throw new Error("a linked Google account was sent back to signup");
    }
    const returningSession = await returningPage.evaluate(async (api) => {
        const response = await fetch(`${api}/auth/session`, { credentials: "include" });
        return response.json();
    }, apiOrigin);
    // THE assertion. `google` here can only come from an active external-subject
    // link on this account, so it proves the signup wrote the link rather than
    // having merely appeared to succeed.
    if (returningSession?.method !== "google") {
        throw new Error(
            `a returning Google sign-in reported ${JSON.stringify(returningSession)}`,
        );
    }
    // Only one account exists in this state root, so a resolved link can only be
    // the one the signup wrote. `/auth/session` deliberately projects the method
    // and nothing else — it is not an identity disclosure surface.
    await returning.close();

    console.log("google-first account signup: OK");
} catch (error) {
    console.error(`FAILED during ${progress}: ${error?.message ?? error}`);
    if (serverOutput) console.error(serverOutput.slice(-4000));
    process.exitCode = 1;
} finally {
    await browser?.close();
    server.kill("SIGTERM");
    staticServer.close();
    await rm(stateRoot, { recursive: true, force: true });
}
