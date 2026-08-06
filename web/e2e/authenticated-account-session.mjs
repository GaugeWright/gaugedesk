import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { createServer } from "node:http";
import { mkdtemp, rm, stat } from "node:fs/promises";
import { createServer as createTcpServer } from "node:net";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { chromium } from "playwright";
import { build } from "vite";
import {
    assertStateTreeExcludes,
    assertStateUnchanged,
    stateTreeDigest,
} from "./authenticated-state.mjs";

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
if (!issuer) throw new Error("OIDC_ISSUER is required");
await stat(serverBinary);

const accountBootstrapPaths = [
    "/account/tenants",
    "/account/homes",
    "/account/home-routes",
    "/account/facilities",
    "/account/invitations",
    "/account/devices",
    "/account/settings",
    "/account/credentials",
    "/account/managed-inference",
    "/account/oauth/openai-codex",
    "/account/onboarding-status",
    "/account/default-model",
];
const accountMutationProperties = [
    {
        method: "POST",
        path: "/account/tenants",
        body: { display_name: "Denied wiring organization" },
    },
    {
        method: "PUT",
        path: "/account/settings/denied-wiring",
        body: { value: "denied" },
    },
    {
        method: "POST",
        path: "/account/facilities",
        body: { id: "denied-wiring-facility" },
    },
    {
        method: "DELETE",
        path: "/account/facilities/denied-wiring-facility",
    },
    {
        method: "PUT",
        path: "/account/homes/selected",
        body: { home_id: "home:denied-wiring" },
    },
    {
        method: "DELETE",
        path: "/account/homes/home%3Adenied-wiring",
    },
    {
        method: "POST",
        path: "/account/home-routes",
        body: {
            project: "project:denied-wiring",
            home_id: "home:denied-wiring",
            endpoint: "http://localhost:65534",
        },
    },
    {
        method: "DELETE",
        path: "/account/home-routes/project%3Adenied-wiring",
    },
];
const accountCredentialMutationProperties = [
    {
        method: "POST",
        path: "/account/credentials",
        body: {
            provider: "denied-wiring-provider",
            token: "denied-wiring-credential-token",
        },
    },
    {
        method: "DELETE",
        path: "/account/credentials/denied-wiring-provider",
    },
];
const accountDeviceRevocationProperties = [
    {
        method: "POST",
        path: "/account/devices/denied-wiring-device/revoke",
    },
];

async function freePort() {
    const server = createTcpServer();
    await new Promise((resolveReady, reject) => {
        server.once("error", reject);
        server.listen(0, "127.0.0.1", resolveReady);
    });
    const address = server.address();
    if (!address || typeof address === "string") {
        throw new Error("ephemeral port did not resolve");
    }
    await new Promise((resolveClosed) => server.close(resolveClosed));
    return address.port;
}

async function waitForHealth(child) {
    const deadline = Date.now() + 30_000;
    while (Date.now() < deadline) {
        if (child.exitCode !== null) {
            throw new Error(`enterprise server exited before readiness (${child.exitCode})`);
        }
        try {
            const response = await fetch(`${apiOrigin}/health`);
            if (response.ok) return;
        } catch {
            // Startup is still in progress.
        }
        await new Promise((resolveWait) => setTimeout(resolveWait, 100));
    }
    throw new Error("enterprise server did not become ready");
}

async function fetchInPage(page, path, init = {}) {
    return page.evaluate(async ({ url, request }) => {
        try {
            const response = await fetch(url, {
                ...request,
                credentials: "include",
            });
            return { status: response.status, body: await response.text() };
        } catch (error) {
            return {
                status: 0,
                body: error instanceof Error ? error.message : String(error),
            };
        }
    }, { url: `${apiOrigin}${path}`, request: init });
}

async function clientCall(page, staticOrigin, name, args = []) {
    return page.evaluate(async ({ moduleUrl, operation, base, parameters }) => {
        const client = await import(moduleUrl);
        return client[operation](base, ...parameters);
    }, {
        moduleUrl: `${staticOrigin}/__wiring/authenticated-session-client-probe.js`,
        operation: name,
        base: apiOrigin,
        parameters: args,
    });
}

function handoffChallenge(verifier) {
    return createHash("sha256").update(verifier).digest("base64url");
}

async function issueMobileHandoff(browser, verifier) {
    const challenge = handoffChallenge(verifier);
    const context = await browser.newContext();
    const page = await context.newPage();
    const login = new URL(`${apiOrigin}/auth/login`);
    login.searchParams.set("return_to", "gaugewright://auth/callback");
    login.searchParams.set("handoff_challenge", challenge);
    try {
        await page.goto(login.toString(), { waitUntil: "domcontentloaded" });
        await page.locator("#username").fill(username);
        await page.locator("#password").fill(password);
        const callbackPromise = page.waitForResponse((response) =>
            response.url().startsWith(`${apiOrigin}/auth/callback?`));
        await page.locator("#kc-login").click();
        const callback = await callbackPromise;
        const location = callback.headers().location;
        if (callback.status() !== 303 || !location) {
            throw new Error(
                `native callback returned ${callback.status()} without a redirect`,
            );
        }
        const returned = new URL(location);
        if (
            returned.protocol !== "gaugewright:"
            || returned.hostname !== "auth"
            || returned.pathname !== "/callback"
        ) {
            throw new Error(`native callback target was not allowlisted: ${location}`);
        }
        const code = new URLSearchParams(returned.hash.slice(1)).get("code");
        if (!code) throw new Error("native callback did not carry an opaque code");
        return code;
    } finally {
        await context.close();
    }
}

const stateRoot = await mkdtemp(resolve(tmpdir(), "gw-auth-session-wiring-"));
const staticPort = await freePort();
const staticOrigin = `http://localhost:${staticPort}`;
const clientBuild = await build({
    configFile: false,
    logLevel: "error",
    resolve: {
        alias: {
            "@gaugewright/control-plane-client": resolve(
                repositoryRoot,
                "web/packages/control-plane-client/src/index.ts",
            ),
        },
    },
    build: {
        write: false,
        minify: false,
        lib: {
            entry: resolve(
                import.meta.dirname,
                "authenticated-session-client-probe.ts",
            ),
            formats: ["es"],
        },
        rollupOptions: {
            output: {
                entryFileNames: "authenticated-session-client-probe.js",
            },
        },
    },
});
const clientChunk = (Array.isArray(clientBuild) ? clientBuild : [clientBuild])
    .flatMap((result) => result.output)
    .find((output) =>
        output.type === "chunk"
        && output.fileName === "authenticated-session-client-probe.js");
if (!clientChunk || clientChunk.type !== "chunk") {
    throw new Error("production account-session client probe did not build");
}

const staticServer = createServer((request, response) => {
    const pathname = new URL(request.url ?? "/", staticOrigin).pathname;
    if (pathname === "/__wiring/authenticated-session-client-probe.js") {
        response.writeHead(200, {
            "cache-control": "no-store",
            "content-type": "text/javascript; charset=utf-8",
        });
        response.end(clientChunk.code);
        return;
    }
    response.writeHead(200, {
        "cache-control": "no-store",
        "content-type": "text/html; charset=utf-8",
    });
    response.end("<!doctype html><title>Authenticated session wiring</title>");
});
await new Promise((resolveReady, reject) => {
    staticServer.once("error", reject);
    staticServer.listen(staticPort, "127.0.0.1", resolveReady);
});

// production-enterprise-router
let serverOutput = "";
let progress = "server startup";
const enterprise = spawn(serverBinary, [], {
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
    },
    stdio: ["ignore", "pipe", "pipe"],
});
enterprise.stdout.on("data", (chunk) => {
    serverOutput += chunk.toString();
});
enterprise.stderr.on("data", (chunk) => {
    serverOutput += chunk.toString();
});

let browser;
try {
    await waitForHealth(enterprise);

    // production-health-contract, public-health-only, and health-method-state-properties
    progress = "health contract and method properties";
    const health = await fetch(`${apiOrigin}/health`);
    const healthBody = await health.json();
    if (
        health.status !== 200
        || healthBody.ok !== true
        || health.headers.get("strict-transport-security")
            !== "max-age=63072000; includeSubDomains"
    ) {
        throw new Error(`health contract was malformed: ${health.status}`);
    }
    const beforeHealthProperties = await stateTreeDigest(stateRoot);
    for (const method of ["POST", "PUT", "PATCH", "DELETE"]) {
        const response = await fetch(`${apiOrigin}/health`, { method });
        if (response.status !== 400) {
            throw new Error(`${method} /health returned ${response.status}, expected 400`);
        }
    }
    await assertStateUnchanged(
        stateRoot,
        beforeHealthProperties,
        "health method properties",
    );

    // cookie-authority-and-callback-csrf
    // generated-return-state-cookie-method-properties
    // oidc-invalid-return-and-callback-properties
    progress = "invalid OIDC return and callback properties";
    const beforeOidcProperties = await stateTreeDigest(stateRoot);
    const invalidReturnUris = [
        "https://attacker.invalid/callback",
        "gaugewright://auth/callback/extra",
        "file:///tmp/callback",
        "//attacker.invalid/callback",
        `https://example.invalid/${"x".repeat(192)}`,
    ];
    for (const returnTo of invalidReturnUris) {
        const response = await fetch(
            `${apiOrigin}/auth/login?return_to=${encodeURIComponent(returnTo)}`,
        );
        if (response.status !== 400) {
            throw new Error(`invalid login return URI returned ${response.status}`);
        }
    }
    for (const challenge of [
        "",
        "short",
        "x".repeat(42),
        "x".repeat(44),
        `${"x".repeat(42)}+`,
    ]) {
        const login = new URL(`${apiOrigin}/auth/login`);
        login.searchParams.set("return_to", "gaugewright://auth/callback");
        login.searchParams.set("handoff_challenge", challenge);
        const response = await fetch(login);
        if (response.status !== 400) {
            throw new Error(`invalid native handoff challenge returned ${response.status}`);
        }
    }
    for (const state of ["wrong", "wrong:state", "wrong/state", "wrong-%00", "x".repeat(192)]) {
        const response = await fetch(
            `${apiOrigin}/auth/callback?state=${encodeURIComponent(state)}&code=x`,
        );
        if (response.status !== 400) {
            throw new Error(`invalid callback state returned ${response.status}`);
        }
    }
    await assertStateUnchanged(
        stateRoot,
        beforeOidcProperties,
        "OIDC invalid return/state properties",
    );

    browser = await chromium.launch({ channel: "chrome", headless: true });
    const context = await browser.newContext();
    const page = await context.newPage();

    // production-browser-client-session-chain
    // oidc-production-browser-login-callback
    progress = "production browser login and callback";
    await page.goto(`${apiOrigin}/auth/login`, { waitUntil: "domcontentloaded" });
    await page.locator("#username").fill(username);
    await page.locator("#password").fill(password);
    await Promise.all([
        page.waitForURL((url) => url.origin === staticOrigin),
        page.locator("#kc-login").click(),
    ]);

    progress = "production account-session read";
    const session = await clientCall(
        page,
        staticOrigin,
        "readAccountSession",
    );
    if (session?.method !== "oidc" || session?.label !== "Single sign-on (OIDC)") {
        throw new Error(`production session client returned ${JSON.stringify(session)}`);
    }
    // production-authenticated-account-bootstrap
    progress = "production authenticated account bootstrap";
    const bootstrap = await clientCall(
        page,
        staticOrigin,
        "readAccountBootstrap",
    );
    if (
        !Array.isArray(bootstrap.tenants)
        || bootstrap.tenants.length !== 1
        || bootstrap.tenants[0]?.personal !== true
        || !bootstrap.tenants[0]?.id
        || !Array.isArray(bootstrap.homes?.homes)
        || !Array.isArray(bootstrap.homeRoutes)
        || !Array.isArray(bootstrap.facilities)
        || !Array.isArray(bootstrap.invitations)
        || !Array.isArray(bootstrap.devices)
        || typeof bootstrap.settings !== "object"
        || !Array.isArray(bootstrap.credentials)
        || typeof bootstrap.managedInference?.usage !== "object"
        || typeof bootstrap.codex?.linked !== "boolean"
        || typeof bootstrap.onboarding?.credentialRequired !== "boolean"
        || typeof bootstrap.defaultModel?.provider !== "string"
    ) {
        throw new Error(
            `production account bootstrap was malformed: ${JSON.stringify(bootstrap)}`,
        );
    }
    // production-linked-credential-lifecycle
    progress = "production linked credential lifecycle";
    const accountCredential = await clientCall(
        page,
        staticOrigin,
        "mutateAccountCredential",
    );
    if (
        accountCredential.linked !== true
        || accountCredential.unlinked !== true
    ) {
        throw new Error(
            `production credential lifecycle failed: ${JSON.stringify(accountCredential)}`,
        );
    }
    await assertStateTreeExcludes(
        stateRoot,
        ["wiring-credential-token"],
        "linked credential lifecycle",
    );
    // production-account-device-revocation-readback
    progress = "production account device revocation/readback";
    const accountDevice = await clientCall(
        page,
        staticOrigin,
        "mutateAccountDeviceRevocation",
    );
    if (
        accountDevice.registered !== true
        || accountDevice.revoked !== true
    ) {
        throw new Error(
            `production device revocation failed: ${JSON.stringify(accountDevice)}`,
        );
    }
    // production-authenticated-account-mutation-readback
    progress = "production authenticated account mutation/readback";
    const accountMutation = await clientCall(
        page,
        staticOrigin,
        "mutateAccountBootstrap",
    );
    if (
        accountMutation.tenant?.displayName !== "Wiring Organization"
        || accountMutation.tenant?.personal !== false
        || accountMutation.setting !== "verified"
        || accountMutation.facility?.id !== "wiring-facility"
        || accountMutation.facilityAttached !== true
        || accountMutation.facilityDetached !== true
        || accountMutation.homeSelected !== true
        || accountMutation.routePublished !== true
        || accountMutation.routeDeleted !== true
        || accountMutation.homeDeleted !== true
    ) {
        throw new Error(
            `production account mutation readback failed: ${JSON.stringify(accountMutation)}`,
        );
    }
    const loginCookies = await context.cookies(apiOrigin);
    const sessionCookie = loginCookies.find((cookie) => cookie.name === "gw_session");
    if (
        !sessionCookie
        || !sessionCookie.httpOnly
        || sessionCookie.sameSite !== "Lax"
        || sessionCookie.secure
    ) {
        throw new Error(`login cookie attributes were malformed: ${JSON.stringify(loginCookies)}`);
    }

    // authenticated-session-refresh-production-client
    progress = "production hosted-session refresh";
    const refreshed = await clientCall(
        page,
        staticOrigin,
        "refreshAccountSession",
    );
    if (refreshed !== true) {
        throw new Error("production hosted-session refresh was not admitted");
    }
    const afterRefresh = await clientCall(
        page,
        staticOrigin,
        "readAccountSession",
    );
    if (afterRefresh?.method !== "oidc") {
        throw new Error("refreshed cookie no longer authenticated the account session");
    }

    // session-cookie-authority-and-method-properties
    progress = "session cookie authority and method properties";
    const beforeSessionProperties = await stateTreeDigest(stateRoot);
    const anonymousContext = await browser.newContext();
    const anonymousPage = await anonymousContext.newPage();
    await anonymousPage.goto(`${staticOrigin}/`);
    const anonymous = await fetchInPage(anonymousPage, "/auth/session");
    if (anonymous.status !== 401) {
        throw new Error(`anonymous session read returned ${anonymous.status}`);
    }
    // account-bootstrap-cookie-authority-properties
    for (const path of accountBootstrapPaths) {
        const denied = await fetchInPage(anonymousPage, path);
        if (denied.status !== 401) {
            throw new Error(`anonymous ${path} returned ${denied.status}`);
        }
    }
    // account-mutation-cookie-authority-properties
    for (const property of accountMutationProperties) {
        const denied = await fetchInPage(anonymousPage, property.path, {
            method: property.method,
            headers: { "content-type": "application/json" },
            ...(property.body ? { body: JSON.stringify(property.body) } : {}),
        });
        if (denied.status !== 401) {
            throw new Error(
                `anonymous ${property.method} ${property.path} returned ${denied.status}`,
            );
        }
    }
    // credential-mutation-cookie-authority-properties
    for (const property of accountCredentialMutationProperties) {
        const denied = await fetchInPage(anonymousPage, property.path, {
            method: property.method,
            headers: { "content-type": "application/json" },
            ...(property.body ? { body: JSON.stringify(property.body) } : {}),
        });
        if (denied.status !== 401) {
            throw new Error(
                `anonymous ${property.method} ${property.path} returned ${denied.status}`,
            );
        }
    }
    // device-revocation-cookie-authority-properties
    for (const property of accountDeviceRevocationProperties) {
        const denied = await fetchInPage(anonymousPage, property.path, {
            method: property.method,
        });
        if (denied.status !== 401) {
            throw new Error(
                `anonymous ${property.method} ${property.path} returned ${denied.status}`,
            );
        }
    }
    await anonymousContext.close();

    let invalidCookieCases = 0;
    for (const value of [
        "invalid",
        "invalid.token",
        "invalid.token.parts.extra",
        `invalid-${"x".repeat(192)}`,
        "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ3cm9uZyJ9.",
    ]) {
        const invalidContext = await browser.newContext();
        await invalidContext.addCookies([{
            name: "gw_session",
            value,
            domain: "localhost",
            path: "/",
            httpOnly: true,
            sameSite: "Lax",
        }]);
        const invalidPage = await invalidContext.newPage();
        await invalidPage.goto(`${staticOrigin}/`);
        const denied = await fetchInPage(invalidPage, "/auth/session");
        if (denied.status !== 401) {
            throw new Error(`invalid session cookie returned ${denied.status}`);
        }
        for (const path of accountBootstrapPaths) {
            const accountDenied = await fetchInPage(invalidPage, path);
            if (accountDenied.status !== 401) {
                throw new Error(
                    `invalid session cookie reached ${path} (${accountDenied.status})`,
                );
            }
        }
        for (const property of accountMutationProperties) {
            const accountDenied = await fetchInPage(invalidPage, property.path, {
                method: property.method,
                headers: { "content-type": "application/json" },
                ...(property.body ? { body: JSON.stringify(property.body) } : {}),
            });
            if (accountDenied.status !== 401) {
                throw new Error(
                    `invalid session cookie reached ${property.method} `
                    + `${property.path} (${accountDenied.status})`,
                );
            }
        }
        for (const property of accountCredentialMutationProperties) {
            const accountDenied = await fetchInPage(invalidPage, property.path, {
                method: property.method,
                headers: { "content-type": "application/json" },
                ...(property.body ? { body: JSON.stringify(property.body) } : {}),
            });
            if (accountDenied.status !== 401) {
                throw new Error(
                    `invalid session cookie reached ${property.method} `
                    + `${property.path} (${accountDenied.status})`,
                );
            }
        }
        for (const property of accountDeviceRevocationProperties) {
            const accountDenied = await fetchInPage(invalidPage, property.path, {
                method: property.method,
            });
            if (accountDenied.status !== 401) {
                throw new Error(
                    `invalid session cookie reached ${property.method} `
                    + `${property.path} (${accountDenied.status})`,
                );
            }
        }
        invalidCookieCases += 1;
        await invalidContext.close();
    }
    for (const method of ["POST", "PUT", "PATCH", "DELETE"]) {
        const denied = await fetchInPage(page, "/auth/session", { method });
        const expected = method === "PATCH" ? 0 : 400;
        if (denied.status !== expected) {
            throw new Error(`${method} /auth/session returned ${denied.status}`);
        }
    }
    await assertStateUnchanged(
        stateRoot,
        beforeSessionProperties,
        "session authority/method properties",
    );

    // production-client-idempotent-logout
    progress = "production idempotent logout";
    await clientCall(page, staticOrigin, "logoutAccountSession");
    const signedOut = await fetchInPage(page, "/auth/session");
    if (signedOut.status !== 401) {
        throw new Error(`session survived production logout (${signedOut.status})`);
    }
    await clientCall(page, staticOrigin, "logoutAccountSession");
    if ((await context.cookies(apiOrigin)).some((cookie) => cookie.name === "gw_session")) {
        throw new Error("production logout left the HttpOnly session cookie");
    }

    // production-native-handoff-client-chain
    progress = "production native login handoff";
    const wrongProofVerifier = "a".repeat(64);
    const wrongProofCode = await issueMobileHandoff(browser, wrongProofVerifier);
    const nativeClientPage = await context.newPage();
    await nativeClientPage.goto(`${staticOrigin}/`);
    const beforeNativeDenials = await stateTreeDigest(stateRoot);
    // native-proof-replay-and-bearer-authority
    // generated-native-code-verifier-bearer-properties
    const wrongProof = await clientCall(
        nativeClientPage,
        staticOrigin,
        "exchangeMobileAccountHandoffResult",
        [wrongProofCode, "b".repeat(64)],
    );
    if (wrongProof.ok || !wrongProof.error?.includes("(401)")) {
        throw new Error(`wrong native proof was not denied: ${JSON.stringify(wrongProof)}`);
    }
    const consumedAfterWrongProof = await clientCall(
        nativeClientPage,
        staticOrigin,
        "exchangeMobileAccountHandoffResult",
        [wrongProofCode, wrongProofVerifier],
    );
    if (consumedAfterWrongProof.ok || !consumedAfterWrongProof.error?.includes("(401)")) {
        throw new Error("wrong-proof native handoff remained redeemable");
    }
    for (const code of [
        "unknown",
        "unknown-code",
        "unknown_code",
        `unknown-${"x".repeat(64)}`,
        "%00",
    ]) {
        const denied = await clientCall(
            nativeClientPage,
            staticOrigin,
            "exchangeMobileAccountHandoffResult",
            [code, "c".repeat(64)],
        );
        if (denied.ok || !denied.error?.includes("(401)")) {
            throw new Error(`unknown native handoff was not denied: ${code}`);
        }
    }
    await assertStateUnchanged(
        stateRoot,
        beforeNativeDenials,
        "native handoff proof/code denials",
    );

    progress = "production native exchange and refresh";
    const admittedVerifier = "d".repeat(64);
    const admittedCode = await issueMobileHandoff(browser, admittedVerifier);
    const exchanged = await clientCall(
        nativeClientPage,
        staticOrigin,
        "exchangeMobileAccountHandoffResult",
        [admittedCode, admittedVerifier],
    );
    if (!exchanged.ok || typeof exchanged.token !== "string" || !exchanged.token) {
        throw new Error(`production native exchange failed: ${JSON.stringify(exchanged)}`);
    }
    const replayed = await clientCall(
        nativeClientPage,
        staticOrigin,
        "exchangeMobileAccountHandoffResult",
        [admittedCode, admittedVerifier],
    );
    if (replayed.ok || !replayed.error?.includes("(401)")) {
        throw new Error("redeemed native handoff was replayable");
    }
    const nativeRefreshed = await clientCall(
        nativeClientPage,
        staticOrigin,
        "refreshMobileAccountTokenResult",
        [exchanged.token],
    );
    if (
        !nativeRefreshed.ok
        || typeof nativeRefreshed.token !== "string"
        || !nativeRefreshed.token
    ) {
        throw new Error(
            `production native refresh failed: ${JSON.stringify(nativeRefreshed)}`,
        );
    }

    progress = "native refresh bearer properties";
    const beforeRefreshDenials = await stateTreeDigest(stateRoot);
    for (const token of [
        "",
        "invalid",
        "invalid.token",
        "expired-account-token",
        `oversized-${"x".repeat(192)}`,
    ]) {
        const denied = await clientCall(
            nativeClientPage,
            staticOrigin,
            "refreshMobileAccountTokenResult",
            [token],
        );
        if (denied.ok || !denied.error?.includes("(401)")) {
            throw new Error(`invalid native bearer was not denied: ${token.length}`);
        }
    }
    await assertStateUnchanged(
        stateRoot,
        beforeRefreshDenials,
        "native refresh bearer denials",
    );

    console.log(
        "authenticated account-session wiring crossed real Keycloak, production "
        + "login/callback routes, HttpOnly cookie authority, the exact production "
        + "session/refresh/logout and native exchange/refresh clients, a proof-bound "
        + "single-use custom-scheme handoff, 12 exact account-bootstrap projections, "
        + "8 exact account mutation/readback lifecycles, one sealed credential "
        + "link/read/unlink lifecycle, one exact device revocation/readback, 72 "
        + "account-read, 48 account-mutation, 12 credential-mutation, and 6 device "
        + "revocation authority properties, 5 invalid session cookies, 15 OIDC "
        + "return/state/challenge properties, 7 native code/proof properties, 5 native "
        + "bearer properties, 8 unsupported-method properties, denied-state "
        + "preservation, and observable mutation/refresh/logout readback",
    );
} catch (error) {
    throw new Error(
        `${progress}: ${error instanceof Error ? error.message : String(error)}\n`
        + `Enterprise output:\n${serverOutput}`,
    );
} finally {
    await browser?.close();
    enterprise.kill("SIGTERM");
    await new Promise((resolveExit) => {
        if (enterprise.exitCode !== null) resolveExit();
        else enterprise.once("exit", resolveExit);
    });
    await new Promise((resolveClosed) => staticServer.close(resolveClosed));
    await rm(stateRoot, { recursive: true, force: true });
}
