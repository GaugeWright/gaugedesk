/**
 * Client-side OIDC login session (M3 `ID-3` — the shell's client half).
 *
 * The control plane's `GET /auth/login` → IdP → `GET /auth/callback` dance ends by
 * handing the browser the verified **id-token** in the URL *fragment*
 * (`#id_token=…&token_type=Bearer`). That id-token is the bearer the control plane
 * already accepts (`Workbench::authorize` → `idp.authenticate`), so the client just
 * has to: kick off login, capture the token off the callback fragment, persist it,
 * and surface it so the transport sends it as `Authorization: Bearer …` on `/admin/*`.
 *
 * The token is held **in memory only** — a Solid signal, never `localStorage`/
 * `sessionStorage`/a cookie this script can read (`ENTSEC-6`, ADR 0065). The
 * consultant's endpoint is *unmanaged*, so a credential at rest is the sharpest leak:
 * persisting the id-token would let any later local access or storage-scraping XSS lift a
 * live session, and it would survive reloads. In-memory only means the token never
 * touches disk and is gone on reload / tab-close (the user re-authenticates — SSO is
 * typically a silent redirect). It is **never verified here** — it is opaque to the
 * client; the server re-verifies it on every request. The `sub` claim is decoded only for
 * a display label, never trusted.
 *
 * Residual (not closed here): a live XSS *in the running page* can still read the
 * in-memory signal — inherent to a header-bearer SPA. The further hardening is a
 * server-set `HttpOnly` cookie session so the token never lives in JS at all (tracked as
 * the `ENTSEC-6` follow-on; it needs credentialed CORS + CSRF for the cross-origin thin
 * client).
 *
 * The pure helpers ({@link parseCallbackFragment}, {@link decodeSubject}) take explicit
 * inputs so they unit-test without a real `window`.
 */

import { createSignal } from "solid-js";
import { browserRouteRequest } from "./browser-route-json";
import { newIdempotencyKey } from "./control-plane-transport";
import {
    authenticationCredentialJSON,
    publicKeyCreationOptions,
    publicKeyRequestOptions,
    registrationCredentialJSON,
} from "./webauthn-browser";

/**
 * Parse an OIDC callback URL fragment for the delivered id-token. Accepts the
 * `#id_token=…&token_type=Bearer` form `/auth/callback` redirects with; returns the
 * token, or `null` if the fragment carries none.
 */
export function parseCallbackFragment(hash: string): string | null {
    const h = hash.startsWith("#") ? hash.slice(1) : hash;
    if (!h) return null;
    let params: URLSearchParams;
    try {
        params = new URLSearchParams(h);
    } catch {
        return null;
    }
    const tok = params.get("id_token");
    return tok && tok.trim() ? tok : null;
}

/**
 * Decode the `sub` claim from a JWT for a **display label** — not verification (the
 * server verifies signature + claims). Returns `null` if the token is not a decodable
 * JWT carrying a string `sub`.
 */
export function decodeSubject(token: string): string | null {
    const parts = token.split(".");
    if (parts.length !== 3) return null;
    try {
        let b64 = parts[1].replace(/-/g, "+").replace(/_/g, "/");
        b64 += "=".repeat((4 - (b64.length % 4)) % 4); // restore base64url padding
        const claims = JSON.parse(atob(b64)) as { sub?: unknown };
        return typeof claims.sub === "string" && claims.sub ? claims.sub : null;
    } catch {
        return null;
    }
}

// The bearer starts `null` — there is no at-rest copy to rehydrate from (ENTSEC-6). A
// fresh load is signed out until the callback delivers a token (or the user re-logs in).
const [bearer, setBearerSignal] = createSignal<string | null>(null);

/** The current bearer (the verified id-token), or `null` when signed out. Reactive. */
export { bearer };

/** Set / clear the in-memory bearer. The token is **never** written to persistent storage
 *  (`ENTSEC-6`): it lives only for this page's lifetime. */
export function setBearer(token: string | null): void {
    setBearerSignal(token);
}

/** The signed-in subject for display (the token's `sub`), or `null`. Reactive. */
export function authority(): string | null {
    const t = bearer();
    return t ? decodeSubject(t) : null;
}

/** Whether a bearer is held (optimistic — the server still re-verifies each request). */
export function signedIn(): boolean {
    return bearer() !== null;
}

/**
 * On app load: if the URL fragment carries a callback id-token, store it and strip the
 * OIDC fields from the address bar (so a reload or copied URL can't leak / replay it).
 * Other fragment-scoped capabilities are left for their owning consumer to remove.
 * Returns whether a token was consumed. Safe to call when there is no `window`.
 */
export function consumeCallbackToken(): boolean {
    if (typeof window === "undefined") return false;
    const tok = parseCallbackFragment(window.location.hash);
    if (!tok) return false;
    setBearer(tok);
    try {
        const fragment = new URLSearchParams(window.location.hash.replace(/^#/, ""));
        fragment.delete("id_token");
        fragment.delete("token_type");
        const remaining = fragment.toString();
        history.replaceState(
            null,
            "",
            `${window.location.pathname}${window.location.search}${remaining ? `#${remaining}` : ""}`,
        );
    } catch {
        /* ignore — the token is stored regardless */
    }
    return true;
}

/** Read a first-time provider signup ticket out of the URL fragment and remove
 *  it from the address bar and history.
 *
 *  The ticket is a bearer for one verified email address and one provider
 *  subject: whoever holds it can create an account bound to that Google
 *  identity. It rides the fragment rather than a query so it never reaches a
 *  `Referer` or a server log, and it is taken out of the visible URL the moment
 *  it is read, the way the callback token beside it is. */
export function consumeAccountSignupTicket(): string | null {
    if (typeof window === "undefined") return null;
    let ticket: string | null = null;
    try {
        const fragment = new URLSearchParams(window.location.hash.replace(/^#/, ""));
        ticket = fragment.get("account_signup");
        if (!ticket) return null;
        fragment.delete("account_signup");
        const remaining = fragment.toString();
        history.replaceState(
            null,
            "",
            `${window.location.pathname}${window.location.search}${remaining ? `#${remaining}` : ""}`,
        );
    } catch {
        /* a ticket that cannot be cleaned out of the URL is still usable */
    }
    return ticket;
}

/**
 * Begin OIDC login: navigate the browser to the control plane's `/auth/login`, which
 * redirects to the configured IdP. After the IdP, `/auth/callback` returns to this
 * origin with the token in the fragment (the deployment points
 * `GAUGEDESK_OIDC_POST_LOGIN_URL` at this client).
 */
export function beginLogin(controlPlaneBase: string): void {
    if (typeof window === "undefined") return;
    window.location.href = `${controlPlaneBase.replace(/\/+$/, "")}/auth/login`;
}

export interface AccountRecoveryChallenge {
    readonly challengeId: string;
    readonly expiresIn: number;
}

export interface AccountEmailChallenge {
    readonly challengeId: string;
    readonly expiresIn: number;
}

type CredentialContainer = Pick<CredentialsContainer, "create" | "get">;

/** The account-auth authority uses passkey-auth's deliberately smaller finish
 * payload, while Account Settings commands retain the browser-standard nested
 * credential JSON. Both share the same binary codec but not a wire envelope. */
function accountRegistrationResponse(credential: PublicKeyCredential): Record<string, unknown> {
    const encoded = registrationCredentialJSON(credential);
    const response = encoded.response as Record<string, unknown>;
    return {
        id: encoded.rawId,
        transports: response.transports,
        attestationObject: response.attestationObject,
        clientDataJSON: response.clientDataJSON,
    };
}

function accountAuthenticationResponse(credential: PublicKeyCredential): Record<string, unknown> {
    const encoded = authenticationCredentialJSON(credential);
    const response = encoded.response as Record<string, unknown>;
    return {
        id: encoded.rawId,
        authenticatorData: response.authenticatorData,
        signature: response.signature,
        clientDataJSON: response.clientDataJSON,
        userHandle: response.userHandle,
    };
}

async function accountAuthResponse(
    controlPlaneBase: string,
    path: string,
    body: unknown,
): Promise<Response> {
    const request = browserRouteRequest(controlPlaneBase.replace(/\/+$/, ""));
    return request(path, {
        method: "POST",
        credentials: "include",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(body),
    });
}

async function accountAuthJson(
    controlPlaneBase: string,
    path: string,
    body: unknown,
    failure: string,
): Promise<Record<string, unknown>> {
    const response = await accountAuthResponse(controlPlaneBase, path, body);
    if (!response.ok) throw new Error(failure);
    let value: unknown;
    try {
        value = await response.json();
    } catch {
        throw new Error("Account authentication response is malformed.");
    }
    if (!value || typeof value !== "object" || Array.isArray(value)) {
        throw new Error("Account authentication response is malformed.");
    }
    return value as Record<string, unknown>;
}

/** Begin the single-use verified-email proof used only for first-account
 * passkey registration. It creates neither an account nor a session. */
export async function startPasskeyAccountCreation(
    controlPlaneBase: string,
    email: string,
): Promise<AccountEmailChallenge> {
    const body = await accountAuthJson(
        controlPlaneBase,
        "/auth/account/email/start",
        { email },
        "Could not send the verification code. Check the address and try again.",
    );
    if (typeof body.challenge_id !== "string" || !body.challenge_id
        || typeof body.expires_in !== "number" || !Number.isSafeInteger(body.expires_in)
        || body.expires_in <= 0) {
        throw new Error("Account authentication response is malformed.");
    }
    return { challengeId: body.challenge_id, expiresIn: body.expires_in };
}

/** Finish email proof and immediately create the first passkey. The verified
 * email ticket and WebAuthn response remain in this call stack only. Success is
 * the server-set HttpOnly session cookie, never a JavaScript bearer. */
export async function finishPasskeyAccountCreation(
    controlPlaneBase: string,
    challengeId: string,
    code: string,
    displayName: string,
    credentials: CredentialContainer = navigator.credentials,
): Promise<PasskeyAccountCreated> {
    const verified = await accountAuthJson(
        controlPlaneBase,
        "/auth/account/email/complete",
        { challenge_id: challengeId, code },
        "That verification code was not accepted. Start again with a new code.",
    );
    if (typeof verified.email_verification !== "string" || !verified.email_verification) {
        throw new Error("Account authentication response is malformed.");
    }
    const started = await accountAuthJson(
        controlPlaneBase,
        "/auth/account/passkey/register/start",
        { email_verification: verified.email_verification, display_name: displayName },
        "Could not start passkey creation. Request a new email code and try again.",
    );
    if (typeof started.ceremony_id !== "string" || !started.ceremony_id) {
        throw new Error("Account authentication response is malformed.");
    }
    const credential = await credentials.create({ publicKey: publicKeyCreationOptions(started.public_key) });
    if (!credential || credential.type !== "public-key") throw new Error("Passkey creation was cancelled.");
    const finished = await accountAuthJson(
        controlPlaneBase,
        "/auth/account/passkey/register/finish",
        {
            ceremony_id: started.ceremony_id,
            label: "Passkey",
            credential: accountRegistrationResponse(credential as PublicKeyCredential),
        },
        "The passkey could not be verified. Start account creation again.",
    );
    // The only copy. The store holds salted hashes, so nothing can reissue these
    // — a later batch is a different batch and invalidates this one. A response
    // without them is a server that did not mint them, which is the state this
    // whole path existed in until recently; say so rather than show an empty list
    // as though the account were recoverable.
    return createdAccount(finished);
}

/** A created passkey account, with the one copy of its recovery codes. */
export interface PasskeyAccountCreated {
    readonly accountId: string;
    readonly recoveryCodes: readonly string[];
    /** Present only for a desktop signup: the `gaugewright://` URL that hands
     *  the desktop its session. Deliberately returned rather than redirected to,
     *  so the page can show the recovery codes first — following it raises the
     *  desktop window over the one tab that will ever hold them. */
    readonly nativeReturn?: string;
}

/** What the signup page may know about a parked provider ticket before it asks
 *  for a passkey: the address the provider attested, and the name it offered. */
export interface ConsumerSignupClaim {
    readonly email: string;
    readonly displayName: string | null;
    readonly provider: string;
}

/** Read the non-secret projection of a signup ticket. Does not spend it. */
export async function claimConsumerSignup(
    controlPlaneBase: string,
    ticket: string,
): Promise<ConsumerSignupClaim> {
    const body = await accountAuthJson(
        controlPlaneBase,
        "/auth/account/consumer-signup/claim",
        { ticket },
        "That sign-in link has expired. Press Continue with Google again.",
    );
    if (typeof body.email !== "string" || !body.email) {
        throw new Error("Account authentication response is malformed.");
    }
    return {
        email: body.email,
        displayName: typeof body.display_name === "string" && body.display_name
            ? body.display_name
            : null,
        provider: typeof body.provider === "string" ? body.provider : "google",
    };
}

/** Create the account a provider signup ticket describes.
 *
 * This is {@link finishPasskeyAccountCreation} without its two email calls:
 * step 1 of ADR 0146 §1 is already satisfied by the provider's verified-email
 * claim, so the ticket stands where the emailed code would. Everything after is
 * the same route on the same server — including the finish, which keys off the
 * ceremony id and so needs no provider-specific twin. */
export async function finishConsumerSignupAccount(
    controlPlaneBase: string,
    ticket: string,
    displayName: string,
    credentials: CredentialContainer = navigator.credentials,
): Promise<PasskeyAccountCreated> {
    const started = await accountAuthJson(
        controlPlaneBase,
        "/auth/account/consumer-signup/register/start",
        { ticket, display_name: displayName },
        "Could not start passkey creation. Press Continue with Google again.",
    );
    if (typeof started.ceremony_id !== "string" || !started.ceremony_id) {
        throw new Error("Account authentication response is malformed.");
    }
    const credential = await credentials.create({ publicKey: publicKeyCreationOptions(started.public_key) });
    if (!credential || credential.type !== "public-key") throw new Error("Passkey creation was cancelled.");
    const finished = await accountAuthJson(
        controlPlaneBase,
        "/auth/account/passkey/register/finish",
        {
            ceremony_id: started.ceremony_id,
            label: "Passkey",
            credential: accountRegistrationResponse(credential as PublicKeyCredential),
        },
        "The passkey could not be verified. Start account creation again.",
    );
    return createdAccount(finished);
}

/** The shared reading of a `register/finish` body. The empty-codes guard is the
 *  check that would have caught a botched mint, so both entrances run it rather
 *  than one of them trusting the other's server. */
function createdAccount(finished: Record<string, unknown>): PasskeyAccountCreated {
    if (typeof finished.account_id !== "string" || !finished.account_id) {
        throw new Error("Account authentication response is malformed.");
    }
    const codes = Array.isArray(finished.recovery_codes)
        ? finished.recovery_codes.filter((code): code is string => typeof code === "string" && !!code)
        : [];
    if (codes.length === 0) {
        throw new Error(
            "The account was created but no recovery codes were issued. "
            + "Sign in and issue a batch before relying on this account.",
        );
    }
    const nativeReturn = typeof finished.native_return === "string" && finished.native_return
        ? finished.native_return
        : undefined;
    return { accountId: finished.account_id, recoveryCodes: codes, nativeReturn };
}

/** Authenticate an existing passkey account. Account discovery uses the
 * verified address only as ceremony input; success is an HttpOnly session. */
export async function signInWithPasskey(
    controlPlaneBase: string,
    email: string,
    credentials: CredentialContainer = navigator.credentials,
): Promise<string> {
    const started = await accountAuthJson(
        controlPlaneBase,
        "/auth/account/passkey/login/start",
        { email },
        "No passkey account could be opened for that address.",
    );
    if (typeof started.ceremony_id !== "string" || !started.ceremony_id) {
        throw new Error("Account authentication response is malformed.");
    }
    const credential = await credentials.get({ publicKey: publicKeyRequestOptions(started.public_key) });
    if (!credential || credential.type !== "public-key") throw new Error("Passkey sign-in was cancelled.");
    const finished = await accountAuthJson(
        controlPlaneBase,
        "/auth/account/passkey/login/finish",
        {
            ceremony_id: started.ceremony_id,
            credential: accountAuthenticationResponse(credential as PublicKeyCredential),
        },
        "That passkey was not accepted. Try again.",
    );
    if (typeof finished.account_id !== "string" || !finished.account_id) {
        throw new Error("Account authentication response is malformed.");
    }
    return finished.account_id;
}

/** Begin the verified-email half of account recovery. The email and challenge
 * are ceremony inputs only; neither becomes client-owned account state. */
export async function startAccountRecovery(
    controlPlaneBase: string,
    email: string,
): Promise<AccountRecoveryChallenge> {
    const request = browserRouteRequest(controlPlaneBase.replace(/\/+$/, ""));
    const response = await request("/auth/account/recovery/start", {
        method: "POST",
        credentials: "include",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ email }),
    });
    if (!response.ok) {
        throw new Error(response.status === 429
            ? "Recovery is temporarily limited. Wait a few minutes and try again."
            : "Could not start account recovery. Check the address and try again.");
    }
    const body = await response.json() as { challenge_id?: unknown; expires_in?: unknown };
    if (typeof body.challenge_id !== "string" || !body.challenge_id
        || typeof body.expires_in !== "number" || !Number.isSafeInteger(body.expires_in)
        || body.expires_in <= 0) {
        throw new Error("Account recovery response is malformed.");
    }
    return { challengeId: body.challenge_id, expiresIn: body.expires_in };
}

/** Finish one single-use recovery attempt. Success is represented by the
 * server-set HttpOnly account cookie; secret proofs are never returned. */
export async function finishAccountRecovery(
    controlPlaneBase: string,
    challengeId: string,
    emailCode: string,
    recoveryCode: string,
): Promise<string> {
    const request = browserRouteRequest(controlPlaneBase.replace(/\/+$/, ""));
    const response = await request("/auth/account/recovery/finish", {
        method: "POST",
        credentials: "include",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
            challenge_id: challengeId,
            email_code: emailCode,
            recovery_code: recoveryCode,
        }),
    });
    if (!response.ok) {
        throw new Error(response.status === 429
            ? "Recovery is temporarily limited. Wait a few minutes and try again."
            : "Those recovery proofs were not accepted. Start again with a new email code.");
    }
    const body = await response.json() as { account_id?: unknown };
    if (typeof body.account_id !== "string" || !body.account_id) {
        throw new Error("Account recovery response is malformed.");
    }
    return body.account_id;
}

/**
 * The server endpoint for organization sign-in discovery. Kept as a pure URL
 * helper so the account entry can use an ordinary HTML POST form: the address
 * stays out of the URL, redirects to an external IdP work normally, and no
 * JavaScript state participates in routing or admission.
 */
export function workEmailLoginTarget(controlPlaneBase: string): string {
    return `${controlPlaneBase.replace(/\/+$/, "")}/auth/work-email`;
}

/** Sign out locally: drop the bearer (the server-side id-token still self-expires). */
export function signOut(): void {
    setBearer(null);
}

/** End the hosted HttpOnly-cookie session, then clear any in-memory bearer used by a local
 * OIDC client. The server endpoint is idempotent and deliberately works even after the session
 * token expires, giving every account menu a reliable path back to the signed-out screen. */
export async function endSession(controlPlaneBase: string): Promise<void> {
    const base = controlPlaneBase.replace(/\/+$/, "");
    const request = browserRouteRequest(base);
    const response = await request("/auth/logout", {
        method: "POST",
        credentials: "include",
        headers: { "idempotency-key": newIdempotencyKey() },
    });
    if (!response.ok) {
        throw new Error(`Sign out failed (${response.status}). Please try again.`);
    }
    signOut();
}

/** Exchange a native login handoff through the shared browser transport. The
 * custom-scheme callback carries only an opaque single-use code; the verifier
 * is supplied from the initiating device and the returned opaque GaugeDesk
 * account session never appears in a URL. External provider tokens remain in
 * the Hub. */
export async function exchangeMobileAccountHandoff(
    controlPlaneBase: string,
    code: string,
    verifier: string,
): Promise<string> {
    const request = browserRouteRequest(controlPlaneBase);
    const response = await request("/auth/mobile/exchange", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ code, verifier }),
    });
    if (!response.ok) {
        throw new Error(`Mobile sign-in handoff failed (${response.status})`);
    }
    const body = await response.json() as { account_session?: unknown };
    if (typeof body.account_session !== "string" || !body.account_session) {
        throw new Error("Mobile sign-in handoff response is malformed");
    }
    return body.account_session;
}

/** Renew the server-held provider grant behind a still-valid native account
 * session. The opaque bearer is stable: a successful response confirms the
 * Hub admitted and touched this exact device-bound session but returns no
 * external credential. */
export async function refreshMobileAccountToken(
    controlPlaneBase: string,
    token: string,
): Promise<string> {
    const request = browserRouteRequest(controlPlaneBase, {
        bearer: () => token,
    });
    const response = await request("/auth/mobile/refresh", { method: "POST" });
    if (!response.ok) {
        throw new Error(`Mobile account refresh failed (${response.status})`);
    }
    const body = await response.json() as { refreshed?: unknown };
    if (body.refreshed !== true) {
        throw new Error("Mobile account refresh response is malformed");
    }
    return token;
}

/** Proactively refresh one hosted account session (ADR 0147 §1). The opaque session
 * **cookie** is the durable, revocable session and stays unreadable to JavaScript;
 * `GET /auth/refresh` authenticates by that cookie and returns a fresh, short-lived
 * **id-token in its body**. That id-token — never the session cookie — is the access
 * credential the browser presents to project Homes (`Authorization: Bearer`), so we
 * hold it in the in-memory {@link bearer} signal (never at rest, `ENTSEC-6`). This is
 * also the reload-rehydration path: after a reload the in-memory id-token is gone but
 * the opaque cookie survives, so one refresh re-obtains the Home credential. Callers
 * receive only whether the server admitted the refresh; the token stays in memory. */
export async function refreshHostedAccountSession(
    controlPlaneBase: string,
): Promise<boolean> {
    const base = controlPlaneBase.replace(/\/+$/, "");
    const request = browserRouteRequest(base);
    const response = await request("/auth/refresh", {
        method: "GET",
        credentials: "include",
    });
    if (!response.ok) return false;
    // Hold the short-lived id-token in memory as the Home access credential. Tolerate
    // an absent token (a deployment that has not yet moved to the cookie model still
    // reports a successful refresh) so refresh stays a boolean signal to the caller.
    try {
        const body = await response.json() as { id_token?: unknown };
        if (typeof body.id_token === "string" && body.id_token) {
            setBearer(body.id_token);
        }
    } catch {
        /* no JSON body — the session was still refreshed */
    }
    return true;
}

/**
 * Keep a hosted **cookie session** alive (ADR 0077 / ADR 0147 §1). The hub sets an HttpOnly
 * `.gaugewright.com` **opaque** session cookie; `GET /auth/refresh` authenticates by it and returns
 * a fresh ~1h **id-token in its body** while the session is still live (proactive — a revoked or
 * expired session can't refresh itself). {@link refreshHostedAccountSession} holds that id-token in
 * memory as the Home access credential, so this timer both keeps the session warm and keeps the
 * Home credential fresh; a long-open tab never gets logged out mid-use.
 *
 * The **first tick fires immediately**, which is the reload-rehydration path: the in-memory
 * id-token is gone after a reload but the opaque cookie survives, so this re-obtains the Home
 * credential without a re-login. Fire-and-forget + credentialed (the HttpOnly cookie is not
 * JS-readable). No-op unless `base` is a remote `https` Hub API — the loopback desktop has no
 * cookie session. Returns a stop function. Safe when there is no `window`.
 */
export function startSessionRefresh(base: string, intervalMs = 45 * 60 * 1000): () => void {
    if (typeof window === "undefined" || !base.startsWith("https://")) return () => {};
    const tick = () => {
        // Ignore the outcome: a 200 refreshed the session and re-seated the in-memory id-token;
        // a 401/404 just means re-login on next use.
        void refreshHostedAccountSession(base).catch(() => {});
    };
    tick();
    const id = window.setInterval(tick, intervalMs);
    return () => window.clearInterval(id);
}


/** Where an address should sign in, as far as the account service will say.
 *
 * `POST /auth/work-email` (`auth_oidc.rs:294`) is the only discovery there is.
 * A matched organization gets a redirect to its IdP; everything else gets one
 * flat 404 covering "invalid, absent, incomplete, unsupported, and ambiguous",
 * deliberately, so discovery cannot enumerate organizations or accounts. So
 * this can learn *that* an address routes to an organization and nothing more —
 * not its name, because `redirect: "manual"` yields an opaque response whose
 * Location is not readable, and not whether a personal account exists, because
 * the service will not say.
 *
 * The caller completes the organization case by submitting the same address as
 * a real form, so the browser follows the redirect it cannot follow here. That
 * means the authorization request is begun twice and the first is abandoned
 * unused. It is wasteful rather than wrong — the discarded state is never seen
 * by the IdP and the second overwrites it — but it is the seam where a small
 * JSON discovery route would pay for itself, returning the organization's name
 * for the confirm step and leaking no more than the redirect already does.
 */
export async function resolveSignInRoute(
    controlPlaneBase: string,
    email: string,
): Promise<{ organization: boolean }> {
    const response = await fetch(workEmailLoginTarget(controlPlaneBase), {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ email }),
        redirect: "manual",
        credentials: "include",
    });
    // An opaque-redirect response carries status 0; a same-origin 3xx read
    // directly carries its own. Either means an organization matched.
    const redirected =
        response.type === "opaqueredirect"
        || (response.status >= 300 && response.status < 400);
    return { organization: redirected };
}

/** Submit the address as a real form so the browser follows the organization
 *  redirect. A fetch cannot: the destination is cross-origin and the response is
 *  opaque, and the IdP round trip has to happen in the address bar anyway. */
export function beginWorkEmailLogin(controlPlaneBase: string, email: string): void {
    const form = document.createElement("form");
    form.method = "post";
    form.action = workEmailLoginTarget(controlPlaneBase);
    form.style.display = "none";
    const field = document.createElement("input");
    field.type = "hidden";
    field.name = "email";
    field.value = email;
    form.append(field);
    document.body.append(form);
    form.submit();
}
