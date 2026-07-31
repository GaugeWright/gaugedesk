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
 * fragment from the address bar (so a reload or copied URL can't leak / replay it).
 * Returns whether a token was consumed. Safe to call when there is no `window`.
 */
export function consumeCallbackToken(): boolean {
    if (typeof window === "undefined") return false;
    const tok = parseCallbackFragment(window.location.hash);
    if (!tok) return false;
    setBearer(tok);
    try {
        history.replaceState(null, "", window.location.pathname + window.location.search);
    } catch {
        /* ignore — the token is stored regardless */
    }
    return true;
}

/**
 * Begin OIDC login: navigate the browser to the control plane's `/auth/login`, which
 * redirects to the configured IdP. After the IdP, `/auth/callback` returns to this
 * origin with the token in the fragment (the deployment points
 * `GAUGEWRIGHT_OIDC_POST_LOGIN_URL` at this client).
 */
export function beginLogin(controlPlaneBase: string): void {
    if (typeof window === "undefined") return;
    window.location.href = `${controlPlaneBase}/auth/login`;
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
    const response = await fetch(`${base}/auth/logout`, {
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
 * is supplied from the initiating device and the returned account token never
 * appears in a URL. */
export async function exchangeMobileAccountHandoff(
    controlPlaneBase: string,
    code: string,
    verifier: string,
): Promise<string> {
    const response = await browserRouteRequest(controlPlaneBase)(
        "/auth/mobile/exchange",
        {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({ code, verifier }),
        },
    );
    if (!response.ok) {
        throw new Error(`Mobile sign-in handoff failed (${response.status})`);
    }
    const body = await response.json() as { id_token?: unknown };
    if (typeof body.id_token !== "string" || !body.id_token) {
        throw new Error("Mobile sign-in handoff response is malformed");
    }
    return body.id_token;
}

/** Proactively refresh a still-valid native account session through the same
 * credentialed request owner used by every other browser control-plane call. */
export async function refreshMobileAccountToken(
    controlPlaneBase: string,
    token: string,
): Promise<string> {
    const response = await browserRouteRequest(controlPlaneBase, {
        bearer: () => token,
    })("/auth/mobile/refresh", { method: "POST" });
    if (!response.ok) {
        throw new Error(`Mobile account refresh failed (${response.status})`);
    }
    const body = await response.json() as { id_token?: unknown };
    if (typeof body.id_token !== "string" || !body.id_token) {
        throw new Error("Mobile account refresh response is malformed");
    }
    return body.id_token;
}

/** Proactively refresh one hosted HttpOnly-cookie account session. The cookie is
 * the only browser credential and remains unreadable to JavaScript; callers
 * receive only whether the server admitted and refreshed the session. */
export async function refreshHostedAccountSession(
    controlPlaneBase: string,
): Promise<boolean> {
    const base = controlPlaneBase.replace(/\/+$/, "");
    const response = await fetch(`${base}/auth/refresh`, {
        method: "GET",
        credentials: "include",
    });
    return response.ok;
}

/**
 * Keep a hosted **cookie session** alive (ADR 0077 session refresh). The hub sets an HttpOnly
 * `.gaugewright.com` session cookie carrying a ~1h id-token; `GET /auth/refresh` mints a fresh one
 * from the stored refresh token **while the current session is still valid** (proactive — an expired
 * cookie can't refresh itself). So the Console pings `/auth/refresh` on a timer well under the hour;
 * the browser swaps in the new cookie, and a long-open tab never gets logged out mid-use.
 *
 * Fire-and-forget + credentialed (the HttpOnly cookie is not JS-readable). No-op unless `base` is a
 * remote `https` Hub API — the loopback desktop has no cookie session. Returns a
 * stop function. Safe when there is no `window`.
 */
export function startSessionRefresh(base: string, intervalMs = 45 * 60 * 1000): () => void {
    if (typeof window === "undefined" || !base.startsWith("https://")) return () => {};
    const tick = () => {
        // Ignore the outcome: a 200 refreshed the cookie; a 401/404 just means re-login on next use.
        void refreshHostedAccountSession(base).catch(() => {});
    };
    const id = window.setInterval(tick, intervalMs);
    return () => window.clearInterval(id);
}
