export interface RouteOptions {
    /** Stable across retries of one logical command. */
    readonly idempotencyKey?: string;
}

export type RouteJson = (
    method: string,
    path: string,
    body?: unknown,
    options?: RouteOptions,
) => Promise<unknown>;

/** Mint the caller-owned key before a command is sent. Keeping key creation at
 *  the edge lets a retry reuse it instead of asking the server to guess identity. */
export function newIdempotencyKey(): string {
    return globalThis.crypto.randomUUID();
}

/**
 * The control-plane base URL for this client. A multi-machine session points two
 * browser windows at two backends via `?cp=` (e.g. `?cp=http://127.0.0.1:7879`),
 * so the same build can drive either authority; absent, it is the co-resident
 * loopback default (desktop/web single-instance).
 */
const CP_KEY = "gw.cp";

/** The solo default: the co-resident headless control plane (DEPLOY-5). `:7878` in dev/desktop;
 *  the e2e harness overrides it per run via `VITE_CP_BASE` for concurrency-safety (e2e/run.mjs). */
export const SOLO_CONTROL_PLANE =
    (import.meta.env?.VITE_CP_BASE as string | undefined) ?? "http://127.0.0.1:7878";

/** Whether a control-plane endpoint may be connected (ENTSEC-3): **https**, or a **loopback**
 *  host on any scheme (the co-resident solo default / a dev second backend). A non-loopback
 *  `http://` is refused — a remote workspace over cleartext is exactly the leak we forbid.
 *  Pure + total (a malformed URL is insecure). */
export function isSecureControlPlaneEndpoint(url: string): boolean {
    try {
        const u = new URL(url);
        const h = u.hostname;
        const loopback = h === "localhost" || h === "127.0.0.1" || h === "::1" || h === "[::1]";
        return u.protocol === "https:" || loopback;
    } catch {
        return false;
    }
}

/** Resolve the control-plane base (DEPLOY-5, ADR 0059): an explicit `?cp=` per-load override
 *  wins; else a **persisted enterprise org-CP endpoint** (the enrolled app connects there);
 *  else the co-resident **solo** default. Pure — the args are the page's search string and a
 *  storage — so the precedence is unit-testable (mirrors `readDevMode`). */
export function resolveControlPlaneBase(
    search: string,
    storage: Pick<Storage, "getItem"> | null,
): string {
    // ENTSEC-3 (ADR 0065): a **remote** org control plane must be HTTPS — never connect a
    // workspace (transcripts, tokens, files) over plaintext. An insecure `?cp=`/persisted
    // endpoint is **ignored** (fail-safe to solo), not used. Loopback http stays fine for dev.
    const cp = new URLSearchParams(search).get("cp");
    if (cp && isSecureControlPlaneEndpoint(cp)) return cp;
    const saved = storage?.getItem(CP_KEY);
    if (saved && isSecureControlPlaneEndpoint(saved)) return saved;
    return SOLO_CONTROL_PLANE;
}

export function controlPlaneBase(): string {
    if (typeof window !== "undefined") {
        try {
            return resolveControlPlaneBase(window.location.search, window.localStorage);
        } catch {
            return resolveControlPlaneBase(window.location.search, null);
        }
    }
    return SOLO_CONTROL_PLANE;
}

/** Persist the **enterprise** org control-plane endpoint (DEPLOY-5): the enrolled app then
 *  connects there instead of the co-resident solo default. One shell, two runtime configs. */
export function setControlPlaneBase(url: string): void {
    // ENTSEC-3: refuse to persist a plaintext remote endpoint — fail closed at the write too,
    // not only at the read.
    if (!isSecureControlPlaneEndpoint(url)) {
        throw new Error(`refusing an insecure control-plane endpoint (use https): ${url}`);
    }
    try {
        window.localStorage?.setItem(CP_KEY, url);
    } catch {
        /* storage unavailable — fall back to the solo default next load */
    }
}

/** Clear the persisted enterprise endpoint, reverting to the solo co-resident default. */
export function clearControlPlaneBase(): void {
    try {
        window.localStorage?.removeItem(CP_KEY);
    } catch {
        /* storage unavailable */
    }
}
