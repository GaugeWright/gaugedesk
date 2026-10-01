/**
 * The desktop window's credential for its own local control plane (DR-0269).
 *
 * The desktop serves its control plane on loopback, which every process on
 * the computer and every web page can reach. So the shell mints a secret at
 * launch and refuses any request that does not carry it. Only the window can
 * learn it, over Tauri IPC. The window registers it here once, before its
 * first request, and every request this package builds to that exact origin
 * carries it. A request to any other origin never does, so the secret cannot
 * leak to a remote Home, the Hub, or a relay.
 */

export const LOCAL_OPERATOR_HEADER = "x-gaugedesk-operator";

let registered: { readonly origin: string; readonly secret: Promise<string | null> } | null = null;

function originOf(url: string): string | null {
    try {
        return new URL(url).origin;
    } catch {
        return null;
    }
}

/** Register the window's local control plane and the promise of its secret.
 * A browser build never calls this. */
export function registerLocalOperatorCredential(base: string, secret: Promise<string | null>): void {
    const origin = originOf(base);
    if (!origin) return;
    registered = { origin, secret: secret.catch(() => null) };
}

/** The secret to send with a request to `url`, or `null` when `url` is not
 * the registered local control plane or none was issued. */
export async function localOperatorCredentialFor(url: string): Promise<string | null> {
    const current = registered;
    if (!current || originOf(url) !== current.origin) return null;
    const secret = await current.secret;
    return typeof secret === "string" && secret ? secret : null;
}

/** Test seam: forget any registration. */
export function resetLocalOperatorCredentialForTest(): void {
    registered = null;
}
