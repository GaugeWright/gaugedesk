/** Whether Home discovery failed because the hosted account session is absent/expired. */
export function isHomeAuthenticationFailure(error: unknown): boolean {
    const message = error instanceof Error ? error.message : String(error ?? "");
    return /(?:^|:) 401(?:\s|$)/.test(message);
}

export type HomeDiscoveryFailure = {
    readonly kind: "failure";
    readonly authentication: boolean;
    readonly message: string;
};

/**
 * Turn bootstrap rejection into ordinary UI state. Solid resources propagate a
 * rejected fetcher through their error boundary before the recovery controls
 * can reliably mount, so hosted authentication failures must resolve here.
 */
export async function captureHomeDiscovery<T>(
    load: () => Promise<T>,
): Promise<T | HomeDiscoveryFailure> {
    try {
        return await load();
    } catch (error) {
        return {
            kind: "failure",
            authentication: isHomeAuthenticationFailure(error),
            message: error instanceof Error ? error.message : String(error ?? ""),
        };
    }
}
