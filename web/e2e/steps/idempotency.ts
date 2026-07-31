let sequence = 0;

/** Caller-owned key for direct API mutations that bypass the browser transport. */
export function mutationHeaders(headers: Record<string, string> = {}): Record<string, string> {
    return {
        ...headers,
        "idempotency-key": `e2e-${Date.now()}-${sequence++}`,
    };
}
