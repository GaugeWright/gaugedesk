/** Stripe isolation for every standard browser fixture, including model-live. */
export function blocksStripeRequest(raw) {
    let url;
    try { url = new URL(raw); }
    catch { return true; } // A malformed candidate must never escape to the network.
    if (url.protocol !== "http:" && url.protocol !== "https:") return false;
    const host = url.hostname.toLowerCase().replace(/\.$/, "");
    return host === "stripe.com" || host.endsWith(".stripe.com");
}

export async function installStripeOffline(context) {
    await context.route((url) => blocksStripeRequest(url.href), async (route) => {
        await route.abort("blockedbyclient");
    });
}
