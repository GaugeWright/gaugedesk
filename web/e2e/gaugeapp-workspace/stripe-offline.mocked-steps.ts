import type { BrowserContext } from "@playwright/test";
import { blocksStripeRequest } from "../stripe-offline.mjs";

// Presentation-only @ui-mocked guard fault control. Install this local fulfillment
// before the production blocker so an omitted blocker cannot contact Stripe.
// This response is a safety backstop, never payment or real-transport evidence.
export async function installLocalStripeSafetyBackstop(context: BrowserContext, escaped: () => void): Promise<void> {
    await context.route((url) => blocksStripeRequest(url.href), async (route) => {
        escaped();
        await route.fulfill({ status: 200, contentType: "text/html", body: "<!-- local safety backstop -->", headers: { "access-control-allow-origin": "*" } });
    });
}
