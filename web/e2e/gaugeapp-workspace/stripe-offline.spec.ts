import { expect, test } from "@playwright/test";
import { blocksStripeRequest, installStripeOffline } from "../stripe-offline.mjs";
import { installLocalStripeSafetyBackstop } from "./stripe-offline.mocked-steps";

test("default Stripe isolation blocks mounted script, frame and fetch without external egress", { tag: "@ui-mocked" }, async ({ browser, baseURL }) => {
    const context = await browser.newContext({ baseURL });
    let escapes = 0;
    try {
        // Installed first: this lower-priority local backstop makes guard omission safe.
        await installLocalStripeSafetyBackstop(context, () => { escapes += 1; });
        await installStripeOffline(context);
        const page = await context.newPage();
        const blocked: string[] = [];
        page.on("requestfailed", (request) => { if (blocksStripeRequest(request.url())) blocked.push(request.resourceType()); });
        await page.goto("/?app=commercial-operations");
        await expect(page.getByRole("heading", { level: 1 })).toBeVisible();
        const fetchFailed = await page.evaluate(async () => {
            const script = document.createElement("script"); script.src = "https://connect-js.stripe.com/v1.0/connect.js"; document.body.append(script);
            const frame = document.createElement("iframe"); frame.src = "https://connect.stripe.com/embedded"; document.body.append(frame);
            try { await fetch("https://api.stripe.com/fixture-no-payment"); return false; } catch { return true; }
        });
        expect(fetchFailed, `Stripe fetch must be blocked; local safety-backstop escapes: ${escapes}`).toBe(true);
        await expect.poll(() => [...new Set(blocked)].sort()).toEqual(["document", "fetch", "script"]);
        expect(escapes).toBe(0);
        // Unrelated loopback traffic still uses the real local fixture.
        await expect(page.getByRole("button", { name: "Account", exact: true })).toBeVisible();
    } finally { await context.close(); }
});
