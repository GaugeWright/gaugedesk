/**
 * Step bindings for the mobile projection-client flow (MOB-029). They drive the
 * real mobile harness (`?mobile=1`, {@link MobileApp}) in the browser — clicking
 * the committed D-MOBILE islands (PairingFlow, Carousel, ConnectionBanner) and
 * the shared ChatPanel at the chat stop, asserting on the rendered projections —
 * over the live
 * control plane. Like `steps.ts` these never reach into client state; they assert
 * only on what the device actually renders (`principles.md`: thin renderer).
 *
 * The journey under test is the device's real arc: pair (the MOB-027 boundary
 * handshake), navigate the carousel one pane at a time (MOB-014/009), and issue
 * the one standing command — a send — which a degraded connection refuses with an
 * explicit banner (MOB-028) and re-enables once back online.
 */

import { expect, type Page } from "@playwright/test";
import { createBdd } from "playwright-bdd";

const { Given, When, Then } = createBdd();

/** Open the mobile harness and wait for the pairing entry screen. */
async function openMobile(page: Page): Promise<void> {
    await page.goto("/?mobile=1");
    await expect(page.locator("[data-mobile-harness]")).toBeVisible();
    await expect(page.locator("[data-pairing-entry]")).toBeVisible();
}

/** Enter a ticket and pair, waiting until the device settles paired (the carousel
 *  stage replaces the pairing stage once the boundary is Active). */
async function pairWith(page: Page, ticket: string): Promise<void> {
    await page.locator("[data-pairing-code]").fill(ticket);
    await page.locator("[data-pairing-submit]").click();
    await expect(page.locator('[data-mobile-stage="carousel"]')).toBeVisible();
}

Given("the mobile client is open", async ({ page }) => {
    await openMobile(page);
});

Given("I have paired with the ticket {string}", async ({ page }, ticket: string) => {
    await pairWith(page, ticket);
});

When("I pair with the ticket {string}", async ({ page }, ticket: string) => {
    await pairWith(page, ticket);
});

Then("the device is paired", async ({ page }) => {
    await expect(page.locator('[data-mobile-stage="carousel"]')).toBeVisible();
});

Then("the connection is active", async ({ page }) => {
    // `active` ⇒ the banner renders nothing (chromeless happy path, MOB-028).
    await expect(page.locator("[data-connection-banner]")).toHaveCount(0);
    await expect(page.locator("[data-relay='online']")).toBeVisible();
});

// ---- carousel navigation ----------------------------------------------------

/** Tap the labelled toggle segment for a pane (the canonical control, MOB-014). */
async function tapPane(page: Page, label: string): Promise<void> {
    await page.locator(".carousel-seg", { hasText: label }).click();
}

// The chat stop renders the one shared ChatPanel (ADR 0076), so these steps drive
// the same composer the desktop and embed steps drive — scoped to the mobile pane
// so they cannot accidentally match another surface on the page.
const draftBox = (page: Page) =>
    page.locator('.mobile-chat [data-chat-composer] textarea[aria-label="Message"]');
const sendButton = (page: Page) => page.locator(".mobile-chat [data-chat-composer] .send-btn");

When("I open the chat pane", async ({ page }) => {
    await tapPane(page, "Chat");
    await expect(page.locator(".carousel[data-pane='chat']")).toBeVisible();
});

When("I open the browse pane", async ({ page }) => {
    await tapPane(page, "Browse");
    // `data-pane='nav'` is the internal pane token; the user-facing label is "Browse".
    await expect(page.locator(".carousel[data-pane='nav']")).toBeVisible();
});

Then("the chat composer is shown", async ({ page }) => {
    await expect(draftBox(page)).toBeVisible();
});

Then("the paired environment is shown", async ({ page }) => {
    await expect(page.locator("[data-paired-environment]")).not.toHaveText("—");
});

// ---- cross-surface: the device and desktop are one workspace ----------------

When("I start a new chat on the device", async ({ page }) => {
    // The Chat tab's "new chat" affordance starts a chat (the same "just chat"
    // work-chat quick-start the desktop uses) and opens its composer.
    await tapPane(page, "Chat");
    await expect(draftBox(page)).toBeVisible();
});

Then("it shows up as a work chat in the desktop's Personal project", async ({ page }) => {
    // Open the desktop workbench (same control plane) in a sibling page and confirm
    // the chat the device just started is listed under Chats — and is a WORK chat
    // (an edit chat, the old bug, would not match `data-kind="work"`).
    const desktop = await page.context().newPage();
    await desktop.goto("/");
    await desktop.locator('[data-facet="projects"]').click();
    await expect(desktop.locator('[data-project]', { hasText: "Personal" }).locator('[data-chat][data-kind="work"]').first()).toBeVisible();
    await desktop.close();
});

// ---- offline / online send gate ---------------------------------------------

When("I go offline", async ({ page }) => {
    await page.locator("[data-relay-offline]").click();
});

When("I go online", async ({ page }) => {
    await page.locator("[data-relay-online]").click();
});

Then("the offline banner is shown", async ({ page }) => {
    await expect(page.locator("[data-connection-banner='offline']")).toBeVisible();
});

Then("the offline banner is gone", async ({ page }) => {
    await expect(page.locator("[data-connection-banner]")).toHaveCount(0);
});

Then("the composer refuses to send", async ({ page }) => {
    // The banner and the disabled send are one fold (MOB-028): offline disables send.
    await draftBox(page).fill("blocked while offline");
    await expect(sendButton(page)).toBeDisabled();
    // Disabled *for the stated reason*, not incidentally: with text in the box
    // the only thing that can be refusing the send is the connection.
    await expect(sendButton(page)).toHaveAttribute("data-blocked", "");
    // And the draft survives the refusal — a send that cannot be carried must
    // not consume the text (the shared controller refuses before taking it).
    await expect(draftBox(page)).toHaveValue("blocked while offline");
    await draftBox(page).fill("");
});

Then("I can send {string}", async ({ page }, text: string) => {
    const send = sendButton(page);
    await draftBox(page).fill(text);
    await expect(send).toBeEnabled();
    await send.click();
    // Taking the message clears the draft (the shared composer controller).
    await expect(draftBox(page)).toHaveValue("");
});

// ---- stopping a turn from the device ----------------------------------------

// Sent without waiting for the turn to settle, so the stop control can be
// exercised while it runs. `[hold]` opens a window nothing outlasts, so nothing
// here can pass by waiting the turn out.
When("I send {string} from the device", async ({ page }, text: string) => {
    await draftBox(page).fill(text);
    await sendButton(page).click();
    await expect(draftBox(page)).toHaveValue("");
});

Then("the device shows a stop control", async ({ page }) => {
    await expect(page.locator(".mobile-chat [data-testid='stop-turn']")).toBeVisible();
});

// The desktop's delivery menu overhung its stop button and swallowed clicks
// aimed at the leading third (#310). A phone declares no queue, stash or fork,
// so it should never render that menu at all — which is worth asserting rather
// than assuming, because it is a consequence of the capability set rather than
// anything the mobile code says for itself.
Then("every part of the device's stop control reaches stop", async ({ page }) => {
    const covered = await page.evaluate(() => {
        const stop = document.querySelector('.mobile-chat [data-testid="stop-turn"]');
        if (!stop) throw new Error("the device is not showing a stop control");
        const box = stop.getBoundingClientRect();
        return [0.05, 0.25, 0.5, 0.75, 0.95]
            .filter((across) => {
                const at = document.elementFromPoint(
                    box.left + box.width * across,
                    box.top + box.height / 2,
                );
                return !stop.contains(at);
            })
            .map((across) => `${Math.round(across * 100)}%`);
    });
    expect(covered, "these points across the stop control hit something else").toEqual([]);
});

When("I stop the turn from the device", async ({ page }) => {
    await page.locator(".mobile-chat [data-testid='stop-turn']").click();
});

Then("the device's turn ends promptly", async ({ page }) => {
    await expect(page.locator(".mobile-chat [data-testid='stop-turn']")).toHaveCount(0, {
        timeout: 8_000,
    });
    // And the message it stopped is not handed back as a failed send.
    await expect(draftBox(page)).toHaveValue("");
});

// ---- the human task queue (the top bar's Next ③ affordance) ------------------

