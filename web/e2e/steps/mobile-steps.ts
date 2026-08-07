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

When("I request review for the next mobile change", async ({ page }) => {
    const review = page.locator("[data-review-next]");
    await review.click();
    await expect(review).toHaveAttribute("aria-pressed", "true");
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

// ---- the human task queue (the top bar's Next ③ affordance) ------------------

Then("the task queue badge appears", async ({ page }) => {
    // A finished turn queues a review (GET /tasks); the top-bar badge counts it.
    // Auto-retry waits for the turn to settle and the queue to refetch.
    await expect(page.locator("[data-next-task]")).toBeVisible();
});

When("I open the task queue", async ({ page }) => {
    // The `⌄` chevron is the pull-down: it opens the full queue sheet.
    await page.locator("[data-open-queue]").click();
    await expect(page.locator("[data-queue-sheet]")).toBeVisible();
});

Then("the task queue lists a review", async ({ page }) => {
    const item = page.locator("[data-queue-sheet] [data-queue-task]").first();
    await expect(item).toBeVisible();
    await expect(item).toContainText("review");
});

When("I jump to the first task from the queue", async ({ page }) => {
    await page.locator("[data-queue-sheet] [data-queue-task]").first().click();
    // The sheet dismisses on jump (the host closes it as it routes to the chat).
    await expect(page.locator("[data-queue-sheet]")).toHaveCount(0);
});
