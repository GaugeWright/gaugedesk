/**
 * Steps for the embedded panels (EMBED-2). The embed example page mounts the
 * `<gw-session>` + `<gw-chat>`/`<gw-viewer>`/`<gw-files>` custom elements against a
 * browser fixture Session. Production pages pass a hosted deployment through
 * `?host=`; the hermetic fixture isolates component rendering from cloud state.
 * The panels render in **open** shadow roots, which
 * Playwright's selectors pierce automatically. The control-plane reset Before-hook
 * is shared from `steps.ts` (one global hook), so this scenario also starts clean.
 */
import { expect } from "@playwright/test";
import { createBdd } from "playwright-bdd";

const { Given, When, Then } = createBdd();

Given("the embed example page is open", async ({ page }) => {
    await page.goto("/embed-example.html?fixture=1");
    // The composer appears once <gw-session> built the remote Session and <gw-chat>
    // rendered into its shadow root — proof the panel mounted against a non-desktop
    // session (the createEngagement quick-start + bind round-trip).
    await expect(page.locator("[data-embed-composer]")).toBeVisible({ timeout: 15_000 });
});

Given("the chat-only embed Environment is open", async ({ page }) => {
    await page.goto("/embed-example.html?fixture=1&panels=chat");
    await expect(page.locator("[data-embed-composer]")).toBeVisible({ timeout: 15_000 });
});

Given("a block embedded chat sized by min-height is open", async ({ page }) => {
    await page.goto("/embed-example.html?fixture=1&panels=chat");
    await page.locator("gw-session").evaluate((element) => {
        element.style.display = "block";
    });
    await page.locator("gw-chat").evaluate((element) => {
        element.style.display = "block";
        element.style.height = "auto";
        element.style.minHeight = "420px";
    });
    await expect(page.locator("[data-embed-composer]")).toBeVisible({ timeout: 15_000 });
});

Then("the embedded chat shows a composer", async ({ page }) => {
    await expect(page.locator("[data-embed-send]")).toBeVisible();
});

Then("the embedded chat uses the shared docked composer", async ({ page }) => {
    await expect(page.locator("gw-chat [data-chat-composer]")).toBeVisible();
    const panel = await page.locator("gw-chat").boundingBox();
    const composer = await page.locator("gw-chat [data-chat-composer]").boundingBox();
    expect(panel).not.toBeNull();
    expect(composer).not.toBeNull();
    // The only content below the shared dock is the compact attribution line.
    expect(panel!.y + panel!.height - (composer!.y + composer!.height)).toBeLessThan(40);
});

Then("the embedded message field grows with multiline text", async ({ page }) => {
    const composer = page.locator("[data-embed-composer]");
    const panel = page.locator("[data-chat-panel]");
    const initial = await composer.boundingBox();
    await composer.fill("first line\nsecond line\nthird line\nfourth line");
    await expect.poll(async () => (await composer.boundingBox())?.height).toBeGreaterThan(initial!.height);
    const [grown, panelBox] = await Promise.all([composer.boundingBox(), panel.boundingBox()]);
    expect(grown).not.toBeNull();
    expect(panelBox).not.toBeNull();
    expect(grown!.height).toBeLessThanOrEqual(panelBox!.height / 2 + 1);
});

Then("the embedded panel set owns one attribution mark", async ({ page }) => {
    await expect(page.locator("[data-embed-powered-by]")).toHaveCount(1);
});

Then("the unselected files and viewer panels are not composed", async ({ page }) => {
    await expect(page.locator("gw-files")).toHaveCount(0);
    await expect(page.locator("gw-viewer")).toHaveCount(0);
});

When("I send {string} in the embedded chat", async ({ page }, msg: string) => {
    await page.locator("[data-embed-composer]").fill(msg);
    await page.locator("[data-embed-send]").click();
});

Then("the embedded transcript shows {string}", async ({ page }, text: string) => {
    // The optimistic echo lands the instant the turn starts — end-to-end proof that
    // the embedded composer drives the remote Session's send.
    await expect(page.locator("[data-embed-transcript]")).toContainText(text, { timeout: 15_000 });
});

Then("the embedded chat is themed by the workbench palette", async ({ page }) => {
    // The :host theme bridge defines the workbench palette inside the shadow root
    // (styles.css's :root block is inert there) — the default --gw-bg (#0f1115).
    await expect(page.locator("gw-chat")).toHaveCSS("background-color", "rgb(15, 17, 21)");
});

Then("a {string} override cascades into the panel's shadow root", async ({ page }, token: string) => {
    await page.locator("gw-session").evaluate((el, name) => {
        (el as HTMLElement).style.setProperty(name, "rgb(20, 0, 40)");
    }, token);
    // A consultant-set --gw-* token on the ancestor cascades across the shadow
    // boundary into the panel host (custom properties inherit through shadow DOM).
    await expect(page.locator("gw-chat")).toHaveCSS("background-color", "rgb(20, 0, 40)");
});
