/**
 * Steps for the chat log's reading position (`transcript-scroll.ts`): the send
 * anchor, the room reserved under a short conversation, and the jump-to-latest
 * button. The scroll machinery is DOM-bound, so this browser harness is where
 * it is exercised — the decisions themselves are pure functions under vitest.
 */
import { expect, type Page } from "@playwright/test";
import { createBdd } from "playwright-bdd";

const { When, Then } = createBdd();

const transcript = (page: Page) => page.locator(".run .transcript");

const metrics = (page: Page) =>
    transcript(page).evaluate((el) => ({
        scrollTop: el.scrollTop,
        scrollHeight: el.scrollHeight,
        clientHeight: el.clientHeight,
    }));

Then("my sent message is anchored near the top of the chat log", async ({ page }) => {
    // The anchor is a smooth glide and the settle can briefly detach the line
    // being measured, so poll one null-safe predicate: the last user line's
    // top rests just under the log's top edge (the anchor gap plus line
    // spacing), and never above it.
    await expect
        .poll(async () => {
            const log = await transcript(page).boundingBox();
            const sent = await transcript(page).locator(".line.user").last().boundingBox();
            if (!log || !sent) return "detached";
            const offset = sent.y - log.y;
            return offset >= -1 && offset <= 48 ? "anchored" : `off by ${Math.round(offset)}px`;
        })
        .toBe("anchored");
});

Then("blank room is reserved under the conversation", async ({ page }) => {
    // The spacer holds exactly the room the anchor needed; a short
    // conversation therefore ends in reserved blank space.
    const spacer = transcript(page).locator(".transcript-spacer");
    expect(await spacer.evaluate((el) => el.getBoundingClientRect().height)).toBeGreaterThan(0);
});

When("I wheel the chat log to the top", async ({ page }) => {
    await transcript(page).hover();
    await page.mouse.wheel(0, -100_000);
    await expect.poll(async () => (await metrics(page)).scrollTop).toBe(0);
});

Then("a jump-to-latest button is offered", async ({ page }) => {
    await expect(page.locator("[data-jump-latest]")).toBeVisible();
});

Then("no jump-to-latest button is offered", async ({ page }) => {
    await expect(page.locator("[data-jump-latest]")).toHaveCount(0);
});

When("I jump to the latest", async ({ page }) => {
    await page.locator("[data-jump-latest]").click();
});

Then("the chat log rests at its end", async ({ page }) => {
    await expect
        .poll(async () => {
            const m = await metrics(page);
            return m.scrollHeight - m.clientHeight - m.scrollTop;
        })
        .toBeLessThanOrEqual(24);
});
