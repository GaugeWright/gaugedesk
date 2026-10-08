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

When(
    "I send {string} and wheel the chat log to the top as it glides",
    async ({ page }, text: string) => {
        const composer = page.locator('[data-desktop-composer] textarea[aria-label="Message"]');
        await composer.fill(text);
        await transcript(page).hover();
        const from = (await metrics(page)).scrollTop;
        await composer.press("Enter");
        // The send anchors its message with a glide. Wheel in the glide's first
        // frame of movement, so the gesture lands while the glide is running.
        await transcript(page).evaluate(
            (el, start) =>
                new Promise<void>((resolve, reject) => {
                    const deadline = performance.now() + 10_000;
                    const watch = () => {
                        if (el.scrollTop !== start) resolve();
                        else if (performance.now() > deadline) reject(new Error("the send never glided"));
                        else requestAnimationFrame(watch);
                    };
                    watch();
                }),
            from,
        );
        await page.mouse.wheel(0, -100_000);
    },
);

Then("the chat log stays at the top", async ({ page }) => {
    await expect.poll(async () => (await metrics(page)).scrollTop).toBe(0);
    // And it stays there past the glide's window while the turn settles: once
    // the reader has moved, nothing the panel does may move the log back.
    const seen = await transcript(page).evaluate(
        (el) =>
            new Promise<number[]>((resolve) => {
                const samples: number[] = [];
                const until = performance.now() + 1_500;
                const sample = () => {
                    samples.push(el.scrollTop);
                    if (performance.now() < until) requestAnimationFrame(sample);
                    else resolve(samples);
                };
                sample();
            }),
    );
    expect(Math.max(...seen)).toBe(0);
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

Then("the user-message rail has {int} marks", async ({ page }, count: number) => {
    await expect(page.locator("[data-chat-message-mark]")).toHaveCount(count);
});

Then("every user-message mark rests at the same width", async ({ page }) => {
    await page.mouse.move(0, 0);
    await expect.poll(async () => {
        const widths = await page.locator("[data-chat-message-mark] span").evaluateAll((bars) =>
            bars.map((bar) => bar.getBoundingClientRect().width),
        );
        return new Set(widths).size;
    }).toBe(1);
});

When("I hover the first user-message mark", async ({ page }) => {
    await page.locator("[data-chat-message-mark='0']").hover();
});

Then("the message preview shows {string}", async ({ page }, text: string) => {
    await expect(page.locator("[data-chat-message-preview]")).toContainText(text);
});

Then("the hovered mark is wider than its neighbor", async ({ page }) => {
    await expect.poll(async () => {
        const widths = await page.locator("[data-chat-message-mark]").evaluateAll((marks) =>
            marks.slice(0, 2).map((mark) => mark.querySelector("span")?.getBoundingClientRect().width ?? 0),
        );
        return widths[0] > widths[1];
    }).toBe(true);
});

When("I jump to the first user message", async ({ page }) => {
    await page.locator("[data-chat-message-mark='0']").click();
});

Then("the first user message is near the top of the chat log", async ({ page }) => {
    await expect.poll(async () => {
        const log = await transcript(page).boundingBox();
        const message = await transcript(page).locator(".line.user").first().boundingBox();
        if (!log || !message) return "detached";
        const offset = message.y - log.y;
        return offset >= -1 && offset <= 48 ? "placed" : `off by ${Math.round(offset)}px`;
    }).toBe("placed");
});

Then("the first user-message mark shows the reading position", async ({ page }) => {
    await expect(page.locator("[data-chat-message-mark='0']")).toHaveAttribute("aria-current", "location");
});
