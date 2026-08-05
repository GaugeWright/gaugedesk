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

Given("a delayed embedded chat is open", async ({ page }) => {
    await page.goto("/embed-example.html?fixture=1&panels=chat&delay=1200");
    await expect(page.locator("[data-embed-composer]")).toBeVisible({ timeout: 15_000 });
});

Given("an anonymous embedded chat is open", async ({ page }) => {
    await page.goto("/embed-example.html?fixture=1&panels=chat&audience=anonymous");
    await expect(page.locator("[data-embed-composer]")).toBeVisible({ timeout: 15_000 });
});

Given("a block embedded chat sized by the panel min-height token is open", async ({ page }) => {
    await page.goto("/embed-example.html?fixture=1&panels=chat");
    await page.locator("gw-session").evaluate((element) => {
        element.style.display = "block";
    });
    await page.locator("gw-chat").evaluate((element) => {
        element.style.display = "block";
        element.style.height = "auto";
        element.style.setProperty("--gw-panel-min-height", "420px");
    });
    await expect(page.locator("[data-embed-composer]")).toBeVisible({ timeout: 15_000 });
});

Given("all embedded panels are open under broad hostile host styles", async ({ page }) => {
    await page.goto("/embed-example.html?fixture=1&panels=chat,viewer,files,chats");
    await page.locator("gw-session").evaluate((session) => {
        session.style.display = "block";
        const style = document.createElement("style");
        style.dataset.hostilePanelStyles = "";
        style.textContent = `
            gw-chat, gw-viewer, gw-files, gw-chats {
                display: inline !important;
                box-sizing: content-box !important;
                width: 24px !important;
                max-width: none !important;
                height: 4px !important;
                min-height: 0 !important;
                margin: 70px !important;
                padding: 64px !important;
                border: 32px solid magenta !important;
                overflow: hidden !important;
                background: lime !important;
                color: red !important;
                font: 40px serif !important;
            }
            gw-chat::part(panel) { box-shadow: none; }
        `;
        document.head.appendChild(style);
    });
    await expect(page.locator("gw-chat [data-chat-composer]")).toBeVisible();
    await expect(page.locator("gw-viewer [data-viewer-tabs]")).toBeVisible();
    await expect(page.locator("gw-files .status")).toBeVisible();
    await expect(page.locator("gw-chats [data-audience-chats]")).toBeVisible();
});

Then("the embedded chat shows a composer", async ({ page }) => {
    await expect(page.locator("[data-embed-send]")).toBeVisible();
});

Then("the embedded chat shows its configured opening message", async ({ page }) => {
    await expect(page.locator("[data-embed-transcript]")).toContainText(
        "Welcome to the embedded assistant.",
    );
});

Then("the embedded chat shows its configured agent name", async ({ page }) => {
    await expect(page.locator("[data-embed-transcript] .turn-label").first()).toHaveText(
        "Example Assistant",
    );
});

Then("the embedded chat still shows its configured opening message", async ({ page }) => {
    await expect(page.locator("[data-embed-transcript]")).toContainText(
        "Welcome to the embedded assistant.",
    );
});

Then("the embedded chat shows a new session action", async ({ page }) => {
    await expect(page.locator("[data-new-embed-session]")).toHaveText("New session");
});

When("I start a new embedded session", async ({ page }) => {
    await page.locator("[data-new-embed-session]").click();
});

Then("the embedded chat requests a fresh session", async ({ page }) => {
    await expect(page.locator("body")).toHaveAttribute("data-fixture-new-session", "started");
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
    const attribution = page.locator("[data-embed-powered-by]");
    await expect(attribution).toHaveCount(1);
    await expect(attribution).toHaveText("Powered by GaugeWright");
    await expect(attribution).toHaveAttribute("href", "https://gaugewright.com");
});

Then("the unselected files and viewer panels are not composed", async ({ page }) => {
    await expect(page.locator("gw-files")).toHaveCount(0);
    await expect(page.locator("gw-viewer")).toHaveCount(0);
});

When("I send {string} in the embedded chat", async ({ page }, msg: string) => {
    await page.locator("[data-embed-composer]").fill(msg);
    await page.locator("[data-embed-send]").click();
});

When("I send a Markdown message in the embedded chat", async ({ page }) => {
    await page.locator("[data-embed-composer]").fill([
        "**Important**: read the [documentation](https://example.com/docs).",
        "",
        "| Item | Status |",
        "| --- | --- |",
        "| Markdown | working |",
    ].join("\n"));
    await page.locator("[data-embed-send]").click();
});

const TINY_PASTED_PNG =
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+M8AAAMBAQDJ/pLvAAAAAElFTkSuQmCC";

When("I paste a PNG image into the embedded chat", async ({ page }) => {
    await page.locator("[data-embed-composer]").evaluate((composer, base64) => {
        const bytes = Uint8Array.from(atob(base64), (character) => character.charCodeAt(0));
        const transfer = new DataTransfer();
        transfer.items.add(new File([bytes], "pasted-image.png", { type: "image/png" }));
        composer.dispatchEvent(new ClipboardEvent("paste", {
            bubbles: true,
            cancelable: true,
            clipboardData: transfer,
        }));
    }, TINY_PASTED_PNG);
});

Then("the embedded composer shows the pasted image", async ({ page }) => {
    const attachment = page.locator('[data-attachment][data-kind="image"]');
    await expect(attachment).toContainText("pasted-image.png");
    await expect(attachment.locator("img")).toHaveAttribute(
        "src",
        `data:image/png;base64,${TINY_PASTED_PNG}`,
    );
});

When("I send the pasted image in the embedded chat", async ({ page }) => {
    await page.locator("[data-embed-send]").click();
});

Then("the embedded turn carries the pasted image bytes", async ({ page }) => {
    await expect.poll(async () => page.locator("body").getAttribute("data-fixture-turn"))
        .not.toBeNull();
    const turn = JSON.parse(
        (await page.locator("body").getAttribute("data-fixture-turn"))!,
    ) as {
        prompt: string;
        images: { name: string; mimeType: string; data: string }[];
    };
    expect(turn.prompt).toContain("[attached image: pasted-image.png]");
    expect(turn.images).toEqual([{
        name: "pasted-image.png",
        mimeType: "image/png",
        data: TINY_PASTED_PNG,
    }]);
    await expect(page.locator("[data-attachment]")).toHaveCount(0);
});

When("I attach a text file with the embedded paperclip", async ({ page }) => {
    await page.locator("[data-attach-input]").setInputFiles({
        name: "brief.txt",
        mimeType: "text/plain",
        buffer: Buffer.from("The embedded paperclip works."),
    });
});

Then("the embedded composer shows the attached text file", async ({ page }) => {
    await expect(page.locator('[data-attachment][data-kind="text"]')).toContainText("brief.txt");
});

When("I send the attached text file in the embedded chat", async ({ page }) => {
    await page.locator("[data-embed-send]").click();
});

Then("the embedded turn carries the attached text", async ({ page }) => {
    await expect.poll(async () => page.locator("body").getAttribute("data-fixture-turn"))
        .not.toBeNull();
    const turn = JSON.parse(
        (await page.locator("body").getAttribute("data-fixture-turn"))!,
    ) as { prompt: string };
    expect(turn.prompt).toContain("--- attached: brief.txt ---");
    expect(turn.prompt).toContain("The embedded paperclip works.");
});

Then("the embedded composer offers steer, queue, and stop", async ({ page }) => {
    await expect(page.getByTestId("steer-turn")).toBeVisible();
    await expect(page.getByTestId("queue-msg")).toBeVisible();
    await expect(page.getByTestId("stop-turn")).toBeVisible();
});

When("I queue {string} in the embedded chat", async ({ page }, message: string) => {
    await page.locator("[data-embed-composer]").fill(message);
    await page.getByTestId("queue-msg").click();
});

Then("the embedded queue shows {string}", async ({ page }, message: string) => {
    await expect(page.getByTestId("queue-item")).toContainText(message);
});

When("I steer the embedded chat with {string}", async ({ page }, message: string) => {
    await page.locator("[data-embed-composer]").fill(message);
    await page.getByTestId("steer-turn").click();
});

Then("the embedded turn is not interrupted", async ({ page }) => {
    await expect(page.locator("body")).not.toHaveAttribute("data-fixture-stopped", "true");
});

async function fixtureTurnPrompts(page: import("@playwright/test").Page): Promise<string[]> {
    const raw = await page.locator("body").getAttribute("data-fixture-turns");
    if (!raw) return [];
    return (JSON.parse(raw) as { prompt: string }[]).map((turn) => turn.prompt);
}

Then("the embedded runtime admits commands in the order {string}", async ({ page }, order: string) => {
    const expected = order.split(",");
    await expect.poll(async () => {
        const raw = await page.locator("body").getAttribute("data-fixture-commands");
        if (!raw) return [];
        return (JSON.parse(raw) as { kind: string; text: string }[])
            .map(({ kind, text }) => `${kind}:${text}`);
    }).toEqual(expected);
});

Then("the commands join the current turn rather than starting another", async ({ page }) => {
    await expect.poll(() => fixtureTurnPrompts(page)).toEqual(["first request"]);
});

Then("the embedded durable queue eventually drains", async ({ page }) => {
    await expect(page.getByTestId("queue-stack")).toHaveCount(0, { timeout: 15_000 });
});

Then("the embedded transcript renders its formatting without page overflow", async ({ page }) => {
    const message = page.locator("[data-embed-transcript] .line.user .message-markdown");
    await expect(message.locator("strong")).toHaveText("Important");
    await expect(message.locator("table")).toContainText("Markdown");
    const link = message.locator('a[href="https://example.com/docs"]');
    await expect(link).toHaveText("documentation");
    await expect(link).toHaveAttribute("target", "_blank");
    await expect(link).toHaveAttribute("rel", "noopener noreferrer");
    expect(await page.evaluate(() =>
        document.documentElement.scrollWidth - document.documentElement.clientWidth,
    )).toBe(0);
});

Then("the embedded transcript shows {string}", async ({ page }, text: string) => {
    // The optimistic echo lands the instant the turn starts — end-to-end proof that
    // the embedded composer drives the remote Session's send.
    await expect(page.locator("[data-embed-transcript]")).toContainText(text, { timeout: 15_000 });
});

Then("the embedded chat is themed by the workbench palette", async ({ page }) => {
    // The :host theme bridge defines the workbench palette inside the shadow root
    // (styles.css's :root block is inert there) — the default --gw-bg (#0f1115).
    await expect(page.locator('gw-chat [part~="panel"]')).toHaveCSS("background-color", "rgb(15, 17, 21)");
});

Then("a {string} override cascades into the panel's shadow root", async ({ page }, token: string) => {
    await page.locator("gw-session").evaluate((el, name) => {
        (el as HTMLElement).style.setProperty(name, "rgb(20, 0, 40)");
    }, token);
    // A consultant-set --gw-* token on the ancestor cascades across the shadow
    // boundary into the panel host (custom properties inherit through shadow DOM).
    await expect(page.locator('gw-chat [part~="panel"]')).toHaveCSS("background-color", "rgb(20, 0, 40)");
});

Then("every embedded panel keeps its structural defaults", async ({ page }) => {
    const expectations = new Map([
        ["gw-chat", 520],
        ["gw-viewer", 320],
        ["gw-files", 280],
        ["gw-chats", 280],
    ]);
    for (const [tag, minimum] of expectations) {
        const metrics = await page.locator(tag).evaluate((element) => {
            const style = getComputedStyle(element);
            const rect = element.getBoundingClientRect();
            return {
                display: style.display,
                boxSizing: style.boxSizing,
                width: rect.width,
                height: rect.height,
                margin: style.margin,
                padding: style.padding,
                borderWidth: style.borderTopWidth,
                background: style.backgroundColor,
                fontSize: style.fontSize,
            };
        });
        expect(metrics.display).toBe("block");
        expect(metrics.boxSizing).toBe("border-box");
        expect(metrics.width).toBeGreaterThan(500);
        expect(metrics.height).toBeGreaterThanOrEqual(minimum);
        expect(metrics.margin).toBe("0px");
        expect(metrics.padding).toBe("0px");
        expect(metrics.borderWidth).toBe("0px");
        expect(metrics.background).toBe("rgba(0, 0, 0, 0)");
        expect(metrics.fontSize).toBe("13px");
    }
});

Then("every embedded panel exposes intentional styling hooks", async ({ page }) => {
    await page.locator("gw-session").evaluate((session) => {
        session.style.setProperty("--gw-bg", "rgb(20, 0, 40)");
        session.style.setProperty("--gw-panel-padding", "20px");
        session.style.setProperty("--gw-panel-radius", "24px");
        session.style.setProperty("--gw-panel-border", "3px solid rgb(1, 2, 3)");
        session.style.setProperty("--gw-font-size-body", "17px");
    });
    for (const tag of ["gw-chat", "gw-viewer", "gw-files", "gw-chats"]) {
        const panel = page.locator(`${tag} [part~="panel"]`);
        await expect(panel).toHaveCSS("background-color", "rgb(20, 0, 40)");
        await expect(panel).toHaveCSS("padding-top", "20px");
        await expect(panel).toHaveCSS("border-radius", "24px");
        await expect(panel).toHaveCSS("border-top-width", "3px");
        await expect(page.locator(tag)).toHaveCSS("font-size", "17px");
    }
    await expect(page.locator('gw-chat [part~="panel"]')).toHaveCSS("box-shadow", "none");
    await expect(page.locator('gw-chat [part~="attribution"]')).toHaveCount(1);
});

When("the embedded panel host is mobile width", async ({ page }) => {
    await page.setViewportSize({ width: 390, height: 844 });
});

Then("every embedded panel fits without horizontal overflow", async ({ page }) => {
    const viewport = page.viewportSize()!;
    for (const tag of ["gw-chat", "gw-viewer", "gw-files", "gw-chats"]) {
        const metrics = await page.locator(tag).evaluate((element) => {
            const rect = element.getBoundingClientRect();
            const panel = element.shadowRoot!.querySelector<HTMLElement>("[part~=panel]")!;
            return {
                left: rect.left,
                right: rect.right,
                hostScrollWidth: element.scrollWidth,
                hostClientWidth: element.clientWidth,
                panelScrollWidth: panel.scrollWidth,
                panelClientWidth: panel.clientWidth,
            };
        });
        expect(metrics.left).toBeGreaterThanOrEqual(0);
        expect(metrics.right).toBeLessThanOrEqual(viewport.width);
        expect(metrics.hostScrollWidth).toBeLessThanOrEqual(metrics.hostClientWidth);
        expect(metrics.panelScrollWidth).toBeLessThanOrEqual(metrics.panelClientWidth);
    }
});
