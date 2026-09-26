import { expect, test, type Page } from "@playwright/test";

// QA inventory: actual submit/review/intake controls; one-time credential
// visibility and dismissal; page/scope/authorization/disabled/read-denied
// transitions; same-context refresh; A → B → A; competing busy states; stale
// passkey follow-up plus Chromium WebAuthn creation; reviewed account erasure
// with server blockers, exact confirmation, fresh passkey authorization,
// exact retry coordinates, and terminal eviction; embedded payment
// initialization and cleanup; and the ordered corporate sign-in test,
// admission, owner-link, and enforcement lifecycle. Authority replies and
// provider/Stripe ceremonies are isolated fixtures, but the browser-authenticator
// act is not mocked. Visual states include focused nested editors, balanced
// narrow-pane action groups, and visibly inactive disabled controls.
const go = async (page: Page, app = "administration") => {
    await page.goto(`/?app=${app}`);
    await expect(page.getByRole("heading", { level: 1 })).toBeVisible();
};
const click = (page: Page, name: string) => page.getByRole("button", { name, exact: true }).click();
const calls = async (page: Page) => JSON.parse(await page.getByTestId("calls").textContent() ?? "[]") as Record<string, unknown>[];
const noTransient = async (page: Page) => {
    await expect(page.locator(".gaugeapp-one-time")).toHaveCount(0);
    await expect(page.locator(".gaugeapp-status")).toHaveCount(0);
};
const retainedDeviceCredentials = (page: Page) => page.evaluate(async () => {
    const database = await new Promise<IDBDatabase>((resolve, reject) => {
        const request = indexedDB.open("gaugedesk-device-credentials", 1);
        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(request.error);
    });
    try {
        return await new Promise<Array<{ key: string; ecdhExtractable: boolean; accountExtractable: boolean | null }>>((resolve, reject) => {
            const request = database.transaction("credentials", "readonly").objectStore("credentials").getAll();
            request.onsuccess = () => resolve((request.result as Array<{ id: string; ecdhPrivate: CryptoKey; accountKey?: CryptoKey }>).map((record) => ({
                key: record.id,
                ecdhExtractable: record.ecdhPrivate.extractable,
                accountExtractable: record.accountKey?.extractable ?? null,
            })));
            request.onerror = () => reject(request.error);
        });
    } finally {
        database.close();
    }
});

const everyGaugeAppPage = [
    { app: "account-settings", query: "all-pages=1", pages: ["Account Settings", "Provider Connections", "Trusted Devices", "Application Settings"] },
    { app: "administration", query: "all-pages=1", pages: ["Organization", "Plans & services", "People", "Sessions", "Enterprise Identity", "Projects", "Model Providers", "Organization Policy", "Project Hosts", "Backups", "Software policy", "Billing"] },
    { app: "commercial-operations", query: "commercial-lifecycle=draft", pages: ["Products", "Clients", "Engagements", "Payments"] },
] as const;

test("disabled GaugeApp actions are visibly inactive", async ({ page }) => {
    await page.goto("/?app=administration&all-pages=1&shell=1");
    await click(page, "Software policy");
    const apply = page.getByRole("button", { name: "Apply changes", exact: true });
    await expect(apply).toBeDisabled();
    const style = await apply.evaluate((element) => {
        const computed = getComputedStyle(element);
        return { opacity: Number(computed.opacity), cursor: computed.cursor };
    });
    expect(style.opacity).toBeLessThanOrEqual(0.5);
    expect(style.cursor).toBe("default");
});

test("a claimed domain keeps its published record and only a pending one offers verification", async ({ page }) => {
    await page.goto("/?app=administration&all-pages=1&actionable-pages=1&domains=pending");
    const pending = page.locator('.gaugeapp-domain-row[data-status="pending"]');
    const verified = page.locator('.gaugeapp-domain-row[data-status="verified"]');
    await expect(pending).toContainText("pending.example");
    await expect(pending).toContainText("awaiting DNS proof");
    await expect(verified).toContainText("verified.example");

    // The claim is server-held, so the record to publish is on the row itself.
    // Before this it lived in component state behind the add dialog, and a
    // reload lost both the claim and any way to see what was outstanding.
    await expect(pending.locator("code")).toHaveText([
        "_gaugewright-challenge.pending.example",
        "TXT",
        "gaugewright-domain-verification=fixture-challenge-token",
    ]);
    await page.reload();
    await expect(pending.locator("code").first()).toHaveText("_gaugewright-challenge.pending.example");

    // Verification promotes a standing claim, so it is offered on the pending
    // row and nowhere else; a verified domain has nothing left to prove.
    await expect(pending.getByRole("button", { name: "Verify DNS", exact: true })).toBeVisible();
    await expect(verified.getByRole("button", { name: "Verify DNS", exact: true })).toHaveCount(0);
    await expect(verified.getByRole("button", { name: "Remove", exact: true })).toBeVisible();

    await click(page, "Add domain");
    await page.getByLabel("Domain to add").fill("  Third.Example  ");
    await click(page, "Add domain");
    expect(await calls(page)).toContainEqual(
        expect.objectContaining({ command: "organization.domain.add", payload: { domain: "Third.Example" } }),
    );
});

test("Organization Policy presents its open Project Host operator set truthfully", async ({ page }) => {
    await page.goto("/?app=administration&all-pages=1");
    await page.getByRole("button", { name: "Organization Policy", exact: true }).click();

    const operators = page.getByRole("group", { name: "Eligible Project Host operators" });
    await expect(operators.getByRole("checkbox", { name: "Run owner", exact: true })).toBeChecked();
    await expect(operators.getByRole("checkbox", { name: "Counterparty", exact: true })).toBeChecked();
    await expect(operators.getByRole("checkbox", { name: "Neutral provider", exact: true })).toBeChecked();

    await operators.getByRole("checkbox", { name: "Counterparty", exact: true }).uncheck();
    const summary = page.locator(".gaugeapp-change-summary");
    await expect(summary).toContainText("Eligible Project Hosts: all → local, neutral");
    await summary.getByRole("button", { name: "Discard", exact: true }).click();
    await expect(summary).toContainText("No unsaved changes.");
    await expect(operators.getByRole("checkbox", { name: "Counterparty", exact: true })).toBeChecked();
});

test("signed-out GaugeDesk starts account entry without reopening legacy Settings", async ({ page }) => {
    await page.goto("/?account-menu=signed-out");
    await page.getByRole("button", { name: "Sign in", exact: true }).click();
    await page.getByRole("menu").getByText("Sign in", { exact: true }).click();
    await expect(page.getByLabel("Account entry result")).toHaveText("Account sign-in requested");
    await expect(page.getByRole("heading", { name: "Settings", exact: true })).toHaveCount(0);
    await expect(page.getByRole("button", { name: "Account", exact: true })).toHaveCount(0);
    await expect(page.getByRole("button", { name: "Model access", exact: true })).toHaveCount(0);
});

test("signed-out GaugeDesk keeps a failed account ceremony actionable", async ({ page }) => {
    await page.goto("/?account-menu=signed-out-failure");
    await page.getByRole("button", { name: "Sign in", exact: true }).click();
    await page.getByRole("menu").getByText("Sign in", { exact: true }).click();
    await expect(page.getByRole("alert")).toHaveText("Account service unavailable. Try again.");
    await expect(page.getByRole("menu")).toBeVisible();
    await expect(page.getByRole("menuitem", { name: "Sign in", exact: true })).toBeEnabled();
    await expect(page.getByRole("heading", { name: "Settings", exact: true })).toHaveCount(0);
});

test("GaugeDesk keeps a failed sign-out actionable only for its current menu opening", async ({ page }) => {
    await page.goto("/?account-menu=signed-in-failure");
    await page.locator("[data-account-menu-trigger]").click();
    await page.getByRole("menuitem", { name: "Sign out", exact: true }).click();
    await expect(page.getByRole("alert")).toHaveText("Sign out could not be completed. Try again.");
    await expect(page.getByRole("menuitem", { name: "Sign out", exact: true })).toBeEnabled();

    await page.locator(".popover-catcher").click({ position: { x: 2, y: 2 } });
    await expect(page.getByRole("menu")).toHaveCount(0);
    await page.locator("[data-account-menu-trigger]").click();
    await expect(page.getByRole("alert")).toHaveCount(0);
    await expect(page.getByRole("menuitem", { name: "Sign out", exact: true })).toBeEnabled();
});

test("account choices stay behind Change account in the account menu", async ({ page }) => {
    await page.goto("/?account-menu=signed-in-choices");
    await page.locator("[data-account-menu-trigger]").click();
    await expect(page.getByRole("menuitem", { name: "grace@example.test" })).toHaveCount(0);
    await page.getByRole("menuitem", { name: "Change account" }).click();
    await expect(page.getByRole("menuitem", { name: /ada@example.test/ })).toBeDisabled();
    await expect(page.getByRole("menuitem", { name: /old@example.test/ })).toBeDisabled();
    await page.getByRole("menuitem", { name: "grace@example.test" }).click();
    await expect(page.getByLabel("Account entry result")).toHaveText("Selected grace");
    await page.getByRole("menuitem", { name: "‹ Account menu" }).click();
    await expect(page.getByRole("menuitem", { name: "grace@example.test" })).toHaveCount(0);
    await page.getByRole("menuitem", { name: "Change account" }).click();
    await page.getByRole("menuitem", { name: "Add account" }).click();
    await expect(page.getByLabel("Account entry result")).toHaveText("Add account requested");
    await expect(page.getByRole("menu")).toHaveCount(0);
});

test("the account menu shows the account's photo in place of its initials", async ({ page }, info) => {
    await page.goto("/?account-menu=signed-in-photo");
    const trigger = page.locator("[data-account-menu-trigger]");
    const photo = trigger.locator("img[data-account-avatar]");
    await expect(photo).toBeVisible();
    await expect(photo).toHaveAttribute("src", /^data:image\/jpeg;base64,/);
    await expect(trigger.getByText("AL", { exact: true })).toHaveCount(0);
    // The photo occupies exactly the circle the initials would, so the row
    // cannot shift when an avatar arrives.
    const box = await photo.boundingBox();
    expect(box?.width).toBe(22);
    expect(box?.height).toBe(22);
    await page.screenshot({ path: info.outputPath("account-menu-photo.png"), scale: "css" });
});

test("a person uploads, sees, and removes their account photo", async ({ page }, info) => {
    await go(page, "account-settings");
    const editor = page.locator("[data-account-avatar-editor]");
    await expect(editor.getByRole("img", { name: "Your photo" })).toHaveCount(0);
    await expect(editor.locator(".gaugeapp-avatar-initials")).toHaveText("PA");
    await expect(editor.getByRole("button", { name: "Remove photo", exact: true })).toHaveCount(0);

    await editor.locator('input[type="file"]').setInputFiles({
        name: "portrait.png",
        mimeType: "image/png",
        buffer: Buffer.from("iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAIAAACQkWg2AAAB3klEQVR4nA3LIc6GIACA4f843wE8gAfwAI7oSCZmdCQTIzISiRmZyb3BERnJxMwe5vfpz99P0Al6wSAYBVKgBFpgBF4QBYfgElRBE7yCv99EN9FPDBPjhJxQE3rCTPiJOHFMXBN1ok280xdmupl+ZpgZZ+SMmtEzZsbPxJlj5pqpM23mnb+w0C30C8PCuCAX1IJeMAt+IS4cC9dCXWgL7/KFlW6lXxlWxhW5olb0ilnxK3HlWLlW6kpbedcvbHQb/cawMW7IDbWhN8yG34gbx8a1UTfaxrt9wdJZestgGS3SoizaYizeEi2H5bJUS7O89guOztE7BsfokA7l0A7j8I7oOByXozqa43VfCHSBPjAExoAMqIAOmIAPxMARuAI10AJv+MJOt9PvDDvjjtxRO3rH7PiduHPsXDt1p+28+xcSXaJPDIkxIRMqoRMm4RMxcSSuRE20xJu+cNKd9CfDyXgiT9SJPjEn/iSeHCfXST1pJ+/5hUyX6TNDZszIjMrojMn4TMwcmStTMy3z5i8UukJfGApjQRZUQRdMwRdi4ShchVpohbd84aa76W+Gm/FG3qgbfWNu/E28OW6um3rTbt77Cw/dQ/8wPIwP8kE96Afz4B/iw/FwPdSH9vA+/APRNMwQA4k0/gAAAABJRU5ErkJggg==", "base64"),
    });
    await expect(editor.getByRole("img", { name: "Your photo" })).toBeVisible();
    const submitted = (await calls(page)).find((call) => call.command === "account.avatar.set");
    // The browser sends a shrunk image, never the file as chosen.
    expect((submitted?.payload as { image?: string } | undefined)?.image).toMatch(/^data:image\/png;base64,/);
    await page.screenshot({ path: info.outputPath("account-settings-photo.png"), scale: "css" });

    await editor.locator('input[type="file"]').setInputFiles({ name: "notes.pdf", mimeType: "application/pdf", buffer: Buffer.from("%PDF-1.7") });
    await expect(page.locator(".gaugeapp-inline-notice").filter({ hasText: "Choose a PNG, JPEG, WebP or GIF image." })).toBeVisible();
    expect((await calls(page)).filter((call) => call.command === "account.avatar.set")).toHaveLength(1);

    await click(page, "Remove photo");
    await expect(editor.getByRole("img", { name: "Your photo" })).toHaveCount(0);
    await expect(editor.locator(".gaugeapp-avatar-initials")).toHaveText("PA");
});

test("signed-out Desk completes provider-neutral account recovery without retaining proofs", async ({ page }, info) => {
    await page.goto("/?account-entry=recovery");
    await click(page, "Use a recovery code");
    await page.getByLabel("Verified email").fill("person@example.test");
    await click(page, "Send code");
    await expect(page.getByText("Enter the code from your email and one unused recovery code.", { exact: false })).toBeVisible();
    await page.getByLabel("Email code").fill("123456");
    await page.getByLabel("Recovery code").fill("GW-RECOVERY-CODE");
    await page.screenshot({ path: info.outputPath("account-recovery.png"), scale: "css" });
    await click(page, "Recover account");
    await expect(page.getByLabel("Recovery result")).toHaveText("Account recovered");
    await expect(page.locator("[data-account-recovery]")).toHaveCount(0);
    await expect(page.locator("body")).not.toContainText("GW-RECOVERY-CODE");
});

test("a rejected recovery proof is cleared and requires a fresh email challenge", async ({ page }) => {
    await page.goto("/?account-entry=recovery");
    await click(page, "Use a recovery code");
    await page.getByLabel("Verified email").fill("person@example.test");
    await click(page, "Send code");
    await page.getByLabel("Email code").fill("654321");
    await page.getByLabel("Recovery code").fill("FAIL");
    await click(page, "Recover account");
    await expect(page.getByText("Those recovery proofs were not accepted. Start again with a new email code.", { exact: true })).toBeVisible();
    await expect(page.getByLabel("Verified email")).toHaveValue("person@example.test");
    await expect(page.getByLabel("Email code")).toHaveCount(0);
    await expect(page.getByLabel("Recovery code")).toHaveCount(0);
    await expect(page.locator("body")).not.toContainText("654321");
    await expect(page.locator("body")).not.toContainText("FAIL");
});

test("account recovery remains legible and contained in the narrow Desk entry", async ({ page }, info) => {
    await page.setViewportSize({ width: 390, height: 844 });
    await page.goto("/?account-entry=recovery");
    await click(page, "Use a recovery code");
    await page.getByLabel("Verified email").fill("person@example.test");
    await click(page, "Send code");
    await page.getByLabel("Email code").fill("123456");
    await page.getByLabel("Recovery code").fill("GW-RECOVERY-CODE");
    await expect(page.getByRole("button", { name: "Recover account", exact: true })).toBeVisible();
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth)).toBe(true);
    const frame = await page.locator("[data-account-entry]").boundingBox();
    expect(frame).not.toBeNull();
    expect(frame!.x).toBeGreaterThanOrEqual(0);
    expect(frame!.x + frame!.width).toBeLessThanOrEqual(390);
    await page.screenshot({ path: info.outputPath("account-recovery-narrow.png"), scale: "css" });
    await click(page, "Cancel recovery");
    await expect(page.locator("[data-account-recovery]")).toHaveCount(0);
    await expect(page.locator("body")).not.toContainText("GW-RECOVERY-CODE");
});

for (const fixture of everyGaugeAppPage) test(`${fixture.app} renders every admitted page in the production workspace`, async ({ page }) => {
    await page.goto(`/?app=${fixture.app}&${fixture.query}`);
    for (const name of fixture.pages) {
        await page.getByRole("button", { name, exact: true }).click();
        await expect(page.getByRole("heading", { name, exact: true, level: 1 })).toBeVisible();
        expect(await page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth)).toBe(true);
    }
});

for (const fixture of everyGaugeAppPage) test(`${fixture.app} never reduces an admitted page to inert documentation`, async ({ page }) => {
    await page.goto(`/?app=${fixture.app}&${fixture.query}&actionable-pages=1`);
    for (const name of fixture.pages) {
        await page.getByRole("button", { name, exact: true }).click();
        const article = page.getByRole("article");
        const usableControls = article.locator("button:not(:disabled), input:not(:disabled), select:not(:disabled), textarea:not(:disabled)");
        const explainedState = article.locator(".gaugeapp-empty, .gaugeapp-unavailable, [role='alert']");
        expect(
            await usableControls.count() > 0 || await explainedState.count() > 0,
            `${fixture.app}/${name} has neither a usable control nor an explicit empty/unavailable state`,
        ).toBe(true);
    }
});

for (const fixture of everyGaugeAppPage) test(`${fixture.app} keeps every admitted page reachable in the narrow Workbench`, async ({ page }) => {
    await page.setViewportSize({ width: 390, height: 844 });
    await page.goto(`/?app=${fixture.app}&${fixture.query}&shell=1`);
    const panes = page.getByRole("tablist", { name: "panes" });
    for (const name of fixture.pages) {
        await panes.getByRole("tab", { name: "Menu", exact: true }).click();
        await page.getByRole("button", { name, exact: true }).click();
        await panes.getByRole("tab", { name: "Content", exact: true }).click();
        await expect(page.getByRole("heading", { name, exact: true, level: 1 })).toBeVisible();
        expect(await page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth)).toBe(true);
    }
});

test("stacked inline forms keep their actions proportional in a narrow content pane", async ({ page }, info) => {
    await page.setViewportSize({ width: 390, height: 844 });
    await page.goto("/?app=account-settings&shell=1");
    await page.getByRole("tablist", { name: "panes" }).getByRole("tab", { name: "Content", exact: true }).click();

    const form = page.locator(".gaugeapp-inline-form").filter({ has: page.getByLabel("Display name", { exact: true }) });
    const action = form.getByRole("button", { name: "Save", exact: true });
    const [formBox, actionBox] = await Promise.all([form.boundingBox(), action.boundingBox()]);
    expect(formBox).not.toBeNull();
    expect(actionBox).not.toBeNull();
    expect(actionBox!.width).toBeLessThan(formBox!.width / 2);
    expect(Math.abs((actionBox!.x + actionBox!.width) - (formBox!.x + formBox!.width - 8))).toBeLessThanOrEqual(1);
    await page.screenshot({ path: info.outputPath("narrow-proportional-form-action.png"), scale: "css" });
});

test("the native phone composition carries one server GaugeApp through page, conversation, and menu", async ({ page }, info) => {
    await page.setViewportSize({ width: 390, height: 844 });
    await page.goto("/?app=commercial-operations&commercial-lifecycle=accepted&mobile-surface=1");

    const views = page.getByRole("navigation", { name: "Management view" });
    await expect(page.locator("[data-mobile-gaugeapp]")).toBeVisible();
    await expect(page.getByRole("heading", { name: "Products", exact: true, level: 1 })).toBeVisible();

    await views.getByRole("button", { name: "Menu", exact: true }).click();
    await page.getByRole("button", { name: "Engagements", exact: true }).click();
    await views.getByRole("button", { name: "Page", exact: true }).click();
    await expect(page.getByRole("heading", { name: "Engagements", exact: true, level: 1 })).toBeVisible();

    await views.getByRole("button", { name: "Conversation", exact: true }).click();
    await expect(page.getByRole("textbox", { name: "Message", exact: true })).toBeVisible();
    await views.getByRole("button", { name: "Page", exact: true }).click();
    await expect(page.getByRole("heading", { name: "Engagements", exact: true, level: 1 })).toBeVisible();

    const overflow = await page.evaluate(() => ({
        document: document.documentElement.scrollWidth - document.documentElement.clientWidth,
        surface: (() => {
            const element = document.querySelector<HTMLElement>("[data-mobile-gaugeapp]");
            return element ? element.scrollWidth - element.clientWidth : -1;
        })(),
    }));
    expect(overflow.document).toBeLessThanOrEqual(1);
    expect(overflow.surface).toBeLessThanOrEqual(1);
    await page.screenshot({ path: info.outputPath("native-mobile-gaugeapp.png"), scale: "css" });

    await page.getByRole("button", { name: "Back", exact: true }).click();
    await expect.poll(async () => calls(page)).toContainEqual({ closeGaugeApp: "commercial-operations" });
});

for (const fixture of everyGaugeAppPage) test(`${fixture.app} exposes every admitted page in the native phone composition`, async ({ page }) => {
    await page.setViewportSize({ width: 320, height: 700 });
    await page.goto(`/?app=${fixture.app}&${fixture.query}&mobile-surface=1`);
    const views = page.getByRole("navigation", { name: "Management view" });

    for (const name of fixture.pages) {
        await views.getByRole("button", { name: "Menu", exact: true }).click();
        await page.getByRole("button", { name, exact: true }).click();
        await views.getByRole("button", { name: "Page", exact: true }).click();
        await expect(page.getByRole("article").getByRole("heading", { name, exact: true, level: 1 })).toBeVisible();
        expect(await page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth + 1)).toBe(true);
    }
});

for (const fixture of everyGaugeAppPage) test(`${fixture.app} keeps every admitted page usable while updates are delayed`, async ({ page }) => {
    await page.goto(`/?app=${fixture.app}&${fixture.query}&updates=down`);
    await expect(page.getByText("Updates are delayed. Showing the last loaded data.", { exact: false })).toBeVisible();
    for (const name of fixture.pages) {
        await page.getByRole("button", { name, exact: true }).click();
        await expect(page.getByRole("heading", { name, exact: true, level: 1 })).toBeVisible();
    }
    await click(page, "Restore updates");
    await expect(page.locator(".gaugeapp-update-delayed")).toHaveCount(0);
});

test("a current credential survives refresh, can be dismissed, and is cleared on reauthorization", async ({ page }, info) => {
    await go(page);
    await click(page, "Issue credential");
    await expect(page.getByRole("region", { name: "New SCIM credential" })).toContainText("SCIM-A");
    await click(page, "Refresh fixture");
    await expect(page.getByRole("region", { name: "New SCIM credential" })).toContainText("SCIM-A");
    await page.screenshot({ path: info.outputPath("current-credential.png"), scale: "css" });
    await click(page, "I saved it");
    await expect(page.locator(".gaugeapp-one-time")).toHaveCount(0);
    await click(page, "Issue credential");
    await click(page, "New authorization");
    await noTransient(page);
    await page.screenshot({ path: info.outputPath("cleared-credential.png"), scale: "css" });
});

test("an organization OIDC client secret is write-only, replaceable, and removable", async ({ page }) => {
    const secret = "synthetic-secret-for-lifecycle-proof";
    await page.goto("/?app=administration&identity=configured");
    await expect(page.getByRole("heading", { name: "Enterprise Identity", level: 1 })).toBeVisible();
    await click(page, "Add");
    const input = page.getByRole("textbox", { name: "OIDC client secret" });
    await expect(input).toHaveValue("");
    await expect(page.getByRole("button", { name: "Save secret" })).toBeDisabled();
    await input.fill(secret);
    await click(page, "Save secret");
    await expect(input).toHaveCount(0);
    await expect(page.getByText("Saved securely for this organization", { exact: true })).toBeVisible();
    await expect(page.getByRole("button", { name: "Replace", exact: true })).toBeVisible();

    const afterSet = await calls(page);
    expect(afterSet).toContainEqual({
        credential: "enterprise-identity.connection.credential.set",
        scope: "A",
        length: secret.length,
    });
    expect(JSON.stringify(afterSet)).not.toContain(secret);

    await click(page, "Replace");
    await expect(input).toHaveValue("");
    await click(page, "Cancel");
    await expect(input).toHaveCount(0);
    await click(page, "Replace");
    await click(page, "Remove");
    await expect(page.getByText("Not set — use this for a public PKCE client", { exact: true })).toBeVisible();
    await expect(page.getByRole("button", { name: "Add", exact: true })).toBeVisible();
    expect(await calls(page)).toContainEqual({
        credential: "enterprise-identity.connection.credential.remove",
        scope: "A",
        length: 0,
    });
});

test("enterprise recovery setup opens the person-owned account controls", async ({ page }) => {
    await page.goto("/?app=administration&identity=configured");
    await expect(page.getByRole("heading", { name: "Enterprise Identity", level: 1 })).toBeVisible();
    await expect(page.getByText("Set up your account passkey and recovery codes before requiring SSO", { exact: true })).toBeVisible();
    await click(page, "Set up recovery");
    expect(await calls(page)).toContainEqual({ openGaugeApp: "account-settings", page: "account" });
});

test("enterprise sign-in advances through test, admission, owner link, and enforcement", async ({ page }) => {
    await page.addInitScript(() => {
        Object.defineProperty(window, "open", { configurable: true, value: () => null });
    });
    await page.goto("/?app=administration&identity=lifecycle");
    await expect(page.getByRole("heading", { name: "Enterprise Identity", level: 1 })).toBeVisible();

    await expect(page.getByRole("button", { name: "Link", exact: true })).toBeDisabled();
    await expect(page.getByRole("button", { name: "Require SSO", exact: true })).toBeDisabled();
    await click(page, "Test sign-in");
    const fallback = page.getByRole("link", { name: "Continue test", exact: true });
    await expect(fallback).toHaveAttribute("href", "https://identity.example.invalid/A/test");

    await click(page, "Complete sign-in test");
    await expect(page.getByText("Browser sign-in verified", { exact: true })).toBeVisible();
    await expect(page.getByRole("button", { name: "Link", exact: true })).toBeEnabled();

    const admission = page.getByRole("combobox", { name: /Who can join/i });
    await admission.selectOption("verified-domain-jit");
    await click(page, "Save");
    await expect(admission).toHaveValue("verified-domain-jit");
    await click(page, "Link");
    await expect(page.getByText("Linked to this GaugeDesk account", { exact: true })).toBeVisible();

    await expect(page.getByRole("button", { name: "Require SSO", exact: true })).toBeEnabled();
    await click(page, "Require SSO");
    await expect(page.getByText("Enabled", { exact: true })).toBeVisible();
    await expect(page.getByRole("button", { name: "Stop requiring", exact: true })).toBeVisible();
    await click(page, "Stop requiring");
    await expect(page.getByText("Ready to enable", { exact: true })).toBeVisible();

    expect(await calls(page)).toEqual(expect.arrayContaining([
        expect.objectContaining({ command: "enterprise-identity.test.begin", scope: "A" }),
        expect.objectContaining({ command: "enterprise-identity.admission-mode.set", scope: "A", payload: { mode: "verified-domain-jit" } }),
        expect.objectContaining({ command: "enterprise-identity.owner-subject.link", scope: "A", payload: {} }),
        expect.objectContaining({ command: "enterprise-identity.enforcement.enable", scope: "A", payload: {} }),
        expect.objectContaining({ command: "enterprise-identity.enforcement.disable", scope: "A", payload: {} }),
    ]));
});

test("a lapsed organization plan re-enrolls without claiming checkout is entitlement", async ({ page }, info) => {
    await page.goto("/?app=administration&subscription-lifecycle=1");
    await expect(page.getByRole("heading", { name: "Plans & services", level: 1 })).toBeVisible();
    const plan = page.locator(".gaugeapp-panel").first();
    await expect(plan.getByText("Current plan", { exact: true })).toBeVisible();
    await expect(plan.getByRole("heading", { name: "Free", exact: true })).toBeVisible();
    await expect(plan).toContainText("GaugeDesk Cloud ended");
    await expect(plan.getByRole("button", { name: "Re-enroll", exact: true })).toBeVisible();
    await expect(page.getByText("Purchased seats", { exact: true })).toHaveCount(0);
    await expect(page.getByRole("heading", { name: "Renewal", exact: true })).toHaveCount(0);
    await page.screenshot({ path: info.outputPath("organization-plan-lapsed.png"), scale: "css", fullPage: true });

    await plan.getByRole("button", { name: "Re-enroll", exact: true }).click();
    const review = page.getByRole("region", { name: "Pending changes" });
    await expect(review).toContainText("Change organization plan");
    await review.getByRole("button", { name: "Accept", exact: true }).click();

    const handoff = page.getByRole("region", { name: "Stripe handoff" });
    await expect(handoff).toContainText("Checkout ready");
    await expect(handoff.getByRole("link", { name: "Continue in Stripe", exact: true }))
        .toHaveAttribute("href", "https://checkout.stripe.example.test/session");
    await handoff.getByRole("button", { name: "Refresh status", exact: true }).click();
    await expect(plan.getByRole("heading", { name: "Free", exact: true })).toBeVisible();

    await click(page, "Complete plan checkout");
    await expect(plan.getByRole("heading", { name: "GaugeDesk Cloud", exact: true })).toBeVisible();
    await expect(plan.getByText("Current plan", { exact: true })).toBeVisible();
    await expect(page.getByText("Purchased seats", { exact: true })).toBeVisible();
    await expect(page.getByRole("heading", { name: "Renewal", exact: true })).toBeVisible();
    await expect(plan.getByRole("button", { name: "Re-enroll", exact: true })).toHaveCount(0);

    expect(await calls(page)).toEqual(expect.arrayContaining([
        expect.objectContaining({ command: "subscription.plan.change", scope: "A", payload: { quantity: 1 } }),
        expect.objectContaining({ review: "A", decision: "accept" }),
    ]));
    await page.screenshot({ path: info.outputPath("organization-plan-reenrolled.png"), scale: "css", fullPage: true });
});

test("managed Project Host retirement requires retention before separately confirmed erasure", async ({ page }) => {
    await page.goto("/?app=administration&project-host=managed");
    await expect(page.getByRole("heading", { name: "Project Hosts", level: 1 })).toBeVisible();
    await click(page, "View");
    await click(page, "Retire");
    await expect(page.getByText("Retirement stops new work", { exact: false })).toBeVisible();
    const confirmation = page.getByRole("textbox", { name: "Type Studio Host A to confirm" });
    await expect(page.getByRole("button", { name: "Begin retention" })).toBeDisabled();
    await confirmation.fill("Studio Host A");
    await click(page, "Begin retention");
    await expect(page.getByText("In retention", { exact: true }).first()).toBeVisible();
    await expect(page.getByRole("button", { name: "Reinstate" })).toBeVisible();

    await page.locator(".gaugeapp-host-detail").getByRole("button", { name: "Erase permanently" }).click();
    await expect(page.getByText("Permanent erasure deletes this Project Host", { exact: false })).toBeVisible();
    await page.getByRole("textbox", { name: "Type Studio Host A to confirm" }).fill("Studio Host A");
    await page.locator(".gaugeapp-host-editor").getByRole("button", { name: "Erase permanently" }).click();
    await expect(page.getByText("Retired", { exact: true }).first()).toBeVisible();
    await expect(page.getByRole("button", { name: "Retire" })).toHaveCount(0);
    await expect(page.getByRole("button", { name: "Erase permanently" })).toHaveCount(0);

    expect(await calls(page)).toEqual(expect.arrayContaining([
        expect.objectContaining({ command: "project-host.retire", payload: { id: "cloud-home", phase: "retention" } }),
        expect.objectContaining({ command: "project-host.retire", payload: { id: "cloud-home", phase: "erase" } }),
    ]));
});

test("product revision and proposal editing reread the populated commercial ledger", async ({ page }, info) => {
    await page.goto("/?app=commercial-operations&commercial-lifecycle=draft");
    await expect(page.getByRole("heading", { name: "Products", exact: true, level: 1 })).toBeVisible();

    const product = page.locator(".gaugeapp-catalog-card").filter({ hasText: "Research" });
    await product.getByRole("button", { name: "View", exact: true }).click();
    await expect(page.locator(".gaugeapp-product-detail")).toContainText("Source review");
    await product.getByRole("button", { name: "Edit", exact: true }).click();
    await expect(page.locator(".gaugeapp-catalog-card")).toHaveCount(0);
    await expect(page.locator(".gaugeapp-product-detail")).toHaveCount(0);
    await page.getByLabel("Listing title", { exact: true }).fill("Research Studio");
    await page.locator(".gaugeapp-editor").getByLabel("Description", { exact: true }).first().fill("Focused research with reviewed sources.");
    await click(page, "Save revision");
    await expect(product.getByText("Research Studio", { exact: true })).toBeVisible();
    await expect(page.locator(".gaugeapp-product-detail")).toContainText("Research Studio");

    await click(page, "Clients");
    const client = page.locator(".gaugeapp-client-card").filter({ hasText: "Cosmos Design" });
    await client.getByRole("button", { name: "View", exact: true }).click();
    await page.locator(".gaugeapp-client-detail").getByRole("button", { name: "Edit", exact: true }).click();
    await expect(page.locator(".gaugeapp-client-card")).toHaveCount(0);
    await expect(page.locator(".gaugeapp-client-detail")).toHaveCount(0);
    await page.locator(".gaugeapp-editor").getByRole("button", { name: "Close", exact: true }).click();
    await expect(client).toBeVisible();

    await page.getByRole("navigation", { name: "Commercial Operations pages" }).getByRole("button", { name: "Engagements", exact: true }).click();
    await expect(page.getByRole("heading", { name: "Engagements", exact: true, level: 1 })).toBeVisible();
    await page.locator(".gaugeapp-engagement-card").getByRole("button", { name: "View", exact: true }).click();
    const detail = page.locator(".gaugeapp-engagement-detail");
    await detail.getByRole("button", { name: "Edit", exact: true }).click();
    await expect(page.locator(".gaugeapp-engagement-card")).toHaveCount(0);
    await expect(detail).toHaveCount(0);
    await page.getByLabel("Seats", { exact: true }).fill("5");
    await page.getByLabel("Client note", { exact: true }).fill("Start with the research team.");
    await click(page, "Save draft");
    await detail.getByRole("button", { name: "Send proposal", exact: true }).click();
    await expect(detail.getByText("Awaiting client", { exact: true })).toBeVisible();
    await expect(detail.getByRole("button", { name: "Revise", exact: true })).toBeVisible();

    const submitted = await calls(page);
    expect(submitted).toEqual(expect.arrayContaining([
        expect.objectContaining({ command: "commercial-product.revise", scope: "A", payload: expect.objectContaining({ revision: expect.objectContaining({ listing_title: "Research Studio" }) }) }),
        expect.objectContaining({ command: "commercial-engagement.proposal.save", scope: "A", payload: expect.objectContaining({ id: "engagement-a", terms: expect.objectContaining({ seats: 5, client_note: "Start with the research team." }) }) }),
        expect.objectContaining({ command: "commercial-engagement.proposal.send", scope: "A", payload: expect.objectContaining({ id: "engagement-a" }) }),
    ]));
    await page.screenshot({ path: info.outputPath("populated-commercial-proposal.png"), scale: "css", fullPage: true });
});

test("client edit and closure reread authoritative state and remove impossible actions", async ({ page }) => {
    await page.goto("/?app=commercial-operations&commercial-lifecycle=draft");
    await click(page, "Clients");

    const client = page.locator(".gaugeapp-client-card").filter({ hasText: "Cosmos Design" });
    await client.getByRole("button", { name: "View", exact: true }).click();
    const detail = page.locator(".gaugeapp-client-detail");
    await detail.getByRole("button", { name: "Edit", exact: true }).click();
    const editor = page.locator(".gaugeapp-client-editor");
    await editor.getByLabel("Name", { exact: true }).fill("Cosmos Studio");
    await editor.getByLabel("Billing reference", { exact: true }).fill("COSMOS-REVISED");
    await editor.getByRole("button", { name: "Save client", exact: true }).click();

    await expect(detail.getByRole("heading", { name: "Cosmos Studio", exact: true })).toBeVisible();
    await expect(detail).toContainText("COSMOS-REVISED");
    await expect(page.locator(".gaugeapp-client-card").filter({ hasText: "Cosmos Studio" })).toBeVisible();

    await detail.getByRole("button", { name: "Close client", exact: true }).click();
    await expect(detail.getByText("closed", { exact: true })).toBeVisible();
    await expect(detail.getByRole("button", { name: "Edit", exact: true })).toBeDisabled();
    await expect(detail.getByRole("button", { name: "Close client", exact: true })).toHaveCount(0);
    await expect(page.locator(".gaugeapp-client-card").filter({ hasText: "Cosmos Studio" }).getByRole("button", { name: "Edit", exact: true })).toBeDisabled();

    await page.getByRole("navigation", { name: "Commercial Operations pages" }).getByRole("button", { name: "Engagements", exact: true }).click();
    await expect(page.getByRole("button", { name: "New proposal", exact: true })).toBeDisabled();
    expect(await calls(page)).toEqual(expect.arrayContaining([
        expect.objectContaining({ command: "commercial-client.edit", payload: { id: "client-a", display_name: "Cosmos Studio", billing_reference: "COSMOS-REVISED" } }),
        expect.objectContaining({ command: "commercial-client.close", payload: { id: "client-a" } }),
    ]));
});

test("commercial detail inspection uses the owning server reads", async ({ page }, info) => {
    await page.goto("/?app=commercial-operations&commercial-lifecycle=accepted&currency=jpy");

    const product = page.locator(".gaugeapp-catalog-card").filter({ hasText: "Research" });
    await product.getByRole("button", { name: "View", exact: true }).click();
    await expect(page.locator(".gaugeapp-product-detail")).toContainText("Research");

    await click(page, "Clients");
    const client = page.locator(".gaugeapp-client-card").filter({ hasText: "Cosmos Design" });
    await client.getByRole("button", { name: "View", exact: true }).click();
    const clientDetail = page.locator(".gaugeapp-client-detail");
    await clientDetail.getByRole("button", { name: "Engagements", exact: true }).click();
    let evidence = page.getByLabel("Client engagements", { exact: true });
    await expect(evidence).toContainText("engagement-a · accepted");
    await evidence.getByRole("button", { name: "Done", exact: true }).click();
    await clientDetail.getByRole("button", { name: "Payments", exact: true }).click();
    evidence = page.getByLabel("Client payments", { exact: true });
    await expect(evidence).toContainText("1 transactions");
    await evidence.getByRole("button", { name: "Done", exact: true }).click();

    await page.getByRole("navigation", { name: "Commercial Operations pages" }).getByRole("button", { name: "Engagements", exact: true }).click();
    await page.locator(".gaugeapp-engagement-card").getByRole("button", { name: "View", exact: true }).click();
    const engagement = page.locator(".gaugeapp-engagement-detail");
    await engagement.getByRole("button", { name: "Agreement", exact: true }).click();
    evidence = page.getByLabel("Accepted agreement", { exact: true });
    await expect(evidence).toContainText("Research");
    await expect(evidence).toContainText("person-a");
    await evidence.getByRole("button", { name: "Done", exact: true }).click();
    await engagement.getByRole("button", { name: "Payments", exact: true }).click();
    evidence = page.getByLabel("Engagement payments", { exact: true });
    await expect(evidence).toContainText("1 transactions");
    await evidence.getByRole("button", { name: "Done", exact: true }).click();

    await page.getByRole("navigation", { name: "Commercial Operations pages" }).getByRole("button", { name: "Payments", exact: true }).click();
    await page.locator(".gaugeapp-row").filter({ hasText: "pi_jpy" }).getByRole("button", { name: "View", exact: true }).click();
    await expect(page.locator(".gaugeapp-payment-detail")).toContainText("pi_jpy");

    expect(await calls(page)).toEqual(expect.arrayContaining([
        expect.objectContaining({ command: "commercial-product.read", payload: { id: "product-a" } }),
        expect.objectContaining({ command: "commercial-client.read", payload: { id: "client-a" } }),
        expect.objectContaining({ command: "commercial-engagements.read-by-client", payload: { client_id: "client-a" } }),
        expect.objectContaining({ command: "commercial-payments.read-by-client", payload: { client_id: "client-a" } }),
        expect.objectContaining({ command: "commercial-engagement.agreement.read", payload: { id: "engagement-a" } }),
        expect.objectContaining({ command: "commercial-engagement.payments.read", payload: { id: "engagement-a" } }),
        expect.objectContaining({ command: "commercial-payments.payment.read", payload: { id: "pi_jpy" } }),
    ]));
    await page.screenshot({ path: info.outputPath("commercial-authoritative-inspection.png"), scale: "css", fullPage: true });
});

test("new products and proposals appear only after authoritative creation rereads", async ({ page }) => {
    await page.goto("/?app=commercial-operations&commercial-lifecycle=draft");
    await page.getByRole("button", { name: "New product", exact: true }).click();
    const productEditor = page.locator(".gaugeapp-editor");
    await productEditor.getByLabel("Listing title", { exact: true }).fill("Policy Desk");
    await productEditor.getByLabel("Description", { exact: true }).fill("Policy analysis for an admitted team.");
    await productEditor.getByLabel("Amount", { exact: true }).fill("250");
    await productEditor.getByRole("button", { name: "Create product", exact: true }).click();

    const createdProduct = page.locator(".gaugeapp-catalog-card").filter({ hasText: "Policy Desk" });
    await expect(createdProduct).toBeVisible();
    await expect(createdProduct).toContainText(/USD 250\.00\s*\/\s*month/);

    await click(page, "Engagements");
    await page.getByRole("button", { name: "New proposal", exact: true }).click();
    await page.locator(".gaugeapp-editor-grid label").filter({ hasText: "Product" }).locator("select").selectOption({ label: "Policy Desk" });
    const recipients = page.locator(".gaugeapp-recipient-row");
    await recipients.nth(0).getByLabel("Name", { exact: true }).fill("Avery Client");
    await recipients.nth(0).getByLabel("Email", { exact: true }).fill("avery@example.test");
    await recipients.nth(1).getByLabel("Name", { exact: true }).fill("Billing Desk");
    await recipients.nth(1).getByLabel("Email", { exact: true }).fill("billing@example.test");
    await page.getByRole("button", { name: "Create draft", exact: true }).click();

    const createdEngagement = page.locator(".gaugeapp-engagement-card").filter({ hasText: "Policy Desk" });
    await expect(createdEngagement).toBeVisible();
    await expect(createdEngagement.getByText("draft", { exact: true })).toBeVisible();
    await createdEngagement.getByRole("button", { name: "View", exact: true }).click();
    await expect(page.locator(".gaugeapp-engagement-detail").getByRole("heading", { name: "Cosmos Design · Policy Desk", exact: true })).toBeVisible();

    const submitted = await calls(page);
    expect(submitted).toEqual(expect.arrayContaining([
        expect.objectContaining({ command: "commercial-product.create", payload: expect.objectContaining({ revision: expect.objectContaining({ listing_title: "Policy Desk" }) }) }),
        expect.objectContaining({ command: "commercial-engagement.proposal.create", payload: expect.objectContaining({ client_id: "client-a", product_id: expect.stringMatching(/^product-/) }) }),
    ]));
});

test("proposal discard, revision, resend, and withdrawal follow backend lifecycle semantics", async ({ page }, info) => {
    await page.setViewportSize({ width: 390, height: 844 });
    await page.goto("/?app=commercial-operations&commercial-lifecycle=draft&shell=1");
    const panes = page.getByRole("tablist", { name: "panes" });
    await panes.getByRole("tab", { name: "Menu", exact: true }).click();
    await click(page, "Engagements");
    await panes.getByRole("tab", { name: "Content", exact: true }).click();
    const card = page.locator(".gaugeapp-engagement-card");
    await card.getByRole("button", { name: "View", exact: true }).click();
    let detail = page.locator(".gaugeapp-engagement-detail");

    await detail.getByRole("button", { name: "Send proposal", exact: true }).click();
    let deliveryLinks = page.getByLabel("Proposal delivery links", { exact: true });
    await expect(deliveryLinks.getByText("Proposal links ready", { exact: true })).toBeVisible();
    await expect(deliveryLinks.getByRole("link", { name: "Open", exact: true })).toHaveAttribute("href", /proposal_proof=fixture-send-proof/);
    await deliveryLinks.getByRole("button", { name: "Done", exact: true }).click();
    await expect(detail.getByText("Awaiting client", { exact: true })).toBeVisible();
    await detail.getByRole("button", { name: "Resend", exact: true }).click();
    deliveryLinks = page.getByLabel("Proposal delivery links", { exact: true });
    await expect(deliveryLinks.getByRole("link", { name: "Open", exact: true })).toHaveAttribute("href", /proposal_proof=fixture-resend-proof/);
    await deliveryLinks.getByRole("button", { name: "Done", exact: true }).click();
    await detail.getByRole("button", { name: "Delivery", exact: true }).click();
    const deliveryStatus = page.getByLabel("Proposal delivery status", { exact: true });
    await expect(deliveryStatus).toContainText("person-a");
    await expect(deliveryStatus.getByText("Link issued", { exact: true })).toBeVisible();
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth)).toBe(true);
    await page.screenshot({ path: info.outputPath("proposal-delivery-status-narrow.png"), scale: "css" });
    await deliveryStatus.getByRole("button", { name: "Done", exact: true }).click();
    await expect(detail.getByText("Awaiting client", { exact: true })).toBeVisible();
    await detail.getByRole("button", { name: "Revise", exact: true }).click();
    await page.getByLabel("Client note", { exact: true }).fill("Revised scope");
    await page.getByRole("button", { name: "Create revised draft", exact: true }).click();
    detail = page.locator(".gaugeapp-engagement-detail");
    await expect(detail).toContainText("Proposal revision2");

    await detail.getByRole("button", { name: "Send proposal", exact: true }).click();
    await detail.getByRole("button", { name: "Withdraw", exact: true }).click();
    await expect(detail.getByText("This proposal was withdrawn. No agreement or technical access was created.", { exact: true })).toBeVisible();
    await expect(detail.getByRole("button", { name: /Revise|Resend|Withdraw|Send proposal|Discard/ })).toHaveCount(0);
    await expect(detail.getByRole("button", { name: "Delivery", exact: true })).toBeVisible();
    await expect(page.locator(".gaugeapp-engagement-group").filter({ hasText: "Closed" }).getByText("withdrawn", { exact: true })).toBeVisible();
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth)).toBe(true);
    await page.screenshot({ path: info.outputPath("withdrawn-proposal-narrow.png"), scale: "css" });

    const submitted = await calls(page);
    expect(submitted.filter((entry: { command?: string }) => entry.command === "commercial-engagement.proposal.send")).toHaveLength(2);
    expect(submitted).toEqual(expect.arrayContaining([
        expect.objectContaining({ command: "commercial-engagement.proposal.resend", payload: expect.objectContaining({ id: "engagement-a" }) }),
        expect.objectContaining({ command: "commercial-engagement.proposal.revise", payload: expect.objectContaining({ id: "engagement-a", terms: expect.objectContaining({ client_note: "Revised scope" }) }) }),
        expect.objectContaining({ command: "commercial-engagement.proposal.withdraw", payload: { id: "engagement-a" } }),
    ]));
});

test("discarding a draft removes it from authoritative commercial inventories", async ({ page }) => {
    await page.goto("/?app=commercial-operations&commercial-lifecycle=draft");
    await click(page, "Engagements");
    await page.locator(".gaugeapp-engagement-card").getByRole("button", { name: "View", exact: true }).click();
    await page.locator(".gaugeapp-engagement-detail").getByRole("button", { name: "Discard", exact: true }).click();
    await expect(page.locator(".gaugeapp-engagement-card")).toHaveCount(0);
    await expect(page.getByText("No engagements yet. Add a client and product, then create a proposal.", { exact: true })).toBeVisible();
    await click(page, "Products");
    await expect(page.locator(".gaugeapp-catalog-card").filter({ hasText: "Research" })).toContainText("0 active · 0 open · 0 closed");
    expect(await calls(page)).toEqual(expect.arrayContaining([
        expect.objectContaining({ command: "commercial-engagement.proposal.discard", payload: { id: "engagement-a" } }),
    ]));
});

test("Billing tells the truth when Stripe handoffs and documents are not admitted", async ({ page }) => {
    await page.goto("/?app=administration&billing-unavailable=1");
    await expect(page.getByRole("heading", { name: "Billing", exact: true, level: 1 })).toBeVisible();
    await expect(page.getByText("Payment management is temporarily unavailable.", { exact: true })).toBeVisible();
    await expect(page.getByText("Billing documents are temporarily unavailable.", { exact: true })).toBeVisible();
    await expect(page.getByRole("button", { name: "Retrieve", exact: true })).toHaveCount(0);
    await expect(page.getByText("Retrieve the current estimate and recent invoices from Stripe.", { exact: true })).toHaveCount(0);
});

test("zero-decimal product prices and refunds stay in processor minor units", async ({ page }, info) => {
    await page.goto("/?app=commercial-operations&commercial-lifecycle=draft&currency=jpy");
    const product = page.locator(".gaugeapp-catalog-card").filter({ hasText: "Research" });
    await expect(product).toContainText("JPY 500 once");
    await product.getByRole("button", { name: "Edit", exact: true }).click();
    await expect(page.getByLabel("Amount", { exact: true }).first()).toHaveValue("500");
    await expect(page.getByLabel("Amount", { exact: true }).first()).toHaveAttribute("step", "1");
    await click(page, "Cancel");

    await click(page, "Payments");
    await expect(page.getByText("Payment events recorded from Stripe.", { exact: true })).toBeVisible();
    await expect(page.getByText("Webhook-admitted processor evidence.", { exact: true })).toHaveCount(0);
    await expect(page.getByText("JPY 500", { exact: true }).first()).toBeVisible();
    await page.locator(".gaugeapp-row").filter({ hasText: "pi_jpy" }).getByRole("button", { name: "View", exact: true }).click();
    const refund = page.getByLabel("Refund amount JPY", { exact: true });
    await expect(refund).toHaveValue("500");
    await expect(refund).toHaveAttribute("step", "1");
    await refund.fill("250");
    await page.locator(".gaugeapp-refund-row").getByRole("button", { name: "Refund", exact: true }).click();
    expect(await calls(page)).toEqual(expect.arrayContaining([
        expect.objectContaining({ command: "commercial-payments.payment.refund", payload: expect.objectContaining({ transaction_id: "pi_jpy", amount_cents: 250 }) }),
    ]));
    await page.screenshot({ path: info.outputPath("jpy-commercial-minor-units.png"), scale: "css", fullPage: true });
});

test("accepted engagement operations advance only after authoritative rereads", async ({ page }, info) => {
    await page.goto("/?app=commercial-operations&commercial-lifecycle=accepted");
    await click(page, "Engagements");
    await page.locator(".gaugeapp-engagement-card").getByRole("button", { name: "View", exact: true }).click();
    const detail = page.locator(".gaugeapp-engagement-detail");
    const placement = detail.getByPlaceholder("Placement or deployment reference");
    await placement.fill("placement-cosmos-research");
    await detail.getByRole("button", { name: "Link access", exact: true }).click();
    await expect(detail.getByRole("button", { name: "Update link", exact: true })).toBeVisible();
    await detail.getByRole("button", { name: "Activate access", exact: true }).click();
    await detail.getByRole("button", { name: "Close engagement", exact: true }).click();
    await expect(detail.locator("header > div > span")).toHaveText("closed");
    await expect(detail.getByRole("button", { name: "Close engagement", exact: true })).toHaveCount(0);
    await expect(detail.getByRole("button", { name: "Suspend", exact: true })).toBeVisible();
    await expect(detail.getByRole("button", { name: "Resume access", exact: true })).toHaveCount(0);
    await page.screenshot({ path: info.outputPath("closed-commercial-engagement-access.png"), scale: "css", fullPage: true });
    await detail.getByRole("button", { name: "Suspend", exact: true }).click();
    await expect(detail.getByText("suspended", { exact: true }).last()).toBeVisible();
    await expect(detail.getByRole("button", { name: "Resume access", exact: true })).toHaveCount(0);
    await detail.getByRole("button", { name: "Revoke", exact: true }).click();
    await expect(detail.getByText("revoked", { exact: true }).last()).toBeVisible();

    expect(await calls(page)).toEqual(expect.arrayContaining([
        expect.objectContaining({ command: "commercial-engagement.placement.link", payload: { id: "engagement-a", placement_ref: "placement-cosmos-research" } }),
        expect.objectContaining({ command: "commercial-engagement.entitlement.activate", payload: expect.objectContaining({ id: "engagement-a" }) }),
        expect.objectContaining({ command: "commercial-engagement.entitlement.suspend", payload: { id: "engagement-a" } }),
        expect.objectContaining({ command: "commercial-engagement.entitlement.revoke", payload: { id: "engagement-a" } }),
        expect.objectContaining({ command: "commercial-engagement.close", payload: { id: "engagement-a" } }),
    ]));
    await page.screenshot({ path: info.outputPath("closed-commercial-engagement.png"), scale: "css", fullPage: true });
});

test("populated commercial pages remain actionable in the real narrow workbench shell", async ({ page }, info) => {
    await page.setViewportSize({ width: 390, height: 844 });
    await page.goto("/?app=commercial-operations&commercial-lifecycle=accepted&shell=1");

    const panes = page.getByRole("tablist", { name: "panes" });
    await panes.getByRole("tab", { name: "Content", exact: true }).click();
    await expect(page.getByRole("heading", { name: "Products", exact: true, level: 1 })).toBeVisible();
    const product = page.locator(".gaugeapp-catalog-card").filter({ hasText: "Research" });
    await product.getByRole("button", { name: "View", exact: true }).click();
    await expect(page.locator(".gaugeapp-product-detail")).toContainText("Source review");

    await panes.getByRole("tab", { name: "Menu", exact: true }).click();
    await page.getByRole("button", { name: "Engagements", exact: true }).click();
    await panes.getByRole("tab", { name: "Content", exact: true }).click();
    await expect(page.getByRole("heading", { name: "Engagements", exact: true, level: 1 })).toBeVisible();
    await page.locator(".gaugeapp-engagement-card").getByRole("button", { name: "View", exact: true }).click();
    const detail = page.locator(".gaugeapp-engagement-detail");
    await detail.getByRole("button", { name: "Agreement", exact: true }).click();
    const agreement = page.getByLabel("Accepted agreement", { exact: true });
    await expect(agreement).toContainText("person-a");
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth)).toBe(true);
    await page.screenshot({ path: info.outputPath("narrow-commercial-agreement.png"), scale: "css" });
    await agreement.getByRole("button", { name: "Done", exact: true }).click();
    await detail.getByPlaceholder("Placement or deployment reference").fill("placement-mobile-review");
    await detail.getByRole("button", { name: "Link access", exact: true }).click();
    await expect(detail.getByRole("button", { name: "Update link", exact: true })).toBeVisible();

    const overflow = await page.evaluate(() => ({
        document: document.documentElement.scrollWidth - document.documentElement.clientWidth,
        pane: (() => {
            const element = document.querySelector<HTMLElement>(".carousel-pane");
            return element ? element.scrollWidth - element.clientWidth : -1;
        })(),
    }));
    expect(overflow.document).toBeLessThanOrEqual(1);
    expect(overflow.pane).toBeLessThanOrEqual(1);
    await page.screenshot({ path: info.outputPath("narrow-populated-engagement.png"), scale: "css" });
});

test("the resumable update cursor rereads server truth without a local action", async ({ page }) => {
    await go(page, "account-settings");
    await expect(page.getByLabel("Display name", { exact: true })).toHaveValue("Person A");
    await click(page, "Server change");
    await expect(page.getByLabel("Display name", { exact: true })).toHaveValue("Person A · revision 1");
    const update = (await calls(page)).find((call) => call.updates === "A");
    expect(update).toMatchObject({
        after: "fixture-A-0",
        cursor: "fixture-A-1",
    });
});

test("an update outage labels retained page data until cursor recovery", async ({ page }) => {
    await go(page, "account-settings");
    await expect(page.getByLabel("Display name", { exact: true })).toHaveValue("Person A");
    await click(page, "Deny updates");
    await click(page, "Server change");
    await expect(page.getByText("Updates are delayed. Showing the last loaded data.", { exact: false })).toBeVisible();
    await expect(page.getByLabel("Display name", { exact: true })).toHaveValue("Person A");

    await click(page, "Restore updates");
    await expect(page.getByLabel("Display name", { exact: true })).toHaveValue("Person A · revision 1");
    await expect(page.locator(".gaugeapp-update-delayed")).toHaveCount(0);
    const attempts = (await calls(page)).filter((call) => call.updates === "A");
    expect(attempts.at(-1)).toMatchObject({ after: "fixture-A-0", cursor: "fixture-A-1" });
});

test("a direct command outage reports failure without changing server truth", async ({ page }) => {
    const errors: Error[] = [];
    page.on("pageerror", (error) => errors.push(error));
    await go(page, "account-settings");
    const profile = page.locator(".gaugeapp-panel").filter({ hasText: "Profile" });
    await profile.getByLabel("Display name", { exact: true }).fill("Uncommitted name");
    await click(page, "Deny actions");
    await profile.getByRole("button", { name: "Save", exact: true }).click();
    await expect(page.locator(".gaugeapp-status")).toContainText("Could not apply change: action authority unavailable");
    await click(page, "Restore actions");
    await click(page, "Refresh fixture");
    await expect(profile.getByLabel("Display name", { exact: true })).toHaveValue("Person A");
    await expect(page.locator("body")).not.toContainText("Change applied");
    expect(errors).toEqual([]);
});

test("a review outage leaves the proposal pending and discloses no result", async ({ page }) => {
    await go(page);
    await click(page, "Seed proposal");
    await click(page, "Deny actions");
    await click(page, "Accept");
    await expect(page.locator(".gaugeapp-status")).toContainText("Could not review change: Error: action authority unavailable");
    await expect(page.getByRole("button", { name: "Accept", exact: true })).toBeEnabled();
    await expect(page.locator(".gaugeapp-one-time")).toHaveCount(0);
});

test("a credential-intake outage clears the secret and reports no success", async ({ page }) => {
    const errors: Error[] = [];
    page.on("pageerror", (error) => errors.push(error));
    await go(page, "account-settings");
    await click(page, "Provider Connections");
    await click(page, "Add connection");
    await page.getByLabel("API key", { exact: true }).fill("synthetic-not-a-key");
    await click(page, "Deny actions");
    await click(page, "Connect");
    await expect(page.getByLabel("API key", { exact: true })).toHaveValue("");
    await expect(page.locator(".gaugeapp-status")).toContainText("Could not connect provider: action authority unavailable");
    await expect(page.locator("body")).not.toContainText("Connection added");
    expect(JSON.stringify(await calls(page))).not.toContain("synthetic-not-a-key");
    expect(errors).toEqual([]);
});

test("an organization credential outage clears the secret and preserves its prior state", async ({ page }) => {
    await page.goto("/?app=administration&identity=configured");
    await expect(page.getByRole("heading", { name: "Enterprise Identity", level: 1 })).toBeVisible();
    await click(page, "Add");
    const input = page.getByRole("textbox", { name: "OIDC client secret" });
    await input.fill("synthetic-organization-secret");
    await click(page, "Deny actions");
    await click(page, "Save secret");
    await expect(input).toHaveValue("");
    await expect(page.locator(".gaugeapp-status")).toContainText("Could not save client secret: action authority unavailable");
    await expect(page.getByText("Not set — use this for a public PKCE client", { exact: true })).toBeVisible();
    expect(JSON.stringify(await calls(page))).not.toContain("synthetic-organization-secret");
});

test("a consumer sign-in outage remains on the account page with a useful error", async ({ page }) => {
    await go(page, "account-settings");
    await click(page, "Deny actions");
    await click(page, "Link Google");
    await expect(page.locator(".gaugeapp-inline-notice")).toContainText("action authority unavailable");
    await expect(page.getByRole("heading", { name: "Account Settings", level: 1 })).toBeVisible();
    expect(await calls(page)).not.toContainEqual(expect.objectContaining({ openExternal: expect.anything() }));
});

test("consumer sign-in appears only after its server-owned callback and authoritative reread", async ({ page }, info) => {
    const run = `consumer-link-${info.parallelIndex}-${Date.now()}`;
    const lifecycleUrl = `/__fixture/account-lifecycle?key=${encodeURIComponent(run)}`;
    await page.goto(`/?app=account-settings&account-lifecycle=1&run=${encodeURIComponent(run)}`);
    await expect(page.getByRole("heading", { name: "Account Settings", level: 1 })).toBeVisible();

    await click(page, "Link Google");
    await expect(page.locator(".gaugeapp-inline-notice")).toContainText("Finish linking in your browser");
    await expect(page.getByRole("button", { name: "Link Google", exact: true })).toBeVisible();
    expect(await calls(page)).toContainEqual({ openExternal: `https://accounts.example.invalid/link?state=server-held-${encodeURIComponent(run)}` });
    const pending = await page.evaluate(async (url) => (await fetch(url)).json(), lifecycleUrl) as { consumer_oidc_pending: boolean; consumer_oidc_linked: boolean };
    expect(pending).toMatchObject({ consumer_oidc_pending: true, consumer_oidc_linked: false });

    const callback = await page.evaluate(async (url) => {
        const response = await fetch(url, {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({ operation: "fixture.consumer-oidc.callback", payload: {} }),
        });
        return { ok: response.ok, body: await response.text() };
    }, lifecycleUrl);
    expect(callback.ok).toBe(true);
    expect(callback.body).not.toMatch(/token|authorization_code|id_token/i);

    await page.locator(".gaugeapp-inline-notice").getByRole("button", { name: "Refresh", exact: true }).click();
    await expect(page.getByText("Google", { exact: true })).toBeVisible();
    await expect(page.getByRole("button", { name: "Link Google", exact: true })).toHaveCount(0);
    await page.reload();
    await expect(page.getByText("Google", { exact: true })).toBeVisible();
    await expect(page.getByRole("button", { name: "Link Google", exact: true })).toHaveCount(0);

    const googleMethod = page.locator(".gaugeapp-row").filter({ has: page.getByText("Google", { exact: true }) });
    await googleMethod.getByRole("button", { name: "Remove", exact: true }).click();
    await page.getByRole("region", { name: "Pending changes" }).getByRole("button", { name: "Accept", exact: true }).click();
    await expect(googleMethod).toHaveCount(0);
    await expect(page.getByRole("button", { name: "Link Google", exact: true })).toBeVisible();
    expect(await calls(page)).toContainEqual({
        command: "account.authenticator.remove",
        scope: "A",
        payload: { id: `consumer-google-${run}`, kind: "external" },
    });
    await page.reload();
    await expect(page.getByText("Google", { exact: true })).toHaveCount(0);
    await expect(page.getByRole("button", { name: "Link Google", exact: true })).toBeVisible();
});

for (const destination of ["Switch scope", "Toggle active", "Toggle visible", "New authorization", "People", "Deny reads"]) test(`one-time credentials and drafts leave with their context: ${destination}`, async ({ page }) => {
    await go(page);
    await click(page, "Issue credential");
    await expect(page.locator(".gaugeapp-one-time")).toContainText("SCIM-A");
    await click(page, "Set up");
    await page.getByLabel("Issuer", { exact: true }).fill("https://private-draft.example.invalid");
    await click(page, destination);
    await noTransient(page);
    await expect(page.getByLabel("Issuer", { exact: true })).toHaveCount(0);
    if (destination === "Toggle visible") await expect(page.getByLabel("Admission standing")).toHaveText("admitted");
    if (["Switch scope", "Toggle active", "Toggle visible"].includes(destination)) {
        await click(page, destination);
        await expect(page.getByRole("heading", { name: "Enterprise Identity", exact: true })).toBeVisible();
        await noTransient(page);
    }
});

for (const departure of ["Switch scope", "Toggle visible"]) for (const completion of ["Resolve oldest", "Reject oldest"]) test(`late command completion cannot revive after departure and return: ${departure}, ${completion}`, async ({ page }) => {
    await go(page);
    await click(page, "Hold: off");
    await click(page, "Issue credential");
    await expect(page.getByLabel("Pending requests")).toHaveText("1");
    await click(page, departure);
    if (departure === "Switch scope") await expect(page.getByRole("heading", { name: "Enterprise Identity", exact: true })).toBeVisible();
    else await expect(page.getByRole("heading", { name: "Enterprise Identity", exact: true })).toHaveCount(0);
    await click(page, departure);
    await expect(page.getByRole("heading", { name: "Enterprise Identity", exact: true })).toBeVisible();
    const before = (await calls(page)).length;
    await click(page, completion);
    await expect(page.getByLabel("Pending requests")).toHaveText("0");
    await noTransient(page);
    expect((await calls(page)).length).toBe(before);
    await expect(page.locator("body")).not.toContainText("private retired-context failure");
});

test("an older review cannot disclose its credential or unlock a newer review", async ({ page }) => {
    await go(page);
    await click(page, "Seed proposal");
    await click(page, "Hold: off");
    await click(page, "Accept");
    await click(page, "Switch scope");
    await click(page, "Seed proposal");
    await click(page, "Accept");
    await expect(page.getByLabel("Pending requests")).toHaveText("2");
    await click(page, "Resolve oldest");
    await expect(page.getByRole("button", { name: "Accept", exact: true })).toBeDisabled();
    await expect(page.locator(".gaugeapp-one-time")).toHaveCount(0);
    await click(page, "Resolve oldest");
    await expect(page.locator(".gaugeapp-one-time")).toContainText("SCIM-B");
});

test("a late review failure stays out of the replacement context", async ({ page }) => {
    await go(page);
    await click(page, "Seed proposal");
    await click(page, "Hold: off");
    await click(page, "Accept");
    await click(page, "Switch scope");
    await click(page, "Reject oldest");
    await noTransient(page);
    await expect(page.locator("body")).not.toContainText("private retired-context failure");
});

test("a late agent response cannot navigate a later visit, while same-scope page changes preserve chat", async ({ page }) => {
    await go(page);
    await page.getByText("Conversation", { exact: true }).click();
    const composer = page.getByRole("textbox", { name: "Message", exact: true });
    await composer.fill("Unsaved question");
    await click(page, "People");
    await expect(composer).toHaveValue("Unsaved question");
    await click(page, "Hold: off");
    await composer.press("Enter");
    await expect(page.getByLabel("Pending requests")).toHaveText("1");
    await click(page, "Switch scope");
    await expect(composer).toHaveValue("");
    await click(page, "Switch scope");
    await expect(page.getByRole("heading", { name: "People", exact: true, level: 1 })).toBeVisible();
    await click(page, "Resolve oldest");
    await noTransient(page);
    await expect(page.getByRole("heading", { name: "People", exact: true, level: 1 })).toBeVisible();
});

test("clearing a management conversation requires confirmation and rereads server truth", async ({ page }) => {
    await go(page);
    await page.getByText("Conversation", { exact: true }).click();
    const composer = page.getByRole("textbox", { name: "Message", exact: true });
    await composer.fill("Question to erase");
    await composer.press("Enter");
    await expect(page.getByText("Reply for A", { exact: true })).toBeVisible();

    await click(page, "Clear");
    await expect(page.getByRole("alert")).toContainText("cannot be recovered");
    await click(page, "Cancel");
    await expect(page.getByText("Reply for A", { exact: true })).toBeVisible();
    await click(page, "Clear");
    await click(page, "Clear conversation");
    await expect(page.getByText("Reply for A", { exact: true })).toHaveCount(0);
    expect(await calls(page)).toContainEqual({ erase: "A" });
});

test("management conversations rehydrate from server truth after reload and remain App-scoped", async ({ page }) => {
    const run = `browser-restart-${Date.now()}-${Math.random().toString(16).slice(2)}`;
    await page.goto(`/?app=account-settings&persistent-agent=1&run=${encodeURIComponent(run)}`);
    await expect(page.getByRole("heading", { level: 1 })).toBeVisible();
    await page.getByText("Conversation", { exact: true }).click();
    const accountComposer = page.getByRole("textbox", { name: "Message", exact: true });
    await accountComposer.fill("account continuity marker");
    await accountComposer.press("Enter");
    await expect(page.getByText("Server reply to account continuity marker", { exact: true })).toBeVisible();

    await page.reload();
    await page.getByText("Conversation", { exact: true }).click();
    await expect(page.getByText("account continuity marker", { exact: true })).toBeVisible();
    await expect(page.getByText("Server reply to account continuity marker", { exact: true })).toBeVisible();

    await page.goto(`/?app=commercial-operations&persistent-agent=1&run=${encodeURIComponent(run)}`);
    await expect(page.getByRole("heading", { level: 1 })).toBeVisible();
    await page.getByText("Conversation", { exact: true }).click();
    await expect(page.getByText("account continuity marker", { exact: true })).toHaveCount(0);
    const commercialComposer = page.getByRole("textbox", { name: "Message", exact: true });
    await commercialComposer.fill("commercial continuity marker");
    await commercialComposer.press("Enter");
    await expect(page.getByText("Server reply to commercial continuity marker", { exact: true })).toBeVisible();

    await page.reload();
    await page.getByText("Conversation", { exact: true }).click();
    await expect(page.getByText("commercial continuity marker", { exact: true })).toBeVisible();
    await expect(page.getByText("account continuity marker", { exact: true })).toHaveCount(0);
});

for (const stopWith of ["button", "Escape"] as const) test(`stopping a live management turn with ${stopWith} discards partial output and restores the composer`, async ({ page }) => {
    await page.goto("/?app=account-settings&stream-agent=1");
    await expect(page.getByRole("heading", { level: 1 })).toBeVisible();
    await page.getByText("Conversation", { exact: true }).click();
    const composer = page.getByRole("textbox", { name: "Message", exact: true });
    await composer.fill("Start a long-running check");
    await composer.press("Enter");

    await expect(page.getByText("Working on this request…", { exact: true })).toBeVisible();
    if (stopWith === "button") {
        await page.getByRole("button", { name: "Stop the running turn", exact: true }).click();
    } else {
        await composer.press("Escape");
    }

    await expect(page.getByText("Working on this request…", { exact: true })).toHaveCount(0);
    await expect(page.getByRole("button", { name: "Stop the running turn", exact: true })).toHaveCount(0);
    await expect(composer).toBeEnabled();
    expect(await calls(page)).toEqual(expect.arrayContaining([{ send: "A" }, { stop: "A" }]));
});

test("a management stream resumes after its exact cursor without duplicating output", async ({ page }) => {
    await page.goto("/?app=account-settings&stream-agent=1");
    await expect(page.getByRole("heading", { level: 1 })).toBeVisible();
    await page.getByText("Conversation", { exact: true }).click();
    const composer = page.getByRole("textbox", { name: "Message", exact: true });
    await composer.fill("Keep this turn alive across reconnect");
    await composer.press("Enter");
    await expect(page.getByText("Working on this request…", { exact: true })).toBeVisible();

    await click(page, "Drop stream");
    await click(page, "Advance stream");
    const streamed = page.getByText(/Working on this request…Continued after reconnect\./);
    await expect(streamed).toBeVisible({ timeout: 3_000 });
    expect(((await streamed.textContent()) ?? "").match(/Working on this request…/g)).toHaveLength(1);

    await page.getByRole("button", { name: "Stop the running turn", exact: true }).click();
    await expect(page.getByText("Working on this request…", { exact: true })).toHaveCount(0);
    await expect(page.getByText(/Continued after reconnect\./)).toHaveCount(0);
    expect(await calls(page)).toEqual(expect.arrayContaining([{ send: "A" }, { stop: "A" }]));
});

test("recovery codes are visible only in the issuing account visit", async ({ page }) => {
    await go(page, "account-settings");
    await click(page, "Issue new codes");
    await expect(page.getByRole("region", { name: "New recovery codes" })).toContainText("RECOVERY-A");
    await click(page, "Switch scope");
    await noTransient(page);
    await expect(page.getByLabel("Display name", { exact: true })).toHaveValue("Person B");
});

test("Chromium WebAuthn completes the add-passkey ceremony", async ({ page, browserName }) => {
    test.skip(browserName !== "chromium", "Chromium CDP supplies the hermetic platform authenticator");
    const cdp = await page.context().newCDPSession(page);
    await cdp.send("WebAuthn.enable");
    const { authenticatorId } = await cdp.send("WebAuthn.addVirtualAuthenticator", {
        options: {
            protocol: "ctap2",
            transport: "internal",
            hasResidentKey: true,
            hasUserVerification: true,
            isUserVerified: true,
            automaticPresenceSimulation: true,
        },
    });
    try {
        // WebAuthn's relying-party id is a registrable domain, not an IP
        // address. Keep the hermetic server on loopback while exercising the
        // browser ceremony from the sanctioned localhost secure context.
        await page.goto("http://localhost:7662/?app=account-settings");
        await expect(page.getByRole("heading", { level: 1 })).toBeVisible();
        await click(page, "Add passkey");
        await expect.poll(async () => (await calls(page)).filter((call) => call.command === "account.authenticator.complete-add").length).toBe(1);

        const complete = (await calls(page)).find((call) => call.command === "account.authenticator.complete-add");
        expect(complete).toMatchObject({
            scope: "A",
            payload: {
                ceremony_id: "ceremony-A",
                label: "Passkey",
                attestation: {
                    type: "public-key",
                },
            },
        });
        const attestation = (complete?.payload as { attestation?: Record<string, unknown> })?.attestation;
        const response = attestation?.response as Record<string, unknown> | undefined;
        expect(attestation?.id).toMatch(/^[A-Za-z0-9_-]+$/);
        expect(attestation?.rawId).toMatch(/^[A-Za-z0-9_-]+$/);
        expect(response?.clientDataJSON).toMatch(/^[A-Za-z0-9_-]+$/);
        expect(response?.attestationObject).toMatch(/^[A-Za-z0-9_-]+$/);
        expect(JSON.stringify(complete)).not.toContain("privateKey");

        const credentials = await cdp.send("WebAuthn.getCredentials", { authenticatorId });
        expect(credentials.credentials).toHaveLength(1);
        await expect(page.locator(".gaugeapp-status")).toContainText("Change applied");
    } finally {
        await cdp.send("WebAuthn.removeVirtualAuthenticator", { authenticatorId }).catch(() => undefined);
        await cdp.send("WebAuthn.disable").catch(() => undefined);
        await cdp.detach();
    }
});

test("reviewed account deletion uses a fresh passkey and one retry coordinate through terminal eviction", async ({ page, browserName }, info) => {
    test.skip(browserName !== "chromium", "Chromium CDP supplies the hermetic platform authenticator");
    const cdp = await page.context().newCDPSession(page);
    await cdp.send("WebAuthn.enable");
    const { authenticatorId } = await cdp.send("WebAuthn.addVirtualAuthenticator", {
        options: {
            protocol: "ctap2",
            transport: "internal",
            hasResidentKey: true,
            hasUserVerification: true,
            isUserVerified: true,
            automaticPresenceSimulation: true,
        },
    });
    try {
        await page.goto("http://localhost:7662/?app=account-settings&account-erasure=1");
        await expect(page.getByRole("heading", { name: "Account Settings", exact: true, level: 1 })).toBeVisible();

        // Establish a real discoverable credential for the subsequent fresh
        // authorization assertion; only the fixture authority is synthetic.
        await click(page, "Add passkey");
        await expect.poll(async () => (await calls(page)).filter((call) => call.command === "account.authenticator.complete-add").length).toBe(1);

        await click(page, "Delete");
        const confirmation = page.getByLabel("Enter ERASE MY ACCOUNT to continue", { exact: true });
        const proceed = page.getByRole("button", { name: "Continue", exact: true });
        await expect(proceed).toBeDisabled();
        await confirmation.fill("ERASE MY ACCOUN");
        await expect(proceed).toBeDisabled();
        await confirmation.fill("ERASE MY ACCOUNT");
        await expect(proceed).toBeEnabled();
        await proceed.click();

        const pending = page.getByRole("region", { name: "Pending changes", exact: true });
        await expect(pending).toContainText("Delete account");
        await expect(pending.locator("dl div").first().locator("dd")).toHaveText("A");
        await expect(pending).toContainText("ERASE MY ACCOUNT");
        await expect(pending).toContainText("signs out every device");
        await pending.scrollIntoViewIfNeeded();
        await pending.screenshot({ path: info.outputPath("account-erasure-review.png"), scale: "css" });

        await pending.getByRole("button", { name: "Accept", exact: true }).click();
        await expect(page.getByLabel("Account erasure result", { exact: true })).toHaveText("erased", { timeout: 5_000 });
        await expect(page.getByRole("heading", { name: "Account Settings", exact: true, level: 1 })).toHaveCount(0);

        const recorded = await calls(page);
        expect(recorded.filter((call) => call.authorizationStart === "account.erase")).toHaveLength(1);
        expect(recorded.filter((call) => call.authorizationFinish === "account-erasure-authorization-A")).toEqual([
            expect.objectContaining({ credential: expect.objectContaining({ type: "public-key", hasResponse: true }) }),
        ]);
        const reviews = recorded.filter((call) => call.review === "A");
        expect(reviews).toHaveLength(4);
        expect(new Set(reviews.map((call) => call.idempotencyKey)).size).toBe(1);
        expect(new Set(reviews.map((call) => call.authorizationProof))).toEqual(new Set(["fresh-account-erasure-proof-A"]));
        expect(recorded.at(-1)).toEqual({ accountErased: "A", reviewAttempts: 4 });
        expect(JSON.stringify(recorded)).not.toContain("privateKey");
    } finally {
        await cdp.send("WebAuthn.removeVirtualAuthenticator", { authenticatorId }).catch(() => undefined);
        await cdp.send("WebAuthn.disable").catch(() => undefined);
        await cdp.detach();
    }
});

test("account deletion stays unavailable while the server reports a sole-owner organization", async ({ page }, info) => {
    await page.setViewportSize({ width: 390, height: 844 });
    await page.goto("/?app=account-settings&account-erasure=1&erasure-blocked=1&shell=1");
    await page.getByRole("tablist", { name: "panes" }).getByRole("tab", { name: "Content", exact: true }).click();

    const deletion = page.locator(".gaugeapp-danger-zone").filter({ has: page.getByRole("heading", { name: "Delete account", exact: true }) });
    await expect(deletion).toContainText("Transfer ownership or delete these organizations first: Sole-owner organization");
    await expect(deletion.getByRole("button", { name: "Delete", exact: true })).toBeDisabled();
    await expect(page.getByRole("region", { name: "Pending changes", exact: true })).toHaveCount(0);
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth)).toBe(true);
    await deletion.scrollIntoViewIfNeeded();
    await page.screenshot({ path: info.outputPath("account-erasure-blocked-narrow.png"), scale: "css" });
});

test("account rows expose only lifecycle actions the server admits", async ({ page }) => {
    await go(page, "account-settings");
    const solePasskey = page.locator(".gaugeapp-row").filter({ hasText: "Laptop A" });
    await expect(solePasskey).toContainText("Add another passkey before removing this one.");
    await expect(solePasskey.getByRole("button", { name: "Remove", exact: true })).toHaveCount(0);
    await expect(page.getByRole("button", { name: "Sign out other sessions", exact: true })).toHaveCount(0);
    await click(page, "Leave");
    const submitted = await calls(page);
    expect(submitted).toContainEqual({ command: "account.membership.leave", scope: "A", payload: { tenant_id: "organization-A" } });
    await expect(page.getByText("Personal", { exact: true })).toBeVisible();
    await expect(page.getByText("Personal", { exact: true }).locator(".."))
        .not.toContainText("Leave");
});

test("automatic keep is Project Host authority and survives a browser reload", async ({ page }, info) => {
    const run = `project-host-settings-${info.parallelIndex}-${Date.now()}`;
    await page.goto(`/?app=account-settings&all-pages=1&project-host-settings=1&run=${run}`);
    await click(page, "Application Settings");

    await expect(page.getByRole("heading", { name: "Automatic keep", exact: true })).toBeVisible();
    await expect(page.getByText("Off — every changed turn waits for review.", { exact: true })).toBeVisible();
    await page.getByLabel("Path or glob", { exact: true }).fill("docs/**");
    await page.getByRole("button", { name: "Add", exact: true }).click();
    await expect(page.getByText("docs/**", { exact: true })).toBeVisible();

    const submitted = await calls(page);
    expect(submitted).toContainEqual({
        projectHostSetting: "advancement.rules",
        value: JSON.stringify({ version: 1, rules: [{ advance: "writes-within", paths: ["docs/**"] }] }),
    });

    await page.reload();
    await click(page, "Application Settings");
    await expect(page.getByText("docs/**", { exact: true })).toBeVisible();
    await page.getByRole("button", { name: "Remove docs/**", exact: true }).click();
    await expect(page.getByText("Off — every changed turn waits for review.", { exact: true })).toBeVisible();
});

test("account appearance applies to the whole Desk and survives authoritative reload", async ({ page }, info) => {
    const run = `appearance-${info.parallelIndex}-${Date.now()}`;
    await page.goto(`/?app=account-settings&all-pages=1&appearance=1&run=${run}&shell=1`);
    await expect(page.locator("html")).toHaveAttribute("data-gw-interface-scale", "standard");
    await click(page, "Application Settings");
    await expect(page.getByText("Using product defaults", { exact: true })).toBeVisible();

    await page.getByLabel("Interface size", { exact: true }).selectOption("large");
    await expect(page.getByText("Saved for your account", { exact: true })).toBeVisible();
    await expect(page.locator("html")).toHaveAttribute("data-gw-interface-scale", "large");
    await page.getByLabel("Contrast", { exact: true }).selectOption("high");
    await expect(page.locator("html")).toHaveAttribute("data-gw-contrast", "high");
    await page.getByLabel("Motion", { exact: true }).selectOption("reduced");
    await expect(page.locator("html")).toHaveAttribute("data-gw-motion", "reduced");
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth)).toBe(true);
    await page.screenshot({ path: info.outputPath("appearance-large-desktop.png"), scale: "css" });

    const submitted = await calls(page);
    expect(submitted.filter((entry) => entry.command === "application-settings.appearance.set").map((entry) => entry.payload)).toEqual([
        { value: { version: 1, interface_scale: "large", contrast: "standard", motion: "system" } },
        { value: { version: 1, interface_scale: "large", contrast: "high", motion: "system" } },
        { value: { version: 1, interface_scale: "large", contrast: "high", motion: "reduced" } },
    ]);

    await page.reload();
    await expect(page.locator("html")).toHaveAttribute("data-gw-interface-scale", "large");
    await expect(page.locator("html")).toHaveAttribute("data-gw-contrast", "high");
    await expect(page.locator("html")).toHaveAttribute("data-gw-motion", "reduced");
    await click(page, "Application Settings");
    await expect(page.getByText("Saved for your account", { exact: true })).toBeVisible();
    await page.setViewportSize({ width: 390, height: 844 });
    await page.getByRole("tablist", { name: "panes" }).getByRole("tab", { name: "Content", exact: true }).click();
    await expect(page.getByRole("heading", { name: "Appearance & accessibility", exact: true })).toBeVisible();
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth)).toBe(true);
    await page.screenshot({ path: info.outputPath("appearance-large-narrow.png"), scale: "css" });
});

test("automatic keep fails visibly when the current Project Host is unavailable", async ({ page }) => {
    await page.goto("/?app=account-settings&all-pages=1");
    await click(page, "Application Settings");

    await expect(page.getByRole("heading", { name: "Automatic keep", exact: true })).toBeVisible();
    await expect(page.getByText("The current Project Host’s settings are unavailable.", { exact: true })).toBeVisible();
    await expect(page.getByLabel("Path or glob", { exact: true })).toHaveCount(0);
    await page.getByRole("button", { name: "Retry", exact: true }).click();
    await expect(page.getByText("The current Project Host’s settings are unavailable.", { exact: true })).toBeVisible();
});

test("account profile, recovery, invitations, and memberships reread server truth after reload", async ({ page }, info) => {
    const run = `account-lifecycle-${info.parallelIndex}-${Date.now()}`;
    await page.goto(`/?app=account-settings&account-lifecycle=1&run=${run}`);
    await expect(page.getByRole("heading", { name: "Account Settings", exact: true, level: 1 })).toBeVisible();
    await expect(page.getByText("Invited organization", { exact: true })).toBeVisible();

    await page.getByLabel("Display name", { exact: true }).fill("Avery Morgan");
    await click(page, "Save");
    await expect(page.getByLabel("Display name", { exact: true })).toHaveValue("Avery Morgan");

    await click(page, "Issue new codes");
    await expect(page.getByRole("region", { name: "New recovery codes" })).toContainText("RECOVERY-A");
    await expect(page.getByText("8 codes remaining", { exact: true })).toBeVisible();

    const backupKey = page.locator(".gaugeapp-row").filter({ hasText: "Backup key A" });
    await backupKey.getByRole("button", { name: "Remove", exact: true }).click();
    await expect(page.getByRole("region", { name: "Pending changes" })).toBeVisible();
    await page.getByRole("region", { name: "Pending changes" }).getByRole("button", { name: "Accept", exact: true }).click();
    await expect(backupKey).toHaveCount(0);
    const remainingPasskey = page.locator(".gaugeapp-row").filter({ hasText: "Laptop A" });
    await expect(remainingPasskey).toContainText("Add another passkey before removing this one.");
    await expect(remainingPasskey.getByRole("button", { name: "Remove", exact: true })).toHaveCount(0);

    const phoneSession = page.locator(".gaugeapp-row").filter({ hasText: "Phone passkey" });
    await phoneSession.getByRole("button", { name: "Sign out", exact: true }).click();
    await page.getByRole("region", { name: "Pending changes" }).getByRole("button", { name: "Accept", exact: true }).click();
    await expect(phoneSession).toHaveCount(0);

    await click(page, "Sign out other sessions");
    await page.getByRole("region", { name: "Pending changes" }).getByRole("button", { name: "Accept", exact: true }).click();
    await expect(page.getByText("Browser sign-in", { exact: true })).toHaveCount(0);
    await expect(page.getByText("This session", { exact: true })).toBeVisible();
    await expect(page.getByRole("button", { name: "Sign out other sessions", exact: true })).toHaveCount(0);

    const invited = page.locator(".gaugeapp-row").filter({ hasText: "Invited organization" });
    await invited.getByRole("button", { name: "Accept", exact: true }).click();
    await expect(invited.getByRole("button", { name: "Accept", exact: true })).toHaveCount(0);
    await expect(invited).toContainText("member");

    const declined = page.locator(".gaugeapp-row").filter({ hasText: "Second invitation" });
    await declined.getByRole("button", { name: "Decline", exact: true }).click();
    await expect(declined).toHaveCount(0);

    const organization = page.locator(".gaugeapp-row").filter({ has: page.getByText("Organization A", { exact: true }) });
    await organization.getByRole("button", { name: "Leave", exact: true }).click();
    await expect(organization).toHaveCount(0);
    await expect(page.getByText("Personal", { exact: true }).locator("..")).not.toContainText("Leave");
    await page.screenshot({ path: info.outputPath("account-lifecycle.png"), scale: "css" });

    await page.reload();
    await expect(page.getByLabel("Display name", { exact: true })).toHaveValue("Avery Morgan");
    await expect(page.getByText("8 codes remaining", { exact: true })).toBeVisible();
    await expect(page.getByText("Backup key A", { exact: true })).toHaveCount(0);
    await expect(page.getByText("Phone passkey", { exact: true })).toHaveCount(0);
    await expect(page.getByText("Browser sign-in", { exact: true })).toHaveCount(0);
    await expect(page.getByText("This session", { exact: true })).toBeVisible();
    await expect(page.getByText("Invited organization", { exact: true })).toBeVisible();
    await expect(page.getByText("Organization A", { exact: true })).toHaveCount(0);
    await expect(page.getByText("Second invitation", { exact: true })).toHaveCount(0);
    await expect(page.locator("body")).not.toContainText("RECOVERY-A");
});

test("Trusted Devices completes QR/code pairing with matching SAS and non-extractable retained keys", async ({ page }, info) => {
    await page.goto("/?app=account-settings&device-link=1");
    await expect(page.getByRole("heading", { name: "Trusted Devices", exact: true, level: 1 })).toBeVisible();
    await click(page, "New code");
    await expect(page.locator(".gaugeapp-device-qr svg")).toBeVisible();
    await expect(page.getByText("ABCD-EF12", { exact: true })).toBeVisible();

    await page.getByLabel("Link code").fill("ABCD-EF12");
    await page.getByLabel("Device name").fill("Alice’s phone");
    await page.getByLabel("Kind").selectOption("phone");
    await click(page, "Continue");
    await expect(page.getByText("381947", { exact: true })).toHaveCount(2);
    await page.screenshot({ path: info.outputPath("trusted-device-compare.png"), scale: "css" });
    await click(page, "Codes match — accept");

    await expect(page.getByText("Alice’s phone is linked.", { exact: true })).toBeVisible({ timeout: 5_000 });
    await expect(page.getByText("This session", { exact: true })).toBeVisible();
    expect(await retainedDeviceCredentials(page)).toEqual([{
        key: "device:device-phone",
        ecdhExtractable: false,
        accountExtractable: false,
    }]);
    expect(JSON.stringify(await calls(page))).not.toContain("privateKey");
});

test("rejecting a device link forgets the receiving device's pending private key", async ({ page }) => {
    await page.goto("/?app=account-settings&device-link=1");
    await expect(page.getByRole("heading", { name: "Trusted Devices", exact: true, level: 1 })).toBeVisible();
    await click(page, "New code");
    await page.getByLabel("Link code").fill("ABCD-EF12");
    await page.getByLabel("Device name").fill("Unknown phone");
    await page.getByLabel("Kind").selectOption("phone");
    await click(page, "Continue");
    await expect(page.getByText("381947", { exact: true })).toHaveCount(2);
    expect((await retainedDeviceCredentials(page)).map((record) => record.key)).toEqual(["link:device-link-a"]);

    await click(page, "Does not match");
    await expect(page.getByText("The device was rejected. No account material was admitted.", { exact: true })).toBeVisible();
    await expect.poll(async () => retainedDeviceCredentials(page)).toEqual([]);
});

test("Backups exposes the admitted protection, holder, schedule, and point controls", async ({ page }, info) => {
    await go(page);
    await click(page, "Backups");
    await expect(page.getByRole("heading", { name: "Backups", exact: true, level: 1 })).toBeVisible();
    await expect(page.getByText("Studio Host A", { exact: true })).toBeVisible();
    await expect(page.locator(".gaugeapp-backup-summary").getByText("2.5 MB", { exact: true })).toBeVisible();
    await page.getByLabel("Backup interval in days").fill("2");
    await page.getByLabel("Backup retention in days").fill("45");
    await click(page, "Save");
    await click(page, "Create point");
    await click(page, "Add this device");
    await click(page, "Pause");
    const submitted = await calls(page);
    expect(submitted).toContainEqual({ command: "backups.schedule.set", scope: "A", payload: { schedule_days: 2, retention_days: 45 } });
    expect(submitted).toContainEqual({ command: "backups.point.create", scope: "A", payload: {} });
    expect(submitted).toContainEqual({ command: "backups.disable", scope: "A", payload: {} });
    const holder = submitted.find((call) => call.command === "backups.recovery-holder.add");
    expect(holder).toMatchObject({ scope: "A", payload: { label: "This GaugeDesk device" } });
    expect((holder?.payload as { public_key?: string }).public_key).toMatch(/^04[0-9a-f]+$/);
    expect(JSON.stringify(submitted)).not.toContain("privateKey");
    await page.screenshot({ path: info.outputPath("backups-controls.png"), scale: "css" });
});

test("a retired begin-passkey response never opens a browser ceremony", async ({ page }) => {
    await page.addInitScript(() => { Object.defineProperty(navigator.credentials, "create", { value: async () => { document.body.dataset.passkeyStarted = "yes"; return null; } }); });
    await go(page, "account-settings");
    await click(page, "Hold: off");
    await click(page, "Add passkey");
    await click(page, "Switch scope");
    await click(page, "Resolve oldest");
    await noTransient(page);
    await expect(page.locator("body")).not.toHaveAttribute("data-passkey-started", "yes");
});

test("scope departure aborts the passkey prompt and rejects even an abort-ignoring late return", async ({ page }) => {
    await page.addInitScript(() => Object.defineProperty(navigator.credentials, "create", { value: (options: CredentialCreationOptions) => new Promise((resolve) => {
        document.body.dataset.passkeyStarted = "yes";
        options.signal?.addEventListener("abort", () => { document.body.dataset.passkeyAborted = "yes"; });
        const button = document.createElement("button"); button.textContent = "Finish fixture passkey";
        button.onclick = () => { button.remove(); resolve(null); };
        document.querySelector("nav")!.append(button);
    }) }));
    await go(page, "account-settings");
    await click(page, "Add passkey");
    await expect(page.locator("body")).toHaveAttribute("data-passkey-started", "yes");
    await click(page, "Switch scope");
    await expect(page.locator("body")).toHaveAttribute("data-passkey-aborted", "yes");
    await click(page, "Finish fixture passkey");
    await noTransient(page);
    expect((await calls(page)).filter((call) => call.command === "account.authenticator.complete-add")).toHaveLength(0);
});

test("personal key intake clears immediately and cannot report into the next account", async ({ page }) => {
    await go(page, "account-settings");
    await click(page, "Provider Connections");
    await click(page, "Add connection");
    for (const close of ["Close", "Cancel"]) {
        await page.getByLabel("API key", { exact: true }).fill("synthetic-not-a-key");
        await click(page, close);
        await click(page, "Add connection");
        await expect(page.getByLabel("API key", { exact: true })).toHaveValue("");
    }
    await page.getByLabel("API key", { exact: true }).fill("synthetic-not-a-key");
    await click(page, "Hold: off");
    await click(page, "Connect");
    await expect(page.getByLabel("API key", { exact: true })).toHaveValue("");
    await click(page, "Switch scope");
    await click(page, "Resolve oldest");
    await noTransient(page);
    expect(JSON.stringify(await calls(page))).not.toContain("synthetic-not-a-key");
});

test("personal provider connections advance from sealed intake through verification, default selection, rename, and revocation", async ({ page }, info) => {
    await page.goto("/?app=account-settings&provider-lifecycle=1");
    await expect(page.getByRole("heading", { name: "Provider Connections", exact: true, level: 1 })).toBeVisible();
    await click(page, "Add connection");
    await page.getByLabel("Connection type").selectOption("openai-generic");
    await page.getByLabel("Name", { exact: true }).fill("Research gateway");
    await page.getByLabel("Endpoint", { exact: true }).fill("https://models.example.test/v1");
    await page.getByLabel("Models", { exact: true }).fill("research-small, research-large");
    await page.getByLabel("API key", { exact: true }).fill("synthetic-provider-secret");
    await click(page, "Connect");

    const row = page.locator(".gaugeapp-provider-row").filter({ hasText: "Research gateway" });
    await expect(row).toContainText("unverified");
    const defaultModelPanel = page.locator(".gaugeapp-panel").filter({
        has: page.getByRole("heading", { name: "Default model", exact: true }),
    });
    const defaultModel = defaultModelPanel.locator("select");
    await expect(defaultModel.locator("option")).toHaveCount(1);
    await row.getByRole("button", { name: "Verify", exact: true }).click();
    await expect(row).toContainText("reachable");
    await expect(defaultModel.locator("option", { hasText: "research-small · Research gateway" })).toHaveCount(1);

    await row.getByRole("button", { name: "Rename", exact: true }).click();
    const renameField = page.getByLabel("Rename Research gateway", { exact: true });
    await renameField.fill("Research models");
    await renameField.locator("xpath=ancestor::div[contains(@class,'gaugeapp-provider-row')]").getByRole("button", { name: "Save", exact: true }).click();
    const renamed = page.locator(".gaugeapp-provider-row").filter({ hasText: "Research models" });
    await expect(renamed).toBeVisible();
    await defaultModel.selectOption({ label: "research-large · Research models" });
    await defaultModelPanel.getByRole("button", { name: "Save", exact: true }).click();
    await expect.poll(async () => await calls(page)).toEqual(expect.arrayContaining([
        { command: "provider-connection.default-model.set", scope: "A", payload: { connection_id: "openai-generic", model: "research-large" } },
    ]));
    await expect(defaultModel).toHaveValue(JSON.stringify(["openai-generic", "research-large"]));
    await page.screenshot({ path: info.outputPath("provider-connection-default.png"), scale: "css", fullPage: true });

    await renamed.getByRole("button", { name: "Revoke", exact: true }).click();
    await expect(renamed).toContainText("revoked");
    await expect(renamed.getByRole("button", { name: "Rename", exact: true })).toBeDisabled();
    await expect(renamed.getByRole("button", { name: "Verify", exact: true })).toBeDisabled();
    await expect(renamed.getByRole("button", { name: "Revoke", exact: true })).toBeDisabled();
    await expect(defaultModel.locator("option")).toHaveCount(1);
    expect(JSON.stringify(await calls(page))).not.toContain("synthetic-provider-secret");
    expect(await calls(page)).toEqual(expect.arrayContaining([
        { intake: "A", command: "provider-connection.compatible.add", length: 25 },
        { command: "provider-connection.verify", scope: "A", payload: { id: "openai-generic" } },
        { command: "provider-connection.rename", scope: "A", payload: { id: "openai-generic", label: "Research models" } },
        { command: "provider-connection.default-model.set", scope: "A", payload: { connection_id: "openai-generic", model: "research-large" } },
        { command: "provider-connection.revoke", scope: "A", payload: { id: "openai-generic" } },
    ]));
});

test("Grok account sign-in stays server-owned and becomes a verified personal connection", async ({ page }, info) => {
    await page.addInitScript(() => Object.defineProperty(window, "open", {
        configurable: true,
        value: (url: string | URL | undefined) => {
            document.documentElement.dataset.providerWindow = String(url ?? "");
            return null;
        },
    }));
    await page.goto("/?app=account-settings&provider-lifecycle=1");
    await expect(page.getByRole("heading", { name: "Provider Connections", exact: true, level: 1 })).toBeVisible();
    const grok = page.locator(".gaugeapp-provider-account-row").filter({ hasText: "Grok" });
    await grok.getByRole("button", { name: "Sign in", exact: true }).click();
    await expect(page.locator("html")).toHaveAttribute("data-provider-window", "https://accounts.x.ai/device");
    await expect(grok.getByText("GROK-4821", { exact: true })).toBeVisible();
    await expect(grok.getByRole("link", { name: "Open", exact: true })).toHaveAttribute("href", "https://accounts.x.ai/device");
    await grok.getByRole("button", { name: "I finished", exact: true }).click();
    await expect(grok).toContainText("Connected");
    const connection = page.locator(".gaugeapp-provider-row").filter({ hasText: "Grok" });
    await expect(connection).toContainText("reachable");
    const defaultModelPanel = page.locator(".gaugeapp-panel").filter({
        has: page.getByRole("heading", { name: "Default model", exact: true }),
    });
    await expect(defaultModelPanel.locator("select option", { hasText: "grok-4 · Grok" })).toHaveCount(1);
    await page.screenshot({ path: info.outputPath("grok-account-connected.png"), scale: "css", fullPage: true });
    expect(await calls(page)).toEqual(expect.arrayContaining([
        { command: "provider-connection.subscription.begin", scope: "A", payload: { provider: "xai-grok" } },
        { command: "provider-connection.subscription.complete", scope: "A", payload: { provider: "xai-grok", action: "status" } },
    ]));
});

test("Provider Connections exposes only controls admitted by the current session", async ({ page }) => {
    await page.goto("/?app=account-settings&all-pages=1");
    await click(page, "Provider Connections");
    await expect(page.getByRole("button", { name: "Add connection", exact: true })).toHaveCount(0);
    await expect(page.locator(".gaugeapp-provider-account-row").getByRole("button", { name: "Sign in", exact: true })).toHaveCount(2);
    for (const button of await page.locator(".gaugeapp-provider-account-row").getByRole("button", { name: "Sign in", exact: true }).all()) {
        await expect(button).toBeDisabled();
    }
});

test("a retired payment session cannot initialize; a mounted one logs out on departure", async ({ page }) => {
    await go(page, "commercial-operations");
    await click(page, "Hold: off");
    await click(page, "Account");
    await click(page, "Switch scope");
    await click(page, "Resolve oldest");
    await expect(page.getByLabel("Stripe events")).toHaveText("");
    await click(page, "Hold: on");
    await click(page, "Account");
    await expect(page.getByText("Embedded payment tool", { exact: true })).toBeVisible();
    await click(page, "Switch scope");
    await expect(page.getByText("Embedded payment tool", { exact: true })).toHaveCount(0);
    await expect(page.getByLabel("Stripe events")).toContainText("logged out");
});

test("Stripe disputes and reviewed GaugeDesk refunds remain separate paths", async ({ page }) => {
    await go(page, "commercial-operations");
    await expect(page.getByRole("button", { name: "Disputes", exact: true })).toBeVisible();
    await click(page, "Disputes");
    await click(page, "Resolve oldest");
    await expect(page.getByText("Embedded payment tool", { exact: true })).toBeVisible();
    expect(await calls(page)).toEqual(expect.arrayContaining([
        expect.objectContaining({
            command: "commercial-payments.connect-component.open",
            payload: { component: "payments" },
        }),
    ]));
});

test("switching payment tools also fences a late session without leaving the page", async ({ page }) => {
    await go(page, "commercial-operations");
    await click(page, "Hold: off");
    await click(page, "Account");
    await click(page, "Documents");
    await expect(page.getByLabel("Pending requests")).toHaveText("2");
    await click(page, "Resolve oldest");
    await expect(page.getByLabel("Stripe events")).toHaveText("");
    await expect(page.getByText("Embedded payment tool", { exact: true })).toHaveCount(0);
    await click(page, "Resolve oldest");
    await expect(page.getByText("Embedded payment tool", { exact: true })).toBeVisible();
    await expect(page.getByLabel("Stripe events")).toHaveText("initialized, session received");
});
