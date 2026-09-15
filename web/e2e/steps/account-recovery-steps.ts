/** Provider-neutral recovery through the shipped Desk and account authority. */

import { expect, type CDPSession } from "@playwright/test";
import { createBdd } from "playwright-bdd";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { enterpriseAppURL, enterpriseCP, enterpriseState } from "../ports.mjs";
import { mutationHeaders } from "./idempotency";

const { Given, When, Then, After } = createBdd();
const email = "recovery-fixture@gaugewright.test";
const recoveryCode = "GW-E2E-RECOVERY";
const passkeyCP = enterpriseCP.replace("127.0.0.1", "localhost");
const passkeyApp = enterpriseAppURL.replace("127.0.0.1", "localhost");
let challengeId = "";
let emailCode = "";
let passkeyCdp: CDPSession | undefined;
let passkeyAuthenticator = "";
let passkeyAccount = "";
let passkeyTenantProjection = "";

After(async () => {
    if (!passkeyCdp) return;
    if (passkeyAuthenticator) {
        await passkeyCdp.send("WebAuthn.removeVirtualAuthenticator", {
            authenticatorId: passkeyAuthenticator,
        }).catch(() => undefined);
    }
    await passkeyCdp.send("WebAuthn.disable").catch(() => undefined);
    await passkeyCdp.detach().catch(() => undefined);
    passkeyCdp = undefined;
    passkeyAuthenticator = "";
    passkeyAccount = "";
    passkeyTenantProjection = "";
});

Given("a recoverable GaugeDesk account exists", async ({ page, request }) => {
    const reset = await request.post(`${enterpriseCP}/test/reset?account_recovery=true`, {
        headers: mutationHeaders(),
    });
    expect(reset.status()).toBe(200);
    await page.context().clearCookies();
    await page.goto(`${enterpriseAppURL}?cp=${encodeURIComponent(enterpriseCP)}`);
    await expect(page.getByRole("heading", { name: "Sign in" })).toBeVisible();
    await page.getByRole("button", { name: "Use a recovery code" }).click();
});

When("I recover it with the delivered email proof and recovery code", async ({ page }) => {
    await page.getByLabel("Verified email").fill(email);
    const started = page.waitForResponse((response) =>
        response.request().method() === "POST"
        && new URL(response.url()).pathname === "/auth/account/recovery/start"
    );
    await page.getByRole("button", { name: "Send code" }).click();
    const startResponse = await started;
    expect(startResponse.status()).toBe(202);
    challengeId = String((await startResponse.json()).challenge_id ?? "");
    expect(challengeId).not.toBe("");

    const delivered = JSON.parse(await readFile(
        join(enterpriseState, "test-auth-email.json"),
        "utf8",
    )) as { email?: string; code?: string; purpose?: string };
    expect(delivered).toMatchObject({ email, purpose: "recovery" });
    emailCode = delivered.code ?? "";
    expect(emailCode).toMatch(/^\d{8}$/);

    await page.getByLabel("Email code").fill(emailCode);
    await page.getByLabel("Recovery code").fill(recoveryCode);
    const finished = page.waitForResponse((response) =>
        response.request().method() === "POST"
        && new URL(response.url()).pathname === "/auth/account/recovery/finish"
    );
    await page.getByRole("button", { name: "Recover account" }).click();
    expect((await finished).status()).toBe(200);
    await expect(page.locator("[data-account-entry]")).toHaveCount(0);
});

Then("Desk re-enters the same account through a persistent recovery session", async ({ page }) => {
    const session = await page.request.get(`${enterpriseCP}/auth/session`);
    expect(session.status()).toBe(200);
    const body = await session.json() as { method?: string; label?: string };
    expect(body.method).toBe("recovery");
    expect(body.label).toBe("Recovery code");

    await page.reload();
    await expect(page.locator("[data-account-entry]")).toHaveCount(0);
    const refreshed = await page.request.get(`${enterpriseCP}/auth/session`);
    expect(refreshed.status()).toBe(200);
    expect(await refreshed.json()).toMatchObject({ method: "recovery", label: "Recovery code" });
});

Then("the used recovery proof cannot mint another session", async ({ page }) => {
    await page.context().clearCookies();
    const replay = await page.evaluate(async ({ base, challenge, delivered, recovery }) => {
        const response = await fetch(`${base}/auth/account/recovery/finish`, {
            method: "POST",
            credentials: "include",
            headers: {
                "content-type": "application/json",
                "idempotency-key": crypto.randomUUID(),
            },
            body: JSON.stringify({
                challenge_id: challenge,
                email_code: delivered,
                recovery_code: recovery,
            }),
        });
        return { status: response.status, message: await response.text() };
    }, { base: enterpriseCP, challenge: challengeId, delivered: emailCode, recovery: recoveryCode });
    expect(replay).toEqual({
        status: 401,
        message: "invalid or expired authentication proof",
    });
    const session = await page.request.get(`${enterpriseCP}/auth/session`);
    expect(session.status()).toBe(401);
});

Given("a new visitor has a platform passkey authenticator", async ({ page, request }) => {
    const reset = await request.post(`${enterpriseCP}/test/reset`, {
        headers: mutationHeaders(),
    });
    expect(reset.status()).toBe(200);
    await page.context().clearCookies();
    passkeyCdp = await page.context().newCDPSession(page);
    await passkeyCdp.send("WebAuthn.enable");
    const created = await passkeyCdp.send("WebAuthn.addVirtualAuthenticator", {
        options: {
            protocol: "ctap2",
            transport: "internal",
            hasResidentKey: true,
            hasUserVerification: true,
            isUserVerified: true,
            automaticPresenceSimulation: true,
        },
    });
    passkeyAuthenticator = created.authenticatorId;
    await page.goto(`${passkeyApp}?cp=${encodeURIComponent(passkeyCP)}`);
    await expect(page.getByRole("heading", { name: "Sign in" })).toBeVisible();
    await page.getByRole("button", { name: "Create an account" }).click();
});

When("I create an account with delivered email verification and that passkey", async ({ page }) => {
    await page.getByLabel("Your name").fill("Passkey Person");
    await page.getByLabel("Email", { exact: true }).fill("passkey-fixture@gaugewright.test");
    const started = page.waitForResponse((response) =>
        response.request().method() === "POST"
        && new URL(response.url()).pathname === "/auth/account/email/start"
    );
    await page.getByRole("button", { name: "Send verification code" }).click();
    expect((await started).status()).toBe(202);

    const delivered = JSON.parse(await readFile(
        join(enterpriseState, "test-auth-email.json"),
        "utf8",
    )) as { email?: string; code?: string; purpose?: string };
    expect(delivered).toMatchObject({
        email: "passkey-fixture@gaugewright.test",
        purpose: "verification",
    });
    expect(delivered.code).toMatch(/^\d{8}$/);
    await page.getByLabel("Email code").fill(delivered.code ?? "");

    const finished = page.waitForResponse((response) =>
        response.request().method() === "POST"
        && new URL(response.url()).pathname === "/auth/account/passkey/register/finish"
    );
    await page.getByRole("button", { name: "Create passkey account" }).click();
    const response = await finished;
    expect(response.status()).toBe(200);
    const body = await response.json() as { account_id?: string };
    passkeyAccount = body.account_id ?? "";
    expect(passkeyAccount).not.toBe("");
    await expect(page.locator("[data-account-entry]")).toHaveCount(0);
});

Then("Desk enters the new account through a persistent passkey session", async ({ page }) => {
    const session = await page.request.get(`${passkeyCP}/auth/session`);
    expect(session.status()).toBe(200);
    expect(await session.json()).toMatchObject({
        method: "passkey",
        label: "Passkey or security key",
    });
    const projection = await page.evaluate(async (base) => {
        const response = await fetch(`${base}/account/tenants`, { credentials: "include" });
        return { status: response.status, body: await response.text() };
    }, passkeyCP);
    expect(projection.status).toBe(200);
    passkeyTenantProjection = projection.body;
    expect(JSON.parse(passkeyTenantProjection)).toMatchObject({ tenants: expect.any(Array) });
    await page.reload();
    await expect(page.locator("[data-account-entry]")).toHaveCount(0);
});

When("I sign out and use the same passkey again", async ({ page }) => {
    const logout = await page.request.post(`${passkeyCP}/auth/logout`, {
        headers: mutationHeaders(),
    });
    expect(logout.status()).toBe(204);
    await page.reload();
    await expect(page.locator("[data-account-entry]")).toBeVisible();
    await page.getByRole("button", { name: "Sign in with a passkey" }).click();
    await page.getByLabel("Account email").fill("passkey-fixture@gaugewright.test");
    const finished = page.waitForResponse((response) =>
        response.request().method() === "POST"
        && new URL(response.url()).pathname === "/auth/account/passkey/login/finish"
    );
    await page.getByRole("button", { name: "Continue with passkey" }).click();
    expect((await finished).status()).toBe(200);
    await expect(page.locator("[data-account-entry]")).toHaveCount(0);
});

Then("Desk re-enters the same passkey account", async ({ page }) => {
    const session = await page.request.get(`${passkeyCP}/auth/session`);
    expect(session.status()).toBe(200);
    expect(await session.json()).toMatchObject({
        method: "passkey",
        label: "Passkey or security key",
    });
    const projection = await page.evaluate(async (base) => {
        const response = await fetch(`${base}/account/tenants`, { credentials: "include" });
        return { status: response.status, body: await response.text() };
    }, passkeyCP);
    expect(projection).toEqual({ status: 200, body: passkeyTenantProjection });
    if (!passkeyCdp || !passkeyAuthenticator) throw new Error("passkey authenticator missing");
    const credentials = await passkeyCdp.send("WebAuthn.getCredentials", {
        authenticatorId: passkeyAuthenticator,
    });
    expect(credentials.credentials).toHaveLength(1);
});
