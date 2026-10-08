/**
 * The signed-in desktop window (WS-871).
 *
 * The desktop window is served from its own origin (`tauri://localhost`) and
 * calls the control plane on loopback, so every request carrying the window's
 * account session is preceded by a CORS preflight. Signed in, the shell hands
 * the window a Home session over IPC (DR-0188, `home_session`), and the window
 * presents it on its Home requests. The rest of the suite drives the window
 * signed out, which presents nothing — so when 0.8.7's project gate refused the
 * credential-less preflights of a signed-in window, every chat start failed
 * with "Load failed" and nothing here noticed.
 *
 * These steps stand in for that shell: sign in through the native handoff,
 * take the session the shell would hand over (a debug-only, guarded fixture
 * route; the real handover never crosses HTTP), and present it through the
 * same `__TAURI_INTERNALS__` seam the window reads it from. The preview origin
 * differs from the control plane's, as the desktop's does, so the preflights
 * are real. Every request to the control plane that fails at the network
 * layer is recorded, so a red names the request rather than a timeout.
 */

import { expect, type Page } from "@playwright/test";
import { createBdd } from "playwright-bdd";
import { aliceCP, previewURL } from "../ports.mjs";
import { beginSignIn, deliverSignInReturn } from "./hub-session-steps";
import { mutationHeaders } from "./idempotency";
import { openAccountMenu } from "./settings-nav";

const { Given, Then, After } = createBdd();

const controlPlane = new URL(aliceCP).origin;

/** Network-layer failures of control-plane requests, and the requests that
 *  presented the window's account session, since the window signed in. */
const observed = new WeakMap<Page, { failed: Failed[]; presented: string[] }>();

interface Failed {
    method: string;
    path: string;
    errorText: string;
    headers: Record<string, string>;
}

function describe({ method, path, errorText }: Failed): string {
    return `${method} ${path} — ${errorText}`;
}

/** A request the page itself ended (a reload, a closed stream) is not a
 *  refusal: Chrome reports it as ERR_ABORTED, and WebKit as "Load request
 *  cancelled" on Linux and "cancelled" on macOS. A refused preflight reads
 *  ERR_FAILED in Chrome and "Preflight response is not successful" in WebKit,
 *  and is kept. */
function abandoned(errorText: string): boolean {
    return /ERR_ABORTED|NS_BINDING_ABORTED|^(Load request )?cancelled$/.test(errorText);
}

Given("I am signed in to my GaugeWright account on this desktop", async ({ page, request }) => {
    await openAccountMenu(page);
    await beginSignIn(page);
    await deliverSignInReturn(page, "gaugewright://auth/callback#code=e2e-handoff-code");

    // What the shell's `home_session` command would answer now.
    const response = await request.post(`${aliceCP}/test/desktop-home-session`, { headers: mutationHeaders() });
    expect(response.status(), await response.text()).toBe(200);
    const { token } = (await response.json()) as { token: string | null };
    expect(token, "a signed-in desktop's shell hands its window a Home session").toBeTruthy();
    await page.addInitScript((session) => {
        Object.defineProperty(window, "__TAURI_INTERNALS__", {
            configurable: true,
            value: { invoke: async (command: string) => (command === "home_session" ? session : null) },
        });
    }, token);

    await page.reload();
    const record = { failed: [] as Failed[], presented: [] as string[] };
    observed.set(page, record);
    page.on("requestfailed", (failed) => {
        const url = new URL(failed.url());
        const errorText = failed.failure()?.errorText ?? "";
        if (url.origin === controlPlane && !abandoned(errorText)) {
            record.failed.push({ method: failed.method(), path: url.pathname + url.search, errorText, headers: failed.headers() });
        }
    });
    page.on("request", (sent) => {
        const url = new URL(sent.url());
        if (url.origin === controlPlane && sent.headers().authorization === `Bearer ${token}`) {
            record.presented.push(`${sent.method()} ${url.pathname}`);
        }
    });
    await expect(page.locator("[data-account-menu-trigger]")).not.toContainText("Sign in");
});

Then("the window presented its account session to start the chat", async ({ page }) => {
    const record = observed.get(page);
    expect(record, "the window signed in first").toBeDefined();
    expect(
        record!.presented.filter((line) => /^POST \/(projects\/[^/]+\/placements\/[^/]+\/chats|chats)$/.test(line)),
        `requests that carried the session: ${record!.presented.join(", ") || "none"}`,
    ).not.toHaveLength(0);
});

Then("no request to the control plane failed", async ({ page }) => {
    const record = observed.get(page);
    expect(record, "the window signed in first").toBeDefined();
    expect(record!.failed.map(describe), "control-plane requests that failed at the network layer").toEqual([]);
});

// A failed request in a browser is opaque: Chrome says "Failed to fetch" and
// WebKit "Load failed", whatever the server answered. So on a red, ask the
// control plane what it answered to each failed request's CORS preflight, and
// print that, so the transcript names the refusal rather than a timeout.
After(async ({ page, request, $testInfo }) => {
    const record = observed.get(page);
    if (!record?.failed.length || $testInfo.status === $testInfo.expectedStatus) return;
    const lines = [];
    for (const failed of record.failed.slice(0, 8)) {
        const asked = Object.keys(failed.headers)
            .filter((name) => !["accept", "user-agent", "referer", "origin", "content-length"].includes(name.toLowerCase()))
            .join(",");
        const preflight = await request.fetch(`${aliceCP}${failed.path}`, {
            method: "OPTIONS",
            headers: {
                Origin: new URL(previewURL).origin,
                "Access-Control-Request-Method": failed.method,
                ...(asked ? { "Access-Control-Request-Headers": asked } : {}),
            },
            failOnStatusCode: false,
        }).catch((error: unknown) => error);
        const answer = preflight instanceof Error
            ? `preflight failed: ${preflight.message}`
            : `preflight ${preflight.status()} ${Object.entries(preflight.headers())
                .filter(([name]) => name.startsWith("access-control-"))
                .map(([name, value]) => `${name}: ${value}`)
                .join("; ") || "(no access-control-* headers)"} ${(await preflight.text()).slice(0, 200)}`;
        lines.push(`${describe(failed)}\n    ${answer}`);
    }
    console.log(`[signed-in desktop] control-plane requests that failed:\n${lines.join("\n")}`);
});
