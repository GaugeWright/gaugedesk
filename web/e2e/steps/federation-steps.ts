/**
 * Cross-machine federation steps (M8 / FED-7). Drives TWO browser windows — alice at
 * the default backend (7878) and bob via `?cp=http://127.0.0.1:7879` — through the
 * reworked surface: the global **Paired devices** panel (pair a peer machine, co-drive,
 * auto-accept incoming) and the per-project **Engagement pane** (hand off a project's
 * home), opened from the project's node. Peer-side evidence is asserted through the
 * peer's projection, since each mutation crosses a real cert-pinned TLS leg through the
 * broker between two separate control-plane processes.
 */

import { generateKeyPairSync, sign as signBytes } from "node:crypto";
import { expect, type Page } from "@playwright/test";
import { createBdd } from "playwright-bdd";
import { aliceCP, bobCP } from "../ports.mjs";
import { mutationHeaders } from "./idempotency";

const { Given, When, Then } = createBdd();

const ALICE_CP = aliceCP;
const BOB_CP = bobCP;

// The peer (bob) browser window, opened in the same context as the primary page.
let bobPage: Page | null = null;
let combinedInviteLink = "";
let manualHandoffs: Array<{ readonly id: string; readonly name: string }> = [];
let cancellableHandoff: { readonly id: string; readonly name: string } | null = null;
let rejectedController:
    | { readonly requestId: string; readonly secret: string }
    | null = null;
let productionClientResponses: Array<{
    readonly authority: "alice" | "bob";
    readonly method: string;
    readonly path: string;
    readonly status: number;
}> = [];

function recordProductionClientResponses(
    page: Page,
    authority: "alice" | "bob",
    origin: string,
): void {
    page.on("response", (response) => {
        const url = new URL(response.url());
        if (url.origin !== origin) return;
        productionClientResponses.push({
            authority,
            method: response.request().method(),
            path: url.pathname,
            status: response.status(),
        });
    });
}

// Device management lives under Settings ▸ Devices (FED-7): the gear in the Browse
// bottom bar → the Devices option → the single Devices modal.
async function openPairedDevices(page: Page): Promise<void> {
    await page.locator("[data-settings]").click();
    await page.locator("[data-settings-devices]").click();
    await expect(page.locator("[data-devices-modal]")).toBeVisible();
    // The separate-party pairing ticket is minted async on mount; wait for it.
    await expect(page.locator("[data-pd-ticket]")).toHaveText(/.+/);
}

async function openEngagement(page: Page, projectName: string): Promise<void> {
    const devices = page.locator("[data-devices-modal]");
    if (await devices.isVisible()) {
        await devices.locator(".modal-head button").click();
    }
    const engagement = page.locator("[data-engagement-pane]");
    if (await engagement.isVisible()) {
        await engagement.locator(".modal-head button").click();
    }
    await page.locator(".facet", { hasText: "Projects" }).click();
    await page
        .locator(".tree-node.project", { hasText: projectName })
        .click({ button: "right" });
    await page.locator(".menu-item", { hasText: "share & hand off" }).click();
    await expect(page.locator("[data-engagement-pane]")).toBeVisible();
}

Given("the two federated workbenches are open", async ({ page, request }) => {
    // The global Before resets 7878; reset the peer (7879) too for a clean pair.
    const reset = await request.post(`${BOB_CP}/test/reset`, { headers: mutationHeaders() });
    if (!reset.ok()) throw new Error(`peer reset failed: ${reset.status()}`);

    // Seed a real project in alice's library *before* she loads, so the Engagement
    // pane can be opened from its node later (no typed project id anywhere).
    const mk = await request.post(`${ALICE_CP}/projects`, {
        headers: mutationHeaders(),
        data: { name: "Acme Engagement" },
    });
    if (!mk.ok()) throw new Error(`project create failed: ${mk.status()}`);
    const invited = await request.post(`${ALICE_CP}/projects`, {
        headers: mutationHeaders(),
        data: { name: "Invite Engagement" },
    });
    if (!invited.ok()) throw new Error(`invited project create failed: ${invited.status()}`);
    manualHandoffs = [];
    for (const name of [
        "Accept Engagement",
        "Decline Engagement",
        "Batch Engagement One",
        "Batch Engagement Two",
    ]) {
        const response = await request.post(`${ALICE_CP}/projects`, {
            headers: mutationHeaders(),
            data: { name },
        });
        if (!response.ok()) throw new Error(`${name} create failed: ${response.status()}`);
        const project = await response.json() as { id: string };
        manualHandoffs.push({ id: project.id, name });
    }
    const cancellable = await request.post(`${ALICE_CP}/projects`, {
        headers: mutationHeaders(),
        data: { name: "Cancel Engagement" },
    });
    if (!cancellable.ok()) {
        throw new Error(`cancellable project create failed: ${cancellable.status()}`);
    }
    const cancellableProject = await cancellable.json() as { id: string };
    cancellableHandoff = { id: cancellableProject.id, name: "Cancel Engagement" };
    rejectedController = null;

    // Alice on the default backend; Bob via ?cp= on the same Vite preview.
    // federation-production-client-lifecycle
    productionClientResponses = [];
    recordProductionClientResponses(page, "alice", ALICE_CP);
    await page.goto("/");
    // Give the second project a real hub workstream chat before relocation, so
    // the shipped co-drive UI can select that chat instead of bypassing its
    // product precondition in the harness.
    await page.locator(".facet", { hasText: "Projects" }).click();
    const invitedProject = page.locator("[data-project]", { hasText: "Invite Engagement" });
    await invitedProject.locator("[data-create='new-project-chat']").click();
    await page.locator(".facet", { hasText: "Projects" }).click();
    const invitedChat = invitedProject.locator("[data-project-home] .chat-item").first();
    await expect(invitedChat).toBeVisible();
    await invitedChat.click({ button: "right" });
    await page.locator(".menu-item", { hasText: "new workstream" }).click();
    await page.locator(".inline-edit").fill("Federated line");
    await page.locator(".inline-edit").press("Enter");
    const lens = invitedProject.locator(".tree-node.project .lens-toggle");
    if ((await lens.getAttribute("data-lens")) === "chats") await lens.click();
    await expect(
        invitedProject.locator(".ws-group", {
            has: page.locator(".ws-label-name", { hasText: "Federated line" }),
        }).locator(".ws-members .chat-item"),
    ).toBeVisible();

    bobPage = await page.context().newPage();
    recordProductionClientResponses(bobPage, "bob", BOB_CP);
    await bobPage.goto(`/?cp=${encodeURIComponent(BOB_CP)}`);

    await openPairedDevices(page);
    await openPairedDevices(bobPage);
});

When("the two authorities pair with each other", async ({ page }) => {
    const bob = bobPage!;
    const aliceTicket = await page.locator("[data-pd-ticket]").textContent();
    const bobTicket = await bob.locator("[data-pd-ticket]").textContent();
    expect(aliceTicket, "alice minted a ticket").toBeTruthy();
    expect(bobTicket, "bob minted a ticket").toBeTruthy();

    // Each accepts the other's ticket (TOFU pin), so both hold the other's grant.
    await bob.locator("[data-pd-paste]").fill(aliceTicket!.trim());
    await bob.locator("[data-pd-pair]").click();
    await page.locator("[data-pd-paste]").fill(bobTicket!.trim());
    await page.locator("[data-pd-pair]").click();

    // Both render the pairing (alice is `local-user`, bob is `bob`).
    await expect(page.locator('[data-pd-peer="bob"]')).toBeVisible();
    await expect(bob.locator('[data-pd-peer="local-user"]')).toBeVisible();

    // Give the peers' receiver tasks a moment to park on the broker.
    await page.waitForTimeout(800);
});

// The raw "cross a handle" / "remote run" controls were retired from the UI (co-drive
// is now the per-project Engagement-pane flow, FED-7); the FED-1 endpoints still back
// them, so these steps exercise the endpoints directly through the control plane.
let lastRun: { observations_admitted?: number } | null = null;

When("the owner crosses a handle to the peer", async ({ request }) => {
    const r = await request.post(`${ALICE_CP}/federation/cross`, {
        headers: mutationHeaders(),
        data: { peer: "bob", handle: "ctx-method-HANDLE", correlation: `xc-${Date.now()}` },
    });
    expect(r.ok(), "cross admitted").toBeTruthy();
});

Then("the handle appears in the peer's federation inbox", async ({ request }) => {
    await expect
        .poll(
            async () => {
                const r = await request.get(`${BOB_CP}/federation/inbox`);
                const j = (await r.json()) as { federated?: unknown[] };
                return (j.federated ?? []).length;
            },
            { timeout: 8_000 },
        )
        .toBeGreaterThan(0);
});

When("the owner places a remote run on the peer", async ({ request }) => {
    const r = await request.post(`${ALICE_CP}/federation/remote-run`, {
        headers: mutationHeaders(),
        data: { peer: "bob", run_scope: `run-${Date.now()}`, prompt: "go" },
    });
    expect(r.ok(), "remote run ok").toBeTruthy();
    lastRun = (await r.json()) as { observations_admitted?: number };
});

Then("the owner sees the peer's observations were admitted", async () => {
    expect(lastRun?.observations_admitted ?? 0).toBeGreaterThan(0);
});

When("the owner offers projects for manual handoff consent", async ({ request }) => {
    for (const project of manualHandoffs) {
        const response = await request.post(`${ALICE_CP}/federation/handoff/relocate`, {
            headers: mutationHeaders(),
            data: { project: project.id, peer: "bob" },
        });
        expect(response.status(), `offer ${project.name}`).toBe(202);
    }
});

Then(
    "the target accepts, declines, and batch-accepts through the shipped UI",
    async ({ request }) => {
        const bob = bobPage!;
        await bob.locator("[data-devices-modal] .modal-head button").click();
        await openPairedDevices(bob);
        for (const project of manualHandoffs) {
            await expect(bob.locator(`[data-pd-incoming-item="${project.id}"]`)).toBeVisible();
        }

        const accepted = manualHandoffs[0]!;
        await bob.locator(`[data-pd-accept="${accepted.id}"]`).click();
        await expect(bob.locator("[data-pd-status]")).toContainText(`accepted ${accepted.id}`);
        await expect(bob.locator(`[data-pd-incoming-item="${accepted.id}"]`)).toHaveCount(0);

        const declined = manualHandoffs[1]!;
        await bob.locator(`[data-pd-decline="${declined.id}"]`).click();
        await expect(bob.locator("[data-pd-status]")).toContainText(`declined ${declined.id}`);
        await expect(bob.locator(`[data-pd-incoming-item="${declined.id}"]`)).toHaveCount(0);

        await expect(bob.locator("[data-pd-accept-all]")).toBeVisible();
        await bob.locator("[data-pd-accept-all]").click();
        await expect(bob.locator("[data-pd-status]")).toContainText("accepted 2 handoff(s)");
        await expect(bob.locator("[data-pd-incoming-item]")).toHaveCount(0);

        for (const [project, phase] of [
            [accepted, "committed"],
            [declined, "aborted"],
            [manualHandoffs[2]!, "committed"],
            [manualHandoffs[3]!, "committed"],
        ] as const) {
            await expect.poll(async () => {
                const response = await request.get(
                    `${ALICE_CP}/federation/handoff/status?project=${encodeURIComponent(project.id)}`,
                );
                return ((await response.json()) as { phase?: string }).phase;
            }).toBe(phase);
        }

        const required = [
            ["POST", "/federation/handoff/accept"],
            ["POST", "/federation/handoff/decline"],
            ["POST", "/federation/handoff/accept-all"],
        ] as const;
        for (const [method, path] of required) {
            expect(
                productionClientResponses.some((response) =>
                    response.authority === "bob"
                    && response.method === method
                    && response.path === path
                    && response.status >= 200
                    && response.status < 300),
                `bob production client crossed ${method} ${path}: `
                    + JSON.stringify(productionClientResponses),
            ).toBeTruthy();
        }
    },
);

When(
    "the owner offers and cancels another handoff through the shipped UI",
    async ({ page }) => {
        await openEngagement(page, cancellableHandoff!.name);
        await page.locator("[data-engagement-handoff]").click();
        await expect(page.locator("[data-engagement-phase]")).toContainText("offered");
        await page.locator("[data-engagement-cancel]").click();
    },
);

Then(
    "the source stays home and the target cannot accept the cancelled offer",
    async ({ page, request }) => {
        const project = cancellableHandoff!;
        await expect(page.locator("[data-engagement-feedback]")).toContainText(
            "handoff cancelled — the project stays here",
        );
        await expect(page.locator("[data-engagement-phase]")).toContainText("aborted");
        await expect.poll(async () => {
            const response = await request.get(`${BOB_CP}/federation/handoff/incoming`);
            const body = await response.json() as {
                incoming?: Array<{ project?: string }>;
            };
            return (body.incoming ?? []).some((offer) => offer.project === project.id);
        }).toBeFalsy();
        const status = await request.get(
            `${ALICE_CP}/federation/handoff/status?project=${encodeURIComponent(project.id)}`,
        );
        expect(await status.json()).toMatchObject({
            phase: "aborted",
            home_origin: true,
            home_target: false,
        });
        expect(
            productionClientResponses.some((response) =>
                response.authority === "alice"
                && response.method === "POST"
                && response.path === "/federation/handoff/abort"
                && response.status >= 200
                && response.status < 300),
            `alice production client crossed POST /federation/handoff/abort: `
                + JSON.stringify(productionClientResponses),
        ).toBeTruthy();
    },
);

// FED-6/7: relocate a project's home to the peer over the wire, driven from the
// per-project Engagement pane. Bob first pre-authorizes alice (in his Paired devices
// panel), so the relocate auto-accepts on the peer and commits deterministically: bob
// imports the log + becomes home, alice becomes the operator. (The pending-consent path
// is covered by the two-control-plane Rust test `handoff_relocation.rs`.)
When("the owner hands off a project's home", async ({ page }) => {
    const bob = bobPage!;
    await bob.locator('[data-pd-preauth="local-user"]').click();

    // Alice opens the project's Engagement pane from its node (no typed
    // project id — the id comes from the node).
    await openEngagement(page, "Acme Engagement");

    // One action — hand off to the (only) paired device, bob.
    await page.locator("[data-engagement-handoff]").click();
});

Then("the project's handoff is committed to the target", async ({ page }) => {
    await expect(page.locator("[data-engagement-feedback]")).toContainText("home is now there");
    await expect(page.locator("[data-engagement-phase]")).toContainText("committed");

    const required = [
        ["alice", "POST", "/federation/pairing-ticket"],
        ["bob", "POST", "/federation/pairing-ticket"],
        ["alice", "GET", "/federation/peers"],
        ["alice", "GET", "/federation/handoff/incoming"],
        ["alice", "POST", "/federation/pair"],
        ["bob", "POST", "/federation/pair"],
        ["bob", "POST", "/federation/handoff/preauth"],
        ["alice", "GET", "/federation/handoff/status"],
        ["alice", "GET", "/federation/handoff/participants"],
        ["alice", "GET", "/federation/handoff/data"],
        ["alice", "GET", "/federation/run/queue"],
        ["alice", "POST", "/federation/handoff/relocate"],
    ] as const;
    for (const [authority, method, path] of required) {
        expect(
            productionClientResponses.some((response) =>
                response.authority === authority
                && response.method === method
                && response.path === path
                && response.status >= 200
                && response.status < 300),
            `${authority} production client crossed ${method} ${path}: `
                + JSON.stringify(productionClientResponses),
        ).toBeTruthy();
    }
});

When("the owner creates a combined invite for another project", async ({ page }) => {
    await page.locator("[data-engagement-pane] .modal-head button").click();
    await openEngagement(page, "Invite Engagement");
    await page.locator("[data-engagement-invite]").click();
    const link = page.locator("[data-engagement-invite-link]");
    await expect(link).toHaveText(/^gaugewright:\/\/invite\?d=/);
    combinedInviteLink = (await link.textContent())!.trim();
});

When("the target accepts the combined invite", async ({ page }) => {
    const bob = bobPage!;
    await bob.locator("[data-pd-invite-link]").fill(combinedInviteLink);
    await expect(bob.locator("[data-pd-invite-consent]")).toBeVisible();
    await bob.locator("[data-pd-invite-accept]").click();
    await expect(bob.locator("[data-pd-status]")).toContainText("accepted");
    // Once accepted, the resource refetch advances to `committed` and replaces
    // the in-flight invite card, so assert the durable projection and status.
    await expect(page.locator("[data-engagement-phase]")).toContainText("committed", {
        timeout: 10_000,
    });
    await expect(page.locator("[data-engagement-feedback]")).toContainText("accepted by bob");
});

Then("the target manages the invited project's data and operator grant", async () => {
    const bob = bobPage!;
    await bob.reload();
    await expect(bob.locator("[data-settings]")).toBeVisible();
    await openEngagement(bob, "Invite Engagement");
    await expect(bob.locator("[data-engagement-phase]")).toContainText("committed");

    await bob.locator("[data-engagement-connect-data]").click();
    await bob.locator("[data-engagement-folder]").fill("/tmp/invite-data");
    await bob.locator("[data-engagement-connect-data]").click();
    await expect(bob.locator('[data-engagement-data-item="/tmp/invite-data"]')).toHaveText(
        "invite-data",
    );

    const operator = bob.locator('[data-engagement-participant="local-user"]');
    await expect(operator).toBeVisible();
    await operator.locator('[data-engagement-revoke="archetypes"]').click();
    await expect(operator).toContainText("revoked");

    const required = [
        ["alice", "POST", "/federation/invite"],
        ["alice", "GET", "/federation/invite/status"],
        ["bob", "POST", "/federation/invite/accept"],
        ["bob", "POST", "/federation/handoff/connect-data"],
        ["bob", "POST", "/federation/handoff/revoke"],
    ] as const;
    for (const [authority, method, path] of required) {
        expect(
            productionClientResponses.some((response) =>
                response.authority === authority
                && response.method === method
                && response.path === path
                && response.status >= 200
                && response.status < 300),
            `${authority} production client crossed ${method} ${path}: `
                + JSON.stringify(productionClientResponses),
        ).toBeTruthy();
    }
});

async function placeCoDriveRun(page: Page, prompt: string): Promise<void> {
    await page.locator("[data-engagement-run-target-chat]").selectOption({ index: 1 });
    await page.locator("[data-engagement-run-archetype]").fill("analyst");
    await page.locator("[data-engagement-run-prompt]").fill(prompt);
    await page.locator("[data-engagement-place-run]").click();
}

When("the operator places a co-drive run", async ({ page }) => {
    await placeCoDriveRun(page, "admit this once");
    await expect(page.locator("[data-engagement-feedback]")).toContainText(
        "waiting for the host to admit it",
    );
});

Then("the target exercises once, standing, and denied run admission", async ({ page }) => {
    const bob = bobPage!;
    await openEngagement(bob, "Invite Engagement");
    const first = bob.locator("[data-engagement-run]").first();
    await expect(first).toBeVisible();
    await first.locator("[data-engagement-run-once]").click();
    await expect(page.locator("[data-engagement-feedback]")).toContainText("host ran it", {
        timeout: 10_000,
    });

    await placeCoDriveRun(page, "queue then deny");
    await expect(page.locator("[data-engagement-feedback]")).toContainText(
        "waiting for the host to admit it",
    );
    await openEngagement(bob, "Invite Engagement");
    const second = bob.locator("[data-engagement-run]").first();
    await expect(second).toBeVisible();
    await second.locator("[data-engagement-run-allow]").click();
    await expect(bob.locator("[data-engagement-feedback]")).toContainText("allowed");
    await second.locator("[data-engagement-run-deny]").click();
    await expect(second).toHaveCount(0);

    await placeCoDriveRun(page, "standing allow");
    await expect(page.locator("[data-engagement-feedback]")).toContainText(
        "run executed on the host",
        { timeout: 10_000 },
    );

    const required = [
        ["alice", "POST", "/federation/run/place"],
        ["alice", "GET", "/federation/run/result"],
        ["bob", "POST", "/federation/run/admit-once"],
        ["bob", "POST", "/federation/run/allow"],
        ["bob", "POST", "/federation/run/deny"],
    ] as const;
    for (const [authority, method, path] of required) {
        expect(
            productionClientResponses.some((response) =>
                response.authority === authority
                && response.method === method
                && response.path === path
                && response.status >= 200
                && response.status < 300),
            `${authority} production client crossed ${method} ${path}: `
                + JSON.stringify(productionClientResponses),
        ).toBeTruthy();
    }
});

When("a phone proves a controller request", async ({ request }) => {
    const invitationResponse = await request.post(
        `${ALICE_CP}/mobile/enrollment/invitations`,
        {
            headers: mutationHeaders(),
            data: { endpoint: "https://machine.example.test" },
        },
    );
    expect(invitationResponse.status()).toBe(201);
    const invitation = await invitationResponse.json() as {
        invitationId: string;
        secret: string;
        machine: string;
        endpoint: string;
    };
    const { privateKey, publicKey } = generateKeyPairSync("ec", {
        namedCurve: "prime256v1",
    });
    const publicJwk = publicKey.export({ format: "jwk" });
    if (!publicJwk.x || !publicJwk.y) throw new Error("test phone key lacked P-256 coordinates");
    const publicKeyHex = `04${
        Buffer.from(publicJwk.x, "base64url").toString("hex")
    }${Buffer.from(publicJwk.y, "base64url").toString("hex")}`;
    const claimResponse = await request.post(`${ALICE_CP}/mobile/enrollment/claim`, {
        headers: mutationHeaders(),
        data: {
            ...invitation,
            device: "device:rejected-phone",
            publicKey: publicKeyHex,
            label: "Rejected wiring phone",
        },
    });
    expect(claimResponse.status()).toBe(201);
    const claim = await claimResponse.json() as {
        requestId: string;
        challenge: string;
    };
    const signature = signBytes(
        "sha256",
        Buffer.from(claim.challenge),
        { key: privateKey, dsaEncoding: "ieee-p1363" },
    ).toString("base64url");
    const proofResponse = await request.post(`${ALICE_CP}/mobile/enrollment/prove`, {
        headers: mutationHeaders(),
        data: { requestId: claim.requestId, signature },
    });
    expect(proofResponse.status()).toBe(200);
    rejectedController = {
        requestId: claim.requestId,
        secret: invitation.secret,
    };
});

Then(
    "the holder rejects the phone through the shipped Devices UI",
    async ({ page, request }) => {
        const pending = rejectedController!;
        const engagement = page.locator("[data-engagement-pane]");
        if (await engagement.isVisible()) {
            await engagement.locator(".modal-head button").click();
        }
        await openPairedDevices(page);
        const row = page.locator(`[data-controller-request="${pending.requestId}"]`);
        await expect(row).toBeVisible();
        await row.getByRole("button", { name: "reject", exact: true }).click();
        await expect(page.locator("[data-pd-status]")).toContainText("Phone rejected");
        await expect(row).toHaveCount(0);
        const statusResponse = await request.post(
            `${ALICE_CP}/mobile/enrollment/status`,
            {
                headers: mutationHeaders(),
                data: {
                    requestId: pending.requestId,
                    secret: pending.secret,
                },
            },
        );
        expect(statusResponse.status()).toBe(200);
        expect(await statusResponse.json()).toMatchObject({ status: "rejected" });
        expect(
            productionClientResponses.some((response) =>
                response.authority === "alice"
                && response.method === "POST"
                && response.path
                    === `/mobile/enrollment/requests/${pending.requestId}/reject`
                && response.status === 204),
            "alice production client did not cross the controller rejection route",
        ).toBeTruthy();
        await page.locator("[data-devices-modal] .modal-head button").click();
    },
);

When("the holder enrolls the target as another account device", async ({ page }) => {
    const bob = bobPage!;
    for (const workbench of [page, bob]) {
        const engagement = workbench.locator("[data-engagement-pane]");
        if (await engagement.isVisible()) {
            await engagement.locator(".modal-head button").click();
        }
    }
    await openPairedDevices(page);
    await openPairedDevices(bob);
    await page.locator("[data-enroll-host-start]").click();
    const ticket = page.locator("[data-enroll-host-ticket]");
    await expect(ticket).toHaveText(/"session":/);
    await bob.locator("[data-enroll-join-ticket]").fill((await ticket.textContent())!);
    await bob.locator("[data-enroll-join-start]").click();
});

Then("both shipped clients complete the same-code authorization", async ({ page }) => {
    const bob = bobPage!;
    const hostCode = page.locator("[data-enroll-host-code]");
    const joinCode = bob.locator("[data-enroll-join-code]");
    await expect(hostCode).toHaveText(/^[A-Z0-9]{6}$/);
    await expect(joinCode).toHaveText(/^[A-Z0-9]{6}$/);
    expect(await hostCode.textContent()).toBe(await joinCode.textContent());
    await page.locator("[data-enroll-host-confirm]").click();
    await expect(page.locator("[data-enroll-host-done]")).toBeVisible();
    await expect(bob.locator("[data-enroll-join-done]")).toBeVisible();
    await page.locator("[data-devices-modal] .modal-head button").click();
    await page.locator("[data-settings]").click();
    await page.locator("[data-settings-account]").click();
    const enrolledDevice = page.locator("[data-account-panel] [data-device]").first();
    await expect(enrolledDevice).toBeVisible();
    await expect(enrolledDevice.locator(".member-status")).toHaveText("active");

    const required = [
        ["alice", "POST", "/account/devices/enroll/host"],
        ["alice", "GET", "/account/devices/enroll/host/"],
        ["alice", "POST", "/account/devices/enroll/authorize"],
        ["bob", "POST", "/account/devices/enroll/join"],
        ["bob", "GET", "/account/devices/enroll/join/"],
    ] as const;
    for (const [authority, method, pathPrefix] of required) {
        expect(
            productionClientResponses.some((response) =>
                response.authority === authority
                && response.method === method
                && response.path.startsWith(pathPrefix)
                && response.status >= 200
                && response.status < 300),
            `${authority} production client crossed ${method} ${pathPrefix}: `
                + JSON.stringify(productionClientResponses),
        ).toBeTruthy();
    }
});

When("the owner disconnects the peer through the shipped Devices UI", async ({ page }) => {
    const account = page.locator("[data-account-panel]");
    if (await account.isVisible()) {
        await account.locator(".modal-head button").click();
    }
    await openPairedDevices(page);
    const peer = page.locator('[data-pd-peer="bob"]');
    await expect(peer).toContainText("paired");
    const disconnect = peer.locator('[data-pd-revoke="bob"]');
    await disconnect.click();
    await expect(disconnect).toHaveText("confirm disconnect");
    await disconnect.click();
});

Then(
    "the revoked peer is retained for audit and future work is refused",
    async ({ page, request }) => {
        const peer = page.locator('[data-pd-peer="bob"]');
        await expect(page.locator("[data-pd-status]")).toContainText("disconnected bob");
        await expect(peer).toContainText("revoked");
        await expect(peer.locator('[data-pd-revoke="bob"]')).toHaveCount(0);
        await expect(peer.locator('[data-pd-preauth="bob"]')).toHaveCount(0);

        expect(
            productionClientResponses.some((response) =>
                response.authority === "alice"
                && response.method === "DELETE"
                && response.path === "/federation/peers/bob"
                && response.status === 200),
            "alice production client did not cross DELETE /federation/peers/bob",
        ).toBeTruthy();

        const refused = await request.post(`${ALICE_CP}/federation/run/place`, {
            headers: mutationHeaders(),
            data: {
                peer: "bob",
                project: "revoked-peer-project",
                archetype: "analyst",
                data_handle: "revoked-peer-data",
                prompt: "must not run",
            },
        });
        expect(refused.status()).toBe(400);
        expect(await refused.text()).toContain("not paired with bob");
    },
);
