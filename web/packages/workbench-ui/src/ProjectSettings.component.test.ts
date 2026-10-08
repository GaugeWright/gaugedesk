import { createComponent } from "solid-js";
import { render } from "solid-js/web";
import { afterEach, expect, it, vi } from "vitest";
import type { KeyDelegationView, ProjectKeyDelegations, ProjectNode } from "@gaugewright/control-plane-client";
import { ProjectSettingsContent, ProjectSettingsMenu, type ProjectSettingsApi } from "./ProjectSettings";

let dispose: (() => void) | undefined;
afterEach(() => { dispose?.(); document.body.replaceChildren(); });

const base: KeyDelegationView = {
    id: "d1",
    state: "held",
    work: { kind: "workflow", path: "lessons/hello.whip", targetName: "Notes" },
    keys: [{ scope: "project::p::workflow", label: "workflow storage" }],
    grantedFrom: "alice@example.com",
    grantedAtMs: Date.UTC(2026, 9, 1),
    expiresAtMs: Date.UTC(2026, 9, 31),
    lapsedSinceMs: null,
    ended: null,
    useCount: 3,
    uses: [],
    refusals: [],
};

function mount(record: ProjectKeyDelegations) {
    const host = document.createElement("div");
    document.body.append(host);
    const getProjectKeyDelegations = vi.fn(async () => record);
    const api = { getProjectKeyDelegations } as unknown as ProjectSettingsApi;
    const project = { id: "p", name: "Research", isPersonal: false, targets: [], placements: [] } as unknown as ProjectNode;
    const onChanged = vi.fn();
    dispose = render(() => createComponent(ProjectSettingsContent, {
        api, project, library: [], page: "background-work",
        onSelectPage: vi.fn(), onClose: vi.fn(), onChanged,
    }), host);
    return { host, getProjectKeyDelegations, onChanged };
}

// DR-0312: the project shows what background work holds which keys, from
// whose work, and until when. It is a record: it offers no grant or revoke.
it("shows held, paused and finished background work with the keys each holds", async () => {
    const { host, getProjectKeyDelegations } = mount({
        project: "p",
        lapseAfterMs: 30 * 24 * 60 * 60 * 1000,
        lastMemberUseMs: null,
        delegations: [
            base,
            { ...base, id: "d2", state: "lapsed", expiresAtMs: null, lapsedSinceMs: Date.UTC(2026, 9, 2),
              refusals: [{ atMs: 1, label: "chat “Budget”" }, { atMs: 2, label: "chat “Budget”" }] },
        ],
        ended: [{ ...base, id: "d3", state: "ended", expiresAtMs: null, ended: { atMs: Date.UTC(2026, 9, 3), outcome: "completed" }, useCount: 1 }],
    });
    await vi.waitFor(() => expect(host.querySelectorAll(".project-settings-delegation")).toHaveLength(3));
    expect(getProjectKeyDelegations).toHaveBeenCalledWith("p");
    const held = host.querySelector('[data-delegation-state="held"]') as HTMLElement;
    expect(held.textContent).toContain("lessons/hello.whip · Notes");
    expect(held.textContent).toContain("Started by alice@example.com");
    expect(held.textContent).toContain("holds workflow storage");
    expect(held.textContent).toContain("3 unattended steps");
    const lapsed = host.querySelector('[data-delegation-state="lapsed"]') as HTMLElement;
    expect(lapsed.textContent).toContain("Paused");
    expect(lapsed.textContent).toContain("nobody had used this project for 30 days");
    expect(lapsed.querySelector(".project-settings-delegation-refused")?.textContent)
        .toBe("Refused outside its declaration: chat “Budget”");
    const ended = host.querySelector('[data-delegation-state="ended"]') as HTMLElement;
    expect(ended.textContent).toContain("completed");
    expect(ended.textContent).toContain("1 unattended step");
    expect(host.querySelector(".project-settings-section button")?.textContent).toBe("Refresh");
});

// Reading the record is the member use that renewed paused work, so the
// views that showed it paused are refreshed once, not on every render.
it("refreshes what showed the work as paused once after reading it", async () => {
    const { host, onChanged } = mount({ project: "p", lapseAfterMs: 1, lastMemberUseMs: null, delegations: [base], ended: [] });
    await vi.waitFor(() => expect(host.querySelector(".project-settings-delegation")).not.toBeNull());
    await vi.waitFor(() => expect(onChanged).toHaveBeenCalledOnce());
    (host.querySelector(".project-settings-section button") as HTMLButtonElement).click();
    await new Promise((resolve) => setTimeout(resolve, 20));
    expect(onChanged).toHaveBeenCalledOnce();
});

it("says plainly when no background work holds the project's keys", async () => {
    const { host } = mount({ project: "p", lapseAfterMs: 1, lastMemberUseMs: null, delegations: [], ended: [] });
    await vi.waitFor(() => expect(host.textContent).toContain("No background work holds this project's keys."));
    expect(host.textContent).not.toContain("Finished");
});

it("lists Background work among a project's settings pages", () => {
    const host = document.createElement("div");
    document.body.append(host);
    dispose = render(() => createComponent(ProjectSettingsMenu, {
        projectName: "Personal", isPersonal: true, page: "overview", onSelect: vi.fn(), onClose: vi.fn(),
    }), host);
    expect([...host.querySelectorAll("nav button")].map((button) => button.textContent)).toContain("Background work");
});

// Who may open a project and which computer holds it are separate decisions,
// on separate pages, and neither waits on the other (DR-0455).
function mountPage(page: "people" | "hosting") {
    const host = document.createElement("div");
    document.body.append(host);
    const api = {
        handoffParticipants: vi.fn(async () => []),
        handoffStatus: vi.fn(async () => ({ home: "origin" })),
        listPeers: vi.fn(async () => [{ authority: "peer:studio", active: true }]),
        pendingHomeInvitations: vi.fn(async () => []),
        createHomeInvitation: vi.fn(),
    };
    const project = { id: "p", name: "Research", isPersonal: false, organization: null, targets: [], placements: [] } as unknown as ProjectNode;
    dispose = render(() => createComponent(ProjectSettingsContent, {
        api: api as unknown as ProjectSettingsApi, project, library: [], page,
        onSelectPage: vi.fn(), onClose: vi.fn(), onChanged: vi.fn(), onOpenEngagement: vi.fn(),
    }), host);
    return { host, api };
}

it("shares a project on People & sharing without any word about where it is hosted", async () => {
    const { host, api } = mountPage("people");
    await vi.waitFor(() => expect(host.querySelector("[data-invite-by-email]")).not.toBeNull());
    expect(host.textContent).not.toMatch(/Project Host|Hand off|handoff|Paired devices/i);
    expect(host.querySelector("[data-project-engagement]")).toBeNull();
    expect(api.handoffStatus).not.toHaveBeenCalled();
    expect(api.listPeers).not.toHaveBeenCalled();
});

it("moves a project on its own Hosting page, apart from who it is shared with", async () => {
    const { host, api } = mountPage("hosting");
    await vi.waitFor(() => expect(host.querySelector(".project-settings-handoff-form")).not.toBeNull());
    expect(host.querySelector("[data-project-engagement]")).not.toBeNull();
    expect(host.textContent).not.toMatch(/Invite|People with access/);
    expect(api.handoffParticipants).not.toHaveBeenCalled();
});

it("lists Hosting apart from People & sharing, and neither for Personal", () => {
    const pages = (isPersonal: boolean) => {
        const host = document.createElement("div");
        document.body.append(host);
        const unmount = render(() => createComponent(ProjectSettingsMenu, {
            projectName: "Research", isPersonal, page: "overview", onSelect: vi.fn(), onClose: vi.fn(),
        }), host);
        const labels = [...host.querySelectorAll("nav button")].map((button) => button.textContent);
        unmount();
        return labels;
    };
    expect(pages(false)).toEqual(expect.arrayContaining(["People & sharing", "Hosting"]));
    expect(pages(true)).not.toContain("People & sharing");
    expect(pages(true)).not.toContain("Hosting");
});

// Cancelling the invitation whose link the page is showing takes the link
// away with it; leaving Copy and "Email it" on a dead link invited someone to
// send it (founder, 2026-10-08).
it("drops the shown link when its own invitation is cancelled", async () => {
    const hex = (value: unknown) => Array.from(new TextEncoder().encode(JSON.stringify(value)), (byte) => byte.toString(16).padStart(2, "0")).join("");
    const encoded = hex({
        version: 1, invitation: "hinv-shown", invited_authority: "", invited_email: "alex@example.test",
        project: "p", home_id: "home:owner", endpoint: "https://home.example/", secret: "s",
    });
    const { host, api } = mountPage("people");
    const sharing = {
        createHomeInvitation: vi.fn(async () => ({ invite: encoded, url: `https://desk.example/invite?d=${encoded}`, homeId: "home:owner", project: "p", endpoint: "https://home.example/", expiresAt: 4_102_444_800 })),
        pendingHomeInvitations: vi.fn(async () => [{ id: "hinv-shown", email: "alex@example.test", authority: "", role: "member", expiresAt: 4_102_444_800 }]),
        cancelHomeInvitation: vi.fn(async () => undefined),
        emailHomeInvitation: vi.fn(async () => "alex@example.test"),
    };
    Object.assign(api, sharing);
    await vi.waitFor(() => expect(host.querySelector("[data-invite-by-email]")).not.toBeNull());
    const input = host.querySelector<HTMLInputElement>("[data-invite-by-email] input[type=email], [data-invite-by-email] input")!;
    input.value = "alex@example.test";
    input.dispatchEvent(new Event("input", { bubbles: true }));
    const button = (label: RegExp) => [...host.querySelectorAll("button")].find((b) => label.test(b.textContent ?? ""));
    button(/^Create invite$/)!.click();
    await vi.waitFor(() => expect(host.textContent).toContain("Invitation link"));
    await vi.waitFor(() => expect(button(/^Cancel$/)).toBeDefined());
    button(/^Cancel$/)!.click();
    await vi.waitFor(() => expect(button(/^Cancel invitation$/)).toBeDefined());
    button(/^Cancel invitation$/)!.click();
    await vi.waitFor(() => expect(sharing.cancelHomeInvitation).toHaveBeenCalledWith("p", "hinv-shown"));
    await vi.waitFor(() => expect(host.textContent).not.toContain("Invitation link"));
    expect(button(/^Email it to/)).toBeUndefined();
});
