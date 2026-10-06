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
