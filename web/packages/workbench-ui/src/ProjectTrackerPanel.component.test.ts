import { createComponent, createSignal } from "solid-js";
import { render } from "solid-js/web";
import { afterEach, expect, it, vi } from "vitest";
import type { ProjectId, ProjectTrackerIssue, ReadableProjectTracker, RosterPerson } from "@gaugewright/control-plane-client";
import { ProjectTrackerPanel, type PendingTrackerCompletion, type ProjectTrackerApi } from "./ProjectTrackerPanel";

let dispose: (() => void) | undefined;
afterEach(() => { dispose?.(); document.body.replaceChildren(); });

const tracker: ReadableProjectTracker = {
    projectId: "personal", workspaceId: "workspace-personal", queue: "tutorials", resourceId: "tracker", canComplete: true,
};
const issue: ProjectTrackerIssue = {
    id: "WS-1", subjectId: "assistant-subject", title: "Make a personal assistant", body: "Describe how it should help you.",
    status: "open", assignedTo: "learner", claimedBy: null, claimExpiresAt: null, closedBy: null, closingSummary: null,
    filedBy: "learner", labels: [], createdAt: "2026-09-11T00:00:00Z", updatedAt: "2026-09-11T00:00:00Z",
};
const roster: RosterPerson[] = [
    { authority: "learner", display: "Learner", role: "owner" },
    { authority: "colleague", display: "Colleague", role: "member" },
];

function mount(getRoster: () => Promise<RosterPerson[]>) {
    const api: ProjectTrackerApi = {
        subscribeProjectTrackerChanges: vi.fn(async () => () => {}),
        listProjectTrackers: vi.fn(async () => [tracker]),
        readProjectTrackerBacklog: vi.fn(async () => ({ tracker, issues: [issue] })),
        readProjectTrackerTasks: vi.fn(async () => ({ actor: "learner", tracker, issues: [issue] })),
        completeProjectTrackerIssue: vi.fn(),
        controlProjectTrackerIssue: vi.fn(),
        getRoster,
    };
    const host = document.createElement("div");
    document.body.append(host);
    const completions = createSignal<PendingTrackerCompletion[]>([]);
    dispose = render(() => createComponent(ProjectTrackerPanel, {
        api, project: "personal" as ProjectId, projectName: "Personal", completions, onClose: () => {},
    }), host);
    return host;
}

const picker = (host: HTMLElement) => host.querySelector<HTMLSelectElement>("[data-task-assignee]");

// The roster is read beside the backlog, and nothing orders the two. A task
// opened before the roster arrives shows its assignee from the task itself;
// when the roster's option for that person replaces it, the picker must still
// name them rather than fall back to the first option, "Unassigned".
it("keeps a task's assignee selected when the roster arrives after the task is open", async () => {
    let arrive!: (people: RosterPerson[]) => void;
    const host = mount(() => new Promise((resolve) => { arrive = resolve; }));
    await vi.waitFor(() => expect(host.querySelector(".project-task-row")).not.toBeNull());
    host.querySelector<HTMLButtonElement>(".project-task-row")!.click();
    await vi.waitFor(() => expect(picker(host)).not.toBeNull());
    expect(picker(host)!.value).toBe("learner");

    arrive(roster);
    await vi.waitFor(() => expect(picker(host)!.options.length).toBe(3));
    expect(picker(host)!.value).toBe("learner");
    expect(picker(host)!.selectedOptions[0]?.textContent?.trim()).toBe("You (Learner)");
});

it("selects the assignee when the roster is already there", async () => {
    const host = mount(async () => roster);
    await vi.waitFor(() => expect(host.querySelector(".project-task-row")).not.toBeNull());
    host.querySelector<HTMLButtonElement>(".project-task-row")!.click();
    await vi.waitFor(() => expect(picker(host)?.options.length).toBe(3));
    expect(picker(host)!.value).toBe("learner");
});
