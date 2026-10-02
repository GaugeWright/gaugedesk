import { createComponent } from "solid-js";
import { render } from "solid-js/web";
import { afterEach, expect, it, vi } from "vitest";
import type { EngagementId, HumanTask } from "@gaugewright/control-plane-client";
import { TaskBar } from "./TaskBar";

let dispose: (() => void) | undefined;
afterEach(() => { dispose?.(); document.body.replaceChildren(); });

const inbound: HumanTask = {
    id: "proj-a",
    title: "Survey",
    agent: "",
    kind: "screen",
    project: "proj-a",
    waiting: 3,
    placement: "inst-panel-a",
};
const answer: HumanTask = { id: "chat-1", title: "Draft", agent: "Writer", kind: "answer" };

async function mount(tasks: HumanTask[], onOpenInbox?: Parameters<typeof TaskBar>[0]["onOpenInbox"]) {
    const host = document.createElement("div");
    document.body.append(host);
    const onSelect = vi.fn<(id: EngagementId) => void>();
    dispose = render(() => createComponent(TaskBar, {
        api: { getTasks: async () => tasks },
        selected: null,
        refreshKey: 0,
        onSelect,
        onOpenInbox,
        // Signed in: only then is there a personal queue to read.
        assigned: { read: async () => ({ tasks: [], unavailable: [] }), onOpen: vi.fn() },
    }), host);
    await vi.waitFor(() => expect(host.querySelector("[data-task-kind]")).not.toBeNull());
    return { host, onSelect };
}

// The inbound count belongs to a project and names no chat (DR-0143 §6): it
// opens an Inbox, carrying the one placement it came from, and selects nothing.
it("opens the Inbox an inbound count names, never a chat", async () => {
    const onOpenInbox = vi.fn();
    const { host, onSelect } = await mount([inbound, answer], onOpenInbox);
    const pill = host.querySelector('[data-task-kind="screen"]') as HTMLElement;
    expect(pill.querySelector("[data-task-count]")?.textContent).toBe("3");
    pill.click();
    expect(onOpenInbox).toHaveBeenCalledWith({ project: "proj-a", projectName: "Survey", placement: "inst-panel-a" });
    expect(onSelect).not.toHaveBeenCalled();

    (host.querySelector('[data-task-kind="answer"]') as HTMLElement).click();
    expect(onSelect).toHaveBeenCalledWith("chat-1");
    expect(onOpenInbox).toHaveBeenCalledOnce();
});

it("shows the count as a note where there is no Inbox to open", async () => {
    const { host, onSelect } = await mount([inbound]);
    const pill = host.querySelector('[data-task-kind="screen"]') as HTMLElement;
    expect(pill.getAttribute("role")).toBe("note");
    expect(pill.hasAttribute("tabindex")).toBe(false);
    pill.click();
    expect(onSelect).not.toHaveBeenCalled();
});
