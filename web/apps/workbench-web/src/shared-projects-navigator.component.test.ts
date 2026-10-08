// The navigator lists every project shared with a member beside the projects
// of the Home that serves them, or on its own when no Home of theirs does
// (DR-0451, DR-0455, WS-1034). Mounted on the real control plane, so what is
// under test is the whole read: the pin, the pinned route, the relay, and the
// tree the navigator draws from it. Before this, a member with no Home of
// their own met "no reachable Home is selected", and one with their own
// desktop selected saw only its projects.
import { createComponent } from "solid-js";
import { render } from "solid-js/web";
import { afterEach, describe, expect, it, vi } from "vitest";
import { FacetBrowser } from "@gaugewright/workbench-ui";
import { OWNERS, releaseSharedMember, sharedMember } from "./shared-member.fixture";

let dispose: (() => void) | undefined;
afterEach(() => {
    dispose?.();
    dispose = undefined;
    document.body.replaceChildren();
    releaseSharedMember();
});

function navigator(api: ReturnType<typeof sharedMember>["api"]) {
    const host = document.createElement("div");
    document.body.append(host);
    const opened = vi.fn();
    dispose = render(() => createComponent(FacetBrowser, {
        api,
        selected: null,
        onSelect: () => undefined,
        onOpenArchetypeSettings: () => undefined,
        onOpenEngagement: () => undefined,
        onOpenModelAccess: () => undefined,
        onOpenProjectHome: (id, name) => {
            // What the workbench does when a project row is opened.
            api.setCurrentProject(id);
            opened(id, name);
        },
        onOpenForkTree: () => undefined,
        onChatRemoved: () => undefined,
        onStatus: () => undefined,
    }), host);
    const listed = () => [...host.querySelectorAll<HTMLElement>(".tree-group[data-project]")]
        .map((group) => group.dataset.project);
    const row = (project: string) =>
        host.querySelector<HTMLElement>(`.tree-group[data-project="${project}"] .tree-node.project`);
    return { host, listed, row, opened };
}

describe("the navigator of a member a project was shared with", () => {
    it("lists it beside the projects of the member's own desktop, and opens it at the owner's", async () => {
        const { api, carried, hubWrites } = sharedMember("selected");
        await api.bootstrapHome();
        const { listed, row, opened } = navigator(api);
        await vi.waitFor(() => expect(listed()).toEqual(["proj-mine", "proj-shared"]));
        row("proj-shared")!.click();
        expect(opened).toHaveBeenCalledWith("proj-shared", "proj-shared");
        await expect(api.getTranscript("chat-shared" as never)).resolves.toEqual([]);
        expect(carried).toContainEqual({ home: OWNERS, call: "GET /chats/chat-shared/transcript" });
        expect(hubWrites).toEqual([]);
    });

    it("lists it for a member with no Home of their own", async () => {
        const { api, hubWrites } = sharedMember("signed out");
        await expect(api.bootstrapHome()).resolves.toMatchObject({ kind: "connected" });
        const { listed } = navigator(api);
        await vi.waitFor(() => expect(listed()).toEqual(["proj-shared"]));
        expect(hubWrites).toEqual([]);
    });
});
