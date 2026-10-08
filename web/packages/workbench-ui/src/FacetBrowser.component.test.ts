// @vitest-environment happy-dom
// "new chat" in the navigator either starts a chat or says why it did not
// (action-failure.feature). With no work target the placement can read, it
// used to write "no available work target can be read" only to the status,
// which is a refresh key and not on screen: the button did nothing visible
// (WS-965).
import { createComponent } from "solid-js";
import { render } from "solid-js/web";
import { afterEach, describe, expect, it, vi } from "vitest";
import { parseWorkspace, type EngagementId } from "@gaugewright/control-plane-client";
import { FacetBrowser, type FacetBrowserApi } from "./FacetBrowser";

let dispose: (() => void) | undefined;
afterEach(() => {
    dispose?.();
    dispose = undefined;
    document.body.replaceChildren();
});

const target = (status: "available" | "unavailable") => ({
    id: "target-folder",
    name: "Launch folder",
    owner_kind: "project",
    owner_id: "proj-launch",
    authority: "local-user",
    parties: ["local-user"],
    kind: "external-folder",
    adapter: "folder",
    adapter_family: "folder-v1",
    vcs_posture: "unversioned",
    current_basis: null,
    path_scope: ["."],
    capabilities: { read: true, propose: true, apply: false, publish: false, release: false },
    status,
    concurrency: "compare-before-write-weak",
});

function navigator(targetStatus: "available" | "unavailable") {
    const workspace = parseWorkspace({
        archetypes: [],
        projects: [{
            id: "proj-launch",
            name: "Launch plan",
            home_id: "home",
            targets: [target(targetStatus)],
            placements: [{
                placement_id: "inst-general-proj-launch",
                archetype_id: "agent-default",
                archetype_name: "Default",
                is_default: true,
                target_ids: ["target-folder"],
                chats: [],
                workstreams: [],
            }],
        }],
        recent: [],
        workstreams: [],
        work_targets: [target(targetStatus)],
    });
    const createChatUnderPlacement = vi.fn(async () => "chat-new" as EngagementId);
    const api = {
        getWorkspaceCarriage: async () => ({
            value: workspace,
            freshness: { marker: "live", generatedAt: 0, repairHint: null },
            clientRequestId: null,
        }),
        createChatUnderPlacement,
    } as unknown as FacetBrowserApi;
    const failure = vi.fn();
    const status = vi.fn();
    const selected = vi.fn();
    const host = document.createElement("div");
    document.body.append(host);
    dispose = render(() => createComponent(FacetBrowser, {
        api,
        selected: null,
        onSelect: selected,
        onOpenArchetypeSettings: () => undefined,
        onOpenEngagement: () => undefined,
        onOpenModelAccess: () => undefined,
        onOpenProjectHome: () => undefined,
        onOpenForkTree: () => undefined,
        onChatRemoved: () => undefined,
        onStatus: status,
        onFailure: failure,
    }), host);
    const newChat = () => host.querySelector<HTMLButtonElement>("[data-create='new-project-chat']");
    return { newChat, createChatUnderPlacement, failure, status, selected };
}

describe("the navigator's new chat", () => {
    it("starts a chat on the project's one readable target", async () => {
        const { newChat, createChatUnderPlacement, failure, selected } = navigator("available");
        await vi.waitFor(() => expect(newChat()).not.toBeNull());
        newChat()!.click();
        await vi.waitFor(() => expect(selected).toHaveBeenCalledWith("chat-new"));
        expect(createChatUnderPlacement).toHaveBeenCalledWith("proj-launch", "inst-general-proj-launch", "new chat", ["target-folder"]);
        expect(failure).not.toHaveBeenCalled();
    });

    it("says why when no target of the project can be read, and starts nothing", async () => {
        const { newChat, createChatUnderPlacement, failure, selected } = navigator("unavailable");
        await vi.waitFor(() => expect(newChat()).not.toBeNull());
        newChat()!.click();
        await vi.waitFor(() => expect(failure).toHaveBeenCalledWith(
            'couldn\'t start a chat — no work target of this Agent can be read: "Launch folder" is unavailable',
        ));
        expect(createChatUnderPlacement).not.toHaveBeenCalled();
        expect(selected).not.toHaveBeenCalled();
    });
});
