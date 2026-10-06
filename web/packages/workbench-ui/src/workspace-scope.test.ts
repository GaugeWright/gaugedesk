import { describe, expect, it } from "vitest";
import { parseWorkspace, type HumanTask } from "@gaugewright/control-plane-client";
import { navigatorScope, quickStartPlacement, scopeProjects, scopeTasks, scopeWorkspace } from "./workspace-scope";

const ACME = "organization:0123456789abcdef0123456789abcdef";

const TARGET = {
    target_id: "target-files",
    root: "targets/t-files",
    name: "workspace",
    kind: "managed",
    adapter: "whipplescript",
    adapter_family: "whipplescript-v1",
    basis: "cut-1",
    path_scope: ["."],
    capability_ceiling: { read: true, propose: true, apply: true, publish: false, release: false },
    participation: "writable",
};
const chat = (id: string, placement: string | null, kind: "work" | "edit" = "work") => ({
    id,
    title: id,
    kind,
    placement,
    workstream: null,
    workspace_root: `root-${id}`,
    target_set_revision: 1,
    collaboration_workspace_id: `root-${id}`,
    targets: [TARGET],
    candidate_revision: "cut-1",
    available_acts: ["read"],
});
const project = (id: string, organization: string | null, isPersonal = false) => ({
    id,
    name: id,
    home_id: "home",
    is_personal: isPersonal,
    organization,
    targets: [],
    placements: [{
        placement_id: `${id}-general`,
        archetype_id: "default",
        archetype_name: "Default",
        is_default: true,
        pinned_version: null,
        target_ids: [],
        chats: [chat(`${id}-chat`, `${id}-general`)],
        workstreams: [],
    }],
});

const workspace = parseWorkspace({
    archetypes: [],
    projects: [
        project("proj-default", null, true),
        project("notes", null),
        project("proj-org-0123456789abcdef0123456789abcdef", ACME),
    ],
    recent: [
        { ...chat("proj-default-chat", "proj-default-general"), archetype: "Default" },
        { ...chat("proj-org-0123456789abcdef0123456789abcdef-chat", "proj-org-0123456789abcdef0123456789abcdef-general"), archetype: "Default" },
        { ...chat("agent-edit", null, "edit"), archetype: "Writer" },
    ],
    workstreams: [],
    work_targets: [],
    personal_placement: "proj-default-general",
});

describe("the navigator follows the selected organization", () => {
    it("reads each project's owning organization from the projection", () => {
        expect(workspace.projects.map((p) => [p.id, p.organization])).toEqual([
            ["proj-default", null],
            ["notes", null],
            ["proj-org-0123456789abcdef0123456789abcdef", ACME],
        ]);
    });

    it("shows Personal's own projects and their chats under Personal", () => {
        const scoped = scopeWorkspace(workspace, navigatorScope({ id: "personal:root", personal: true }));
        expect(scoped.projects.map((p) => p.id)).toEqual(["proj-default", "notes"]);
        expect(scoped.recent.map((c) => c.id)).toEqual(["proj-default-chat", "agent-edit"]);
    });

    it("shows only the organization's projects under that organization", () => {
        const scoped = scopeWorkspace(workspace, navigatorScope({ id: ACME, personal: false }));
        expect(scoped.projects.map((p) => p.id)).toEqual(["proj-org-0123456789abcdef0123456789abcdef"]);
        // An Agent's edit chat is Workshop's, and Workshop is the person's.
        expect(scoped.recent.map((c) => c.id)).toEqual(["proj-org-0123456789abcdef0123456789abcdef-chat", "agent-edit"]);
        expect(scoped.archetypes).toBe(workspace.archetypes);
    });

    it("shows everything when nothing is selected", () => {
        expect(navigatorScope(null)).toBeUndefined();
        expect(scopeWorkspace(workspace, undefined)).toBe(workspace);
    });

    it("scopes the task bar's asks and tracker reads with the projects", () => {
        const tasks: HumanTask[] = [
            { id: "proj-default-chat", title: "personal ask", agent: "Default", kind: "answer" },
            { id: "proj-org-0123456789abcdef0123456789abcdef-chat", title: "org ask", agent: "Default", kind: "reply" },
            { id: "proj-default-chat", title: "inbound", agent: "", kind: "screen", project: "proj-org-0123456789abcdef0123456789abcdef", waiting: 2 },
            { id: "agent-edit", title: "edit ask", agent: "Writer", kind: "answer" },
        ];
        const organization = navigatorScope({ id: ACME, personal: false });
        expect(scopeTasks(tasks, workspace, organization).map((t) => t.title)).toEqual(["org ask", "inbound", "edit ask"]);
        expect(scopeTasks(tasks, workspace, navigatorScope({ id: "personal:root", personal: true })).map((t) => t.title))
            .toEqual(["personal ask", "edit ask"]);
        expect(scopeProjects(workspace.projects, organization).map((p) => p.id)).toEqual(["proj-org-0123456789abcdef0123456789abcdef"]);
    });

    it("starts a chat from the empty composer only where the navigator shows it", () => {
        const personal = quickStartPlacement(workspace, navigatorScope({ id: "personal:root", personal: true }));
        expect([personal?.project.id, personal?.placementId]).toEqual(["proj-default", "proj-default-general"]);
        const organization = quickStartPlacement(workspace, navigatorScope({ id: ACME, personal: false }));
        expect([organization?.project.id, organization?.placementId])
            .toEqual(["proj-org-0123456789abcdef0123456789abcdef", "proj-org-0123456789abcdef0123456789abcdef-general"]);
        expect(quickStartPlacement(workspace, navigatorScope({ id: "organization:other", personal: false }))).toBeNull();
        expect(quickStartPlacement(workspace, undefined)?.placementId).toBe("proj-default-general");
    });
});
