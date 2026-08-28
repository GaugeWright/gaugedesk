import { describe, expect, it } from "vitest";
import {
    archetypeVisible,
    chatMatches,
    childrenFor,
    groupChatsByArchetype,
    hit,
    lineageVaries,
    markMatch,
    placementVisible,
    projectVisible,
    recentLineage,
    recentVisible,
    searching,
} from "./facet-filter";

describe("hit / searching", () => {
    it("matches everything on an empty or whitespace query", () => {
        expect(hit("anything", "")).toBe(true);
        expect(hit("anything", "   ")).toBe(true);
        expect(searching("")).toBe(false);
        expect(searching("  ")).toBe(false);
    });

    it("is a case-insensitive substring test on a real query", () => {
        expect(hit("Marketing", "mark")).toBe(true);
        expect(hit("Email helper", "MAIL")).toBe(true);
        expect(hit("Marketing", "zzz")).toBe(false);
        expect(searching("mail")).toBe(true);
    });

    it("trims the query before matching", () => {
        expect(hit("Marketing", "  mark  ")).toBe(true);
    });
});

describe("markMatch", () => {
    it("splits a label around the first literal match", () => {
        expect(markMatch("Email helper", "mail")).toEqual({ pre: "E", match: "mail", post: " helper" });
    });

    it("returns null when there is no query (nothing is bolded)", () => {
        expect(markMatch("Email helper", "")).toBeNull();
    });

    it("returns null when the label survived only as an ancestor (no own match)", () => {
        // "Marketing" is kept because a descendant matched "mail", but the label
        // itself doesn't contain "mail" — so nothing in it is highlighted.
        expect(markMatch("Marketing", "mail")).toBeNull();
    });

    it("is case-insensitive but preserves the original casing in the slices", () => {
        expect(markMatch("Email", "EMAIL")).toEqual({ pre: "", match: "Email", post: "" });
    });
});

describe("childrenFor", () => {
    const chats = [{ title: "draft" }, { title: "review" }, { title: "mailout" }];

    it("keeps every child when the parent label itself matches", () => {
        expect(childrenFor("Email helper", chats, "email")).toEqual(chats);
    });

    it("keeps every child on an empty query", () => {
        expect(childrenFor("Email helper", chats, "")).toEqual(chats);
    });

    it("narrows to matching children when only a descendant matched", () => {
        // The parent label "Reviewer" does not contain "mail", so only the matching
        // child survives (search drills into the group).
        expect(childrenFor("Reviewer", chats, "mail")).toEqual([{ title: "mailout" }]);
    });

    it("finds a chat by any selected target name", () => {
        const multi = [{ title: "launch", targets: [{ name: "Frontend" }, { name: "Payments API" }] }];
        expect(childrenFor("Project", multi, "payments")).toEqual(multi);
        expect(chatMatches(multi[0], "frontend")).toBe(true);
    });

    it("returns a fresh array (does not alias the input)", () => {
        const out = childrenFor("x", chats, "");
        expect(out).not.toBe(chats);
        expect(out).toEqual(chats);
    });
});

describe("placementVisible / projectVisible (a node shows iff it or a descendant matches)", () => {
    const placement = { archetypeName: "Email helper", chats: [{ title: "spring blast" }] };

    it("shows a placement when its archetype name matches", () => {
        expect(placementVisible("Acme", placement, "email")).toBe(true);
    });
    it("shows a placement when its owning project matches", () => {
        expect(placementVisible("Acme", placement, "acme")).toBe(true);
    });
    it("shows a placement when one of its chats matches", () => {
        expect(placementVisible("Acme", placement, "spring")).toBe(true);
    });
    it("hides a placement when nothing in its subtree matches", () => {
        expect(placementVisible("Acme", placement, "zzz")).toBe(false);
    });

    const project = {
        name: "Marketing",
        placements: [placement, { archetypeName: "Reviewer", chats: [] }],
    };

    it("shows a project on its own name", () => {
        expect(projectVisible(project, "market")).toBe(true);
    });
    it("shows a project when a descendant placement/chat matches", () => {
        expect(projectVisible(project, "spring")).toBe(true);
    });
    it("hides a project when nothing in it matches", () => {
        expect(projectVisible(project, "zzz")).toBe(false);
    });
});

describe("archetypeVisible", () => {
    const archetype = { name: "Email helper", chats: [{ title: "tweak tone" }] };
    it("shows on a name match", () => {
        expect(archetypeVisible(archetype, "email")).toBe(true);
    });
    it("shows on a chat match", () => {
        expect(archetypeVisible(archetype, "tone")).toBe(true);
    });
    it("hides when nothing matches", () => {
        expect(archetypeVisible(archetype, "zzz")).toBe(false);
    });
});

describe("Recent lineage", () => {
    const projects = [
        { name: "Personal", placements: [{ placementId: "personal-general" }] },
        { name: "Peach", placements: [{ placementId: "peach-pricing" }] },
    ];
    const workstreams = [{ id: "ws-1", name: "bid-day" }];

    it("names the project and archetype for a work chat but keeps Main quiet", () => {
        expect(recentLineage({ kind: "work", archetype: "assistant", placement: "personal-general" }, projects, workstreams))
            .toBe("Personal · assistant");
    });

    it("appends a named workstream", () => {
        expect(recentLineage({ kind: "work", archetype: "pricing", placement: "peach-pricing", workstream: "ws-1" }, projects, workstreams))
            .toBe("Peach · pricing · bid-day");
    });

    it("names only the archetype root for an edit chat", () => {
        expect(recentLineage({ kind: "edit", archetype: "pricing", placement: "authoring", workstream: null }, projects, workstreams))
            .toBe("pricing");
    });

    it("filters on title, displayed lineage, or projected content", () => {
        const chat = { id: "chat-1", title: "compare alternates" };
        expect(recentVisible(chat, "Peach · pricing · bid-day", "alternate")).toBe(true);
        expect(recentVisible(chat, "Peach · pricing · bid-day", "bid-day")).toBe(true);
        expect(recentVisible(chat, "Peach · pricing · bid-day", "deadline", new Set(["chat-1"]))).toBe(true);
        expect(recentVisible(chat, "Peach · pricing · bid-day", "missing")).toBe(false);
    });
});

describe("groupChatsByArchetype / lineageVaries", () => {
    const recent = [
        { title: "spring blast", archetype: "Email helper" },
        { title: "code review", archetype: "Reviewer" },
        { title: "summer blast", archetype: "Email helper" },
    ];

    it("groups by archetype preserving first-seen order", () => {
        const groups = groupChatsByArchetype(recent, "");
        expect(groups.map((g) => g.archetype)).toEqual(["Email helper", "Reviewer"]);
        expect(groups[0].chats.map((c) => c.title)).toEqual(["spring blast", "summer blast"]);
    });

    it("drops rows matching neither the chat title nor the archetype, and empty groups vanish", () => {
        const groups = groupChatsByArchetype(recent, "review");
        expect(groups.map((g) => g.archetype)).toEqual(["Reviewer"]);
    });

    it("keeps a whole archetype's chats when the archetype label matches", () => {
        const groups = groupChatsByArchetype(recent, "email");
        expect(groups).toHaveLength(1);
        expect(groups[0].chats).toHaveLength(2);
    });

    it("detects when the chat list spans more than one archetype", () => {
        expect(lineageVaries(recent)).toBe(true);
        expect(lineageVaries([{ title: "a", archetype: "x" }, { title: "b", archetype: "x" }])).toBe(false);
        expect(lineageVaries([])).toBe(false);
    });
});

describe("content-match tier (SEARCH-1: title or chat-log content)", () => {
    it("chatMatches on title, on content-hit id, or neither", () => {
        const hits = new Set(["c2"]);
        expect(chatMatches({ id: "c1", title: "mailout" }, "mail", hits)).toBe(true); // title
        expect(chatMatches({ id: "c2", title: "draft" }, "mail", hits)).toBe(true); // content
        expect(chatMatches({ id: "c3", title: "draft" }, "mail", hits)).toBe(false); // neither
    });

    it("defaults to title-only when no content-hit set is given", () => {
        expect(chatMatches({ id: "c1", title: "draft" }, "mail")).toBe(false);
    });

    it("childrenFor surfaces a content-only chat and ranks title hits first", () => {
        const chats = [
            { id: "c1", title: "draft" }, // content-only hit
            { id: "c2", title: "mailout" }, // title hit
            { id: "c3", title: "review" }, // no match
        ];
        // Parent label doesn't match, so we narrow: title hit "mailout" leads, then
        // the content-only "draft"; "review" is dropped.
        expect(childrenFor("Reviewer", chats, "mail", new Set(["c1"]))).toEqual([
            { id: "c2", title: "mailout" },
            { id: "c1", title: "draft" },
        ]);
    });

    it("placement/project/archetype surface a chat that only matches in content", () => {
        const hits = new Set(["c9"]);
        const placement = { archetypeName: "Reviewer", chats: [{ id: "c9", title: "untitled" }] };
        expect(placementVisible("Acme", placement, "deadline", hits)).toBe(true);
        expect(projectVisible({ name: "Marketing", placements: [placement] }, "deadline", hits)).toBe(true);
        expect(archetypeVisible({ name: "Reviewer", chats: [{ id: "c9", title: "untitled" }] }, "deadline", hits)).toBe(true);
        // …and stay hidden without the content hit.
        expect(placementVisible("Acme", placement, "deadline")).toBe(false);
    });

    it("groupChatsByArchetype keeps a content-only chat, title hits first within a group", () => {
        const recent = [
            { id: "c1", title: "untitled", archetype: "Email helper" }, // content-only
            { id: "c2", title: "deadline plan", archetype: "Email helper" }, // title hit
        ];
        const groups = groupChatsByArchetype(recent, "deadline", new Set(["c1"]));
        expect(groups).toHaveLength(1);
        expect(groups[0].chats.map((c) => c.id)).toEqual(["c2", "c1"]);
    });
});
