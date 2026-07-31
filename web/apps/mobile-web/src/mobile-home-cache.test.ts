import { describe, expect, it } from "vitest";
import type {
    HomeId,
    ProjectId,
} from "@gaugewright/control-plane-client";
import {
    MobileHomeCache,
    parseMobileTargetReference,
    projectScopedWorkspace,
} from "./mobile-home-cache";

const home = (id: string) => id as HomeId;
const project = (id: string) => id as ProjectId;

describe("MobileHomeCache", () => {
    it("cannot satisfy one Home with another Home's projection", () => {
        const cache = new MobileHomeCache<string>("account:one");
        cache.put({
            homeId: home("home:one"),
            project: project("project:one"),
            key: "workspace",
            value: "one",
            freshness: "live",
            updatedAt: 1,
        });
        cache.put({
            homeId: home("home:two"),
            project: project("project:two"),
            key: "workspace",
            value: "two",
            freshness: "live",
            updatedAt: 2,
        });

        expect(
            cache.get(home("home:one"), project("project:one"), "workspace")?.value,
        ).toBe("one");
        expect(
            cache.get(home("home:two"), project("project:one"), "workspace"),
        ).toBeNull();
    });

    it("marks and clears only the addressed Home", () => {
        const cache = new MobileHomeCache<string>("account:one");
        for (const id of ["one", "two"]) {
            cache.put({
                homeId: home(`home:${id}`),
                project: project(`project:${id}`),
                key: "workspace",
                value: id,
                freshness: "live",
                updatedAt: 1,
            });
        }
        cache.markHome(home("home:one"), "offline");
        expect(cache.snapshot().find((entry) => entry.homeId === "home:one")?.freshness)
            .toBe("offline");
        expect(cache.snapshot().find((entry) => entry.homeId === "home:two")?.freshness)
            .toBe("live");
        cache.clearHome(home("home:one"));
        expect(cache.snapshot().map((entry) => entry.homeId)).toEqual(["home:two"]);
    });

    it("partitions persisted values by identity and restores them only as stale", () => {
        const values = new Map<string, string>();
        const storage = {
            getItem: (key: string) => values.get(key) ?? null,
            setItem: (key: string, value: string) => values.set(key, value),
            removeItem: (key: string) => values.delete(key),
        };
        const first = new MobileHomeCache<string>("account:one", storage);
        first.put({
            homeId: home("home:one"),
            project: project("project:one"),
            key: "workspace",
            value: "protected",
            freshness: "live",
            updatedAt: 10,
        });

        const restored = new MobileHomeCache<string>("account:one", storage);
        expect(
            restored.get(home("home:one"), project("project:one"), "workspace"),
        ).toMatchObject({ value: "protected", freshness: "stale" });
        const otherIdentity = new MobileHomeCache<string>("account:two", storage);
        expect(
            otherIdentity.get(home("home:one"), project("project:one"), "workspace"),
        ).toBeNull();
    });
});

describe("projectScopedWorkspace", () => {
    it("does not embed sibling project data under a project-partitioned cache key", () => {
        const workspace = {
            archetypes: [{ id: "archetype:shared", name: "Shared" }],
            projects: [
                {
                    id: "project:one",
                    homeId: "home:one",
                    name: "One",
                    targets: [{ id: "target:one" }],
                    placements: [{
                        placementId: "placement:one",
                        chats: [{ id: "chat:one" }],
                    }],
                },
                {
                    id: "project:two",
                    homeId: "home:one",
                    name: "Two",
                    targets: [{ id: "target:two" }],
                    placements: [{
                        placementId: "placement:two",
                        chats: [{ id: "chat:two" }],
                    }],
                },
            ],
            recent: [
                { id: "chat:one", title: "One" },
                { id: "chat:two", title: "Two" },
            ],
            workstreams: [
                {
                    id: "line:one",
                    placementId: "placement:one",
                    members: ["chat:one", "chat:two"],
                },
                {
                    id: "line:two",
                    placementId: "placement:two",
                    members: ["chat:two"],
                },
            ],
            workTargets: [
                { id: "target:one", name: "One" },
                { id: "target:two", name: "Two" },
            ],
            personalPlacement: "placement:one",
        } as unknown as Parameters<typeof projectScopedWorkspace>[0];

        const scoped = projectScopedWorkspace(
            workspace,
            project("project:one"),
        );
        expect(scoped?.projects.map((item) => item.id)).toEqual(["project:one"]);
        expect(scoped?.recent.map((item) => item.id)).toEqual(["chat:one"]);
        expect(scoped?.workstreams.map((item) => item.id)).toEqual(["line:one"]);
        expect(scoped?.workstreams[0]?.members).toEqual(["chat:one"]);
        expect(scoped?.workTargets.map((item) => item.id)).toEqual(["target:one"]);
        expect(scoped?.archetypes).toEqual([]);
        expect(JSON.stringify(scoped)).not.toContain("project:two");
        expect(JSON.stringify(scoped)).not.toContain("chat:two");
        expect(JSON.stringify(scoped)).not.toContain("target:two");
    });
});

describe("mobile target references", () => {
    it("parses reference-only custom and universal links", () => {
        const expected = {
            version: 1,
            project: "project:one",
            kind: "chat",
            id: "chat:one",
            pane: "chat",
            engagement: null,
        };
        expect(
            parseMobileTargetReference(
                "gaugewright://open?project=project%3Aone&kind=chat&id=chat%3Aone&pane=chat",
            ),
        ).toEqual(expected);
        expect(
            parseMobileTargetReference(
                "https://app.gaugewright.com/link?project=project%3Aone&kind=chat&id=chat%3Aone&pane=chat",
            ),
        ).toEqual(expected);
    });

    it("rejects protected notification payload content", () => {
        expect(
            parseMobileTargetReference(
                "gaugewright://open?project=p&kind=chat&id=c&pane=chat&message=secret",
            ),
        ).toBeNull();
        expect(
            parseMobileTargetReference(
                "gaugewright://open?project=p&kind=file&id=README.md&pane=content",
            ),
        ).toBeNull();
    });
});
