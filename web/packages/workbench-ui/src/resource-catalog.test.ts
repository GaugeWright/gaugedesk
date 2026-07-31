import { describe, expect, it } from "vitest";
import type { ResourceView } from "@gaugewright/control-plane-client";
import {
    availabilityLabel,
    availabilityOf,
    contextSources,
    isContextSource,
    isOutput,
    kindLabel,
    outputProtectionLabel,
    outputs,
    resourceTitle,
    reviewPhaseLabel,
} from "./resource-catalog";

function res(over: Partial<ResourceView>): ResourceView {
    return {
        id: "r1",
        kind: "context",
        owner: "local-user",
        stakeholders: [],
        access: "Granted",
        tombstoned: false,
        ...over,
    };
}

describe("availabilityOf", () => {
    it("granted, non-tombstoned → available", () => {
        expect(availabilityOf(res({ access: "Granted" }))).toBe("available");
    });
    it("init / requested → pending access", () => {
        expect(availabilityOf(res({ access: "Init" }))).toBe("pending");
        expect(availabilityOf(res({ access: "Requested" }))).toBe("pending");
    });
    it("revoked / denied → blocked", () => {
        expect(availabilityOf(res({ access: "Revoked" }))).toBe("blocked");
        expect(availabilityOf(res({ access: "Denied" }))).toBe("blocked");
    });
    it("tombstone wins over any access phase", () => {
        expect(availabilityOf(res({ access: "Granted", tombstoned: true }))).toBe("erased");
        expect(availabilityOf(res({ access: "Revoked", tombstoned: true }))).toBe("erased");
    });
    it("an unknown access phase reads as pending", () => {
        expect(availabilityOf(res({ access: "Weird" as never }))).toBe("pending");
    });
});

describe("availabilityLabel", () => {
    it("maps each availability to a human caption", () => {
        expect(availabilityLabel("available")).toBe("available");
        expect(availabilityLabel("pending")).toBe("awaiting access");
        expect(availabilityLabel("blocked")).toBe("access blocked");
        expect(availabilityLabel("erased")).toBe("erased");
    });
});

describe("partitioning", () => {
    const list: ResourceView[] = [
        res({ id: "ctx-a", kind: "context" }),
        res({ id: "method-x", kind: "method" }),
        res({ id: "out-1", kind: "output" }),
        res({ id: "out-2", kind: "output", tombstoned: true }),
    ];

    it("context sources are everything that is not an output", () => {
        expect(isContextSource(res({ kind: "context" }))).toBe(true);
        expect(isContextSource(res({ kind: "method" }))).toBe(true);
        expect(isContextSource(res({ kind: "output" }))).toBe(false);
        expect(contextSources(list).map((r) => r.id)).toEqual(["ctx-a", "method-x"]);
    });

    it("outputs are only the output kind, order preserved", () => {
        expect(isOutput(res({ kind: "output" }))).toBe(true);
        expect(outputs(list).map((r) => r.id)).toEqual(["out-1", "out-2"]);
    });
});

describe("labels", () => {
    it("kindLabel names the known kinds and passes others through", () => {
        expect(kindLabel("method")).toBe("archetype");
        expect(kindLabel("context")).toBe("context");
        expect(kindLabel("output")).toBe("output");
        expect(kindLabel("custom")).toBe("custom");
    });
    it("resourceTitle strips a known handle prefix", () => {
        expect(resourceTitle(res({ id: "out-report" }))).toBe("report");
        expect(resourceTitle(res({ id: "ctx-folder" }))).toBe("folder");
        expect(resourceTitle(res({ id: "bare" }))).toBe("bare");
    });
    it("resourceTitle shows a short tag for an opaque hex handle, not a scary raw id (round-12 A)", () => {
        expect(resourceTitle(res({ id: "chat-1c3c39b88c0a" }))).toBe("1c3c39");
        expect(resourceTitle(res({ id: "out-9984ab12cd" }))).toBe("9984ab");
        // A nested handle (out-chat-<hex>) is fully stripped to a short tag.
        expect(resourceTitle(res({ id: "out-chat-c786ffdf6377" }))).toBe("c786ff");
        // A human-named handle still passes through untouched.
        expect(resourceTitle(res({ id: "out-tagline-draft" }))).toBe("tagline-draft");
    });
});

describe("output protection labels — plain words, never raw phase tokens (round-12 A)", () => {
    it("shows a plain baseline for the initial state (Init/Init) — never a raw token", () => {
        expect(outputProtectionLabel("Init", "Init")).toBe("not yet reviewed");
        expect(outputProtectionLabel(undefined, undefined)).toBe("not yet reviewed");
    });
    it("translates review phases plainly", () => {
        expect(reviewPhaseLabel("Proposed")).toBe("awaiting review");
        expect(reviewPhaseLabel("Cleared")).toBe("reviewed");
        expect(reviewPhaseLabel("Released")).toBe("released");
        expect(reviewPhaseLabel("Init")).toBeNull();
    });
    it("prefers the later export stage when it is meaningful", () => {
        expect(outputProtectionLabel("Cleared", "Exported")).toBe("sent out");
        expect(outputProtectionLabel("Proposed", "Init")).toBe("awaiting review");
    });
});
