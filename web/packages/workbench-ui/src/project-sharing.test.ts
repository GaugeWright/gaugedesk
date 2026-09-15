import { describe, expect, it } from "vitest";
import type { Participant } from "@gaugewright/control-plane-client";
import { availableProjectShareCandidates } from "./project-sharing";

describe("project sharing directory", () => {
    it("offers active directory identities without duplicating current access", () => {
        const participants = [
            { authority: "authority:current", role: "member", owns: "access", revoked: false },
            { authority: "authority:revoked", role: "viewer", owns: "access", revoked: true },
        ] as Participant[];
        expect(availableProjectShareCandidates([
            { authority: "authority:current", label: "current@example.test" },
            { authority: "authority:revoked", label: "revoked@example.test" },
            { authority: "authority:new", label: "new@example.test" },
        ], participants)).toEqual([
            { authority: "authority:revoked", label: "revoked@example.test" },
            { authority: "authority:new", label: "new@example.test" },
        ]);
    });
});
