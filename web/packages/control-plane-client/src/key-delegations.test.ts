import { describe, expect, it } from "vitest";
import { getProjectKeyDelegations } from "./key-delegations";
import type { WorkbenchTransport } from "./control-plane-workbench";

function transport(body: unknown, seen: string[] = []): WorkbenchTransport {
    return { base: "", json: async (method, path) => { seen.push(`${method} ${path}`); return body; } };
}

const held = {
    id: "d1",
    state: "held",
    work: { kind: "workflow", target: "t1", target_name: "Notes", path: "lessons/hello.whip" },
    keys: [{ scope: "project::p::workflow", label: "workflow storage" }],
    granted_from: "alice",
    granted_at_ms: 1000,
    expires_at_ms: 2000,
    use_count: 1,
    uses: [{ at_ms: 1500, effect: "e1" }],
    refusals: [],
    lapsed_at_ms: null,
};

describe("getProjectKeyDelegations", () => {
    it("reads the project's record at its own path", async () => {
        const seen: string[] = [];
        const record = await getProjectKeyDelegations(
            transport(
                {
                    project: "p 1",
                    lapse_after_ms: 2_592_000_000,
                    last_member_use_ms: null,
                    delegations: [held, { ...held, id: "d2", state: "lapsed", expires_at_ms: undefined, lapsed_since_ms: 1800 }],
                    ended: [{ ...held, id: "d3", state: "ended", expires_at_ms: undefined, ended: { at_ms: 1900, outcome: "completed" } }],
                },
                seen,
            ),
            "p 1",
        );
        expect(seen).toEqual(["GET /projects/p%201/key-delegations"]);
        expect(record.delegations[0]).toMatchObject({
            state: "held",
            work: { path: "lessons/hello.whip", targetName: "Notes" },
            keys: [{ label: "workflow storage" }],
            grantedFrom: "alice",
            expiresAtMs: 2000,
            useCount: 1,
        });
        expect(record.delegations[1]).toMatchObject({ state: "lapsed", lapsedSinceMs: 1800, expiresAtMs: null });
        expect(record.ended[0]).toMatchObject({ state: "ended", ended: { atMs: 1900, outcome: "completed" } });
    });

    it("refuses a record that is about another project or a state it does not know", async () => {
        await expect(
            getProjectKeyDelegations(transport({ project: "other", lapse_after_ms: 1, delegations: [], ended: [] }), "p"),
        ).rejects.toThrow("another project");
        await expect(
            getProjectKeyDelegations(
                transport({ project: "p", lapse_after_ms: 1, delegations: [{ ...held, state: "borrowed" }], ended: [] }),
                "p",
            ),
        ).rejects.toThrow("state");
    });
});
