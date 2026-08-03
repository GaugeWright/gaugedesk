import { describe, expect, it } from "vitest";
import {
    parseDeploymentPlacement,
    parsePlacementPolicy,
    placementPolicyAdmits,
    readPlacementGovernance,
    type PlacementOperator,
} from "./placement-policy";

const operators: readonly PlacementOperator[] = ["local", "counterparty", "neutral"];

describe("placement policy", () => {
    it("fails closed on malformed policy and placement projections", () => {
        expect(() => parsePlacementPolicy({ require_attested: false, allowed_operators: ["other"] }))
            .toThrow("unknown operator");
        expect(() => parsePlacementPolicy({ require_attested: "false", allowed_operators: [] }))
            .toThrow("require_attested");
        expect(() => parseDeploymentPlacement({ operator: "local", attested: "false" }))
            .toThrow("attested");
    });

    // exhausts-every-policy-and-placement-combination
    it("exhausts every operator, attestation, measurement, and policy combination", () => {
        const allowedSets: readonly (readonly PlacementOperator[])[] = [
            [],
            ["local"],
            ["counterparty"],
            ["neutral"],
            ["local", "counterparty"],
            ["local", "neutral"],
            ["counterparty", "neutral"],
            operators,
        ];
        let cases = 0;
        for (const requireAttested of [false, true]) {
            for (const allowed of allowedSets) {
                for (const operator of operators) {
                    for (const attested of [false, true]) {
                        for (const measurementVerified of [false, true]) {
                            const expected = (!requireAttested || attested)
                                && (allowed.length === 0 || allowed.includes(operator))
                                && (!attested || measurementVerified);
                            expect(placementPolicyAdmits(
                                { require_attested: requireAttested, allowed_operators: allowed },
                                { operator, attested },
                                measurementVerified,
                            )).toBe(expected);
                            cases += 1;
                        }
                    }
                }
            }
        }
        expect(cases).toBe(192);
    });
});

describe("placement governance read", () => {
    const respond = (response: Response) => () => Promise.resolve(response);

    it("treats a control plane without the governance route as unmanaged", async () => {
        expect(await readPlacementGovernance(respond(new Response("not found", { status: 404 }))))
            .toEqual({ managed: false });
    });

    it("carries the policy of a governed control plane", async () => {
        const body = JSON.stringify({
            placement_policy: { require_attested: true, allowed_operators: ["local"] },
        });
        expect(await readPlacementGovernance(respond(new Response(body, { status: 200 }))))
            .toEqual({
                managed: true,
                policy: { require_attested: true, allowed_operators: ["local"] },
            });
    });

    // Every failure mode must land as a value, never a rejection: an errored
    // resource read throws mid-render and killed the Devices modal (2026-07-31).
    it("fails closed as managed-without-policy on every other failure", async () => {
        expect(await readPlacementGovernance(respond(new Response("boom", { status: 500 }))))
            .toEqual({ managed: true });
        expect(await readPlacementGovernance(respond(new Response("denied", { status: 401 }))))
            .toEqual({ managed: true });
        expect(await readPlacementGovernance(respond(new Response("not json", { status: 200 }))))
            .toEqual({ managed: true });
        const malformed = JSON.stringify({
            placement_policy: { require_attested: "yes", allowed_operators: [] },
        });
        expect(await readPlacementGovernance(respond(new Response(malformed, { status: 200 }))))
            .toEqual({ managed: true });
        expect(await readPlacementGovernance(() => Promise.reject(new Error("network down"))))
            .toEqual({ managed: true });
    });
});
