import { describe, expect, it } from "vitest";
import {
    parseDeploymentPlacement,
    parsePlacementPolicy,
    placementPolicyAdmits,
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
