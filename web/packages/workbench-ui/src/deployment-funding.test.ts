/**
 * Who pays (ADR 0085 §1/§6, FUND-1).
 *
 * These pin the property the whole managed path rests on: an empty
 * `credential_ref` *means* managed funding, so nothing may produce one by
 * accident, and nothing may produce both a plan and a credential.
 */

import { describe, expect, it } from "vitest";
import {
    fundingBlockerFor,
    fundingFieldsFrom,
    isManagedPlanRef,
    managedPlanRefFromBilling,
    MANAGED_PLAN_PREFIX,
    type FundingDraft,
} from "./deployment-funding";

const PLAN = `${MANAGED_PLAN_PREFIX}74656e616e74:73747269706500`;
const KEY = "credential:public:abc123:openai:def456";

const draft = (over: Partial<FundingDraft> = {}): FundingDraft => ({
    mode: "managed",
    managedPlanRef: PLAN,
    credentialRef: "",
    credentialClass: "managed-openai",
    ...over,
});

describe("managed funding", () => {
    it("discovers only an active authenticated plan", () => {
        expect(managedPlanRefFromBilling({ plan: { status: "active" }, funding_ref: PLAN })).toBe(PLAN);
        expect(managedPlanRefFromBilling({ plan: { status: "suspended" }, funding_ref: PLAN })).toBe("");
        expect(managedPlanRefFromBilling({ plan: { status: "active" }, funding_ref: KEY })).toBe("");
        expect(managedPlanRefFromBilling({ plan: null, funding_ref: null })).toBe("");
    });

    it("publishes a plan and deliberately no credential", () => {
        const fields = fundingFieldsFrom(draft());
        expect(fields?.funding_ref).toBe(PLAN);
        // The load-bearing assertion: emptiness is the signal the edge and the
        // runtime both read as "managed".
        expect(fields?.credential_ref).toBe("");
    });

    it("is unpublishable when this Home has no plan", () => {
        // Better than publishing a plan-shaped blank and failing at admission.
        expect(fundingFieldsFrom(draft({ managedPlanRef: "" }))).toBeNull();
        expect(fundingBlockerFor(draft({ managedPlanRef: "" }))).toMatch(/no managed plan/i);
    });

    it("refuses a credential masquerading as a plan", () => {
        expect(fundingFieldsFrom(draft({ managedPlanRef: KEY }))).toBeNull();
    });
});

describe("BYOK funding", () => {
    const byok = draft({ mode: "byok", credentialRef: KEY });

    it("publishes funding equal to the credential, as the edge requires", () => {
        const fields = fundingFieldsFrom(byok);
        expect(fields?.credential_ref).toBe(KEY);
        // The edge refuses any other pairing: "BYOK funding must use the exact
        // owner credential reference".
        expect(fields?.funding_ref).toBe(KEY);
    });

    it("never yields an empty credential, which would read as managed", () => {
        // The failure this prevents: a BYOK deployment silently funded by
        // GaugeWright because a blank slipped through.
        for (const credentialRef of ["", "   "]) {
            expect(fundingFieldsFrom(draft({ mode: "byok", credentialRef }))).toBeNull();
        }
        expect(fundingBlockerFor(draft({ mode: "byok", credentialRef: "" })))
            .toMatch(/provider key/i);
    });

    it("refuses a plan reference offered as a provider key", () => {
        expect(fundingFieldsFrom(draft({ mode: "byok", credentialRef: PLAN }))).toBeNull();
        expect(fundingBlockerFor(draft({ mode: "byok", credentialRef: PLAN })))
            .toMatch(/billing plan, not a provider key/i);
    });

    it("refuses a credential with no class to match against the release", () => {
        expect(fundingBlockerFor(draft({ mode: "byok", credentialRef: KEY, credentialClass: "" })))
            .toMatch(/class/i);
    });
});

describe("the two reference spaces stay disjoint", () => {
    it("a plan is never a credential and a credential is never a plan", () => {
        expect(isManagedPlanRef(PLAN)).toBe(true);
        expect(isManagedPlanRef(KEY)).toBe(false);
        expect(PLAN.startsWith("credential:")).toBe(false);
    });
});
