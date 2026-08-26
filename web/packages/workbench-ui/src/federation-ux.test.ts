import { describe, expect, it } from "vitest";
import {
    distributionStateLabel,
    protectedRunRefusal,
    shortIdentity,
} from "./EngagementPane";
import {
    inviteRequiresDistributionConsent,
    type InviteDistributionSummary,
} from "./DevicesModal";

const protectedDistribution: InviteDistributionSummary = {
    agent_id: "agent:analysis",
    agent_name: "Analysis Agent",
    revision: "7",
    release_digest: "sha256:release",
    profile: "protected_commercial",
    owner_authority: "tenant:owner",
    recipient_authority: "tenant:recipient",
    recipient_display_name: "Recipient & Co",
    lease_seconds: 2_592_000,
    max_runs: 25,
    expires_at: null,
};

describe("federation distribution UX", () => {
    it("requires explicit invite consent whenever Agent terms are disclosed", () => {
        expect(inviteRequiresDistributionConsent(undefined)).toBe(false);
        expect(inviteRequiresDistributionConsent([])).toBe(false);
        expect(inviteRequiresDistributionConsent([protectedDistribution])).toBe(true);
    });

    it("presents lifecycle states in user language", () => {
        expect(distributionStateLabel("licensed")).toBe("Licensed copy");
        expect(distributionStateLabel("awaiting_issue")).toBe("Release pending");
        expect(distributionStateLabel("issued")).toBe("Ready");
        expect(distributionStateLabel("expired")).toBe("Expired");
        expect(distributionStateLabel("revoked")).toBe("Revoked");
    });

    it("explains protected refusals without implying a silent downgrade", () => {
        expect(protectedRunRefusal("protected release expired")).toContain("expired");
        expect(protectedRunRefusal("license was revoked")).toContain("revoked");
        expect(protectedRunRefusal("protected profile service unavailable")).toContain("unavailable");
        expect(protectedRunRefusal("ordinary admission refusal")).toBeNull();
    });

    it("keeps long authorities legible in the contract summary", () => {
        expect(shortIdentity("tenant:0123456789abcdefghijklmnop")).toBe("tenant:012…klmnop");
        expect(shortIdentity("")).toBe("pending");
    });
});
