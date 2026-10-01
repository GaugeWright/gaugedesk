import { describe, expect, it } from "vitest";
import { accountMenuIdentity } from "./account-menu-identity";

describe("the account menu follows person sign-in", () => {
    it("names the selected local account even while an old account projection is clearing", () => {
        expect(accountMenuIdentity({ name: "Previous account" }, true, null, "host", true))
            .toEqual({ name: "Local account" });
    });
    it("does not treat organization/Home admission as account sign-in", () => {
        expect(accountMenuIdentity(null, true, null, "org-member")).toBeNull();
        expect(accountMenuIdentity(null, true, { linked: false, expired: false, label: "old", person: "old" }, "org-member")).toBeNull();
        expect(accountMenuIdentity(null, true, { linked: true, expired: true, label: "old", person: "old" }, "org-member")).toBeNull();
    });
    it("uses an admitted account independently of organization selection", () => {
        const account = { name: "Person", email: "person@example.test" };
        expect(accountMenuIdentity(account, true, null, "other-member")).toBe(account);
    });
    it("names the live sealed native account even before its hosted page arrives", () => {
        expect(accountMenuIdentity(null, true, { linked: true, expired: false, label: "person@example.test", person: "account-1" }, "other-member"))
            .toEqual({ name: "person", email: "person@example.test" });
    });
    it("keeps direct account-session display for compositions without the hosted account surface", () => {
        expect(accountMenuIdentity(null, false, null, "direct-person")).toEqual({ name: "direct-person" });
    });
});
