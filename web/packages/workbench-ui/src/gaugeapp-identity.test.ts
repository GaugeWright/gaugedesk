import { describe, expect, it } from "vitest";
import type { GaugeAppPageModel, GaugeAppSession } from "@gaugewright/control-plane-client";
import { gaugeAppMenuIdentity } from "./gaugeapp-identity";

const session: GaugeAppSession = {
    id: "session-1", generation: "epoch-1", app: "account-settings",
    scope: { kind: "person", id: "person-1" }, actor: "person-1",
    capabilities: [], pages: [], commands: [], update_cursor: "cursor-1",
};
const page = (displayName: unknown = "Avery", actor = session.actor): GaugeAppPageModel => ({
    app: "account-settings", scope: { kind: "person", id: actor },
    id: "account", read_model: "AccountSettingsPageV1", version: 1,
    resource_basis: "basis-1", freshness: "live",
    model: { profile: { account_id: actor, display_name: displayName },
        verified_contacts: [{ email: "avery@example.invalid" }] },
});

describe("GaugeApp account menu identity", () => {
    it("uses the admitted account profile without a desktop bearer", () => {
        expect(gaugeAppMenuIdentity(session, page())).toEqual({ name: "Avery", email: "avery@example.invalid" });
    });
    it("names an authenticated person before their profile has loaded", () => {
        expect(gaugeAppMenuIdentity(session, undefined)).toEqual({ name: "person-1" });
        expect(gaugeAppMenuIdentity(session, page(""))).toEqual({ name: "avery", email: "avery@example.invalid" });
    });
    it("does not retain identity after admission is lost", () => {
        expect(gaugeAppMenuIdentity(undefined, page())).toBeNull();
    });
    it("never labels an account with a previous actor's cached profile", () => {
        expect(gaugeAppMenuIdentity(session, page("Other person", "person-2"))).toEqual({ name: "person-1" });
    });
    it("does not confuse a tenant or another management app with account admission", () => {
        expect(gaugeAppMenuIdentity({ ...session, scope: { kind: "tenant", id: "org-1" } }, page())).toBeNull();
        expect(gaugeAppMenuIdentity({ ...session, app: "administration" }, page())).toBeNull();
    });
    it("refuses a mislabeled page even when its embedded profile names this person", () => {
        expect(gaugeAppMenuIdentity(session, { ...page(), scope: { kind: "person", id: "person-2" } })).toEqual({ name: "person-1" });
        expect(gaugeAppMenuIdentity(session, { ...page(), app: "administration" })).toEqual({ name: "person-1" });
        expect(gaugeAppMenuIdentity(session, { ...page(), read_model: "AccountPageV1" })).toEqual({ name: "person-1" });
    });
});
