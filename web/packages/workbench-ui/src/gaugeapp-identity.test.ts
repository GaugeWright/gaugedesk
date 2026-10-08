import { describe, expect, it } from "vitest";
import type { AccountSettingsSummary, GaugeAppPageModel, GaugeAppSession } from "@gaugewright/control-plane-client";
import { gaugeAppMenuIdentity, summaryMenuIdentity, UNNAMED_ACCOUNT } from "./gaugeapp-identity";

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
    it("carries the account's avatar and never a URL that is not an image data URI", () => {
        const withAvatar = (avatar: unknown): GaugeAppPageModel => {
            const base = page();
            const model = base.model as { profile: Record<string, unknown> };
            return { ...base, model: { ...model, profile: { ...model.profile, avatar } } };
        };
        const jpeg = "data:image/jpeg;base64,/9j/4AAQ";
        expect(gaugeAppMenuIdentity(session, withAvatar(jpeg))).toEqual({
            name: "Avery", email: "avery@example.invalid", avatar: jpeg,
        });
        expect(gaugeAppMenuIdentity(session, withAvatar(null))).toEqual({ name: "Avery", email: "avery@example.invalid" });
        expect(gaugeAppMenuIdentity(session, withAvatar("https://lh3.googleusercontent.com/a/x")))
            .toEqual({ name: "Avery", email: "avery@example.invalid" });
    });

    it("uses the admitted account profile without a desktop bearer", () => {
        expect(gaugeAppMenuIdentity(session, page())).toEqual({ name: "Avery", email: "avery@example.invalid" });
    });
    it("says an authenticated person is signed in, never their account id, before their profile has loaded", () => {
        expect(gaugeAppMenuIdentity(session, undefined)).toEqual({ name: UNNAMED_ACCOUNT, pending: true });
        expect(gaugeAppMenuIdentity(session, page(""))).toEqual({ name: "avery", email: "avery@example.invalid" });
    });
    it("names a profile with neither a display name nor an address without its account id", () => {
        const bare: GaugeAppPageModel = { ...page(), model: { profile: { account_id: session.actor }, verified_contacts: [] } };
        expect(gaugeAppMenuIdentity(session, bare)).toEqual({ name: UNNAMED_ACCOUNT });
    });
    it("does not retain identity after admission is lost", () => {
        expect(gaugeAppMenuIdentity(undefined, page())).toBeNull();
    });
    it("never labels an account with a previous actor's cached profile", () => {
        expect(gaugeAppMenuIdentity(session, page("Other person", "person-2"))).toEqual({ name: UNNAMED_ACCOUNT, pending: true });
    });
    it("does not confuse a tenant or another management app with account admission", () => {
        expect(gaugeAppMenuIdentity({ ...session, scope: { kind: "tenant", id: "org-1" } }, page())).toBeNull();
        expect(gaugeAppMenuIdentity({ ...session, app: "administration" }, page())).toBeNull();
    });
    it("refuses a mislabeled page even when its embedded profile names this person", () => {
        expect(gaugeAppMenuIdentity(session, { ...page(), scope: { kind: "person", id: "person-2" } })).toEqual({ name: UNNAMED_ACCOUNT, pending: true });
        expect(gaugeAppMenuIdentity(session, { ...page(), app: "administration" })).toEqual({ name: UNNAMED_ACCOUNT, pending: true });
        expect(gaugeAppMenuIdentity(session, { ...page(), read_model: "AccountPageV1" })).toEqual({ name: UNNAMED_ACCOUNT, pending: true });
    });
});

describe("account summary menu identity (WS-916)", () => {
    const summary = (profile: Partial<AccountSettingsSummary["profile"]>): AccountSettingsSummary => ({
        actor: "person-1",
        profile: { display_name: null, email: null, avatar: null, ...profile },
        memberships: [],
        appearance: undefined,
    });

    it("shows what the admitted Account page would show", () => {
        const jpeg = "data:image/jpeg;base64,/9j/4AAQ";
        const from = summary({ display_name: "Avery", email: "avery@example.invalid", avatar: jpeg });
        expect(summaryMenuIdentity(from)).toEqual({ name: "Avery", email: "avery@example.invalid", avatar: jpeg });
        const admitted = page();
        const model = admitted.model as { profile: Record<string, unknown> };
        expect(gaugeAppMenuIdentity(session, { ...admitted, model: { ...model, profile: { ...model.profile, avatar: jpeg } } }))
            .toEqual(summaryMenuIdentity(from));
    });

    it("falls back to the address, never to the account id, and never carries a non-image avatar", () => {
        expect(summaryMenuIdentity(summary({ email: "avery@example.invalid" })))
            .toEqual({ name: "avery", email: "avery@example.invalid" });
        expect(summaryMenuIdentity(summary({ display_name: "  " }))).toEqual({ name: UNNAMED_ACCOUNT });
        expect(summaryMenuIdentity(summary({ display_name: "Avery", avatar: "https://lh3.googleusercontent.com/a/x" })))
            .toEqual({ name: "Avery" });
        expect(summaryMenuIdentity(undefined)).toBeNull();
    });
});
