import { describe, expect, it } from "vitest";
import type { HubSessionStatus } from "@gaugewright/control-plane-client";
import { claimWithoutAsking, type DesktopHomeDefaultInput } from "./desktop-home-default";

const session = (homeClaim: HubSessionStatus["homeClaim"], extra: Partial<HubSessionStatus> = {}): HubSessionStatus => ({
    available: true,
    linked: true,
    local: false,
    localChoiceRequired: false,
    person: "jack",
    label: "jack@example.com",
    expires: null,
    expired: false,
    device: null,
    homeClaim,
    ...extra,
});

const input = (over: Partial<DesktopHomeDefaultInput> = {}): DesktopHomeDefaultInput => ({
    desktop: true,
    session: session({ state: "available", projects: 1, fresh: true }),
    noHome: { homes: [], routes: [], selectedHome: null },
    invitation: false,
    ...over,
});

describe("claiming a desktop for a signed-in account no Home serves", () => {
    it("claims a fresh computer without asking", () => {
        expect(claimWithoutAsking(input())).toBe(true);
    });

    it("never claims a computer holding local work, or one another account owns", () => {
        expect(claimWithoutAsking(input({
            session: session({ state: "available", projects: 4, fresh: false }),
        }))).toBe(false);
        expect(claimWithoutAsking(input({
            session: session({ state: "claimed", owner: "someone-else", owners: ["someone-else"] }),
        }))).toBe(false);
        expect(claimWithoutAsking(input({ session: session({ state: "governed" }) }))).toBe(false);
    });

    it("leaves an account a Home or a shared route already serves to its cards", () => {
        expect(claimWithoutAsking(input({ noHome: { homes: [{}], routes: [] } }))).toBe(false);
        expect(claimWithoutAsking(input({ noHome: { homes: [], routes: [{}] } }))).toBe(false);
        expect(claimWithoutAsking(input({ noHome: { homes: [], routes: [], selectedHome: "home:laptop" } }))).toBe(false);
    });

    it("claims nothing while an invitation waits, off the desktop, or without a live session", () => {
        expect(claimWithoutAsking(input({ invitation: true }))).toBe(false);
        expect(claimWithoutAsking(input({ desktop: false }))).toBe(false);
        expect(claimWithoutAsking(input({ noHome: null }))).toBe(false);
        expect(claimWithoutAsking(input({ session: session(null, { linked: false }) }))).toBe(false);
        expect(claimWithoutAsking(input({
            session: session({ state: "available", projects: 1, fresh: true }, { expired: true }),
        }))).toBe(false);
    });
});
