// The native device handoff's client half (ADR 0123, LOGIN-2): the deep-link
// parser routes only the account sign-in return, and the status/callback
// wrappers pass exactly the one-time code — never token material.

import { describe, expect, it } from "vitest";
import {
    handoffCodeFromPaste,
    hubSessionCallback,
    hubSessionClaimHome,
    hubSessionAccounts,
    hubSessionReach,
    hubSessionSelect,
    hubSessionStart,
    hubSessionStatus,
    parseNativeHandoffCode,
    parseWebReturnHandoffCode,
    type RouteJson,
} from "./index";

describe("parseNativeHandoffCode", () => {
    it("reads the code off the sign-in return fragment", () => {
        expect(parseNativeHandoffCode("gaugewright://auth/callback#code=abc123")).toBe("abc123");
        expect(
            parseNativeHandoffCode("gaugewright://auth/callback#code=a-b_c&extra=1"),
        ).toBe("a-b_c");
    });

    it("returns null for every other URL", () => {
        expect(parseNativeHandoffCode("gaugewright://invite#blob")).toBeNull();
        expect(parseNativeHandoffCode("gaugewright://auth/callback")).toBeNull();
        expect(parseNativeHandoffCode("gaugewright://auth/callback#code=")).toBeNull();
        expect(parseNativeHandoffCode("https://auth.example.test/callback#code=x")).toBeNull();
        expect(parseNativeHandoffCode("")).toBeNull();
    });
});

describe("handoffCodeFromPaste", () => {
    it("reads the code out of a pasted return link", () => {
        expect(handoffCodeFromPaste("gaugewright://auth/callback#code=abc123")).toBe("abc123");
        expect(handoffCodeFromPaste("  gaugewright://auth/callback#code=abc123  ")).toBe("abc123");
    });

    it("accepts the bare code copied off the return page", () => {
        expect(handoffCodeFromPaste("abc123")).toBe("abc123");
        expect(handoffCodeFromPaste("  a-b_c.d~e  ")).toBe("a-b_c.d~e");
    });

    it("refuses pastes that are neither", () => {
        expect(handoffCodeFromPaste("")).toBeNull();
        expect(handoffCodeFromPaste("   ")).toBeNull();
        // A gaugewright:// link that is not the sign-in return.
        expect(handoffCodeFromPaste("gaugewright://invite#blob")).toBeNull();
        // A link to anywhere else is a wrong paste, not a code.
        expect(handoffCodeFromPaste("https://hub.example.test/auth/login")).toBeNull();
        // Prose is not a code.
        expect(handoffCodeFromPaste("the browser said it could not open it")).toBeNull();
    });
});

describe("parseWebReturnHandoffCode", () => {
    it("reads the code off the dev web-return fragment", () => {
        expect(parseWebReturnHandoffCode("#code=abc123")).toBe("abc123");
        expect(parseWebReturnHandoffCode("code=abc123")).toBe("abc123");
        expect(parseWebReturnHandoffCode("#code=a-b_c&extra=1")).toBe("a-b_c");
    });

    it("ignores empty, foreign, and local-OIDC fragments", () => {
        expect(parseWebReturnHandoffCode("")).toBeNull();
        expect(parseWebReturnHandoffCode("#")).toBeNull();
        expect(parseWebReturnHandoffCode("#code=")).toBeNull();
        expect(parseWebReturnHandoffCode("#section-3")).toBeNull();
        // The local-OIDC callback fragment belongs to the bearer flow, even if a
        // stray `code` rides along.
        expect(parseWebReturnHandoffCode("#id_token=jwt&token_type=Bearer")).toBeNull();
        expect(parseWebReturnHandoffCode("#id_token=jwt&code=x")).toBeNull();
    });
});

function jsonReturning(payload: unknown, calls: Array<{ path: string; body?: unknown }>): RouteJson {
    return async (_method, path, body) => {
        calls.push({ path, body });
        return payload;
    };
}

describe("hub session wrappers", () => {
    it("projects status with safe defaults", async () => {
        const calls: Array<{ path: string }> = [];
        const status = await hubSessionStatus(
            jsonReturning({ available: true, linked: true, person: "alice", expires: 5 }, calls),
        );
        expect(status).toEqual({
            available: true,
            linked: true,
            local: false,
            localChoiceRequired: false,
            person: "alice",
            // No label from an older control plane: the subject stands in.
            label: "alice",
            expires: 5,
            expired: false,
            device: null,
            homeClaim: null,
        });
        expect(calls[0].path).toBe("/account/hub-session");

        const empty = await hubSessionStatus(jsonReturning({}, []));
        expect(empty).toEqual({
            available: false,
            linked: false,
            local: false,
            localChoiceRequired: false,
            person: null,
            label: null,
            expires: null,
            expired: false,
            device: null,
            homeClaim: null,
        });
    });

    it("shows the unclaimed local project count and sends the exact selected account to claim", async () => {
        const calls: Array<{ path: string; body?: unknown }> = [];
        const status = await hubSessionStatus(jsonReturning({
            linked: true, person: "alice", home_claim: { state: "available", projects: 3 },
        }, calls));
        expect(status.homeClaim).toEqual({ state: "available", projects: 3 });
        const claimed = await hubSessionClaimHome(jsonReturning({
            linked: true, person: "alice", home_claim: { state: "claimed", owner: "alice" },
        }, calls), "alice");
        expect(calls.at(-1)).toEqual({
            path: "/account/hub-session/claim-home", body: { person: "alice", confirm: true },
        });
        expect(claimed.homeClaim).toEqual({ state: "claimed", owner: "alice" });
    });

    it("start demands a login URL", async () => {
        await expect(hubSessionStart(jsonReturning({}, []))).rejects.toThrow(/no login URL/);
        const started = await hubSessionStart(jsonReturning({ url: "https://hub/auth/login" }, []));
        expect(started.url).toBe("https://hub/auth/login");
        expect(started.webReturn).toBe(false);
    });

    it("start reports a dev web return so the caller keeps the tab", async () => {
        const native = await hubSessionStart(
            jsonReturning({ url: "https://hub/auth/login", return: "gaugewright://auth/callback" }, []),
        );
        expect(native.webReturn).toBe(false);
        const web = await hubSessionStart(
            jsonReturning(
                { url: "https://hub/auth/login", return: "http://localhost:5176/" },
                [],
            ),
        );
        expect(web.webReturn).toBe(true);
    });

    it("prefers the label over the opaque subject when the server sends one", async () => {
        const status = await hubSessionStatus(
            jsonReturning(
                {
                    available: true,
                    linked: true,
                    person: "100000000000000000001",
                    label: "alice@example.test",
                },
                [],
            ),
        );
        expect(status.person).toBe("100000000000000000001");
        expect(status.label).toBe("alice@example.test");
    });

    it("callback posts exactly the one-time code", async () => {
        const calls: Array<{ path: string; body?: unknown }> = [];
        await hubSessionCallback(jsonReturning({ linked: true, available: true }, calls), "c0de");
        expect(calls[0].path).toBe("/account/hub-session/callback");
        expect(calls[0].body).toEqual({ code: "c0de" });
    });

    it("lists retained accounts without credentials and selects an exact live session", async () => {
        const calls: Array<{ path: string; body?: unknown }> = [];
        const roster = await hubSessionAccounts(jsonReturning({
            selected: "alice",
            accounts: [
                { person: "alice", label: "Alice", expired: false },
                { person: "bob", expired: true },
            ],
        }, calls));
        expect(roster).toEqual({
            selected: "alice",
            accounts: [
                { person: "alice", label: "Alice", expired: false },
                { person: "bob", label: "bob", expired: true },
            ],
        });
        expect(calls[0]).toEqual({ path: "/account/hub-sessions", body: undefined });

        const selected = await hubSessionSelect(jsonReturning({
            available: true, linked: true, person: "bob", expired: false,
        }, calls), "bob");
        expect(selected.person).toBe("bob");
        expect(calls[1]).toEqual({ path: "/account/hub-session/select", body: { person: "bob" } });
        await expect(hubSessionSelect(jsonReturning({ linked: true, person: "alice" }, []), "bob"))
            .rejects.toThrow("unavailable");
    });

    it("uses only verified native routes for relay pins", async () => {
        const relay = {
            endpoint: "wss://relay.example.test",
            handle: "a".repeat(43),
            proof: "b".repeat(43),
            route_epoch: 1,
            home_fingerprint: "ab".repeat(32),
        };
        const reach = await hubSessionReach(jsonReturning({
            person: "alice",
            homes: { homes: [] },
            routes: { routes: [
                { project: "direct", home_id: "home:one", endpoint: "https://home.example.test" },
                { project: "unsigned", home_id: "home:two", relay },
            ] },
            signed_routes: { routes: [
                { project: "signed", home_id: "home:three", relay },
            ] },
        }, []));
        expect(reach.routes.map((route) => route.project)).toEqual(["direct", "signed"]);
        expect(reach.routes[1]?.relay?.homeFingerprint).toBe("ab".repeat(32));
    });
});
