// The native device handoff's client half (ADR 0123, LOGIN-2): the deep-link
// parser routes only the account sign-in return, and the status/callback
// wrappers pass exactly the one-time code — never token material.

import { describe, expect, it } from "vitest";
import {
    hubSessionCallback,
    hubSessionStart,
    hubSessionStatus,
    parseNativeHandoffCode,
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
            person: "alice",
            expires: 5,
            expired: false,
            device: null,
        });
        expect(calls[0].path).toBe("/account/hub-session");

        const empty = await hubSessionStatus(jsonReturning({}, []));
        expect(empty).toEqual({
            available: false,
            linked: false,
            person: null,
            expires: null,
            expired: false,
            device: null,
        });
    });

    it("start demands a login URL", async () => {
        await expect(hubSessionStart(jsonReturning({}, []))).rejects.toThrow(/no login URL/);
        const started = await hubSessionStart(jsonReturning({ url: "https://hub/auth/login" }, []));
        expect(started.url).toBe("https://hub/auth/login");
    });

    it("callback posts exactly the one-time code", async () => {
        const calls: Array<{ path: string; body?: unknown }> = [];
        await hubSessionCallback(jsonReturning({ linked: true, available: true }, calls), "c0de");
        expect(calls[0].path).toBe("/account/hub-session/callback");
        expect(calls[0].body).toEqual({ code: "c0de" });
    });
});
