import { describe, expect, it } from "vitest";
import {
    enrollAuthorize,
    enrollHost,
    enrollHostStatus,
    enrollJoin,
    enrollJoinStatus,
    type EnrollmentTicket,
} from "./control-plane-account";

/** Records every (method, path, body) a client call issues, returning a canned reply. */
function recorder(reply: unknown = {}) {
    const calls: { method: string; path: string; body?: unknown }[] = [];
    const json = async (method: string, path: string, body?: unknown) => {
        calls.push({ method, path, body });
        return reply;
    };
    return { json, calls };
}

const TICKET: EnrollmentTicket = {
    session: "sess-1",
    account_root: "04root",
    broker: "wss://relay.gaugewright.com",
};

describe("device-enrollment handshake client (ACCT-1)", () => {
    it("holder starts a host leg and unwraps the ticket", async () => {
        const { json, calls } = recorder({ ticket: TICKET });
        const out = await enrollHost(json);
        expect(out).toEqual(TICKET);
        expect(calls[0]).toEqual({
            method: "POST",
            path: "/account/devices/enroll/host",
            body: undefined,
        });
    });

    it("polls the host leg status (phase + SAS)", async () => {
        const { json, calls } = recorder({ phase: "sas_ready", sas: "123456", error: null });
        const out = await enrollHostStatus(json, "sess-1");
        expect(out).toEqual({ phase: "sas_ready", sas: "123456", error: null });
        expect(calls[0]).toEqual({
            method: "GET",
            path: "/account/devices/enroll/host/sess-1",
            body: undefined,
        });
    });

    it("authorizes only by session (the human-confirmed SAS act)", async () => {
        const { json, calls } = recorder();
        await enrollAuthorize(json, "sess-1");
        expect(calls[0]).toEqual({
            method: "POST",
            path: "/account/devices/enroll/authorize",
            body: { session: "sess-1" },
        });
    });

    it("new device joins with a ticket and gets a session to poll", async () => {
        const { json, calls } = recorder({ session: "sess-1" });
        const out = await enrollJoin(json, TICKET);
        expect(out).toBe("sess-1");
        expect(calls[0]).toEqual({
            method: "POST",
            path: "/account/devices/enroll/join",
            body: { ticket: TICKET },
        });
    });

    it("polls the join leg status and url-encodes the session", async () => {
        const { json, calls } = recorder({ phase: "completed", sas: "123456", error: null });
        const out = await enrollJoinStatus(json, "sess/1");
        expect(out.phase).toBe("completed");
        expect(calls[0]).toEqual({
            method: "GET",
            path: "/account/devices/enroll/join/sess%2F1",
            body: undefined,
        });
    });
});
