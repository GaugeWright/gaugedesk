import { afterEach, describe, expect, it, vi } from "vitest";

const invoke = vi.fn();
vi.mock("@tauri-apps/api/core", () => ({ invoke }));

import { desktopHomeSession, followDesktopHomeSession, type DesktopHomeSessionAnswer } from "./desktop-home-session";

describe("desktop Home session", () => {
    afterEach(() => {
        invoke.mockReset();
        delete (globalThis as Record<string, unknown>).window;
    });
    it("is never asked for outside the desktop shell", async () => {
        (globalThis as Record<string, unknown>).window = {};
        expect(await desktopHomeSession()).toBeNull();
        expect(invoke).not.toHaveBeenCalled();
    });
    it("takes the shell's session over IPC, and nothing else", async () => {
        (globalThis as Record<string, unknown>).window = { __TAURI_INTERNALS__: {} };
        invoke.mockResolvedValueOnce("home-session-token");
        expect(await desktopHomeSession()).toBe("home-session-token");
        expect(invoke).toHaveBeenCalledWith("home_session");
    });
    it("keeps the local posture when the shell has none or refuses", async () => {
        (globalThis as Record<string, unknown>).window = { __TAURI_INTERNALS__: {} };
        for (const answer of [null, "", undefined]) {
            invoke.mockResolvedValueOnce(answer);
            expect(await desktopHomeSession()).toBeNull();
        }
        invoke.mockRejectedValueOnce(new Error("unknown command"));
        expect(await desktopHomeSession()).toBeNull();
    });
});

describe("following the desktop Home session", () => {
    function harness(sessions: Array<string | null | Promise<string | null>>) {
        const events: string[] = [];
        const answers: DesktopHomeSessionAnswer[] = [];
        let remote = false;
        const follow = followDesktopHomeSession({
            read: async () => {
                const next = sessions.shift();
                if (next === undefined) throw new Error("unexpected session read");
                return next;
            },
            present: (token) => events.push(`present ${token}`),
            reachRemotely: (next) => {
                const moved = next !== remote;
                remote = next;
                return moved;
            },
            answered: (answer) => {
                events.push("answered");
                answers.push(answer);
            },
        });
        return { follow, events, answers };
    }
    const settle = () => new Promise((resolve) => setTimeout(resolve, 0));

    it("presents a signed-in account's session before the window may read anything", async () => {
        const { follow, events, answers } = harness(["account-session"]);
        follow(true);
        expect(answers).toEqual([]);
        await settle();
        expect(events).toEqual(["present account-session", "answered"]);
        expect(answers).toEqual([{ first: true, credentialMoved: true, remoteMoved: false }]);
    });

    it("answers the local posture without presenting or withdrawing anything", async () => {
        const { follow, events, answers } = harness([]);
        follow(false);
        await settle();
        expect(events).toEqual(["answered"]);
        expect(answers).toEqual([{ first: true, credentialMoved: false, remoteMoved: false }]);
    });

    it("reports a session that replaces the local posture as moved, so the window re-reads", async () => {
        const { follow, answers } = harness(["account-session"]);
        follow(false);
        await settle();
        follow(true);
        await settle();
        expect(answers.at(-1)).toEqual({ first: false, credentialMoved: true, remoteMoved: false });
    });

    it("does not report a keep-alive re-read that hands back the same session", async () => {
        const { follow, answers } = harness(["account-session", "account-session"]);
        follow(true);
        await settle();
        follow(true);
        await settle();
        expect(answers.at(-1)).toEqual({ first: false, credentialMoved: false, remoteMoved: false });
    });

    it("withdraws the session it presented when the sign-in ends", async () => {
        const { follow, events, answers } = harness(["account-session"]);
        follow(true);
        await settle();
        follow(false);
        await settle();
        expect(events).toEqual(["present account-session", "answered", "present null", "answered"]);
        expect(answers.at(-1)).toEqual({ first: false, credentialMoved: true, remoteMoved: false });
    });

    it("reaches the Home through the account plane for an account with no standing here", async () => {
        const { follow, events, answers } = harness([null]);
        follow(true);
        await settle();
        expect(events).toEqual(["answered"]);
        expect(answers).toEqual([{ first: true, credentialMoved: false, remoteMoved: true }]);
    });

    it("drops a read superseded before its session arrives", async () => {
        let release: (token: string) => void = () => undefined;
        const late = new Promise<string>((resolve) => { release = resolve; });
        const { follow, events, answers } = harness([late]);
        follow(true);
        follow(false);
        await settle();
        release("stale-session");
        await settle();
        expect(events).toEqual(["answered"]);
        expect(answers).toEqual([{ first: true, credentialMoved: false, remoteMoved: false }]);
    });
});
