import { afterEach, describe, expect, it, vi } from "vitest";
import { engagementId } from "./control-plane-domain";
import { RemoteControlPlane } from "./remote-control-plane";

afterEach(() => vi.unstubAllGlobals());

describe("RemoteControlPlane", () => {
    it("routes product commands through the shared control-plane contract", async () => {
        const calls: unknown[][] = [];
        const route = async (method: string, path: string, body?: unknown) => {
            calls.push([method, path, body]);
            if (path === "/chats") return { engagements: ["chat-1"] };
            return { stopped: true };
        };
        const control = new RemoteControlPlane("https://cp.example/", { route });
        expect(await control.listEngagements()).toEqual([engagementId("chat-1")]);
        expect(await control.stopTurn(engagementId("chat-1"))).toEqual({ stopped: true });
        expect(calls).toEqual([
            ["GET", "/chats", undefined],
            ["POST", "/chats/chat-1/stop", undefined],
        ]);
    });

    it("authenticates raw file transport and never sends it over an ambient local path", async () => {
        const fetch = vi.fn(async (_input: RequestInfo | URL, _init?: RequestInit) =>
            new Response("hello", { status: 200 }));
        vi.stubGlobal("fetch", fetch);
        const control = new RemoteControlPlane("https://cp.example", {
            bearer: "member-token",
            route: async () => null,
        });
        expect(await control.getFile(engagementId("chat-1"), "notes/a b.md")).toBe("hello");
        const [url, init] = fetch.mock.calls[0] ?? [];
        expect(url).toBe("https://cp.example/chats/chat-1/file?path=notes%2Fa%20b.md");
        expect(init).toEqual(expect.objectContaining({ method: "GET", credentials: "include" }));
        expect(new Headers(init?.headers).get("authorization")).toBe("Bearer member-token");
    });

    it("performs target admission and sends that memory-only credential on every raw call", async () => {
        const fetch = vi
            .fn<(_input: RequestInfo | URL, _init?: RequestInit) => Promise<Response>>()
            .mockResolvedValueOnce(
                new Response(JSON.stringify({ home: "home:alpha", admission: "home-token" }), {
                    status: 201,
                }),
            )
            .mockResolvedValueOnce(new Response("notes", { status: 200 }));
        vi.stubGlobal("fetch", fetch);
        const control = new RemoteControlPlane("https://home.example", {
            bearer: "member-token",
        });

        await expect(control.admitHome()).resolves.toBe("home:alpha");
        await expect(control.getFile(engagementId("chat-1"), "notes.md")).resolves.toBe("notes");

        const admissionRequest = fetch.mock.calls[0];
        expect(admissionRequest?.[0]).toBe("https://home.example/home/admissions");
        expect(new Headers(admissionRequest?.[1]?.headers).has("x-gaugewright-home-admission")).toBe(false);
        const fileRequest = fetch.mock.calls[1];
        expect(new Headers(fileRequest?.[1]?.headers).get("x-gaugewright-home-admission")).toBe(
            "home-token",
        );
    });

    it("reads a count-only review notification projection through the admitted Home", async () => {
        const calls: unknown[][] = [];
        const control = new RemoteControlPlane("https://home.example", {
            bearer: "member-token",
            route: async (method, path) => {
                calls.push([method, path]);
                return { review_count: 3 };
            },
        });

        await expect(control.reviewNotificationCount()).resolves.toBe(3);
        expect(calls).toEqual([["GET", "/console/review-count"]]);
    });
});
