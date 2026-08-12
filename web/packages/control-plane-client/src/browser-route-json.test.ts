import { afterEach, describe, expect, it, vi } from "vitest";
import { browserRouteEventStream, browserRouteJson } from "./browser-route-json";
import { Rejected } from "./control-plane-domain";

/** Stub `fetch` with a canned Response for the one call under test. */
function stubFetch(res: Response) {
    vi.stubGlobal(
        "fetch",
        vi.fn(async () => res),
    );
}

afterEach(() => vi.unstubAllGlobals());

describe("browserRouteJson error surfacing", () => {
    it("carries a caller key on mutations and never adds one to reads", async () => {
        const fetch = vi
            .fn()
            .mockResolvedValueOnce(new Response(null, { status: 204 }))
            .mockResolvedValueOnce(new Response(null, { status: 204 }));
        vi.stubGlobal("fetch", fetch);
        const json = browserRouteJson("http://cp");

        await json("POST", "/scopes/s/run/command", "RequestRun", { idempotencyKey: "turn-7" });
        await json("GET", "/scopes/s/run");

        expect(new Headers(fetch.mock.calls[0]?.[1]?.headers).get("idempotency-key")).toBe("turn-7");
        expect(new Headers(fetch.mock.calls[1]?.[1]?.headers).has("idempotency-key")).toBe(false);
    });

    it("carries account and target-Home credentials on JSON and SSE without putting them in URLs", async () => {
        const encoder = new TextEncoder();
        const stream = new ReadableStream({
            start(controller) {
                controller.enqueue(encoder.encode('data: {"type":"ready"}\n\n'));
                controller.close();
            },
        });
        const fetch = vi
            .fn()
            .mockResolvedValueOnce(new Response(JSON.stringify({ ok: true }), { status: 200 }))
            .mockResolvedValueOnce(new Response(stream, { status: 200 }));
        vi.stubGlobal("fetch", fetch);
        const auth = {
            bearer: () => "account-login",
            homeAdmission: () => "home-secret",
            machineSession: () => "machine-session",
        };

        await browserRouteJson("https://home.example", auth)("GET", "/workspace");
        const messages: string[] = [];
        browserRouteEventStream("https://home.example", auth)("/workspace/events", (data) => {
            messages.push(data);
        });
        await vi.waitFor(() => expect(messages).toEqual(['{"type":"ready"}']));

        for (const [url, init] of fetch.mock.calls) {
            expect(url).not.toContain("account-login");
            expect(url).not.toContain("home-secret");
            expect(url).not.toContain("machine-session");
            const headers = new Headers(init?.headers);
            expect(headers.get("authorization")).toBe("Bearer account-login");
            expect(headers.get("x-gaugewright-home-admission")).toBe("home-secret");
            expect(headers.get("x-gaugewright-machine-session")).toBe("machine-session");
        }
    });

    it("carries tenant context as a header, never as a URL or authority claim", async () => {
        const fetch = vi.fn().mockResolvedValue(new Response(JSON.stringify({ ok: true })));
        vi.stubGlobal("fetch", fetch);

        await browserRouteJson("https://hub.example", { tenant: () => "personal:owner" })(
            "GET",
            "/admin/capabilities",
        );

        const [url, init] = fetch.mock.calls[0] ?? [];
        expect(url).toBe("https://hub.example/admin/capabilities");
        expect(new Headers(init?.headers).get("x-gaugewright-tenant")).toBe("personal:owner");
        expect(new Headers(init?.headers).has("authorization")).toBe(false);
    });

    it("reports the same client build declaration on JSON and SSE", async () => {
        const encoder = new TextEncoder();
        const stream = new ReadableStream({
            start(controller) {
                controller.enqueue(encoder.encode('data: {"type":"ready"}\n\n'));
                controller.close();
            },
        });
        const fetch = vi
            .fn()
            .mockResolvedValueOnce(new Response(JSON.stringify({ ok: true }), { status: 200 }))
            .mockResolvedValueOnce(new Response(stream, { status: 200 }));
        vi.stubGlobal("fetch", fetch);
        const options = {
            clientBuild: () => ({
                version: "2.4.1",
                protocol: 7,
                channel: "beta" as const,
                platform: "desktop" as const,
            }),
        };

        await browserRouteJson("https://home.example", options)("GET", "/workspace");
        const messages: string[] = [];
        browserRouteEventStream("https://home.example", options)("/workspace/events", (data) => {
            messages.push(data);
        });
        await vi.waitFor(() => expect(messages).toEqual(['{"type":"ready"}']));

        for (const [, init] of fetch.mock.calls) {
            const headers = new Headers(init?.headers);
            expect(headers.get("x-gaugedesk-client-version")).toBe("2.4.1");
            expect(headers.get("x-gaugedesk-client-protocol")).toBe("7");
            expect(headers.get("x-gaugedesk-client-channel")).toBe("beta");
            expect(headers.get("x-gaugedesk-client-platform")).toBe("desktop");
        }
    });

    it("includes the server's `error` message from a JSON body", async () => {
        stubFetch(
            new Response(JSON.stringify({ error: "runtime unavailable" }), {
                status: 502,
                headers: { "content-type": "application/json" },
            }),
        );
        const json = browserRouteJson("http://cp");
        await expect(json("POST", "/account/oauth/openai-codex/start", {})).rejects.toThrow(
            /502 runtime unavailable/,
        );
    });

    it("falls back to the raw body when it is not JSON", async () => {
        stubFetch(new Response("upstream exploded", { status: 500 }));
        const json = browserRouteJson("http://cp");
        await expect(json("GET", "/thing", undefined)).rejects.toThrow(/500 upstream exploded/);
    });

    it("falls back to the bare status when the body is empty", async () => {
        stubFetch(new Response(null, { status: 503 }));
        const json = browserRouteJson("http://cp");
        await expect(json("GET", "/thing", undefined)).rejects.toThrow(/GET \/thing: 503$/);
    });

    it("still maps 409 to Rejected with its reason", async () => {
        stubFetch(
            new Response(JSON.stringify({ rejected: "over budget" }), {
                status: 409,
                headers: { "content-type": "application/json" },
            }),
        );
        const json = browserRouteJson("http://cp");
        await expect(json("POST", "/scopes/s/run", {})).rejects.toThrowError(Rejected);
    });

    it("carries the command-receipt status, which is what separates ran from running", async () => {
        // A caller retrying under a stable key has to tell "it already happened"
        // from "it might be happening" (ADR 0137 §3). The reason string conflates
        // them; the receipt status does not.
        stubFetch(
            new Response(
                JSON.stringify({
                    rejected: "command already applied; refresh its projection",
                    command_status: "applied",
                }),
                { status: 409, headers: { "content-type": "application/json" } },
            ),
        );
        const json = browserRouteJson("http://cp");
        await expect(json("POST", "/chats/c/task", {})).rejects.toMatchObject({
            commandStatus: "applied",
        });
    });
});
