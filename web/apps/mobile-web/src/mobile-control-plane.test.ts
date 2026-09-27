import { afterEach, describe, expect, it, vi } from "vitest";
import {
    MOBILE_CONTROL_PLANE_INVENTORY,
    MobileControlPlane,
} from "./mobile-control-plane";

afterEach(() => vi.unstubAllGlobals());

describe("mobile control-plane authority inventory", () => {
    it("classifies every public route so new mutations cannot bypass review", () => {
        const implementation = Object.getOwnPropertyNames(MobileControlPlane.prototype)
            .filter((name) =>
                !["constructor", "routeJson", "workbenchTransport"].includes(name),
            )
            .sort();
        expect(Object.keys(MOBILE_CONTROL_PLANE_INVENTORY).sort())
            .toEqual(implementation);
    });

    it("carries both account identity and exact Home admission on work commands", async () => {
        let request: Request | null = null;
        vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
            request = new Request(input, init);
            return new Response("{}", {
                status: 200,
                headers: { "content-type": "application/json" },
            });
        }));
        const api = new MobileControlPlane("https://home.example", {
            bearer: () => "account-token",
            homeAdmission: () => "home-admission",
        });
        await api.runTask("chat:one" as never, "hello").catch(() => undefined);
        expect(request).not.toBeNull();
        expect(request!.headers.get("authorization")).toBe("Bearer account-token");
        expect(request!.headers.get("x-gaugewright-home-admission"))
            .toBe("home-admission");
    });

    it("does not confuse a direct Machine session with account admission", async () => {
        let request: Request | null = null;
        vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
            request = new Request(input, init);
            return new Response("{}", {
                status: 200,
                headers: { "content-type": "application/json" },
            });
        }));
        const api = new MobileControlPlane("https://machine.example", {
            machineSession: () => "machine-session",
        });
        await api.runTask("chat:one" as never, "hello").catch(() => undefined);
        expect(request).not.toBeNull();
        expect(request!.headers.get("x-gaugewright-machine-session"))
            .toBe("machine-session");
        expect(request!.headers.get("authorization")).toBeNull();
        expect(request!.headers.get("x-gaugewright-home-admission")).toBeNull();
    });

    it("reports Home authorization rejection without collapsing its repair reason", async () => {
        vi.stubGlobal("fetch", vi.fn(async () =>
            new Response(
                JSON.stringify({ error: "target Home admission required" }),
                {
                    status: 401,
                    headers: { "content-type": "application/json" },
                },
            )));
        const rejected = vi.fn();
        const api = new MobileControlPlane("https://home.example", {
            bearer: () => "account-token",
            homeAdmission: () => "stale-admission",
            onAuthorizationRejected: rejected,
        });
        await expect(api.runTask("chat:one" as never, "hello")).rejects.toThrow(
            "target Home admission required",
        );
        expect(rejected).toHaveBeenCalledWith(
            401,
            expect.stringContaining("target Home admission required"),
        );
    });

    it("reports transport loss separately from an authorization refusal", async () => {
        vi.stubGlobal("fetch", vi.fn(async () => {
            throw new TypeError("Failed to fetch");
        }));
        const unavailable = vi.fn();
        const rejected = vi.fn();
        const api = new MobileControlPlane("https://home.example", {
            bearer: () => "account-token",
            homeAdmission: () => "home-admission",
            onAuthorizationRejected: rejected,
            onTransportUnavailable: unavailable,
        });

        await expect(api.getTasks()).rejects.toThrow("Failed to fetch");
        expect(unavailable).toHaveBeenCalledWith(expect.stringContaining("Failed to fetch"));
        expect(rejected).not.toHaveBeenCalled();
    });

    /** A response whose body is an SSE stream of `frames`, ending after them. */
    function eventStream(frames: string[]): Response {
        const body = new ReadableStream<Uint8Array>({
            start(controller) {
                for (const frame of frames) controller.enqueue(new TextEncoder().encode(frame));
                controller.close();
            },
        });
        return new Response(body, { status: 200, headers: { "content-type": "text/event-stream" } });
    }

    it("carries account identity and Home admission on its event streams (DR-0232)", async () => {
        // A bare EventSource carries no headers, so every stream a Home checks
        // was refused — over the relay, where a desktop Home admits only its
        // owner, that was every stream.
        const requests: Request[] = [];
        vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
            requests.push(new Request(input, init));
            return eventStream([
                'data: {"type":"workspacechanged","record":"project","id":"p1","op":"upsert"}\n\n',
            ]);
        }));
        const api = new MobileControlPlane("http://127.0.0.1:4100", {
            bearer: () => "account-token",
            homeAdmission: () => "home-admission",
        });
        const changes: string[] = [];
        const stop = api.subscribeWorkspace((change) => changes.push(change.id));
        await vi.waitFor(() => expect(changes).toContain("p1"));
        stop();
        const stream = requests.find((r) => r.url.endsWith("/workspace/events"));
        expect(stream?.headers.get("authorization")).toBe("Bearer account-token");
        expect(stream?.headers.get("x-gaugewright-home-admission")).toBe("home-admission");
        expect(stream?.headers.get("accept")).toBe("text/event-stream");
    });

    it("opens its stream again when the one it had ends, as EventSource did", async () => {
        // A stream over the relay ends whenever its tunnel does.
        let opened = 0;
        vi.stubGlobal("fetch", vi.fn(async () => {
            opened += 1;
            return eventStream([`data: {"type":"hello","n":${opened}}\n\n`]);
        }));
        const api = new MobileControlPlane("http://127.0.0.1:4100", {
            bearer: () => "account-token",
            homeAdmission: () => "home-admission",
        });
        const stop = api.subscribe("chat:one" as never, () => undefined);
        await vi.waitFor(() => expect(opened).toBeGreaterThanOrEqual(2), { timeout: 3_000 });
        stop();
    });

    it("reports a refused stream the way a refused call is reported", async () => {
        vi.stubGlobal("fetch", vi.fn(async () => new Response(
            JSON.stringify({ error: "target Home admission required" }),
            { status: 401, headers: { "content-type": "application/json", "content-length": "41" } },
        )));
        const rejected: Array<[number, string]> = [];
        const api = new MobileControlPlane("http://127.0.0.1:4100", {
            bearer: () => "account-token",
            homeAdmission: () => "stale-admission",
            onAuthorizationRejected: (status, detail) => rejected.push([status, detail]),
        });
        const stop = api.subscribeWorkspace(() => undefined);
        await vi.waitFor(() => expect(rejected.length).toBeGreaterThan(0));
        stop();
        expect(rejected[0]).toEqual([401, "target Home admission required"]);
    });
});
