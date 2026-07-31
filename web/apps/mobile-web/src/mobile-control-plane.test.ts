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
});
