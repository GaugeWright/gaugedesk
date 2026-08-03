import { afterEach, describe, expect, it, vi } from "vitest";
import {
    bearer,
    decodeSubject,
    endSession,
    exchangeMobileAccountHandoff,
    parseCallbackFragment,
    refreshHostedAccountSession,
    refreshMobileAccountToken,
    setBearer,
    signedIn,
} from "./auth-session";

afterEach(() => vi.unstubAllGlobals());

/** Build an unsigned JWT-shaped string with the given payload (base64url, no padding) —
 *  enough to exercise the display-only `sub` decode (the client never verifies). */
function fakeJwt(payload: object): string {
    const b64url = (o: object) =>
        btoa(JSON.stringify(o)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    return `${b64url({ alg: "RS256" })}.${b64url(payload)}.sig`;
}

describe("parseCallbackFragment", () => {
    it("pulls the id-token out of the callback fragment", () => {
        expect(parseCallbackFragment("#id_token=abc.def.ghi&token_type=Bearer")).toBe("abc.def.ghi");
        expect(parseCallbackFragment("id_token=xyz")).toBe("xyz"); // tolerates a missing leading '#'
    });

    it("returns null when no token is present", () => {
        expect(parseCallbackFragment("")).toBeNull();
        expect(parseCallbackFragment("#")).toBeNull();
        expect(parseCallbackFragment("#error=access_denied")).toBeNull();
        expect(parseCallbackFragment("#id_token=")).toBeNull();
    });
});

describe("decodeSubject", () => {
    it("decodes the sub claim for display", () => {
        expect(decodeSubject(fakeJwt({ sub: "alice@example.test", aud: "x" }))).toBe(
            "alice@example.test",
        );
    });

    it("returns null for a non-JWT or a token without a sub", () => {
        expect(decodeSubject("not-a-jwt")).toBeNull();
        expect(decodeSubject("a.b")).toBeNull(); // wrong segment count
        expect(decodeSubject(fakeJwt({ aud: "x" }))).toBeNull(); // no sub
        expect(decodeSubject("a.!!!notbase64!!!.c")).toBeNull();
    });
});

describe("bearer is in-memory only (ENTSEC-6)", () => {
    it("never writes the token to a Storage, even when one is available", () => {
        // Install recording Storage stubs (the test env is `node`, no DOM): if setBearer ever
        // persisted the credential, these would capture the write.
        const writes: Record<string, string> = {};
        const stub = {
            store: writes,
            getItem: (k: string) => writes[k] ?? null,
            setItem: (k: string, v: string) => { writes[k] = v; },
            removeItem: (k: string) => { delete writes[k]; },
        };
        const g = globalThis as unknown as { localStorage?: unknown; sessionStorage?: unknown };
        const prevLocal = g.localStorage;
        const prevSession = g.sessionStorage;
        g.localStorage = stub;
        g.sessionStorage = stub;
        try {
            setBearer("header.payload.sig");
            expect(bearer()).toBe("header.payload.sig"); // held in the in-memory signal
            expect(signedIn()).toBe(true);
            // The credential must NOT be at rest anywhere a later local access / XSS could scrape.
            expect(Object.keys(writes)).toHaveLength(0);

            setBearer(null);
            expect(bearer()).toBeNull();
            expect(signedIn()).toBe(false);
            expect(Object.keys(writes)).toHaveLength(0);
        } finally {
            g.localStorage = prevLocal;
            g.sessionStorage = prevSession;
        }
    });
});

describe("endSession", () => {
    it("expires the hosted cookie before clearing the in-memory bearer", async () => {
        setBearer("header.payload.sig");
        const fetch = vi.fn(async (_input: RequestInfo | URL, _init?: RequestInit) =>
            new Response(null, { status: 204 }));
        vi.stubGlobal("fetch", fetch);

        await endSession("https://auth.example/");

        expect(fetch).toHaveBeenCalledOnce();
        expect(fetch.mock.calls[0]?.[0]).toBe("https://auth.example/auth/logout");
        expect(fetch.mock.calls[0]?.[1]).toMatchObject({ method: "POST", credentials: "include" });
        expect(new Headers(fetch.mock.calls[0]?.[1]?.headers).get("idempotency-key")).toBeTruthy();
        expect(bearer()).toBeNull();
    });

    it("keeps local auth state when the server could not clear its cookie", async () => {
        setBearer("header.payload.sig");
        vi.stubGlobal("fetch", vi.fn(async () => new Response(null, { status: 502 })));

        await expect(endSession("https://auth.example")).rejects.toThrow("Sign out failed (502)");
        expect(bearer()).toBe("header.payload.sig");
        setBearer(null);
    });
});

describe("native account session transport", () => {
    it("exchanges the device-bound handoff through the shared request owner", async () => {
        const fetch = vi.fn(async (_input: RequestInfo | URL, _init?: RequestInit) =>
            new Response(JSON.stringify({ id_token: "header.payload.signature" }), {
                status: 200,
                headers: { "content-type": "application/json" },
            }));
        vi.stubGlobal("fetch", fetch);

        await expect(exchangeMobileAccountHandoff(
            "https://auth.example/",
            "handoff-code",
            "device-verifier",
        )).resolves.toBe("header.payload.signature");

        expect(fetch.mock.calls[0]?.[0]).toBe("https://auth.example/auth/mobile/exchange");
        const init = fetch.mock.calls[0]?.[1];
        expect(JSON.parse(String(init?.body))).toEqual({
            code: "handoff-code",
            verifier: "device-verifier",
        });
        expect(new Headers(init?.headers).get("idempotency-key")).toBeTruthy();
        expect(init?.credentials).toBe("include");
    });

    it("refreshes with the exact current bearer and rejects malformed success", async () => {
        const fetch = vi.fn(async (_input: RequestInfo | URL, _init?: RequestInit) =>
            new Response(JSON.stringify({ id_token: "replacement" }), {
                status: 200,
                headers: { "content-type": "application/json" },
            }));
        vi.stubGlobal("fetch", fetch);

        await expect(refreshMobileAccountToken(
            "https://auth.example",
            "current-token",
        )).resolves.toBe("replacement");

        const init = fetch.mock.calls[0]?.[1];
        expect(new Headers(init?.headers).get("authorization")).toBe("Bearer current-token");
        expect(new Headers(init?.headers).get("idempotency-key")).toBeTruthy();

        vi.stubGlobal("fetch", vi.fn(async () =>
            new Response(JSON.stringify({ refreshed: true }), {
                status: 200,
                headers: { "content-type": "application/json" },
            })));
        await expect(refreshMobileAccountToken(
            "https://auth.example",
            "current-token",
        )).rejects.toThrow("response is malformed");
    });
});

describe("hosted account session refresh", () => {
    it("uses the credentialed production refresh route without exposing a token", async () => {
        const fetch = vi.fn(async () =>
            new Response(JSON.stringify({ refreshed: true, person: "person:one" }), {
                status: 200,
                headers: { "content-type": "application/json" },
            }));
        vi.stubGlobal("fetch", fetch);

        await expect(refreshHostedAccountSession("https://auth.example/")).resolves.toBe(true);
        expect(fetch.mock.calls[0]?.[0]).toBe("https://auth.example/auth/refresh");
        const init = fetch.mock.calls[0]?.[1];
        expect(init?.method).toBe("GET");
        expect(init?.credentials).toBe("include");
        expect(new Headers(init?.headers).has("authorization")).toBe(false);

        fetch.mockResolvedValueOnce(new Response(null, { status: 401 }));
        await expect(refreshHostedAccountSession("https://auth.example")).resolves.toBe(false);
    });
});
