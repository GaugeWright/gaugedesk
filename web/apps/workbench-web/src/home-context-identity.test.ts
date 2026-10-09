import { afterEach, describe, expect, it, vi } from "vitest";
import { setDirectoryModuleLoader } from "@gaugewright/control-plane-client";
import { HomeContextChangedError } from "./home-bootstrap";
import { claimedSubject, sameAccountCredential, WorkbenchControlPlane } from "./workbench-control-plane";

// WS-1061. A hosted load starts with no bearer: `startSessionRefresh` sends
// `/auth/refresh` at once and seats what it answers while Home discovery is
// already reading the account's Homes, and the same refresh renews it every 45
// minutes. Since WS-1049 a context change drops work begun before it, so a
// change that is not one failed discovery ("We couldn't load your Homes — the
// account service could not be reached") and work in flight at a renewal.
const HUB = "https://hub.example";
const OWN = "https://own.example";
const ID = "home:local-user";

const base64url = (value: string) => btoa(value).replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_");
/** A provider credential naming `sub`; `n` makes each renewal a new string. */
const credential = (sub: string, n: number) => `${base64url('{"alg":"none"}')}.${base64url(JSON.stringify({ sub, n }))}.signature`;

function fixture({ hasOwn = true }: { hasOwn?: boolean } = {}) {
    setDirectoryModuleLoader(async () => ({ verify_signed_put_json: () => true }));
    vi.stubGlobal("localStorage", { getItem: () => null, setItem: () => undefined });
    let hold = false;
    let release: (() => void) | null = null;
    let reached: (() => void) | null = null;
    const workspaces: string[] = [];
    vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = new URL(String(input));
        const method = init?.method ?? "GET";
        const bearer = new Headers(init?.headers).get("authorization") ?? "";
        if (url.origin === HUB) {
            if (url.pathname === "/account/homes") {
                if (hold) {
                    hold = false;
                    await new Promise<void>((resolve) => { release = resolve; reached?.(); });
                }
                return Response.json({
                    homes: hasOwn ? [{ id: ID, endpoint: OWN, kind: "registered" }] : [],
                    selected_home: hasOwn ? ID : null,
                });
            }
            if (url.pathname === "/account/directory") return Response.json({ root_pubkey: "root", origin: "https://directory.example", subject: "person" });
            if (url.pathname === "/account/home-routes") return Response.json({ routes: [] });
            throw new Error(`unexpected Hub ${method} ${url.pathname}`);
        }
        if (url.origin === "https://directory.example") return Response.json({ version: 1, puts: [] });
        if (method === "POST" && url.pathname === "/home/admissions") return Response.json({ home: ID, admission: "admitted" }, { status: 201 });
        if (url.pathname === "/workspace") {
            workspaces.push(bearer);
            return Response.json({ archetypes: [], projects: [], recent: [], workstreams: [], work_targets: [], personal_placement: null });
        }
        throw new Error(`unexpected ${method} ${url}`);
    }));
    const api = new WorkbenchControlPlane(HUB, { splitHomes: true });
    return {
        api,
        workspaces,
        /** Hold the next `/account/homes` read; resolves once it is in flight. */
        holdHomes(): Promise<void> {
            hold = true;
            return new Promise<void>((resolve) => { reached = resolve; });
        },
        releaseHomes() { release?.(); release = null; },
    };
}

afterEach(() => { setDirectoryModuleLoader(null); vi.unstubAllGlobals(); });

describe("which credential changes are a change of account (WS-1061)", () => {
    it("decides by the account a credential names, not by its string", () => {
        expect(claimedSubject(credential("alice", 1))).toBe("alice");
        expect(claimedSubject("opaque-session")).toBeNull();
        expect(sameAccountCredential(null, null)).toBe(true);
        // The first credential a page receives, after a reload.
        expect(sameAccountCredential(null, credential("alice", 1))).toBe(true);
        expect(sameAccountCredential(null, "opaque-session")).toBe(true);
        // A renewal: the same session again, or a new token for the same subject.
        expect(sameAccountCredential("opaque-session", "opaque-session")).toBe(true);
        expect(sameAccountCredential(credential("alice", 1), credential("alice", 2))).toBe(true);
        // A sign-out, and a credential naming someone else.
        expect(sameAccountCredential(credential("alice", 1), null)).toBe(false);
        expect(sameAccountCredential(credential("alice", 1), credential("bob", 2))).toBe(false);
        // Opaque credentials cannot be told apart from a change of person.
        expect(sameAccountCredential("opaque-session", "other-session")).toBe(false);
        expect(sameAccountCredential(credential("alice", 1), "opaque-session")).toBe(false);
    });
});

describe("Home discovery while the first refresh lands (WS-1061)", () => {
    for (const [situation, hasOwn, kind] of [["with a Home of their own", true, "connected"], ["with no Home", false, "none"]] as const) {
        it(`finds the Home of a person ${situation} when the bearer is first seated mid-discovery`, async () => {
            const f = fixture({ hasOwn });
            f.api.setBearer(null); // a reload: the cookie survives, the bearer does not
            const held = f.holdHomes();
            const discovery = f.api.bootstrapHome();
            await held;
            f.api.setBearer("opaque-session"); // /auth/refresh answers
            f.releaseHomes();
            await expect(discovery).resolves.toMatchObject({ kind });
        });
    }

    it("runs discovery again when the account really changes under it, in the new account", async () => {
        const f = fixture();
        f.api.setBearer(credential("alice", 1));
        const held = f.holdHomes();
        const discovery = f.api.bootstrapHome();
        await held;
        f.api.setBearer(credential("bob", 2));
        f.releaseHomes();
        await expect(discovery).resolves.toMatchObject({ kind: "connected" });
    });
});

describe("work in flight at a renewal (WS-1061)", () => {
    it("completes a request whose Home was being resolved when the same account's credential renewed", async () => {
        const f = fixture();
        f.api.setBearer(credential("alice", 1));
        const held = f.holdHomes();
        const read = f.api.getWorkspace();
        await held;
        f.api.setBearer(credential("alice", 2)); // the 45-minute tick
        f.releaseHomes();
        await expect(read).resolves.toMatchObject({ projects: [] });
        // It reached the Home under the renewed credential.
        expect(f.workspaces).toEqual([`Bearer ${credential("alice", 2)}`]);
    });

    for (const [change, before, after] of [
        ["to another subject", credential("alice", 1), credential("bob", 2)],
        ["from one opaque session to another", "opaque-session", "other-session"],
        ["to signed out", credential("alice", 1), null],
    ] as const) {
        it(`still drops work begun for one account when the credential changes ${change}`, async () => {
            const f = fixture();
            f.api.setBearer(before);
            const held = f.holdHomes();
            const read = f.api.getWorkspace();
            await held;
            f.api.setBearer(after);
            f.releaseHomes();
            await expect(read).rejects.toBeInstanceOf(HomeContextChangedError);
            expect(f.workspaces).toEqual([]);
        });
    }
});
