// A member of a project shared from someone else's desktop, as desk reaches
// it (DR-0451, DR-0455, WS-1034): shared by the control-plane tests and the
// navigator's component test. Both desktops are relay-only Homes behind a
// stand-in tunnel module and relay socket; the Hub and the directory are
// stubbed `fetch` answers. Call `releaseSharedMember` after each test.
import { vi } from "vitest";
import {
    setDirectoryModuleLoader,
    setTunnelModuleLoader,
    type RawTunnelFacade,
} from "@gaugewright/control-plane-client";
import { WorkbenchControlPlane } from "./workbench-control-plane";

export function releaseSharedMember(): void {
    setTunnelModuleLoader(null);
    setDirectoryModuleLoader(null);
    vi.unstubAllGlobals();
}

/** The member's own desktop and the owner's, each `home:local-user` like
 * every desktop today (WS-1024), told apart only by the certificate each
 * relay locator pins. */
export const MINE = "aa".repeat(32);
export const OWNERS = "bb".repeat(32);
const locator = (fingerprint: string) => ({
    endpoint: "wss://relay.example",
    handle: (fingerprint === MINE ? "M" : "O").repeat(43),
    proof: "P".repeat(43),
    route_epoch: 1,
    home_fingerprint: fingerprint,
});
const project = (id: string) => ({
    id, home_id: "home:local-user", name: id, is_personal: false, targets: [], placements: [],
});
const workspace = (...projects: string[]) => ({
    archetypes: [], projects: projects.map(project), recent: [], workstreams: [],
    work_targets: [], personal_placement: null,
});

/** A member who accepted an invitation to `proj-shared` on the owner's
 * desktop, so this browser pins it. `own` is the member's own desktop:
 * registered and selected, serving `proj-mine`; or signed out, with its
 * root-signed entry still routing their Personal project to
 * `home:local-user` through its own locator, and nothing answering it. */
export function sharedMember(own: "selected" | "signed out") {
    const dialed: string[] = [];
    const carried: Array<{ home: string; call: string }> = [];
    const hubWrites: string[] = [];
    const homes = {
        [MINE]: workspace("proj-mine"),
        // The owner's Home lists only what the member may see, but a
        // second project here shows that nothing else is taken from it.
        [OWNERS]: workspace("proj-shared", "proj-owners-other"),
    } as Record<string, unknown>;
    class Tunnel implements RawTunnelFacade {
        private reply: { status: number; body: string } | null = null;
        constructor(private readonly fingerprint: string) {
            dialed.push(fingerprint);
        }
        sendRequestHead(): void { this.reply = { status: 404, body: "" }; }
        sendBody(): void {}
        bufferedBytes(): number { return 0; }
        takeBodyBytes(): Uint8Array { return new Uint8Array(); }
        takeHeaders(): Record<string, string> { return {}; }
        receiveFrame(): void {}
        takeOutgoing(): Uint8Array { return new Uint8Array(); }
        isHandshaking(): boolean { return false; }
        isPaired(): boolean { return true; }
        takeCredit(): Uint8Array { return new Uint8Array(); }
        pollStatus(): number | undefined { return this.reply?.status; }
        takeBody(): string {
            const body = this.reply?.body ?? "";
            this.reply = null;
            return body;
        }
        sendRequest(method: string, path: string, _body?: string, headers?: Record<string, string>): void {
            const call = `${method} ${path}`;
            const fingerprint = this.fingerprint;
            carried.push({ home: fingerprint, call });
            const minted = `minted-${fingerprint.slice(0, 2)}`;
            if (own === "signed out" && fingerprint === MINE) {
                this.reply = { status: 502, body: '{"error":"no Home leg is parked"}' };
            } else if (call === "POST /home/admissions") {
                this.reply = { status: 201, body: JSON.stringify({ home: "home:local-user", admission: minted }) };
            } else if (headers?.["x-gaugewright-home-admission"] !== minted) {
                this.reply = { status: 401, body: '{"error":"present the Home admission"}' };
            } else if (call === "GET /workspace") {
                this.reply = { status: 200, body: JSON.stringify(homes[fingerprint]) };
            } else if (call === "GET /projections/library/workspace?freshness=live") {
                this.reply = { status: 200, body: JSON.stringify({
                    value: homes[fingerprint], freshness: { marker: "live", generated_at: 1 },
                }) };
            } else if (call === "POST /projects/proj-shared/placements/pl-shared/chats") {
                this.reply = { status: 201, body: '{"id":"chat-shared"}' };
            } else if (call === "GET /chats/chat-shared/transcript") {
                this.reply = { status: 200, body: "[]" };
            } else {
                this.reply = { status: 404, body: '{"error":"not here"}' };
            }
        }
    }
    setTunnelModuleLoader(async () => ({
        BrowserTunnel: Object.assign(Tunnel, { relayHandshake: () => new Uint8Array([1]) }) as never,
        BrowserEventTunnel: class {} as never,
    }));
    setDirectoryModuleLoader(async () => ({ verify_signed_put_json: () => true }));
    class Socket {
        readonly OPEN = 1;
        readyState = 1;
        binaryType = "blob";
        onopen: (() => void) | null = null;
        onclose: ((event: CloseEvent) => void) | null = null;
        onmessage: ((event: MessageEvent) => void) | null = null;
        onerror: (() => void) | null = null;
        constructor() { setTimeout(() => this.onopen?.(), 0); }
        send(): void {}
        close(): void { this.readyState = 3; this.onclose?.({ reason: "" } as CloseEvent); }
    }
    vi.stubGlobal("WebSocket", Socket);
    // What acceptance pinned in this browser (DR-0370 §2).
    const held = new Map<string, string>([["gw.shared-projects.v1", JSON.stringify({
        "person-1": {
            "proj-shared": {
                project: "proj-shared",
                homeId: "home:local-user",
                projectKey: "project-key",
                route: {
                    project: "proj-shared", home_id: "home:local-user", endpoint: "",
                    relay: locator(OWNERS), placement: { project_key: "project-key" },
                },
            },
        },
    })]]);
    vi.stubGlobal("localStorage", {
        getItem: (key: string) => held.get(key) ?? null,
        setItem: (key: string, value: string) => void held.set(key, value),
    });
    // The member's account record: their own desktop, as it registered itself.
    const accountHomes = own === "selected"
        ? { homes: [{ id: "home:local-user", kind: "registered", endpoint: "", relay: locator(MINE) }],
            selected_home: "home:local-user" }
        : { homes: [], selected_home: null };
    vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input);
        if ((init?.method ?? "GET") !== "GET") {
            hubWrites.push(`${init?.method} ${url}`);
            return new Response(null, { status: 204 });
        }
        if (url === "https://hub.example/account/directory") {
            return Response.json({ root_pubkey: "ed25519:member", origin: "https://dir.example", subject: "person-1" });
        }
        // The member's own desktop's entry under their root, still published.
        if (url === `https://dir.example/directory/${encodeURIComponent("ed25519:member")}/entries`) {
            return Response.json({ version: 1, puts: [JSON.stringify({ entry: { directory: {
                root_pubkey: "ed25519:member",
                home_routes: [{
                    project: own === "selected" ? "proj-mine" : "proj-default",
                    home_id: "home:local-user", endpoint: "", relay: locator(MINE),
                }],
            } } })] });
        }
        if (url === "https://hub.example/account/home-routes") return Response.json({ routes: [] });
        if (url === "https://hub.example/account/homes") return Response.json(accountHomes);
        throw new Error(`unexpected fetch ${url}`);
    }));
    const api = new WorkbenchControlPlane("https://hub.example", { splitHomes: true });
    api.setBearer("person-token");
    const projects = async () => (await api.getWorkspaceCarriage()).value.projects.map((p) => p.id);
    return { api, dialed, carried, hubWrites, projects };
}
