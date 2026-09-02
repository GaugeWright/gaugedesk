import { describe, expect, it, vi } from "vitest";

import { boxRouteJson, claimBox, forgetBox, listBoxes } from "./tokenwright-box-store";
import type { RouteJson } from "./control-plane-transport";

/** A pairing string the box produced. The only thing a browser ever holds. */
const PAIRING_STRING =
    "tw1_eyJ2IjoxLCJyIjoid3NzOi8vcmVsYXkuZXhhbXBsZTo0NDMvciIsImMiOiJBQkNELUVGR0gtSktNTi1QUVJTLVRWV1giLCJmIjoic2hhMjU2OmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWIifQ";
const FINGERPRINT = `sha256:${"ab".repeat(32)}`;
const RELAY = "wss://relay.example:443/r";
/** Capabilities this package must never see. Named so the tests can prove it. */
const ROUTE = "F8E0l3whZo41YL6B8yzSJAQdF8E0l3whZo41YL6B8yw";
const BOX_KEY = "tw_box_key_do_not_leak";

describe("claiming a box", () => {
    it("hands the Home a pairing string and nothing else", async () => {
        // The browser does not parse it, derive a rendezvous, dial a relay, or
        // pin a certificate. The Home does all of that, because the Home is what
        // holds the credential afterwards.
        const json = vi.fn(async () => ({
            fingerprint: FINGERPRINT,
            relay_endpoint: RELAY,
            paired_at: "2026-09-01T20:00:00Z",
            home_id: "home_a",
            key_id: "key_c30f",
            sealed: true,
        }));
        const stored = await claimBox(json, PAIRING_STRING);
        expect(json).toHaveBeenCalledWith("POST", "/account/boxes/claim", {
            pairing_string: PAIRING_STRING,
        });
        expect(stored.sealed).toBe(true);
        expect(stored.fingerprint).toBe(FINGERPRINT);
    });

    it("reports a box the Home did not confirm sealing as unsealed", async () => {
        const json = vi.fn(async () => ({ fingerprint: FINGERPRINT }));
        expect((await claimBox(json, PAIRING_STRING)).sealed).toBe(false);
    });

    it("lets a failure surface rather than swallowing it", async () => {
        // A claim that succeeded and was not sealed has spent a single-use code
        // and lost the box. A rejected promise is the only honest answer.
        const json = vi.fn(async () => { throw new Error("502 the box did not answer"); });
        await expect(claimBox(json, PAIRING_STRING)).rejects.toThrow(/502/);
    });
});

describe("what comes back", () => {
    it("carries what is public and no capability at all", async () => {
        const json = vi.fn(async () => ({
            boxes: [{
                fingerprint: FINGERPRINT,
                relay_endpoint: RELAY,
                paired_at: "2026-09-01T20:00:00Z",
                home_id: "home_a",
                key_id: "key_c30f",
                sealed: true,
            }],
        }));
        const boxes = await listBoxes(json);
        expect(boxes).toEqual([{
            fingerprint: FINGERPRINT,
            relayEndpoint: RELAY,
            pairedAt: "2026-09-01T20:00:00Z",
            homeId: "home_a",
            keyId: "key_c30f",
            sealed: true,
        }]);
        // The shape itself has nowhere to put them, which is the guarantee —
        // not that this response happened to omit them.
        const rendered = JSON.stringify(boxes[0]);
        expect(rendered).not.toContain(ROUTE);
        expect(rendered).not.toContain(BOX_KEY);
    });

    it("drops a route or key a server tried to hand back", async () => {
        // Belt and braces against a future server, a proxy, or a mock that
        // returns more than it should: this layer must not become the thing
        // that carries a capability into a page.
        const json = vi.fn(async () => ({
            boxes: [{
                fingerprint: FINGERPRINT,
                relay_endpoint: RELAY,
                route: ROUTE,
                key: BOX_KEY,
                sealed: true,
            }],
        }));
        const rendered = JSON.stringify(await listBoxes(json));
        expect(rendered).not.toContain(ROUTE);
        expect(rendered).not.toContain(BOX_KEY);
    });

    it("survives a server that returns nothing useful", async () => {
        for (const answer of [{}, { boxes: null }, { boxes: [null] }]) {
            const boxes = await listBoxes(vi.fn(async () => answer));
            expect(Array.isArray(boxes)).toBe(true);
        }
    });
});

describe("forgetting a box", () => {
    it("addresses it by bare hex however the pin was spelled", async () => {
        const paths: string[] = [];
        // Typed as the route it stands in for, so the call signature is checked
        // rather than inferred from a zero-argument stub.
        const json: RouteJson = async (_method, path) => { paths.push(path); return null; };
        await forgetBox(json, FINGERPRINT);
        await forgetBox(json, "ab".repeat(32));
        expect(paths).toEqual([
            `/account/boxes/${"ab".repeat(32)}`,
            `/account/boxes/${"ab".repeat(32)}`,
        ]);
    });
});

describe("reaching a box through the Home", () => {
    it("prefixes the box's own path and rewrites nothing else", async () => {
        // A proxy that understood the surface would be a second copy of it in
        // this repository, drifting from the box that owns it.
        const calls: Array<[string, string, unknown, unknown]> = [];
        const json: RouteJson = async (method, path, body, options) => {
            calls.push([method, path, body, options]);
            return null;
        };
        const carried = boxRouteJson(json, FINGERPRINT);

        await carried("POST", "/environments/tokenwright/sessions", { scope: null });
        await carried("GET", "/environments/tokenwright/documents/tokenwright.inference");
        await carried(
            "POST",
            "/environments/tokenwright/commands",
            { command_id: "x" },
            { idempotencyKey: "once" },
        );

        const bare = "ab".repeat(32);
        expect(calls.map(([method, path]) => `${method} ${path}`)).toEqual([
            `POST /account/boxes/${bare}/surface/environments/tokenwright/sessions`,
            `GET /account/boxes/${bare}/surface/environments/tokenwright/documents/tokenwright.inference`,
            `POST /account/boxes/${bare}/surface/environments/tokenwright/commands`,
        ]);
        // Body and options pass through untouched — the idempotency key
        // especially, or every retry of a command performs the work twice.
        expect(calls[0]![2]).toEqual({ scope: null });
        expect(calls[2]![3]).toEqual({ idempotencyKey: "once" });
    });

    it("takes a fingerprint in either spelling", async () => {
        const seen: string[] = [];
        const json: RouteJson = async (_method, path) => { seen.push(path); return null; };
        await boxRouteJson(json, FINGERPRINT)("GET", "/environments/tokenwright/audit");
        await boxRouteJson(json, "ab".repeat(32))("GET", "/environments/tokenwright/audit");
        expect(new Set(seen).size).toBe(1);
    });

    it("carries a path given without a leading slash", async () => {
        const seen: string[] = [];
        const json: RouteJson = async (_method, path) => { seen.push(path); return null; };
        await boxRouteJson(json, FINGERPRINT)("GET", "environments/tokenwright/audit");
        expect(seen[0]).toBe(
            `/account/boxes/${"ab".repeat(32)}/surface/environments/tokenwright/audit`,
        );
    });
});
