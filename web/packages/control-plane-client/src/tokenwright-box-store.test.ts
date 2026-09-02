import { describe, expect, it, vi } from "vitest";

import { claimBox, forgetBox, listBoxes } from "./tokenwright-box-store";
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
