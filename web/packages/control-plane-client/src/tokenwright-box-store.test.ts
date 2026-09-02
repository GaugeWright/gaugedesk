import { describe, expect, it, vi } from "vitest";

import { forgetBox, listBoxes, recordPairedBox } from "./tokenwright-box-store";
import type { RouteJson } from "./control-plane-transport";
import type { TokenWrightConnection } from "./tokenwright-pairing";

const CONNECTION: TokenWrightConnection = {
    relayEndpoint: "wss://relay.example:443/r",
    route: "F8E0l3whZo41YL6B8yzSJAQdF8E0l3whZo41YL6B8yw",
    fingerprint: `sha256:${"ab".repeat(32)}`,
    key: "tw_box_key_do_not_leak",
    keyId: "key_c30f",
    homeId: "home_a",
    pairedAt: "2026-09-01T20:00:00Z",
};

describe("sealing a box the account will hold", () => {
    it("sends both capabilities up, exactly once", async () => {
        // This is the only moment the route exists anywhere but on the box.
        const json = vi.fn(async () => ({
            fingerprint: CONNECTION.fingerprint,
            relay_endpoint: CONNECTION.relayEndpoint,
            sealed: true,
        }));
        const stored = await recordPairedBox(json, CONNECTION);
        expect(json).toHaveBeenCalledOnce();
        expect(json).toHaveBeenCalledWith("POST", "/account/boxes", {
            fingerprint: CONNECTION.fingerprint,
            route: CONNECTION.route,
            key: CONNECTION.key,
            relay_endpoint: CONNECTION.relayEndpoint,
            paired_at: CONNECTION.pairedAt,
            home_id: CONNECTION.homeId,
            key_id: CONNECTION.keyId,
        });
        expect(stored.sealed).toBe(true);
    });

    it("reports a box the server did not confirm sealing as unsealed", async () => {
        // A caller must be able to tell "recorded and openable" from "recorded".
        const json = vi.fn(async () => ({ fingerprint: CONNECTION.fingerprint }));
        expect((await recordPairedBox(json, CONNECTION)).sealed).toBe(false);
    });

    it("lets a failure surface rather than swallowing it", async () => {
        // A claim that succeeded and was not recorded has spent a single-use
        // code and lost the box. A rejected promise is the only honest answer.
        const json = vi.fn(async () => { throw new Error("422 fingerprint"); });
        await expect(recordPairedBox(json, CONNECTION)).rejects.toThrow(/422/);
    });
});

describe("what comes back", () => {
    it("carries what is public and no capability at all", async () => {
        const json = vi.fn(async () => ({
            boxes: [{
                fingerprint: CONNECTION.fingerprint,
                relay_endpoint: CONNECTION.relayEndpoint,
                paired_at: CONNECTION.pairedAt,
                home_id: "home_a",
                key_id: "key_c30f",
                sealed: true,
            }],
        }));
        const boxes = await listBoxes(json);
        expect(boxes).toEqual([{
            fingerprint: CONNECTION.fingerprint,
            relayEndpoint: CONNECTION.relayEndpoint,
            pairedAt: CONNECTION.pairedAt,
            homeId: "home_a",
            keyId: "key_c30f",
            sealed: true,
        }]);
        // The shape itself has nowhere to put them, which is the guarantee —
        // not that this response happened to omit them.
        const rendered = JSON.stringify(boxes[0]);
        expect(rendered).not.toContain(CONNECTION.route);
        expect(rendered).not.toContain(CONNECTION.key);
    });

    it("drops a route or key a server tried to hand back", async () => {
        // Belt and braces against a future server, a proxy, or a mock that
        // returns more than it should: this layer must not become the thing
        // that carries a capability into a page.
        const json = vi.fn(async () => ({
            boxes: [{
                fingerprint: CONNECTION.fingerprint,
                relay_endpoint: CONNECTION.relayEndpoint,
                route: CONNECTION.route,
                key: CONNECTION.key,
                sealed: true,
            }],
        }));
        const rendered = JSON.stringify(await listBoxes(json));
        expect(rendered).not.toContain(CONNECTION.route);
        expect(rendered).not.toContain(CONNECTION.key);
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
        await forgetBox(json, CONNECTION.fingerprint);
        await forgetBox(json, "ab".repeat(32));
        expect(paths).toEqual([
            `/account/boxes/${"ab".repeat(32)}`,
            `/account/boxes/${"ab".repeat(32)}`,
        ]);
    });
});
