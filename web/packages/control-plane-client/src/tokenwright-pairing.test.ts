import { describe, expect, it, vi } from "vitest";

import {
    claimLocator,
    claimProof,
    claimRouteToken,
    claimTokenWrightBox,
    connectionLocator,
    normalizeClaimCode,
    parseTokenWrightInvite,
    tokenwrightLocator,
    type TokenWrightConnection,
} from "./tokenwright-pairing";

/**
 * Vectors produced by the box itself (`tokenwright.pairing`,
 * `tokenwright.relay_wire`), not by this implementation.
 *
 * These are the only tests here that can catch the failure that matters: the
 * two sides deriving different bytes from the same code. That failure has no
 * good symptom — the relay pairs nobody, or the box refuses a proof it cannot
 * explain — so it has to be caught by agreeing with a recorded answer rather
 * than with ourselves.
 */
const VECTORS = [
    {
        code: "ABCD-EFGH-JKMN-PQRS-TVWX",
        normalized: "ABCDEFGHJKMNPQRSTVWX",
        handle: "ARcI4-5AsZGNAe-NBaNL6EZlJPEfd8IcKB-npdUgGs8",
        claimProof: "d4a1a5a6d21543d10ff53f7f172413541d565901af544f5dae0b0435d8b0c908",
        relayProof: "gfpUk0DpnlGVnz40Ug6dYPPBd5DPBjVVIxZBpuqjj1c",
    },
    {
        // Same code, typed in lower case.
        code: "abcd-efgh-jkmn-pqrs-tvwx",
        normalized: "ABCDEFGHJKMNPQRSTVWX",
        handle: "ARcI4-5AsZGNAe-NBaNL6EZlJPEfd8IcKB-npdUgGs8",
        claimProof: "d4a1a5a6d21543d10ff53f7f172413541d565901af544f5dae0b0435d8b0c908",
        relayProof: "gfpUk0DpnlGVnz40Ug6dYPPBd5DPBjVVIxZBpuqjj1c",
    },
    {
        code: "0000-0000-0000-0000-0000",
        normalized: "00000000000000000000",
        handle: "Tt2MVbAtg9jFAI9TQMVyFaIp3U4rdkwW07VO7YqhIlM",
        claimProof: "b92055e66bb196ce39c0ff8a0bbafb343f907bc0a119527fe700d8522e443bfe",
        relayProof: "ZULX6Zd-zxf0gN1dqhUf9cZF6UKOr7aXwPhpkoo5LDY",
    },
    {
        code: "ZZZZ ZZZZ ZZZZ ZZZZ ZZZZ",
        normalized: "ZZZZZZZZZZZZZZZZZZZZ",
        handle: "ggffRdIHiBXmhArV5nNvudNusPtysUOuGVo3kPKjk1Q",
        claimProof: "6e62eb9f8f00b93af9d1bd86aaae547064f64ef4a33d844744f09691d9552e35",
        relayProof: "kusnct-rCIJYR8qUiwAaIo4E5vv7C0WAgjGsp-UFS_A",
    },
    {
        // Read aloud and typed with stray spaces.
        code: "M W 1 7-J81G-WEBE-ZD0C-MQJ3",
        normalized: "MW17J81GWEBEZD0CMQJ3",
        handle: "ftvdZ6DlLNxDiOqTJ4WtQuJUKzu4bRbQkdHy9U-2mNo",
        claimProof: "7ab90489b88e09a49f20f2f5700901aa66ec1c0c5c167a8cdcdad3d5230e25df",
        relayProof: "oYiUU_1CBQZwwo6urafNTLuZnriDBcCxLGB0CAfyY9A",
    },
] as const;

const PIN = `sha256:${"ab".repeat(32)}`;
/** Produced by the box's own `tokenwright.invite.encode`. */
const INVITE =
    "tw1_eyJ2IjoxLCJyIjoid3NzOi8vcmVsYXkuZXhhbXBsZTo0NDMvciIsImMiOiJBQkNELUVGR0gtSktNTi1QUVJTLVRWV1giLCJmIjoic2hhMjU2OmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWIifQ";

describe("agreeing with the box about a claim code", () => {
    it.each(VECTORS)("normalizes $code the way the box does", ({ code, normalized }) => {
        expect(normalizeClaimCode(code)).toBe(normalized);
    });

    it.each(VECTORS)("derives the rendezvous handle for $code", async ({ code, handle }) => {
        const locator = await tokenwrightLocator({
            relayEndpoint: "wss://relay.example",
            token: await claimRouteToken(code),
            fingerprint: PIN,
        });
        expect(locator.handle).toBe(handle);
    });

    it.each(VECTORS)("derives the relay proof for $code", async ({ code, relayProof }) => {
        const locator = await tokenwrightLocator({
            relayEndpoint: "wss://relay.example",
            token: await claimRouteToken(code),
            fingerprint: PIN,
        });
        expect(locator.proof).toBe(relayProof);
    });

    it.each(VECTORS)("derives the claim proof for $code", async ({ code, claimProof: expected }) => {
        expect(await claimProof(code)).toBe(expected);
    });

    it("keeps the claim proof separate from the relay proof", async () => {
        // The relay sees the handle and its proof. If the claim proof could be
        // derived from either, the relay could claim every box it carries.
        const locator = await tokenwrightLocator({
            relayEndpoint: "wss://relay.example",
            token: await claimRouteToken(VECTORS[0].code),
            fingerprint: PIN,
        });
        expect(await claimProof(VECTORS[0].code)).not.toBe(locator.proof);
        expect(await claimProof(VECTORS[0].code)).not.toBe(locator.handle);
    });
});

describe("reading a pairing string", () => {
    it("reads one the box produced", () => {
        expect(parseTokenWrightInvite(INVITE)).toEqual({
            relayEndpoint: "wss://relay.example:443/r",
            claimCode: "ABCD-EFGH-JKMN-PQRS-TVWX",
            fingerprint: PIN,
        });
    });

    it("survives being pasted with surrounding whitespace", () => {
        expect(parseTokenWrightInvite(`\n  ${INVITE}\t`)).toEqual(parseTokenWrightInvite(INVITE));
    });

    it("names the claim code as the likeliest wrong paste", () => {
        // It is printed directly above the pairing string and looks like the
        // thing you want.
        expect(() => parseTokenWrightInvite("ABCD-EFGH-JKMN-PQRS-TVWX")).toThrow(/tw1_/);
    });

    it.each([
        ["nothing", "   ", /Paste the pairing string/],
        ["a URL", "https://gaugedesk.example/boxes/1", /tw1_/],
        ["a half-copied token", INVITE.slice(0, 40), /damaged/],
    ])("refuses %s", (_label, token, message) => {
        expect(() => parseTokenWrightInvite(token)).toThrow(message);
    });

    it("says when the pin is missing rather than failing to connect later", () => {
        // Without a pin there is no handshake to attempt. "Connection failed"
        // would send someone to look at their network.
        const token = `tw1_${btoa(JSON.stringify({ v: 1, r: "wss://r", c: "ABCD" }))
            .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "")}`;
        expect(() => parseTokenWrightInvite(token)).toThrow(/fingerprint/);
    });

    it("refuses a version it does not read", () => {
        const token = `tw1_${btoa(JSON.stringify({ v: 9, r: "wss://r", c: "ABCD", f: PIN }))
            .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "")}`;
        expect(() => parseTokenWrightInvite(token)).toThrow(/version/);
    });

    it("never echoes the token it rejected", () => {
        // It carries a live claim code, and a message quoting it lands in
        // whatever log the caller happens to write.
        for (const damaged of [INVITE.slice(0, 40), "ABCD-EFGH-JKMN-PQRS-TVWX"]) {
            expect(() => parseTokenWrightInvite(damaged)).toThrow(
                expect.objectContaining({ message: expect.not.stringContaining(damaged) }),
            );
        }
    });

    it("refuses the standard base64 alphabet as a second spelling", () => {
        expect(() => parseTokenWrightInvite("tw1_ab+cd")).toThrow(/damaged/);
    });
});

describe("claiming a box", () => {
    const invite = parseTokenWrightInvite(INVITE);
    const route = "F8E0l3whZo41YL6B8yzSJAQdF8E0l3whZo41YL6B8yw";

    function answering(answer: unknown) {
        return vi.fn(async () => answer);
    }

    it("returns everything needed to reach the box again", async () => {
        const json = answering({
            paired: { home: "home_a", paired_at: "2026-09-01T20:00:00Z", fingerprint: PIN, route },
            key: { id: "key_c30f", name: "paired-home", secret: "s3cret" },
        });
        const connection = await claimTokenWrightBox({
            json, invite, homeId: "home_a", homeKey: "home-root",
            presentedFingerprint: PIN,
        });
        expect(connection).toEqual({
            relayEndpoint: "wss://relay.example:443/r",
            route,
            fingerprint: PIN,
            key: "s3cret",
            keyId: "key_c30f",
            homeId: "home_a",
            pairedAt: "2026-09-01T20:00:00Z",
        });
        expect(json).toHaveBeenCalledWith("POST", "/pair/claim", {
            proof: VECTORS[0].claimProof,
            home: { id: "home_a", key: "home-root" },
        });
    });

    it("dials the durable route on reconnect, not the claim handle", async () => {
        // The two are different addresses, and this is the whole reason a claim
        // response carries a route at all.
        const connection: TokenWrightConnection = {
            relayEndpoint: "wss://relay.example:443/r", route, fingerprint: PIN,
            key: "s3cret", keyId: "key_c30f", homeId: "home_a", pairedAt: "",
        };
        const first = await claimLocator(invite);
        const later = await connectionLocator(connection);
        expect(first.handle).toBe(VECTORS[0].handle);
        expect(later.handle).toBe(route);
        expect(later.handle).not.toBe(first.handle);
        expect(later.homeFingerprint).toBe("ab".repeat(32));
    });

    it("refuses a box whose certificate disagrees with what it says about itself", async () => {
        // Two different layers: a claim in a JSON body, and the certificate the
        // handshake actually verified. Agreement is the point of pinning.
        const json = answering({
            paired: { fingerprint: PIN, route, paired_at: "" },
            key: { id: "k", secret: "s" },
        });
        await expect(claimTokenWrightBox({
            json, invite, homeId: "h", homeKey: "k",
            presentedFingerprint: `sha256:${"cd".repeat(32)}`,
        })).rejects.toThrow(/certificate does not match/);
    });

    it("refuses a box reporting a pin the pairing string did not name", async () => {
        const json = answering({
            paired: { fingerprint: `sha256:${"cd".repeat(32)}`, route, paired_at: "" },
            key: { id: "k", secret: "s" },
        });
        await expect(claimTokenWrightBox({ json, invite, homeId: "h", homeKey: "k" }))
            .rejects.toThrow(/different certificate/);
    });

    it("refuses a box that hands over no route", async () => {
        // Older boxes derived their durable route instead of sending it, so no
        // client could compute it. Storing this connection would work until the
        // box's next restart and then fail with nothing to look at.
        const json = answering({
            paired: { fingerprint: PIN, paired_at: "" },
            key: { id: "k", secret: "s" },
        });
        await expect(claimTokenWrightBox({ json, invite, homeId: "h", homeKey: "k" }))
            .rejects.toThrow(/newer TokenWright/);
    });

    it("refuses a route that is not 32 bytes", async () => {
        const json = answering({
            paired: { fingerprint: PIN, route: "c2hvcnQ", paired_at: "" },
            key: { id: "k", secret: "s" },
        });
        await expect(claimTokenWrightBox({ json, invite, homeId: "h", homeKey: "k" }))
            .rejects.toThrow(/malformed route/);
    });

    it("refuses a claim answered with no key", async () => {
        const json = answering({ paired: { fingerprint: PIN, route, paired_at: "" }, key: {} });
        await expect(claimTokenWrightBox({ json, invite, homeId: "h", homeKey: "k" }))
            .rejects.toThrow(/did not return a key/);
    });
});
