import { describe, expect, it } from "vitest";
import vector from "../../../../crates/app/tests/account-link-seal-vector.json";
import { linkCopyKey, sealLinkCopies, sealLinkCopy, type LinkContext, type SealedLinkCopy } from "./account-link-seal";

function fromHex(value: string): Uint8Array {
    return Uint8Array.from(value.match(/../g)!, (part) => Number.parseInt(part, 16));
}

function base64url(bytes: Uint8Array): string {
    return Buffer.from(bytes).toString("base64url");
}

/** The device's half, which this module deliberately does not ship: import the
 *  vector's private key and open a copy the way a desktop does. */
async function open(context: LinkContext, copy: SealedLinkCopy): Promise<string> {
    const point = fromHex(vector.recipient_public_key_hex);
    const privateKey = await crypto.subtle.importKey("jwk", {
        kty: "EC", crv: "P-256",
        d: base64url(fromHex(vector.recipient_private_seed_hex)),
        x: base64url(point.slice(1, 33)), y: base64url(point.slice(33, 65)),
    }, { name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"]);
    const ephemeral = await crypto.subtle.importKey(
        "raw", Uint8Array.from(fromHex(copy.ephemeral_pubkey)).buffer, { name: "ECDH", namedCurve: "P-256" }, false, [],
    );
    const shared = await crypto.subtle.deriveBits({ name: "ECDH", public: ephemeral }, privateKey, 256);
    const key = await linkCopyKey(shared, context, copy.device_id, ["decrypt"]);
    const sealed = fromHex(copy.ciphertext);
    const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: sealed.slice(0, 12) }, key, sealed.slice(12));
    return new TextDecoder().decode(plain);
}

const context: LinkContext = { account: vector.account, provider: vector.provider, version: vector.version };
const device = { device_id: "device:vector", public_key: vector.recipient_public_key_hex };

describe("sealing a provider link for each trusted device (DR-0334)", () => {
    it("derives the same copy key as the desktop that opens it", async () => {
        await expect(open(context, vector.rust_copy)).resolves.toBe(vector.secret);
    });

    it("seals a copy only its device opens, bound to the link's version", async () => {
        const copy = await sealLinkCopy(context, "sk-fresh", device);
        expect(copy.device_id).toBe("device:vector");
        await expect(open(context, copy)).resolves.toBe("sk-fresh");
        await expect(open({ ...context, version: context.version + 1 }, copy)).rejects.toThrow();
        await expect(open(context, { ...copy, device_id: "device:other" })).rejects.toThrow();
    });

    it("seals one fresh copy per device", async () => {
        const copies = await sealLinkCopies(context, "sk-fresh", [device, { ...device, device_id: "device:second" }]);
        expect(copies.map((copy) => copy.device_id)).toEqual(["device:vector", "device:second"]);
        expect(copies[0].ephemeral_pubkey).not.toBe(copies[1].ephemeral_pubkey);
    });

    it("refuses to seal without a version or to a malformed device key", async () => {
        await expect(sealLinkCopy({ ...context, version: 0 }, "sk", device)).rejects.toThrow(/version/);
        await expect(sealLinkCopy(context, "sk", { ...device, public_key: "zz" })).rejects.toThrow(/malformed/);
    });
});
