/**
 * Seal a provider link for every trusted device before it leaves the page
 * (DR-0334).
 *
 * A person's provider link is held by their account as one copy per trusted
 * device, each sealed to that device's public recipient key, so the Hub
 * stores only ciphertext it cannot open. The page that makes a link is where
 * the secret exists in the clear, so it seals here and submits only copies.
 *
 * Byte-for-byte port of `crates/app/src/account_link_seal.rs`: P-256 ECIES
 * with a fresh ephemeral key per copy, SHA-256 over a domain and the
 * length-prefixed account, provider, version and device id, then AES-256-GCM
 * with the wire form `nonce(12) || ciphertext || tag(16)`. The shared vector
 * in `crates/app/tests/account-link-seal-vector.json` pins the two together.
 * This module only seals; opening is a device's business.
 */

/** One version of one account's link to one provider. */
export interface LinkContext {
    readonly account: string;
    readonly provider: string;
    readonly version: number;
}

/** A trusted device and its public recipient key (hex, uncompressed SEC1). */
export interface LinkRecipient {
    readonly device_id: string;
    readonly public_key: string;
}

/** One device's copy, in the wire shape the account authority stores. */
export interface SealedLinkCopy {
    readonly device_id: string;
    readonly ephemeral_pubkey: string;
    readonly ciphertext: string;
}

const DOMAIN = "gaugewright/account-link/ecies/v1";

function hex(bytes: Uint8Array): string {
    return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function fromHex(value: string): Uint8Array {
    if (!/^[0-9a-f]+$/i.test(value) || value.length % 2) {
        throw new Error("A device's recipient key is malformed.");
    }
    return Uint8Array.from(value.match(/../g)!, (part) => Number.parseInt(part, 16));
}

function validComponent(value: string): boolean {
    return value.trim().length > 0 && value.length <= 256 && !/[\u0000-\u001f\u007f-\u009f]/.test(value);
}

function component(value: string): Uint8Array {
    const bytes = new TextEncoder().encode(value);
    const length = new Uint8Array(8);
    new DataView(length.buffer).setBigUint64(0, BigInt(bytes.byteLength));
    return new Uint8Array([...length, ...bytes]);
}

/** The AES-GCM key one copy is sealed under. Exported for the vector test. */
export async function linkCopyKey(
    shared: ArrayBuffer,
    context: LinkContext,
    deviceId: string,
    usages: readonly KeyUsage[] = ["encrypt"],
): Promise<CryptoKey> {
    const input = new Uint8Array([
        ...new TextEncoder().encode(DOMAIN),
        ...component(context.account),
        ...component(context.provider),
        ...component(String(context.version)),
        ...component(deviceId),
        ...new Uint8Array(shared),
    ]);
    const raw = await crypto.subtle.digest("SHA-256", input);
    return crypto.subtle.importKey("raw", raw, { name: "AES-GCM" }, false, [...usages]);
}

function checkContext(context: LinkContext): void {
    if (!validComponent(context.account) || !validComponent(context.provider)
        || !Number.isSafeInteger(context.version) || context.version < 1) {
        throw new Error("A provider link cannot be sealed without its account, provider and version.");
    }
}

/** Seal `secret` for one device. */
export async function sealLinkCopy(
    context: LinkContext,
    secret: string | Uint8Array,
    recipient: LinkRecipient,
): Promise<SealedLinkCopy> {
    checkContext(context);
    if (!validComponent(recipient.device_id)) throw new Error("A trusted device id is malformed.");
    const peer = await crypto.subtle.importKey(
        "raw", Uint8Array.from(fromHex(recipient.public_key)).buffer,
        { name: "ECDH", namedCurve: "P-256" }, false, [],
    );
    const ephemeral = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
    const shared = await crypto.subtle.deriveBits({ name: "ECDH", public: peer }, ephemeral.privateKey, 256);
    const key = await linkCopyKey(shared, context, recipient.device_id);
    const nonce = crypto.getRandomValues(new Uint8Array(12));
    const plaintext = typeof secret === "string" ? new TextEncoder().encode(secret) : Uint8Array.from(secret);
    const sealed = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce }, key, plaintext));
    const ephemeralPublic = new Uint8Array(await crypto.subtle.exportKey("raw", ephemeral.publicKey));
    return {
        device_id: recipient.device_id,
        ephemeral_pubkey: hex(ephemeralPublic),
        ciphertext: hex(new Uint8Array([...nonce, ...sealed])),
    };
}

/** Seal `secret` for every device in `recipients`, in order. */
export async function sealLinkCopies(
    context: LinkContext,
    secret: string | Uint8Array,
    recipients: readonly LinkRecipient[],
): Promise<SealedLinkCopy[]> {
    const copies: SealedLinkCopy[] = [];
    for (const recipient of recipients) copies.push(await sealLinkCopy(context, secret, recipient));
    return copies;
}
