import {
    newIdempotencyKey,
    type AccountDeviceLink,
    type AccountDeviceLinkStatus,
} from "@gaugewright/control-plane-client";

const DATABASE = "gaugedesk-device-credentials";
const STORE = "credentials";
const VERSION = 1;
const textEncoder = new TextEncoder();

export interface DeviceLinkInvitation {
    readonly id: string;
    readonly code: string;
}

/** Parse either the server's native QR payload or its browser landing URL. */
export function parseDeviceLinkInvitation(value: string): DeviceLinkInvitation | null {
    try {
        const url = new URL(value);
        const native = url.protocol === "gaugewright:"
            && url.hostname === "auth"
            && url.pathname === "/device-link";
        const browser = (url.protocol === "https:" || url.protocol === "http:")
            && url.searchParams.get("gaugeapp") === "account-settings"
            && url.searchParams.get("page") === "trusted-devices";
        if (!native && !browser) return null;
        const id = url.searchParams.get("id") ?? url.searchParams.get("device_link_id") ?? "";
        const code = url.searchParams.get("code") ?? url.searchParams.get("device_link_code") ?? "";
        return id && code ? { id, code } : null;
    } catch {
        return null;
    }
}

/** A QR must open the receiving Desk even when no native scheme handler exists. */
export function deviceLinkBrowserUrl(invitation: DeviceLinkInvitation, currentHref: string): string {
    const current = new URL(currentHref);
    const browserOrigin = current.protocol === "http:" || current.protocol === "https:"
        ? current.origin
        : "https://desk.gaugewright.com";
    const url = new URL("/", browserOrigin);
    url.searchParams.set("gaugeapp", "account-settings");
    url.searchParams.set("page", "trusted-devices");
    url.searchParams.set("device_link_id", invitation.id);
    url.searchParams.set("device_link_code", invitation.code);
    return url.toString();
}

interface GeneratedDeviceKey {
    readonly publicKey: string;
    readonly ecdhPrivate: CryptoKey;
    readonly ecdsaPrivate: CryptoKey;
}

interface PendingDeviceKey extends GeneratedDeviceKey {
    readonly id: string;
    readonly state: "pending" | "recovered";
    readonly accountRoot?: string;
    readonly accountKey?: CryptoKey;
    readonly completion?: DeviceLinkCompletion;
    readonly completionIdempotencyKey?: string;
}

interface DeviceLinkCompletion {
    readonly account_key_proof: string;
    readonly signature: string;
}

function bytesToHex(bytes: ArrayBuffer | ArrayBufferView): string {
    const view = bytes instanceof ArrayBuffer
        ? new Uint8Array(bytes)
        : new Uint8Array(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    return [...view].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

function hexToBytes(value: string): Uint8Array {
    if (!/^[0-9a-f]*$/i.test(value) || value.length % 2 !== 0) throw new Error("Malformed hexadecimal device material.");
    return Uint8Array.from(value.match(/.{2}/g) ?? [], (byte) => Number.parseInt(byte, 16));
}

function exactBuffer(bytes: Uint8Array): ArrayBuffer {
    return Uint8Array.from(bytes).buffer;
}

function u64be(value: number): Uint8Array {
    const bytes = new Uint8Array(8);
    new DataView(bytes.buffer).setBigUint64(0, BigInt(value), false);
    return bytes;
}

function concatenate(...parts: readonly Uint8Array[]): Uint8Array {
    const total = parts.reduce((sum, part) => sum + part.byteLength, 0);
    const joined = new Uint8Array(total);
    let offset = 0;
    for (const part of parts) {
        joined.set(part, offset);
        offset += part.byteLength;
    }
    return joined;
}

function openDatabase(): Promise<IDBDatabase> {
    if (!globalThis.indexedDB) return Promise.reject(new Error("This client cannot retain a device credential."));
    return new Promise((resolve, reject) => {
        const request = indexedDB.open(DATABASE, VERSION);
        request.onupgradeneeded = () => {
            if (!request.result.objectStoreNames.contains(STORE)) request.result.createObjectStore(STORE, { keyPath: "id" });
        };
        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(request.error ?? new Error("Could not open the device credential store."));
    });
}

async function readCredential(id: string): Promise<PendingDeviceKey | undefined> {
    const database = await openDatabase();
    try {
        return await new Promise((resolve, reject) => {
            const request = database.transaction(STORE, "readonly").objectStore(STORE).get(id);
            request.onsuccess = () => resolve(request.result as PendingDeviceKey | undefined);
            request.onerror = () => reject(request.error ?? new Error("Could not read the device credential."));
        });
    } finally {
        database.close();
    }
}

async function writeCredential(value: PendingDeviceKey): Promise<void> {
    const database = await openDatabase();
    try {
        await new Promise<void>((resolve, reject) => {
            const request = database.transaction(STORE, "readwrite").objectStore(STORE).put(value);
            request.onsuccess = () => resolve();
            request.onerror = () => reject(request.error ?? new Error("Could not save the device credential."));
        });
    } finally {
        database.close();
    }
}

async function deleteCredential(id: string): Promise<void> {
    const database = await openDatabase();
    try {
        await new Promise<void>((resolve, reject) => {
            const request = database.transaction(STORE, "readwrite").objectStore(STORE).delete(id);
            request.onsuccess = () => resolve();
            request.onerror = () => reject(request.error ?? new Error("Could not finish the device credential."));
        });
    } finally {
        database.close();
    }
}

/** Forget a receiving device's unfinished key after the server has made the
 * link terminal. Transient transport failures deliberately retain it so the
 * authorized completion remains resumable. */
export async function discardPendingDeviceLink(linkId: string): Promise<void> {
    await deleteCredential(`link:${linkId}`);
}

export async function generateDeviceLinkKey(): Promise<GeneratedDeviceKey> {
    if (!globalThis.crypto?.subtle) throw new Error("This client cannot create a device credential.");
    const generated = await crypto.subtle.generateKey(
        { name: "ECDH", namedCurve: "P-256" },
        true,
        ["deriveBits"],
    ) as CryptoKeyPair;
    const privateJwk = await crypto.subtle.exportKey("jwk", generated.privateKey);
    const publicKey = bytesToHex(await crypto.subtle.exportKey("raw", generated.publicKey));
    const ecdhPrivate = await crypto.subtle.importKey(
        "jwk",
        privateJwk,
        { name: "ECDH", namedCurve: "P-256" },
        false,
        ["deriveBits"],
    );
    const ecdsaPrivate = await crypto.subtle.importKey(
        "jwk",
        { ...privateJwk, key_ops: ["sign"] },
        { name: "ECDSA", namedCurve: "P-256" },
        false,
        ["sign"],
    );
    return { publicKey, ecdhPrivate, ecdsaPrivate };
}

export async function retainPendingDeviceLink(linkId: string, key: GeneratedDeviceKey): Promise<void> {
    await writeCredential({ id: `link:${linkId}`, state: "pending", ...key });
}

export async function hasPendingDeviceLink(linkId: string): Promise<boolean> {
    return Boolean(await readCredential(`link:${linkId}`));
}

function completionMaterial(status: AccountDeviceLinkStatus): Uint8Array {
    if (!status.authorization || !status.completion_challenge) throw new Error("The server has not authorized this device.");
    const expected = `gaugewright-device-enrollment-complete::v1::link=${status.link.id}::root=${status.authorization.delegation.authority_root}::sub=${status.authorization.delegation.subkey}::exp=${status.authorization.delegation.expiry}`;
    if (status.completion_challenge !== expected) throw new Error("The device completion challenge does not match its authorization.");
    return textEncoder.encode(expected);
}

async function verifyDelegation(status: AccountDeviceLinkStatus, publicKey: string): Promise<void> {
    const authorization = status.authorization;
    if (!authorization) throw new Error("The server has not authorized this device.");
    if (authorization.delegation.authority_root !== status.account_root
        || authorization.delegation.subkey !== publicKey
        || authorization.delegation.expiry <= Math.floor(Date.now() / 1000)) {
        throw new Error("The device delegation is for another root, key, or time window.");
    }
    const root = await crypto.subtle.importKey(
        "raw",
        exactBuffer(hexToBytes(status.account_root)),
        { name: "ECDSA", namedCurve: "P-256" },
        false,
        ["verify"],
    );
    const signed = textEncoder.encode(`gaugewright-device-delegation::v1::root=${status.account_root}::sub=${publicKey}::exp=${authorization.delegation.expiry}`);
    const valid = await crypto.subtle.verify(
        { name: "ECDSA", hash: "SHA-256" },
        root,
        exactBuffer(Uint8Array.from(authorization.delegation.signature)),
        exactBuffer(signed),
    );
    if (!valid) throw new Error("The account root did not sign this device delegation.");
}

async function openAccountKey(status: AccountDeviceLinkStatus, key: PendingDeviceKey): Promise<Uint8Array> {
    const sealed = status.authorization?.sealed_key;
    if (!sealed) throw new Error("The server has not released sealed account material.");
    const ephemeral = await crypto.subtle.importKey(
        "raw",
        exactBuffer(hexToBytes(sealed.ephemeral_pubkey)),
        { name: "ECDH", namedCurve: "P-256" },
        false,
        [],
    );
    const shared = new Uint8Array(await crypto.subtle.deriveBits(
        { name: "ECDH", public: ephemeral },
        key.ecdhPrivate,
        256,
    ));
    const encryptionKey = await crypto.subtle.digest(
        "SHA-256",
        exactBuffer(concatenate(textEncoder.encode("gaugewright/acct-1/device-enroll/ecies/v1"), shared)),
    );
    const ciphertext = hexToBytes(sealed.ciphertext);
    if (ciphertext.byteLength < 28) throw new Error("The sealed account material is malformed.");
    const plaintext = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: exactBuffer(ciphertext.slice(0, 12)), tagLength: 128 },
        await crypto.subtle.importKey("raw", encryptionKey, "AES-GCM", false, ["decrypt"]),
        exactBuffer(ciphertext.slice(12)),
    );
    const accountKey = new Uint8Array(plaintext);
    if (accountKey.byteLength !== 32) throw new Error("The recovered account key has the wrong length.");
    return accountKey;
}

export async function prepareDeviceLinkCompletion(status: AccountDeviceLinkStatus): Promise<{
    readonly completion: DeviceLinkCompletion;
    readonly idempotencyKey: string;
}> {
    const id = `link:${status.link.id}`;
    const stored = await readCredential(id);
    if (!stored) throw new Error("This client no longer holds the pending device key.");
    if (stored.state === "recovered" && stored.completion && stored.completionIdempotencyKey) {
        return { completion: stored.completion, idempotencyKey: stored.completionIdempotencyKey };
    }
    await verifyDelegation(status, stored.publicKey);
    const material = completionMaterial(status);
    const rawAccountKey = await openAccountKey(status, stored);
    const proof = bytesToHex(await crypto.subtle.digest(
        "SHA-256",
        exactBuffer(concatenate(
            textEncoder.encode("gaugewright-device-enrollment-account-key-proof::v1"),
            rawAccountKey,
            u64be(material.byteLength),
            material,
        )),
    ));
    const signature = bytesToHex(await crypto.subtle.sign(
        { name: "ECDSA", hash: "SHA-256" },
        stored.ecdsaPrivate,
        exactBuffer(material),
    ));
    const accountKey = await crypto.subtle.importKey("raw", exactBuffer(rawAccountKey), "AES-GCM", false, ["encrypt", "decrypt"]);
    rawAccountKey.fill(0);
    const completion = { account_key_proof: proof, signature };
    const completionIdempotencyKey = newIdempotencyKey();
    await writeCredential({
        ...stored,
        state: "recovered",
        accountRoot: status.account_root,
        accountKey,
        completion,
        completionIdempotencyKey,
    });
    return { completion, idempotencyKey: completionIdempotencyKey };
}

export async function finalizeDeviceLink(link: AccountDeviceLink): Promise<void> {
    if (!link.device) throw new Error("The enrolled device has no durable identity.");
    const pending = await readCredential(`link:${link.id}`);
    if (!pending || pending.state !== "recovered" || !pending.accountRoot || !pending.accountKey) {
        throw new Error("The recovered device credential is unavailable.");
    }
    await writeCredential({ ...pending, id: `device:${link.device.id}` });
    await deleteCredential(`link:${link.id}`);
}
