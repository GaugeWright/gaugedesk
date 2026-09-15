/**
 * Browser custody for a backup recovery holder.
 *
 * The private ECDH key is generated non-extractable and persisted only by an
 * IndexedDB structured clone. This module deliberately has no private-key
 * export, seed, serialization, or server transport API.
 */

export interface BrowserRecoveryHolder {
    readonly id: string;
    readonly publicKey: string;
}

export interface OpaqueBackupWrap {
    readonly recipient_id: string;
    readonly ephemeral_pubkey: string;
    readonly ciphertext: string;
}

interface StoredRecoveryHolder extends BrowserRecoveryHolder {
    readonly privateKey: CryptoKey;
}

// Preserve the store used by the former Console surface so the replacement
// GaugeApp does not strand an already-enrolled recovery holder.
const DB = "gaugewright-backup-keyring-v1";
const STORE = "recipients";

function hex(bytes: Uint8Array): string {
    return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function fromHex(value: string): Uint8Array {
    if (!/^[0-9a-f]+$/i.test(value) || value.length % 2) {
        throw new Error("Backup key material is malformed.");
    }
    return Uint8Array.from(value.match(/../g)!, (part) => Number.parseInt(part, 16));
}

function bytesBuffer(bytes: Uint8Array): ArrayBuffer {
    return Uint8Array.from(bytes).buffer;
}

function component(value: string): Uint8Array {
    const bytes = new TextEncoder().encode(value);
    const length = new Uint8Array(8);
    new DataView(length.buffer).setBigUint64(0, BigInt(bytes.byteLength));
    return new Uint8Array([...length, ...bytes]);
}

async function wrappingKey(shared: ArrayBuffer, tenant: string, keyId: string, recipientId: string): Promise<CryptoKey> {
    const domain = new TextEncoder().encode("gaugewright/b17/backup-keyring/ecies/v1");
    const input = new Uint8Array([
        ...domain,
        ...component(tenant),
        ...component(keyId),
        ...component(recipientId),
        ...new Uint8Array(shared),
    ]);
    const raw = await crypto.subtle.digest("SHA-256", input);
    return crypto.subtle.importKey("raw", raw, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
}

function database(): Promise<IDBDatabase> {
    if (typeof indexedDB === "undefined" || !globalThis.crypto?.subtle) {
        return Promise.reject(new Error("This device cannot hold a non-exportable backup recovery key."));
    }
    return new Promise((resolve, reject) => {
        const request = indexedDB.open(DB, 1);
        request.onupgradeneeded = () => request.result.createObjectStore(STORE);
        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(new Error("Unable to open protected backup key storage."));
    });
}

async function read(db: IDBDatabase, key: string): Promise<StoredRecoveryHolder | undefined> {
    return new Promise((resolve, reject) => {
        const request = db.transaction(STORE, "readonly").objectStore(STORE).get(key);
        request.onsuccess = () => resolve(request.result as StoredRecoveryHolder | undefined);
        request.onerror = () => reject(new Error("Unable to read protected backup key storage."));
    });
}

async function write(db: IDBDatabase, key: string, value: StoredRecoveryHolder): Promise<void> {
    return new Promise((resolve, reject) => {
        const request = db.transaction(STORE, "readwrite").objectStore(STORE).put(value, key);
        request.onsuccess = () => resolve();
        request.onerror = () => reject(new Error("Unable to save protected backup key storage."));
    });
}

async function localHolder(tenant: string): Promise<StoredRecoveryHolder> {
    const db = await database();
    try {
        const current = await read(db, tenant);
        if (!current?.id || !current.publicKey || !current.privateKey) {
            throw new Error("This device does not hold a backup recovery key for this account.");
        }
        return current;
    } finally {
        db.close();
    }
}

export async function browserRecoveryHolder(tenant: string): Promise<BrowserRecoveryHolder> {
    const current = await localHolder(tenant);
    return { id: current.id, publicKey: current.publicKey };
}

export async function ensureBrowserRecoveryHolder(tenant: string): Promise<BrowserRecoveryHolder> {
    if (!tenant) throw new Error("A recovery holder requires an account.");
    const db = await database();
    try {
        const current = await read(db, tenant);
        if (current?.id && current.publicKey && current.privateKey) {
            return { id: current.id, publicKey: current.publicKey };
        }
        const keys = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"]);
        const publicKey = hex(new Uint8Array(await crypto.subtle.exportKey("raw", keys.publicKey)));
        const id = `device-${crypto.randomUUID()}`;
        const holder = { id, publicKey, privateKey: keys.privateKey };
        await write(db, tenant, holder);
        return { id, publicKey };
    } finally {
        db.close();
    }
}

/**
 * Open an existing point wrap locally and immediately create a new opaque wrap
 * for the exact one-time receiving Home. Neither the recovered point key nor
 * the holder's private key is returned from this module.
 */
export async function rewrapBackupPointKey(
    tenant: string,
    pointHandle: string,
    oldWrap: OpaqueBackupWrap,
    receiver: BrowserRecoveryHolder,
): Promise<OpaqueBackupWrap> {
    const holder = await localHolder(tenant);
    if (oldWrap.recipient_id !== holder.id) throw new Error("This device is not the selected recovery holder.");
    const ephemeral = await crypto.subtle.importKey(
        "raw",
        bytesBuffer(fromHex(oldWrap.ephemeral_pubkey)),
        { name: "ECDH", namedCurve: "P-256" },
        false,
        [],
    );
    const shared = await crypto.subtle.deriveBits({ name: "ECDH", public: ephemeral }, holder.privateKey, 256);
    const oldKey = await wrappingKey(shared, tenant, pointHandle, oldWrap.recipient_id);
    const sealed = fromHex(oldWrap.ciphertext);
    if (sealed.byteLength < 13) throw new Error("Backup key material is malformed.");
    const dataKey = await crypto.subtle.decrypt({ name: "AES-GCM", iv: sealed.slice(0, 12) }, oldKey, sealed.slice(12));
    const receiverPublic = await crypto.subtle.importKey(
        "raw",
        bytesBuffer(fromHex(receiver.publicKey)),
        { name: "ECDH", namedCurve: "P-256" },
        false,
        [],
    );
    const ephemeralPair = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"]);
    const receiverShared = await crypto.subtle.deriveBits({ name: "ECDH", public: receiverPublic }, ephemeralPair.privateKey, 256);
    const receiverKey = await wrappingKey(receiverShared, tenant, receiver.id, receiver.id);
    const nonce = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce }, receiverKey, dataKey));
    return {
        recipient_id: receiver.id,
        ephemeral_pubkey: hex(new Uint8Array(await crypto.subtle.exportKey("raw", ephemeralPair.publicKey))),
        ciphertext: hex(new Uint8Array([...nonce, ...ciphertext])),
    };
}
