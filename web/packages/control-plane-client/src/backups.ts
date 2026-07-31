import type { RouteJson } from "./control-plane-transport";

export interface BackupCiphertext { readonly bytes: readonly number[]; }
export interface BackupKeyWrap { readonly recipient_id: string; readonly ephemeral_pubkey: string; readonly ciphertext: string; }
export interface RestoreMaterial { readonly ciphertext: BackupCiphertext; readonly wrap: BackupKeyWrap; }

function path(tenant: string, suffix = ""): string {
    return `/account/tenants/${encodeURIComponent(tenant)}/backups${suffix}`;
}

function object(value: unknown, message: string): Record<string, unknown> {
    if (!value || typeof value !== "object") throw new Error(message);
    return value as Record<string, unknown>;
}

/** Read-only recovery-holder seam. Backup configuration and restore admission
 * are Administration commands; a holder may only fetch sealed material for a
 * local rewrap, and this response never contains the private key. */
export async function restoreMaterial(
    json: RouteJson,
    tenant: string,
    pointHandle: string,
    recipientId: string,
): Promise<RestoreMaterial> {
    const row = object(
        await json("GET", path(tenant, `/points/${encodeURIComponent(pointHandle)}/restore-material/${encodeURIComponent(recipientId)}`)),
        "Restore material response is malformed",
    );
    const ciphertext = object(row.ciphertext, "Restore material response is malformed");
    const wrap = object(row.wrap, "Restore material response is malformed");
    if (
        !Array.isArray(ciphertext.bytes)
        || !ciphertext.bytes.every((byte) => typeof byte === "number" && Number.isInteger(byte) && byte >= 0 && byte <= 255)
        || typeof wrap.recipient_id !== "string"
        || typeof wrap.ephemeral_pubkey !== "string"
        || typeof wrap.ciphertext !== "string"
    ) throw new Error("Restore material response is malformed");
    return {
        ciphertext: { bytes: ciphertext.bytes as number[] },
        wrap: {
            recipient_id: wrap.recipient_id,
            ephemeral_pubkey: wrap.ephemeral_pubkey,
            ciphertext: wrap.ciphertext,
        },
    };
}
