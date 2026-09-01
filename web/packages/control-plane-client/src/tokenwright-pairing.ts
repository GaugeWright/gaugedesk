/**
 * Connecting to a TokenWright box: the first time, and every time after.
 *
 * A box is not a Home and GaugeDesk does not run its control plane (ADR 0158).
 * All GaugeDesk holds is a way to reach it and a key to use it, and both arrive
 * through one bootstrap: the operator copies a pairing string off the box's
 * console and pastes it here.
 *
 * The two halves of the journey use *different* rendezvous addresses, and that
 * is the part worth being careful about:
 *
 * - **Claiming** dials a handle derived from the claim code, so finding the box
 *   and guessing the code are the same problem. The code is single-use and
 *   expires in fifteen minutes.
 * - **Every reconnect after that** dials a route the box minted at claim and
 *   returned in the claim response. Nothing derives it and nothing can recover
 *   it: it is sent once, over the pinned channel, and a client that loses it has
 *   lost the box until someone unpairs it with physical access.
 *
 * So `claim` returns a record that must be *persisted before it is used*, and
 * everything in it — the route especially — is a capability, not a name.
 */

import type { OpaqueRelayLocator } from "./home-routing";

/**
 * The alphabet a claim code is printed in: Crockford-style with the characters
 * that are misread or misheard removed. Kept in step with the box's own
 * `pairing.ALPHABET` — the code is normalised into this set before hashing, so
 * a disagreement here is a proof neither side can explain.
 */
const CODE_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/** Domain separators. Each derivation from the claim code is distinct, so the
 * relay seeing a handle learns nothing that would let it claim the box. */
const HANDLE_DOMAIN = "tokenwright/relay-handle/v1";
const CLAIM_PROOF_DOMAIN = "tokenwright/claim-proof/v1";
/** The relay's own proof domain, from `relay-transport`'s wire format. The
 * trailing NUL is part of it. */
const RELAY_PROOF_DOMAIN = "gaugewright-relay-proof-v1\0";

const INVITE_PREFIX = "tw1_";

/** What a pairing string carries. Three things, because a tunnel needs all
 * three: somewhere to rendezvous, a certificate to trust, and proof you may
 * take the box. */
export interface TokenWrightInvite {
    readonly relayEndpoint: string;
    readonly claimCode: string;
    /** `sha256:<64 hex>`, the spelling the box's documents use. */
    readonly fingerprint: string;
}

/**
 * Everything needed to reach a claimed box again, and nothing that can be
 * derived from anything else.
 *
 * Persist this whole record. `route` is the only copy that will ever exist.
 */
export interface TokenWrightConnection {
    readonly relayEndpoint: string;
    /** Base64url of the 32-byte rendezvous token the box parks on. */
    readonly route: string;
    readonly fingerprint: string;
    /** The key the box minted for this Home. Bearer credential. */
    readonly key: string;
    readonly keyId: string;
    readonly homeId: string;
    readonly pairedAt: string;
}

function fail(message: string): never {
    throw new Error(message);
}

function decodeBase64Url(value: string): Uint8Array {
    // The alphabet is checked before decoding. `atob` after a `-_` → `+/`
    // translation would also accept `+` and `/`, which are a second spelling of
    // bytes that have only one on the wire — and the relay matches legs by
    // comparing handle strings, not bytes.
    if (!value || /[^A-Za-z0-9\-_]/.test(value)) fail("not base64url");
    const padded = value.replace(/-/g, "+").replace(/_/g, "/")
        + "=".repeat((4 - (value.length % 4)) % 4);
    const binary = atob(padded);
    const bytes = new Uint8Array(binary.length);
    for (let index = 0; index < binary.length; index += 1) {
        bytes[index] = binary.charCodeAt(index);
    }
    return bytes;
}

function encodeBase64Url(bytes: Uint8Array): string {
    let binary = "";
    for (const byte of bytes) binary += String.fromCharCode(byte);
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function toHex(bytes: Uint8Array): string {
    return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function concat(prefix: string, rest: Uint8Array): Uint8Array {
    const head = new TextEncoder().encode(prefix);
    const joined = new Uint8Array(head.length + rest.length);
    joined.set(head, 0);
    joined.set(rest, head.length);
    return joined;
}

async function sha256(input: Uint8Array): Promise<Uint8Array> {
    // A fresh copy, because `digest` wants an ArrayBuffer and a subarray view
    // would hand it the whole backing store.
    const digest = await crypto.subtle.digest("SHA-256", input.slice().buffer as ArrayBuffer);
    return new Uint8Array(digest);
}

/** One spelling of a code. The person reading it aloud is not the one hashing
 * it, so case and the printed hyphens must not change a derivation. */
export function normalizeClaimCode(code: string): string {
    return Array.from((code ?? "").toUpperCase())
        .filter((character) => CODE_ALPHABET.includes(character))
        .join("");
}

/**
 * Read a pairing string, or say which part of it is wrong.
 *
 * Every failure here is someone having mistyped or half-copied something, so
 * each names the thing to look at. None of them echo the token: it contains a
 * live claim code, and a message quoting it lands in whatever log the caller
 * happens to write.
 */
export function parseTokenWrightInvite(token: string): TokenWrightInvite {
    const trimmed = (token ?? "").trim();
    if (!trimmed) fail("Paste the pairing string printed on the box.");
    if (!trimmed.startsWith(INVITE_PREFIX)) {
        fail(`That is not a TokenWright pairing string — they begin with "${INVITE_PREFIX}".`);
    }
    let payload: Record<string, unknown>;
    try {
        payload = JSON.parse(new TextDecoder().decode(
            decodeBase64Url(trimmed.slice(INVITE_PREFIX.length)),
        )) as Record<string, unknown>;
    } catch {
        fail("That pairing string is damaged; copy the whole line from the box.");
    }
    if (typeof payload !== "object" || payload === null) {
        fail("That pairing string is damaged; copy the whole line from the box.");
    }
    if (payload.v !== 1) {
        fail(`That pairing string is version ${String(payload.v)}, which this version of GaugeDesk does not read.`);
    }
    const relayEndpoint = payload.r;
    const claimCode = payload.c;
    const fingerprint = payload.f;
    if (typeof relayEndpoint !== "string" || !relayEndpoint) fail("That pairing string carries no relay endpoint.");
    if (typeof claimCode !== "string" || !claimCode) fail("That pairing string carries no claim code.");
    if (typeof fingerprint !== "string" || !/^sha256:[0-9a-f]{64}$/.test(fingerprint)) {
        // Its own message: without a pin there is no handshake to attempt, and
        // "connection failed" would send someone to look at the network.
        fail("The certificate fingerprint in that pairing string is not a SHA-256 digest.");
    }
    if (!normalizeClaimCode(claimCode)) fail("That pairing string carries no claim code.");
    return { relayEndpoint, claimCode, fingerprint };
}

/** The 32-byte rendezvous token an unclaimed box parks on. */
export async function claimRouteToken(claimCode: string): Promise<Uint8Array> {
    const normalized = normalizeClaimCode(claimCode);
    if (!normalized) fail("That claim code is empty.");
    return sha256(concat(HANDLE_DOMAIN, new TextEncoder().encode(normalized)));
}

/** What the box compares, in constant time, before it will admit a claim.
 * A separate derivation from the handle: the relay sees the handle, so a proof
 * derivable from it would let the relay claim every box it carries. */
export async function claimProof(claimCode: string): Promise<string> {
    const normalized = normalizeClaimCode(claimCode);
    if (!normalized) fail("That claim code is empty.");
    return toHex(await sha256(concat(CLAIM_PROOF_DOMAIN, new TextEncoder().encode(normalized))));
}

/** Build the relay locator for a rendezvous token, claim-time or durable. */
export async function tokenwrightLocator(input: {
    readonly relayEndpoint: string;
    readonly token: Uint8Array;
    readonly fingerprint: string;
    readonly routeEpoch?: number;
}): Promise<OpaqueRelayLocator> {
    if (input.token.length !== 32) {
        fail(`a relay token is 32 bytes, not ${input.token.length}`);
    }
    return {
        endpoint: input.relayEndpoint,
        handle: encodeBase64Url(input.token),
        proof: encodeBase64Url(await sha256(concat(RELAY_PROOF_DOMAIN, input.token))),
        routeEpoch: input.routeEpoch ?? 1,
        // The wasm tunnel compares against a certificate's DER, so it wants the
        // bare hex rather than the `sha256:` spelling the documents carry.
        homeFingerprint: input.fingerprint.replace(/^sha256:/, ""),
    };
}

/** Where to dial to claim a box that has never been claimed. */
export async function claimLocator(invite: TokenWrightInvite): Promise<OpaqueRelayLocator> {
    return tokenwrightLocator({
        relayEndpoint: invite.relayEndpoint,
        token: await claimRouteToken(invite.claimCode),
        fingerprint: invite.fingerprint,
    });
}

/** Where to dial to reach a box already claimed. */
export async function connectionLocator(
    connection: TokenWrightConnection,
): Promise<OpaqueRelayLocator> {
    return tokenwrightLocator({
        relayEndpoint: connection.relayEndpoint,
        token: decodeBase64Url(connection.route),
        fingerprint: connection.fingerprint,
    });
}

/**
 * Claim the box, and return what must be stored to reach it again.
 *
 * `json` is a route already opened against the claim locator — this function
 * does not open one, because who owns the socket and when it is closed differs
 * between the workbench and a test, and a helper that opened its own would leave
 * a leg spliced to a caller that has gone.
 *
 * `presentedFingerprint` is what the transport actually pinned. It is compared
 * against what the box says about itself: they come from different layers, and
 * a box whose body disagrees with its own certificate is not one to keep talking
 * to.
 */
export async function claimTokenWrightBox(input: {
    readonly json: (method: string, path: string, body?: unknown) => Promise<unknown>;
    readonly invite: TokenWrightInvite;
    readonly homeId: string;
    readonly homeKey: string;
    readonly presentedFingerprint?: string;
}): Promise<TokenWrightConnection> {
    const proof = await claimProof(input.invite.claimCode);
    const answer = (await input.json("POST", "/pair/claim", {
        proof,
        home: { id: input.homeId, key: input.homeKey },
    })) as { paired?: Record<string, unknown>; key?: Record<string, unknown> };

    const paired = answer?.paired;
    const key = answer?.key;
    if (!paired || !key) fail("The box did not answer the claim.");

    const fingerprint = paired.fingerprint;
    const route = paired.route;
    const secret = key.secret;
    const keyId = key.id;

    if (typeof fingerprint !== "string" || fingerprint !== input.invite.fingerprint) {
        fail("The box reported a different certificate than the pairing string named.");
    }
    if (input.presentedFingerprint !== undefined && input.presentedFingerprint !== fingerprint) {
        // Different layers: one is a claim in a JSON body, the other is the
        // certificate the TLS handshake actually verified. Agreement is the
        // whole point of pinning, so disagreement ends the conversation.
        fail("The box's certificate does not match the one it reports.");
    }
    if (typeof route !== "string" || !route) {
        // Old boxes derived their durable route instead of sending it, which
        // meant no client could compute it. Say so, rather than storing a
        // connection that will fail silently at the box's next restart.
        fail("This box did not hand over a route to reach it again; it needs a newer TokenWright.");
    }
    if (decodeBase64Url(route).length !== 32) fail("The box returned a malformed route.");
    if (typeof secret !== "string" || !secret) fail("The box did not return a key.");

    return {
        relayEndpoint: input.invite.relayEndpoint,
        route,
        fingerprint,
        key: secret,
        keyId: typeof keyId === "string" ? keyId : "",
        homeId: input.homeId,
        pairedAt: typeof paired.paired_at === "string" ? paired.paired_at : "",
    };
}
