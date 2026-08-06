/**
 * Device identity, bridge grants, and the client's local pairing state — the
 * client-side mirror of the boundary's `DeviceBinding` phase (D-MOBILE / ADR
 * 0009; MOB-011). These are the *facts the device knows about itself*: which
 * device it is, which grants bind it to which environments, and whether each of
 * those grants is currently usable.
 *
 * The split mirrors the Rust core exactly so the wire round-trips without
 * reinterpretation:
 *
 *   - `DeviceIdentity` is this physical endpoint — a `DeviceId` and the
 *     `PublicKey` device key a bridge call must present (`gaugedesk_core::ids`,
 *     `BridgeGrant.device_key`). The client never holds the *private* key in
 *     this layer; secure storage of the secret is a native concern (MOB-025,
 *     needs-infra), so this type carries only the public handle.
 *   - `BridgeGrant` is the durable governed-route record, a structural mirror of
 *     `gaugedesk_core::bridge_grant::BridgeGrant`. Validity is the *same pure
 *     predicate* (`active && now < expiry`) so the client decides usability the
 *     way the core does — the shell supplies `now`, the type decides
 *     (`is_valid`).
 *   - `LocalState` is the *device's own* paired state: its identity plus the set
 *     of grants it currently holds, keyed by the environment each reaches. It is
 *     the substrate the connection state machine (MOB-018) reduces over —
 *     `unpaired` when no grant binds an environment, `paired`/`revoked`
 *     following the grant's `active` flag and expiry.
 *
 * Like the rest of the transport edge (`control-plane.ts`,
 * `projection-carriage.ts`), the raw wire JSON is parsed here into branded
 * domain types; UI and reducer code consume the parsed shapes and never the raw
 * JSON (`principles.md`, "Contracts at the boundary"; `INV-5`).
 */

import { scopeId, type ScopeId } from "./control-plane-domain";

declare const brand: unique symbol;
type Brand<T, B> = T & { readonly [brand]: B };

// ----- Branded identities (mirror `gaugedesk_core::ids`) -------------------------

/** A paired device — one physical endpoint that presents a device key. Mirrors
 *  `gaugedesk_core::ids::DeviceId`; the stable handle the boundary's `DeviceBinding`
 *  phase records so a revoked device cannot keep delivering. */
export type DeviceId = Brand<string, "DeviceId">;

export function deviceId(raw: string): DeviceId {
    if (!raw) throw new Error("empty DeviceId");
    return raw as DeviceId;
}

/** Stable identifier for a `BridgeGrant`. Mirrors
 *  `gaugedesk_core::ids::BridgeGrantId` — the typed handle a federated delivery
 *  carries so the target binds the crossing to exactly the issued grant. */
export type BridgeGrantId = Brand<string, "BridgeGrantId">;

export function bridgeGrantId(raw: string): BridgeGrantId {
    if (!raw) throw new Error("empty BridgeGrantId");
    return raw as BridgeGrantId;
}

/** A public key in hex form — a root identity key or a device key. Mirrors
 *  `gaugedesk_core::ids::PublicKey`. The client carries only public handles in this
 *  layer; the device *secret* is a native secure-storage concern (MOB-025). */
export type PublicKey = Brand<string, "PublicKey">;

export function publicKey(raw: string): PublicKey {
    if (!raw) throw new Error("empty PublicKey");
    return raw as PublicKey;
}

// ----- Device identity -------------------------------------------------------

/** This physical endpoint: the `DeviceId` the boundary binds grants to, and the
 *  `PublicKey` device key a bridge call presents (`BridgeGrant.device_key`). */
export interface DeviceIdentity {
    readonly id: DeviceId;
    /** The device's public key — must match a grant's `deviceKey` to use it. */
    readonly deviceKey: PublicKey;
}

// ----- Bridge grant (mirror `gaugedesk_core::bridge_grant::BridgeGrant`) ----------

/** A governed bridge grant: source authority → target environment/route, bound
 *  to a device key and a governance scope, with an expiry and an active flag. A
 *  structural mirror of the core record so it round-trips unchanged. */
export interface BridgeGrant {
    readonly id: BridgeGrantId;
    /** The root identity key of the source authority that issued the grant. */
    readonly sourceAuthorityRootPubkey: PublicKey;
    /** Selects which governance subkey of the source authority signed the grant. */
    readonly sourceAuthorityKeyId: string;
    /** The environment the grant authorizes reaching (also exposed as a scope). */
    readonly targetEnvironment: string;
    /** The route within the target environment the grant authorizes. */
    readonly targetRoute: string;
    /** The device key a bridge call must present to use this grant. */
    readonly deviceKey: PublicKey;
    /** The governance scope the grant was issued under. */
    readonly governanceScope: string;
    /** The clock value at and after which the grant is no longer valid. */
    readonly expiry: number;
    /** Whether the grant is currently active (not revoked). */
    readonly active: boolean;
}

/** Whether the grant is usable at `now`: active and not yet expired. The *same*
 *  pure predicate as `BridgeGrant::is_valid` — the shell supplies `now`. */
export function bridgeGrantIsValid(grant: BridgeGrant, now: number): boolean {
    return grant.active && now < grant.expiry;
}

/** Whether `identity` may present `grant`: the grant's bound device key must be
 *  exactly this device's key (`BridgeGrant.device_key`). A grant for another
 *  device is unusable here even when otherwise valid. */
export function bridgeGrantBindsDevice(
    grant: BridgeGrant,
    identity: DeviceIdentity,
): boolean {
    return grant.deviceKey === identity.deviceKey;
}

/** The target environment of a grant as a `ScopeId` — what downstream gates and
 *  projections key on (mirrors `DeepLink.scope`). */
export function bridgeGrantScope(grant: BridgeGrant): ScopeId {
    return scopeId(grant.targetEnvironment);
}

// ----- Local pairing state ---------------------------------------------------

/** The device's own paired state: its identity plus the grants it currently
 *  holds. This is the substrate the connection state machine (MOB-018) reduces
 *  over — there is no environment connection without a grant binding it. */
export interface LocalState {
    /** Who this device is — the identity every held grant must bind to. */
    readonly identity: DeviceIdentity;
    /** The grants this device holds, in arrival order. */
    readonly grants: readonly BridgeGrant[];
}

/** The grant (if any) this device holds for `environment` that is bound to this
 *  device and usable at `now`. Returns `null` when unpaired, revoked, expired,
 *  or bound to a different device — every not-usable case collapses to "no
 *  active bridge", which the connection reducer reads as not-connected. */
export function activeGrantFor(
    state: LocalState,
    environment: string,
    now: number,
): BridgeGrant | null {
    for (const grant of state.grants) {
        if (
            grant.targetEnvironment === environment &&
            bridgeGrantBindsDevice(grant, state.identity) &&
            bridgeGrantIsValid(grant, now)
        ) {
            return grant;
        }
    }
    return null;
}

// ----- Parse at the transport edge -------------------------------------------

function asString(raw: unknown, field: string): string {
    if (typeof raw !== "string") {
        throw new Error(`${field} must be a string`);
    }
    return raw;
}

/** Parse a wire device-identity envelope (snake_case) into the branded type. */
export function parseDeviceIdentity(raw: {
    id?: unknown;
    device_key?: unknown;
}): DeviceIdentity {
    return {
        id: deviceId(asString(raw.id, "DeviceIdentity.id")),
        deviceKey: publicKey(asString(raw.device_key, "DeviceIdentity.device_key")),
    };
}

/** Wire shape of a bridge grant as emitted by the boundary (snake_case, mirrors
 *  the CBOR `BridgeGrant` field names). */
interface RawBridgeGrant {
    id?: unknown;
    source_authority_root_pubkey?: unknown;
    source_authority_key_id?: unknown;
    target_environment?: unknown;
    target_route?: unknown;
    device_key?: unknown;
    governance_scope?: unknown;
    expiry?: unknown;
    active?: unknown;
}

/** Parse a wire bridge-grant envelope into the branded domain type. */
export function parseBridgeGrant(raw: RawBridgeGrant): BridgeGrant {
    if (typeof raw.expiry !== "number") {
        throw new Error("BridgeGrant.expiry must be a number");
    }
    if (typeof raw.active !== "boolean") {
        throw new Error("BridgeGrant.active must be a boolean");
    }
    return {
        id: bridgeGrantId(asString(raw.id, "BridgeGrant.id")),
        sourceAuthorityRootPubkey: publicKey(
            asString(raw.source_authority_root_pubkey, "BridgeGrant.source_authority_root_pubkey"),
        ),
        sourceAuthorityKeyId: asString(
            raw.source_authority_key_id,
            "BridgeGrant.source_authority_key_id",
        ),
        targetEnvironment: asString(raw.target_environment, "BridgeGrant.target_environment"),
        targetRoute: asString(raw.target_route, "BridgeGrant.target_route"),
        deviceKey: publicKey(asString(raw.device_key, "BridgeGrant.device_key")),
        governanceScope: asString(raw.governance_scope, "BridgeGrant.governance_scope"),
        expiry: raw.expiry,
        active: raw.active,
    };
}

/** Parse a wire local-state envelope (identity + grants) into the branded type. */
export function parseLocalState(raw: {
    identity?: { id?: unknown; device_key?: unknown };
    grants?: unknown;
}): LocalState {
    if (raw.identity == null) {
        throw new Error("LocalState missing identity");
    }
    const grants = raw.grants ?? [];
    if (!Array.isArray(grants)) {
        throw new Error("LocalState.grants must be an array");
    }
    return {
        identity: parseDeviceIdentity(raw.identity),
        grants: grants.map((g) => parseBridgeGrant(g as RawBridgeGrant)),
    };
}
