/**
 * Offline projection cache — the client's last-known-good store for projections
 * it has already received, so the carousel can render *something* while offline
 * or between refreshes (`mobile-client.md`, "Offline & freshness"; MOB-017).
 *
 * The doctrine carried from the core (`gaugedesk_core::freshness`, ADR 0037): a
 * cached projection must never silently read as current. A value served from the
 * cache is, by construction, no longer connected to the live admitted basis the
 * moment it is stored — so on **read** the cache *decays* its freshness against
 * the supplied clock: a `live` carriage that has aged past the stale threshold
 * comes back marked `stale`, and one past the hard TTL comes back
 * `indeterminate` (the cache can no longer vouch for its currentness at all). A
 * non-live carriage never decays *upward*; the cache only ever lowers
 * confidence, never raises it. This is the read-side mirror of `is_current`:
 * only a `live` carriage may be presented as truth, and the cache can only mint
 * one by storing it *and* reading it back within the stale window.
 *
 * The store is an injected `CacheStorage` (the `localStorage` shape) so this
 * module stays pure and framework-agnostic (tested without a DOM, like the rest
 * of `state/`); the Solid shell hands it the real `window.localStorage`.
 */

import type { ScopeId } from "@gaugewright/control-plane-client";
import {
    type Freshness,
    type FreshnessMarker,
    type ProjectionCarriage,
    clientRequestId,
} from "@gaugewright/control-plane-client";

// ----- The injected store (the localStorage subset we use) -------------------

/** The slice of the `localStorage` API the cache depends on. Injecting it keeps
 *  the cache pure and testable; the shell supplies `window.localStorage`. */
export interface CacheStorage {
    getItem(key: string): string | null;
    setItem(key: string, value: string): void;
    removeItem(key: string): void;
}

// ----- Decay policy ----------------------------------------------------------

/** How long a `live` cached projection may be read back as `live`, and how long
 *  before it can no longer be vouched for at all. Times share the clock unit the
 *  shell stamps `generatedAt` with (milliseconds in the browser). */
export interface DecayPolicy {
    /** Age (in clock units) past which a `live` carriage decays to `stale`. */
    readonly staleAfter: number;
    /** Age past which a carriage decays to `indeterminate` (no basis to decide). */
    readonly indeterminateAfter: number;
}

/** A conservative default: a cached `live` view is trusted for 30s, then read as
 *  stale, and after 5 minutes the cache can no longer decide its currentness. */
export const DEFAULT_DECAY: DecayPolicy = {
    staleAfter: 30_000,
    indeterminateAfter: 300_000,
};

/**
 * Decay a freshness stamp by its age against `now`. Confidence only ever drops:
 *
 *   - past `indeterminateAfter` → `indeterminate` (oldest wins),
 *   - else past `staleAfter` → `stale`,
 *   - else unchanged.
 *
 * A marker that is already lower-confidence than the age implies is left alone
 * (the cache never raises confidence; `partial`/`redacted` caveats are
 * preserved). A repair hint is added when a previously-live view goes stale so
 * the UI has an affordance to refresh.
 */
export function decayFreshness(
    freshness: Freshness,
    now: number,
    policy: DecayPolicy = DEFAULT_DECAY,
): Freshness {
    const age = now - freshness.generatedAt;
    const decayed = decayMarker(freshness.marker, age, policy);
    if (decayed === freshness.marker) return freshness;
    return {
        marker: decayed,
        generatedAt: freshness.generatedAt,
        repairHint: freshness.repairHint ?? "reconnect to refresh",
    };
}

/** The rank of a marker's confidence — higher is *more* current. The cache only
 *  ever moves a marker to an equal-or-lower rank. */
const MARKER_RANK: Record<FreshnessMarker, number> = {
    live: 4,
    partial: 3,
    redacted: 2,
    stale: 1,
    indeterminate: 0,
};

function decayMarker(
    marker: FreshnessMarker,
    age: number,
    policy: DecayPolicy,
): FreshnessMarker {
    let floor: FreshnessMarker = marker;
    if (age >= policy.indeterminateAfter) floor = "indeterminate";
    else if (age >= policy.staleAfter) floor = "stale";
    // Never raise confidence: keep whichever is *lower* rank (more cautious).
    return MARKER_RANK[floor] < MARKER_RANK[marker] ? floor : marker;
}

// ----- Keying ----------------------------------------------------------------

const KEY_PREFIX = "gaugewright:projection:";

/** The storage key for a `(scope, kind)` projection. Kept stable and namespaced
 *  so cache entries never collide with other client storage. */
export function cacheKey(scope: ScopeId, kind: string): string {
    if (!kind) throw new Error("empty projection kind");
    return `${KEY_PREFIX}${encodeURIComponent(scope)}:${encodeURIComponent(kind)}`;
}

// ----- The serialized record (snake_case wire form, like the carriage edge) --

interface StoredCarriage {
    value: unknown;
    freshness: { marker: FreshnessMarker; generated_at: number; repair_hint: string | null };
    client_request_id: string | null;
}

function toStored<T>(carriage: ProjectionCarriage<T>): StoredCarriage {
    return {
        value: carriage.value,
        freshness: {
            marker: carriage.freshness.marker,
            generated_at: carriage.freshness.generatedAt,
            repair_hint: carriage.freshness.repairHint,
        },
        client_request_id: carriage.clientRequestId == null ? null : String(carriage.clientRequestId),
    };
}

// ----- The cache -------------------------------------------------------------

/**
 * A last-known-good projection store with read-time freshness decay. Pure over
 * its injected `CacheStorage`: the same calls against the same store and clock
 * always produce the same result, so it is unit-tested without a DOM.
 */
export class ProjectionCache {
    constructor(
        private readonly storage: CacheStorage,
        private readonly policy: DecayPolicy = DEFAULT_DECAY,
        private readonly parseValue: (value: unknown) => unknown = (v) => v,
    ) {}

    /** Store the last-known-good carriage for `(scope, kind)`, overwriting any
     *  prior entry. The stamped `generatedAt` is the basis decay reads against. */
    put<T>(scope: ScopeId, kind: string, carriage: ProjectionCarriage<T>): void {
        this.storage.setItem(cacheKey(scope, kind), JSON.stringify(toStored(carriage)));
    }

    /**
     * Read the cached carriage for `(scope, kind)`, decayed against `now`.
     * Returns `null` if nothing is cached or the stored record is unreadable.
     * The returned carriage is never more current than its age allows — a `live`
     * entry read back stale comes back `stale` (the read-side `is_current`
     * guard, MOB-017 / ADR 0037).
     */
    get<T>(scope: ScopeId, kind: string, now: number): ProjectionCarriage<T> | null {
        const raw = this.storage.getItem(cacheKey(scope, kind));
        if (raw == null) return null;
        let stored: StoredCarriage;
        try {
            stored = JSON.parse(raw) as StoredCarriage;
        } catch {
            // A corrupt entry is a cache miss, not a crash; drop it.
            this.storage.removeItem(cacheKey(scope, kind));
            return null;
        }
        const f = stored.freshness;
        const base: Freshness = {
            marker: f.marker,
            generatedAt: f.generated_at,
            repairHint: f.repair_hint,
        };
        return {
            value: this.parseValue(stored.value) as T,
            freshness: decayFreshness(base, now, this.policy),
            clientRequestId:
                stored.client_request_id == null ? null : clientRequestId(stored.client_request_id),
        };
    }

    /** Forget the cached carriage for `(scope, kind)` (e.g. on revocation). */
    evict(scope: ScopeId, kind: string): void {
        this.storage.removeItem(cacheKey(scope, kind));
    }
}
