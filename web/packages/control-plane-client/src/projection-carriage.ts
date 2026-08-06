/**
 * `ProjectionCarriage<T>` — the wrapper every projection travels in on the wire
 * to the mobile (and desktop) client (ADR 0037, spec 015; MOB-007).
 *
 * The core decision: projection uncertainty must be **explicit** (mirrors
 * `gaugedesk_core::freshness`). A projection never travels bare — it carries a
 * `Freshness` marker and the basis (`generatedAt`) the marker was decided
 * against, so the client can never silently render stale state as current. It
 * also carries the optimistic-reconcile correlation id (`clientRequestId`,
 * MOB-003): a projection produced in answer to a specific optimistic command
 * names that command so the client can retire its pending entry.
 *
 * Like the rest of the control-plane edge (`control-plane.ts`), the raw wire
 * shape is parsed here into a branded domain type; UI code consumes the parsed
 * `ProjectionCarriage<T>` and never the raw JSON (`principles.md`, "Contracts at
 * the boundary"; `INV-5`).
 */

declare const brand: unique symbol;
type Brand<T, B> = T & { readonly [brand]: B };

// ----- Optimistic-reconcile correlation id (mirrors core `ClientRequestId`) ---

/** Correlates an optimistic client command with the projection that retires it
 *  (MOB-003 `RunState.pending_commands`). */
export type ClientRequestId = Brand<string, "ClientRequestId">;

export function clientRequestId(raw: string): ClientRequestId {
    if (!raw) throw new Error("empty ClientRequestId");
    return raw as ClientRequestId;
}

// ----- Freshness (mirrors `gaugedesk_core::freshness`, snake_case wire tags) -------

/** How current a projection is, relative to the requested scope's admitted
 *  basis. A consumer must never render anything but `live` as current — every
 *  other marker is an explicit caveat that must surface rather than read as
 *  success (mirrors `FreshnessMarker`, ADR 0037). */
export type FreshnessMarker =
    /** Connected to the current admitted basis for the requested scope. */
    | "live"
    /** Known to be behind, or unable to refresh from its last basis. */
    | "stale"
    /** Intentionally missing material outside the requested/allowed scope. */
    | "partial"
    /** Material exists but is hidden or minimized by policy (`INV-10`). */
    | "redacted"
    /** The authority cannot decide currentness from the available basis. */
    | "indeterminate";

const FRESHNESS_MARKERS: readonly FreshnessMarker[] = [
    "live",
    "stale",
    "partial",
    "redacted",
    "indeterminate",
];

/** Whether a projection carrying this marker may be presented as current truth.
 *  Only `live` may (mirrors `FreshnessMarker::is_current`). */
export function isCurrent(marker: FreshnessMarker): boolean {
    return marker === "live";
}

/** A freshness stamp: the marker plus the basis it was decided against. A
 *  projection is never shown as current without one (mirrors `Freshness`). */
export interface Freshness {
    readonly marker: FreshnessMarker;
    /** The clock value the marker was decided against (the shell supplies it). */
    readonly generatedAt: number;
    /** An optional affordance describing how to refresh a non-live view. */
    readonly repairHint: string | null;
}

// ----- The carriage ----------------------------------------------------------

/** A projection of `T` together with its freshness and optional reconcile id.
 *  Every projection the client renders arrives wrapped in one of these. */
export interface ProjectionCarriage<T> {
    /** The projected value (already parsed into its branded domain type). */
    readonly value: T;
    /** How current `value` is — never render a non-`live` carriage as truth. */
    readonly freshness: Freshness;
    /** The optimistic command this projection answers, if any (MOB-003). */
    readonly clientRequestId: ClientRequestId | null;
}

/** Whether this carriage may be presented as current truth. */
export function carriageIsCurrent<T>(carriage: ProjectionCarriage<T>): boolean {
    return isCurrent(carriage.freshness.marker);
}

// ----- Parse at the transport edge -------------------------------------------

function parseMarker(raw: unknown): FreshnessMarker {
    if (typeof raw === "string" && (FRESHNESS_MARKERS as readonly string[]).includes(raw)) {
        return raw as FreshnessMarker;
    }
    throw new Error(`unknown FreshnessMarker: ${JSON.stringify(raw)}`);
}

function parseFreshness(raw: {
    marker?: unknown;
    generated_at?: unknown;
    repair_hint?: unknown;
}): Freshness {
    if (typeof raw.generated_at !== "number") {
        throw new Error("Freshness missing numeric generated_at");
    }
    const repairHint = raw.repair_hint;
    if (repairHint != null && typeof repairHint !== "string") {
        throw new Error("Freshness repair_hint must be a string or null");
    }
    return {
        marker: parseMarker(raw.marker),
        generatedAt: raw.generated_at,
        repairHint: repairHint == null ? null : repairHint,
    };
}

/** Wire shape of a carriage as emitted by the projection API. The value is
 *  carried opaquely and parsed by the caller-supplied `parseValue`. */
interface RawProjectionCarriage {
    value: unknown;
    freshness: { marker?: unknown; generated_at?: unknown; repair_hint?: unknown };
    client_request_id?: unknown;
}

/** Parse a raw projection-carriage envelope, delegating the inner value to a
 *  caller-supplied parser so each projection keeps its own branded type. */
export function parseProjectionCarriage<T>(
    raw: RawProjectionCarriage,
    parseValue: (value: unknown) => T,
): ProjectionCarriage<T> {
    const rid = raw.client_request_id;
    if (rid != null && typeof rid !== "string") {
        throw new Error("client_request_id must be a string or null");
    }
    return {
        value: parseValue(raw.value),
        freshness: parseFreshness(raw.freshness),
        clientRequestId: rid == null ? null : clientRequestId(rid),
    };
}
