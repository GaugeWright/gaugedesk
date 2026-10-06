import type { WorkbenchTransport } from "./control-plane-workbench";

/** One project key a piece of background work holds, in words a member reads. */
export interface DelegatedKey {
    readonly scope: string;
    readonly label: string;
}

/** What background work holds which of a project's keys (DR-0312): granted
 *  from whose work, until when, and every step it took with nobody present.
 *  `held` work has its keys; `lapsed` work is paused because nobody used the
 *  project for 30 days, and resumes when a member does; `ended` work holds
 *  nothing. */
export interface KeyDelegationView {
    readonly id: string;
    readonly state: "held" | "lapsed" | "ended";
    readonly work: { readonly kind: "workflow"; readonly path: string; readonly targetName: string | null };
    readonly keys: readonly DelegatedKey[];
    readonly grantedFrom: string;
    readonly grantedAtMs: number;
    /** `held`: when it lapses unless a member uses the project first. */
    readonly expiresAtMs: number | null;
    /** `lapsed`: when it lapsed. */
    readonly lapsedSinceMs: number | null;
    readonly ended: { readonly atMs: number; readonly outcome: string } | null;
    readonly useCount: number;
    /** Newest first, at most the latest twenty. */
    readonly uses: readonly { readonly atMs: number; readonly effect: string }[];
    readonly refusals: readonly { readonly atMs: number; readonly label: string }[];
}

export interface ProjectKeyDelegations {
    readonly project: string;
    readonly lapseAfterMs: number;
    readonly lastMemberUseMs: number | null;
    /** Held or paused work, newest first. */
    readonly delegations: readonly KeyDelegationView[];
    /** Work that has finished, newest first. */
    readonly ended: readonly KeyDelegationView[];
}

function record(value: unknown, what: string): Record<string, unknown> {
    if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(`Invalid ${what}`);
    return value as Record<string, unknown>;
}
function text(value: unknown, what: string): string {
    if (typeof value !== "string") throw new Error(`Invalid ${what}`);
    return value;
}
function time(value: unknown, what: string): number {
    if (typeof value !== "number" || !Number.isFinite(value)) throw new Error(`Invalid ${what}`);
    return value;
}
function optionalTime(value: unknown, what: string): number | null {
    return value === null || value === undefined ? null : time(value, what);
}
function list(value: unknown, what: string): unknown[] {
    if (!Array.isArray(value)) throw new Error(`Invalid ${what}`);
    return value;
}

function delegation(raw: unknown): KeyDelegationView {
    const d = record(raw, "delegation");
    const state = d.state;
    if (state !== "held" && state !== "lapsed" && state !== "ended") throw new Error("Invalid delegation state");
    const work = record(d.work, "delegated work");
    if (work.kind !== "workflow") throw new Error("Invalid delegated work");
    const ended = d.ended === undefined || d.ended === null ? null : record(d.ended, "ending");
    return {
        id: text(d.id, "delegation id"),
        state,
        work: {
            kind: "workflow",
            path: text(work.path, "workflow path"),
            targetName: typeof work.target_name === "string" ? work.target_name : null,
        },
        keys: list(d.keys, "delegated keys").map((raw) => {
            const key = record(raw, "delegated key");
            return { scope: text(key.scope, "key scope"), label: text(key.label, "key label") };
        }),
        grantedFrom: text(d.granted_from, "grantor"),
        grantedAtMs: time(d.granted_at_ms, "grant time"),
        expiresAtMs: optionalTime(d.expires_at_ms, "expiry"),
        lapsedSinceMs: optionalTime(d.lapsed_since_ms, "lapse"),
        ended: ended ? { atMs: time(ended.at_ms, "end time"), outcome: text(ended.outcome, "outcome") } : null,
        useCount: time(d.use_count, "use count"),
        uses: list(d.uses, "uses").map((raw) => {
            const use = record(raw, "use");
            return { atMs: time(use.at_ms, "use time"), effect: text(use.effect, "effect") };
        }),
        refusals: list(d.refusals, "refusals").map((raw) => {
            const refusal = record(raw, "refusal");
            return { atMs: time(refusal.at_ms, "refusal time"), label: text(refusal.label, "refused key") };
        }),
    };
}

/** `GET /projects/:project/key-delegations`, read at the project's Home. Any
 *  member may read it, and reading it is itself a member using the project,
 *  which renews any background work that had lapsed. */
export async function getProjectKeyDelegations(transport: WorkbenchTransport, project: string): Promise<ProjectKeyDelegations> {
    const raw = record(
        await transport.json("GET", `/projects/${encodeURIComponent(project)}/key-delegations`),
        "key delegation record",
    );
    if (raw.project !== project) throw new Error("Key delegation record names another project");
    return {
        project,
        lapseAfterMs: time(raw.lapse_after_ms, "lapse window"),
        lastMemberUseMs: optionalTime(raw.last_member_use_ms, "last member use"),
        delegations: list(raw.delegations, "delegations").map(delegation),
        ended: list(raw.ended, "ended delegations").map(delegation),
    };
}
