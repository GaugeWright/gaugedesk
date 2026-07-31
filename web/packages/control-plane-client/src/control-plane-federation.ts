import type { ProjectId } from "./control-plane-domain";
import type { RouteJson } from "./control-plane-transport";
import {
    localDeploymentPlacement,
    parseDeploymentPlacement,
    type DeploymentPlacement,
} from "./placement-policy";

/** A pairing ticket: everything a peer needs to reach + trust this authority. */
export interface PairingTicket {
    readonly authority: string;
    readonly governance_pubkey: string;
    readonly cert_fingerprint: string;
    readonly broker_addr: string;
    readonly scope: string;
    readonly expiry: number;
}
/** A paired peer as `GET /federation/peers` projects it. */
export interface FederationPeer {
    readonly authority: string;
    readonly governance_pubkey: string;
    readonly cert_fingerprint: string;
    readonly grant_id: string;
    readonly broker_addr: string;
    readonly active: boolean;
}
/** The handoff projection: a project's relocation phase + which authority is home.
 *  `project` is the same branded `ProjectId` the command side takes — opaque
 *  foreign tokens (`source`/`authority`/`peer`/`correlation`) stay plain `string`. */
export type HandoffPhase = "draft" | "offered" | "log_synced" | "committed" | "aborted";
export interface HandoffStatus {
    readonly project: ProjectId;
    readonly phase: HandoffPhase;
    /** Which side currently holds the project's home. A single union (not the wire's
     *  two `home_origin`/`home_target` bools) so the illegal both/neither states are
     *  unrepresentable — the reducer guarantees exactly one home (`INV-1`). */
    readonly home: "origin" | "target";
    readonly targetHasLog: boolean;
}
/** A pending incoming handoff awaiting this authority's consent. */
export interface IncomingHandoff {
    readonly project: ProjectId;
    readonly source: string;
    readonly deployment: DeploymentPlacement;
}
/** The result of an operator placing a co-drive run (FED-7). */
export interface PlacedRun {
    readonly status: "admitted" | "pending" | "refused";
    readonly correlation: string;
    readonly observations_admitted?: number;
    readonly assistant_text?: string;
    readonly reason?: string;
}
/** The operator's local projection of a placed run's result (FED-7 Allow once). */
export interface RunResult {
    readonly correlation: string;
    readonly status: "pending" | "done";
    readonly observations_admitted?: number;
    readonly assistant_text?: string;
}
/** A run in the host's admission queue (handles + correlation only, INV-10). */
export interface QueuedRun {
    readonly correlation: string;
    readonly operator: string;
    readonly project: ProjectId;
    readonly archetype: string;
    readonly data_handle: string;
    readonly prompt: string;
    readonly target_chat?: string;
}
/** A minted combined engagement invite (FED-7 Slice 2): the deep link + confirm code. */
export interface EngagementInvite {
    readonly invite_id: string;
    readonly invite_url: string;
    readonly confirm_code: string;
    readonly project: ProjectId;
    readonly deployment: DeploymentPlacement;
}
/** The origin's pending-invite status (poll while waiting for the client to accept). */
export interface InviteStatus {
    readonly invite_id: string;
    readonly pending: boolean;
    readonly accepted: boolean;
    readonly accepted_by: string | null;
    readonly confirm_code: string;
}
/** The target's result of accepting a combined invite. */
export interface InviteAcceptResult {
    readonly ok: boolean;
    readonly project?: string;
    readonly project_name?: string;
    readonly origin?: string;
    readonly confirm_code?: string;
    readonly reason?: string;
}
/** A project participant: host (owns data) or operator (owns archetypes), revocable. */
export interface Participant {
    readonly authority: string;
    readonly role: string;
    readonly owns: string;
    readonly revoked: boolean;
}
/** A host-owned data handle connected to a project (handle + label only, INV-10). */
export interface ConnectedData {
    readonly handle: string;
    readonly label?: string;
}

// ----- Federation projection parsers (parse-and-brand at the edge, INV-5) -----
//
// The FED-6/FED-7 surface folds untrusted cross-authority JSON. Like every other
// projection, it is validated here, never cast: a malformed, absent, or renamed
// field throws at the transport edge instead of mis-rendering in the UI.

function fedObj(raw: unknown): Record<string, unknown> {
    if (raw === null || typeof raw !== "object") {
        throw new Error(`federation: expected object, got ${raw === null ? "null" : typeof raw}`);
    }
    return raw as Record<string, unknown>;
}
function fStr(o: Record<string, unknown>, k: string): string {
    const v = o[k];
    if (typeof v !== "string") throw new Error(`federation field ${k}: expected string`);
    return v;
}
function fOptStr(o: Record<string, unknown>, k: string): string | undefined {
    const v = o[k];
    if (v == null) return undefined;
    if (typeof v !== "string") throw new Error(`federation field ${k}: expected string`);
    return v;
}
function fBool(o: Record<string, unknown>, k: string): boolean {
    const v = o[k];
    if (typeof v !== "boolean") throw new Error(`federation field ${k}: expected boolean`);
    return v;
}
function fOptNum(o: Record<string, unknown>, k: string): number | undefined {
    const v = o[k];
    if (v == null) return undefined;
    if (typeof v !== "number") throw new Error(`federation field ${k}: expected number`);
    return v;
}
function fArr(o: Record<string, unknown>, k: string): unknown[] {
    const v = o[k];
    return Array.isArray(v) ? v : [];
}

const HANDOFF_PHASES: readonly HandoffPhase[] = ["draft", "offered", "log_synced", "committed", "aborted"];
function parseHandoffPhase(v: unknown): HandoffPhase {
    if (typeof v === "string" && (HANDOFF_PHASES as readonly string[]).includes(v)) return v as HandoffPhase;
    throw new Error(`bad handoff phase: ${JSON.stringify(v)}`);
}
function parsePlacedRunStatus(v: unknown): PlacedRun["status"] {
    if (v === "admitted" || v === "pending" || v === "refused") return v;
    throw new Error(`bad placed-run status: ${JSON.stringify(v)}`);
}
function parseRunResultStatus(v: unknown): RunResult["status"] {
    if (v === "pending" || v === "done") return v;
    throw new Error(`bad run-result status: ${JSON.stringify(v)}`);
}

function parsePairingTicket(raw: unknown): PairingTicket {
    const o = fedObj(raw);
    return {
        authority: fStr(o, "authority"),
        governance_pubkey: fStr(o, "governance_pubkey"),
        cert_fingerprint: fStr(o, "cert_fingerprint"),
        broker_addr: fStr(o, "broker_addr"),
        scope: fStr(o, "scope"),
        expiry: fOptNum(o, "expiry") ?? 0,
    };
}
function parseFederationPeer(raw: unknown): FederationPeer {
    const o = fedObj(raw);
    return {
        authority: fStr(o, "authority"),
        governance_pubkey: fStr(o, "governance_pubkey"),
        cert_fingerprint: fStr(o, "cert_fingerprint"),
        grant_id: fStr(o, "grant_id"),
        broker_addr: fStr(o, "broker_addr"),
        active: fBool(o, "active"),
    };
}
function parseHandoffStatus(raw: unknown): HandoffStatus {
    const o = fedObj(raw);
    return {
        project: fStr(o, "project") as ProjectId,
        phase: parseHandoffPhase(o.phase),
        // Derive the single home side from the wire's two flags, so the illegal
        // both/neither states are unrepresentable in the client type.
        home: fBool(o, "home_target") ? "target" : "origin",
        targetHasLog: fBool(o, "target_has_log"),
    };
}
function parseIncomingHandoff(raw: unknown): IncomingHandoff {
    const o = fedObj(raw);
    return {
        project: fStr(o, "project") as ProjectId,
        source: fStr(o, "source"),
        deployment: o.deployment_mode == null
            ? localDeploymentPlacement
            : parseDeploymentPlacement(o.deployment_mode),
    };
}
function parsePlacedRun(raw: unknown): PlacedRun {
    const o = fedObj(raw);
    return {
        status: parsePlacedRunStatus(o.status),
        correlation: fStr(o, "correlation"),
        observations_admitted: fOptNum(o, "observations_admitted"),
        assistant_text: fOptStr(o, "assistant_text"),
        reason: fOptStr(o, "reason"),
    };
}
function parseRunResult(raw: unknown): RunResult {
    const o = fedObj(raw);
    return {
        correlation: fStr(o, "correlation"),
        status: parseRunResultStatus(o.status),
        observations_admitted: fOptNum(o, "observations_admitted"),
        assistant_text: fOptStr(o, "assistant_text"),
    };
}
function parseQueuedRun(raw: unknown): QueuedRun {
    const o = fedObj(raw);
    return {
        correlation: fStr(o, "correlation"),
        operator: fStr(o, "operator"),
        project: fStr(o, "project") as ProjectId,
        archetype: fStr(o, "archetype"),
        data_handle: fStr(o, "data_handle"),
        prompt: fStr(o, "prompt"),
        target_chat: fOptStr(o, "target_chat"),
    };
}
function parseEngagementInvite(raw: unknown): EngagementInvite {
    const o = fedObj(raw);
    return {
        invite_id: fStr(o, "invite_id"),
        invite_url: fStr(o, "invite_url"),
        confirm_code: fStr(o, "confirm_code"),
        project: fStr(o, "project") as ProjectId,
        deployment: o.deployment_mode == null
            ? localDeploymentPlacement
            : parseDeploymentPlacement(o.deployment_mode),
    };
}
function parseInviteStatus(raw: unknown): InviteStatus {
    const o = fedObj(raw);
    return {
        invite_id: fStr(o, "invite_id"),
        pending: fBool(o, "pending"),
        accepted: fBool(o, "accepted"),
        accepted_by: o.accepted_by == null ? null : fStr(o, "accepted_by"),
        confirm_code: fStr(o, "confirm_code"),
    };
}
function parseInviteAcceptResult(raw: unknown): InviteAcceptResult {
    const o = fedObj(raw);
    return {
        ok: fBool(o, "ok"),
        project: fOptStr(o, "project"),
        project_name: fOptStr(o, "project_name"),
        origin: fOptStr(o, "origin"),
        confirm_code: fOptStr(o, "confirm_code"),
        reason: fOptStr(o, "reason"),
    };
}
function parseParticipant(raw: unknown): Participant {
    const o = fedObj(raw);
    return {
        authority: fStr(o, "authority"),
        role: fStr(o, "role"),
        owns: fStr(o, "owns"),
        revoked: fBool(o, "revoked"),
    };
}
function parseConnectedData(raw: unknown): ConnectedData {
    const o = fedObj(raw);
    return { handle: fStr(o, "handle"), label: fOptStr(o, "label") };
}

/** Mint a pairing ticket describing this authority (governance key + TLS cert
 *  fingerprint + broker) — handed out-of-band to a peer to pair (TOFU). */
export async function mintPairingTicket(json: RouteJson): Promise<PairingTicket> {
    return parsePairingTicket(await json("POST", "/federation/pairing-ticket", {}));
}

/** Accept a peer's ticket: pin its key + cert and start listening for it. */
export async function pair(json: RouteJson, ticket: PairingTicket): Promise<FederationPeer> {
    return parseFederationPeer(await json("POST", "/federation/pair", ticket));
}

/** The peers this authority has paired with. */
export async function listPeers(json: RouteJson): Promise<FederationPeer[]> {
    const o = fedObj(await json("GET", "/federation/peers"));
    return fArr(o, "peers").map(parseFederationPeer);
}

/** Revoke one paired authority. The durable roster keeps its inactive audit
 *  record, while its grant and transport pin stop authorizing future work. */
export async function revokePeer(json: RouteJson, authority: string): Promise<void> {
    await json("DELETE", `/federation/peers/${encodeURIComponent(authority)}`);
}

/** Abort an in-flight handoff; home rolls back to the origin. */
export async function handoffAbort(json: RouteJson, project: ProjectId): Promise<HandoffStatus> {
    return parseHandoffStatus(await json("POST", "/federation/handoff/abort", { project }));
}

/** The handoff projection for a project: phase + which authority is home. */
export async function handoffStatus(json: RouteJson, project: ProjectId): Promise<HandoffStatus> {
    return parseHandoffStatus(
        await json("GET", `/federation/handoff/status?project=${encodeURIComponent(project)}`),
    );
}

/** Relocate a project's home to a paired peer over the wire. */
export async function handoffRelocate(
    json: RouteJson,
    project: ProjectId,
    peer: string,
): Promise<HandoffStatus> {
    return parseHandoffStatus(
        await json("POST", "/federation/handoff/relocate", { project, peer }),
    );
}

/** Co-drive: the operator places a project-scoped run on the host (FED-7). */
export async function placeRun(
    json: RouteJson,
    peer: string,
    project: ProjectId,
    archetype: string,
    dataHandle: string,
    prompt: string,
    targetChat?: string,
): Promise<PlacedRun> {
    return parsePlacedRun(
        await json("POST", "/federation/run/place", {
            peer,
            project,
            archetype,
            data_handle: dataHandle,
            prompt,
            target_chat: targetChat,
        }),
    );
}

/** The host's admission queue: operator runs awaiting a decision. */
export async function runQueue(json: RouteJson): Promise<QueuedRun[]> {
    const r = fedObj(await json("GET", "/federation/run/queue"));
    return fArr(r, "queue").map(parseQueuedRun);
}

/** The host sets/revokes a standing per-project allow for an operator. */
export async function allowRuns(
    json: RouteJson,
    project: ProjectId,
    operator: string,
    allow = true,
): Promise<void> {
    await json("POST", "/federation/run/allow", { project, operator, allow });
}

/** The host denies a queued run (fail-closed; it never executes). */
export async function denyRun(json: RouteJson, correlation: string): Promise<void> {
    await json("POST", "/federation/run/deny", { correlation });
}

/** The host admits this one queued run without setting a standing allow. */
export async function admitRunOnce(json: RouteJson, correlation: string): Promise<void> {
    await json("POST", "/federation/run/admit-once", { correlation });
}

/** The operator's local projection of a placed run's result. */
export async function runResult(json: RouteJson, correlation: string): Promise<RunResult> {
    return parseRunResult(
        await json("GET", `/federation/run/result?correlation=${encodeURIComponent(correlation)}`),
    );
}

/** Mint a combined engagement invite for a project. */
export async function invite(json: RouteJson, project: ProjectId): Promise<EngagementInvite> {
    return parseEngagementInvite(await json("POST", "/federation/invite", { project }));
}

/** Accept a combined invite (target side). */
export async function inviteAccept(json: RouteJson, invite: string): Promise<InviteAcceptResult> {
    return parseInviteAcceptResult(await json("POST", "/federation/invite/accept", { invite }));
}

/** The origin's pending-invite projection. */
export async function inviteStatus(json: RouteJson, inviteId: string): Promise<InviteStatus> {
    return parseInviteStatus(
        await json("GET", `/federation/invite/status?id=${encodeURIComponent(inviteId)}`),
    );
}

/** Pending incoming handoffs awaiting this authority's consent. */
export async function handoffIncoming(json: RouteJson): Promise<IncomingHandoff[]> {
    const o = fedObj(await json("GET", "/federation/handoff/incoming"));
    return fArr(o, "incoming").map(parseIncomingHandoff);
}

/** Consent to a pending incoming handoff. */
export async function handoffAccept(
    json: RouteJson,
    project: string,
    source: string,
): Promise<HandoffStatus> {
    return parseHandoffStatus(
        await json("POST", "/federation/handoff/accept", { project, source }),
    );
}

/** Decline a pending incoming handoff. */
export async function handoffDecline(
    json: RouteJson,
    project: string,
    source: string,
): Promise<void> {
    await json("POST", "/federation/handoff/decline", { project, source });
}

/** Consent to all pending incoming handoffs at once. */
export async function handoffAcceptAll(json: RouteJson): Promise<string[]> {
    const o = fedObj(await json("POST", "/federation/handoff/accept-all", {}));
    return fArr(o, "accepted").map((v, i) => {
        if (typeof v !== "string") throw new Error(`accepted[${i}]: expected string`);
        return v;
    });
}

/** Standing pre-authorization: auto-accept handoffs from `peer`. */
export async function handoffPreauth(
    json: RouteJson,
    peer: string,
    allow = true,
): Promise<void> {
    await json("POST", "/federation/handoff/preauth", { peer, allow });
}

/** A project's host/operator participants + the payload each owns + revoked state. */
export async function handoffParticipants(
    json: RouteJson,
    project: ProjectId,
): Promise<Participant[]> {
    const o = fedObj(
        await json("GET", `/federation/handoff/participants?project=${encodeURIComponent(project)}`),
    );
    return fArr(o, "participants").map(parseParticipant);
}

/** Revoke an owner's access to its payload class (licensing, not secrecy). */
export async function handoffRevoke(
    json: RouteJson,
    project: ProjectId,
    authority: string,
    owns: string,
): Promise<void> {
    await json("POST", "/federation/handoff/revoke", { project, authority, owns });
}

/** Register a host-owned data handle into a project. */
export async function handoffConnectData(
    json: RouteJson,
    project: ProjectId,
    handle: string,
    label?: string,
): Promise<void> {
    await json("POST", "/federation/handoff/connect-data", { project, handle, label });
}

/** The host-owned data handles connected to a project. */
export async function handoffData(json: RouteJson, project: ProjectId): Promise<ConnectedData[]> {
    const o = fedObj(
        await json("GET", `/federation/handoff/data?project=${encodeURIComponent(project)}`),
    );
    return fArr(o, "data").map(parseConnectedData);
}
