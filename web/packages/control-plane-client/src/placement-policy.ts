import type { RouteJson } from "./control-plane-transport";
import type { RouteRequest } from "./browser-route-json";

export type PlacementOperator = "local" | "counterparty" | "neutral";

/** The two independent axes an engagement declares before the client admits it. */
export interface DeploymentPlacement {
    readonly operator: PlacementOperator;
    readonly attested: boolean;
}

/** The organization's restrict-only floor for engagements touching its data. */
export interface PlacementPolicy {
    readonly require_attested: boolean;
    readonly allowed_operators: readonly PlacementOperator[];
}

export const localDeploymentPlacement: DeploymentPlacement = {
    operator: "local",
    attested: false,
};

function object(raw: unknown, context: string): Record<string, unknown> {
    if (raw === null || typeof raw !== "object" || Array.isArray(raw)) {
        throw new Error(`${context}: expected object`);
    }
    return raw as Record<string, unknown>;
}

function operator(raw: unknown, context: string): PlacementOperator {
    if (raw === "local" || raw === "counterparty" || raw === "neutral") return raw;
    throw new Error(`${context}: unknown operator`);
}

export function parseDeploymentPlacement(raw: unknown): DeploymentPlacement {
    const value = object(raw, "deployment placement");
    if (typeof value.attested !== "boolean") {
        throw new Error("deployment placement: attested must be boolean");
    }
    return {
        operator: operator(value.operator, "deployment placement"),
        attested: value.attested,
    };
}

export function parsePlacementPolicy(raw: unknown): PlacementPolicy {
    const value = object(raw, "placement policy");
    if (typeof value.require_attested !== "boolean") {
        throw new Error("placement policy: require_attested must be boolean");
    }
    if (!Array.isArray(value.allowed_operators)) {
        throw new Error("placement policy: allowed_operators must be an array");
    }
    return {
        require_attested: value.require_attested,
        allowed_operators: value.allowed_operators.map((item, index) =>
            operator(item, `placement policy allowed_operators[${index}]`)),
    };
}

/** Mirror the pure server admission predicate for immediate client refusal.
 * The server always evaluates the same floor again; this is never the authority. */
export function placementPolicyAdmits(
    policy: PlacementPolicy,
    declared: DeploymentPlacement,
    measurementVerified: boolean,
): boolean {
    if (policy.require_attested && !declared.attested) return false;
    if (
        policy.allowed_operators.length > 0
        && !policy.allowed_operators.includes(declared.operator)
    ) return false;
    return !declared.attested || measurementVerified;
}

/** Enrolled-client recovery read. Any malformed policy fails closed at the edge. */
export async function readPlacementPolicy(json: RouteJson): Promise<PlacementPolicy> {
    const response = object(await json("GET", "/admin/placement-policy"), "placement response");
    return parsePlacementPolicy(response.placement_policy);
}

/** Whether an organization placement floor governs this control plane at all,
 * and the policy when it does. `managed: false` means the control plane serves
 * no org-governance surface (the solo/local case) and the client renders
 * unmanaged controls. `managed: true` with no policy is a governed control
 * plane whose policy could not be read; the UI fails closed on it. */
export type PlacementGovernance =
    | { readonly managed: false }
    | { readonly managed: true; readonly policy?: PlacementPolicy };

/** Resolve governance from the placement-policy route without ever throwing.
 * This exists because the read runs in every enterprise composition, including
 * against a solo control plane where the route does not exist: a 404 is the
 * unmanaged signal, and every failure mode must land as a value — a rejection
 * here once reached the UI as an errored resource whose read threw mid-render
 * and killed the Devices modal (2026-07-31). */
export async function readPlacementGovernance(
    request: RouteRequest,
): Promise<PlacementGovernance> {
    let response: Response;
    try {
        response = await request("/admin/placement-policy");
    } catch {
        return { managed: true };
    }
    if (response.status === 404) return { managed: false };
    if (!response.ok) return { managed: true };
    try {
        const value = (await response.json()) as { placement_policy?: unknown };
        return { managed: true, policy: parsePlacementPolicy(value.placement_policy) };
    } catch {
        return { managed: true };
    }
}
