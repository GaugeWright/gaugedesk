import type { ProjectHost } from "@gaugewright/control-plane-client";

export const hostKind = (host: ProjectHost): string => host.kind === "cloud" ? "GaugeWright-managed" : "Self-managed";
export const hostStanding = (host: ProjectHost): string => ({
    provisioning: "Preparing", active: host.state === "live" ? "Connected" : "Active",
    suspended: "Suspended", retention: "In retention", deleted: "Retired", revoked: "Retired",
})[host.lifecycle];
export const retiredHost = (host: ProjectHost): boolean => host.lifecycle === "deleted" || host.lifecycle === "revoked";

export function nanoUsdInput(value: number): string {
    const amount = BigInt(value);
    const fraction = (amount % 1_000_000_000n).toString().padStart(9, "0").replace(/0+$/, "");
    return `${amount / 1_000_000_000n}${fraction ? `.${fraction}` : ""}`;
}
export function parseNanoUsd(value: string): number | null {
    const match = /^(\d+)(?:\.(\d{1,9}))?$/.exec(value.trim());
    if (!match) return null;
    const nanos = BigInt(match[1]) * 1_000_000_000n + BigInt((match[2] ?? "").padEnd(9, "0"));
    return nanos <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(nanos) : null;
}
export const hostBytes = (bytes: number): string => new Intl.NumberFormat(undefined, { style: "unit", unit: "gigabyte", maximumFractionDigits: 2 }).format(bytes / 1_000_000_000);

/** A Home's refusal of an Isolated workspace change, in the words the dialog
 *  shows rather than the route's status line. The Home always accepts turning
 *  Isolated off, so every refusal here is about turning it on or changing it. */
export function homePolicyRefusal(error: unknown): string {
    const status = typeof (error as { status?: unknown })?.status === "number"
        ? (error as { status: number }).status
        : null;
    switch (status) {
        case 401: return "Your session no longer reaches this host. Sign in again and retry.";
        case 403: return "Only the organization's owner can change Isolated workspace on this host.";
        case 422: return "The per-attempt limit must be more than zero and no more than this host allows.";
        case 423: return "This host is not active, so Isolated workspace can only be turned off.";
        case 503: return "This host has no Isolated workspace prices yet, so it can only be turned off.";
        case 507: return "This host's storage is full, so Isolated workspace can only be turned off.";
        default: return error instanceof Error ? error.message : String(error);
    }
}
