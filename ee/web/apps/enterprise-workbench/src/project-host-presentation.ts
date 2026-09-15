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
