/**
 * Panel Settings read models (DR-0305).
 *
 * A Panel placement's settings are the GaugeApp pages its Home serves at
 * `/placements/{id}/settings`: the same models the management agent reads, so
 * what the page shows and what the agent is told cannot disagree. This turns
 * those pages into what the surface renders, and refuses a shape it does not
 * recognise rather than rendering a guess.
 *
 * The Inbox here is an index. A person reads an item through the reviewer's
 * route; nothing in these models carries what a visitor wrote (ADR 0110 §1).
 */

import type { PanelPublicProfile, PublicDeploymentBindingSummary } from "@gaugewright/control-plane-client";

export type PanelSettingsPage = "overview" | "deployments" | "inbox";

export const PANEL_SETTINGS_PAGES: readonly PanelSettingsPage[] = ["overview", "deployments", "inbox"];

export const PANEL_SETTINGS_PAGE_LABELS: Readonly<Record<PanelSettingsPage, string>> = {
    overview: "Overview",
    deployments: "Deployments",
    inbox: "Inbox",
};

export interface PanelSettingsOverview {
    readonly name: string;
    readonly version: number;
    readonly currentVersion: number | null;
    readonly upgradeAvailable: boolean;
    readonly collects: boolean;
    readonly profile: PanelPublicProfile | null;
}

export interface PanelSettingsDeployment extends PublicDeploymentBindingSummary {
    readonly allowedOrigins: readonly string[];
    readonly retentionIdleSeconds: number | null;
}

export type PanelInboxStatus = "pending" | "approved" | "rejected";

export interface PanelInboxItem {
    readonly itemId: string;
    readonly deploymentId: string | null;
    readonly sessionId: string | null;
    readonly schema: string;
    readonly bytes: number;
    readonly arrivedAtUnixMs: number;
    readonly status: PanelInboxStatus;
    readonly workspacePath: string | null;
}

export interface PanelSettingsView {
    readonly overview: PanelSettingsOverview;
    readonly deployments: readonly PanelSettingsDeployment[];
    readonly inbox: { readonly pending: number; readonly items: readonly PanelInboxItem[] } | { readonly unavailable: string };
}

type Model = Record<string, unknown>;

const text = (value: unknown): string | null => typeof value === "string" ? value : null;
const count = (value: unknown): number | null =>
    typeof value === "number" && Number.isFinite(value) && value >= 0 ? Math.floor(value) : null;

function malformed(what: string): never {
    throw new Error(`Panel settings ${what} was malformed`);
}

const BINDING_STATUSES = new Set(["pending_publish", "active", "legacy_confirmation_required"]);
const ITEM_STATUSES = new Set(["pending", "approved", "rejected"]);

function deployment(value: unknown): PanelSettingsDeployment {
    const row = (value ?? {}) as Model;
    const id = text(row.id);
    const deploymentId = text(row.deployment_id);
    const edgeOrigin = text(row.edge_origin);
    const status = text(row.status);
    if (!id || !deploymentId || !edgeOrigin || !status || !BINDING_STATUSES.has(status)) malformed("deployment");
    return {
        id,
        deploymentId,
        edgeOrigin,
        activeReleaseId: text(row.active_release_id),
        status: status as PublicDeploymentBindingSummary["status"],
        allowedOrigins: Array.isArray(row.allowed_origins) ? row.allowed_origins.filter((origin): origin is string => typeof origin === "string") : [],
        retentionIdleSeconds: count(row.retention_idle_ttl_seconds),
    };
}

function item(value: unknown): PanelInboxItem {
    const row = (value ?? {}) as Model;
    const itemId = text(row.item_id);
    const status = text(row.status);
    const bytes = count(row.bytes);
    const arrived = count(row.arrived_at_unix_ms);
    if (!itemId || !status || !ITEM_STATUSES.has(status) || bytes === null || arrived === null) malformed("Inbox item");
    return {
        itemId,
        deploymentId: text(row.deployment_id),
        sessionId: text(row.public_session_id),
        schema: text(row.schema) ?? "",
        bytes,
        arrivedAtUnixMs: arrived,
        status: status as PanelInboxStatus,
        workspacePath: text(row.workspace_path),
    };
}

/** The surface's view of the pages a Panel Settings session returned. */
export function panelSettingsView(pages: readonly { readonly id: string; readonly model: unknown }[]): PanelSettingsView {
    const model = (id: PanelSettingsPage): Model => {
        const page = pages.find((candidate) => candidate.id === id);
        if (!page || typeof page.model !== "object" || page.model === null) malformed(`${id} page`);
        return page.model as Model;
    };
    const overview = model("overview");
    const version = count(overview.version);
    if (version === null) malformed("overview");
    const deployments = model("deployments").deployments;
    const inbox = model("inbox");
    return {
        overview: {
            name: text(overview.name) ?? "Panel agent",
            version,
            currentVersion: count(overview.current_version),
            upgradeAvailable: overview.upgrade_available === true,
            collects: overview.collects === true,
            profile: (overview.profile ?? null) as PanelPublicProfile | null,
        },
        deployments: Array.isArray(deployments) ? deployments.map(deployment) : malformed("deployments page"),
        inbox: typeof inbox.unavailable === "string"
            ? { unavailable: inbox.unavailable }
            : {
                pending: count(inbox.pending) ?? 0,
                items: Array.isArray(inbox.items) ? inbox.items.map(item) : malformed("Inbox page"),
            },
    };
}

/** What an Inbox row says about where an item stands, in a reviewer's words. */
export function panelInboxStatusCopy(item: PanelInboxItem): { label: string; tone: string } {
    switch (item.status) {
        case "approved":
            return { label: "kept", tone: "ok" };
        case "rejected":
            return { label: "flagged", tone: "warn" };
        default:
            return { label: "awaiting review", tone: "pending" };
    }
}

/** Where a kept item is, as a work chat in the project sees it. */
export function keptItemCopy(item: PanelInboxItem): string | null {
    return item.workspacePath
        ? `Kept. Work chats in this project can read it at ${item.workspacePath} in the project's folder.`
        : null;
}
