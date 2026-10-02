/**
 * Panel Settings read models (DR-0305).
 *
 * The surface renders the pages the Home's GaugeApp serves, which are what the
 * management agent reads too. These pin that a well-formed session renders, and
 * that a shape the surface does not recognise is refused rather than shown as
 * something actionable.
 */

import { describe, expect, it } from "vitest";
import { keptItemCopy, panelInboxStatusCopy, panelSettingsView } from "./panel-settings";

const pages = (inbox: unknown = {
    placement: "inst-1",
    project: "proj-1",
    pending: 1,
    items: [
        { item_id: "a", deployment_id: "dep-1", public_session_id: "s-1", schema: "survey.v1", bytes: 40, arrived_at_unix_ms: 2, status: "pending", workspace_path: null },
        { item_id: "b", deployment_id: "dep-1", public_session_id: "s-2", schema: "survey.v1", bytes: 41, arrived_at_unix_ms: 3, status: "approved", workspace_path: "inbound/b.json" },
    ],
}) => [
    { id: "overview", model: { name: "Survey", version: 2, current_version: 3, upgrade_available: true, collects: true, profile: null } },
    { id: "deployments", model: { deployments: [{ id: "binding-1", deployment_id: "dep-1", edge_origin: "https://panels.example", active_release_id: "sha256:r", status: "active", allowed_origins: ["https://site.example"], retention_idle_ttl_seconds: 3600 }] } },
    { id: "inbox", model: inbox },
];

describe("Panel Settings", () => {
    it("reads the version, deployments and Inbox a session returned", () => {
        const view = panelSettingsView(pages());
        expect(view.overview).toMatchObject({ name: "Survey", version: 2, currentVersion: 3, upgradeAvailable: true, collects: true });
        expect(view.deployments).toEqual([{
            id: "binding-1", deploymentId: "dep-1", edgeOrigin: "https://panels.example", activeReleaseId: "sha256:r",
            status: "active", allowedOrigins: ["https://site.example"], retentionIdleSeconds: 3600,
        }]);
        expect("items" in view.inbox && view.inbox.items.map((item) => [item.itemId, item.status])).toEqual([["a", "pending"], ["b", "approved"]]);
    });

    it("says where a kept item is and that work chats read it there", () => {
        const view = panelSettingsView(pages());
        const items = "items" in view.inbox ? view.inbox.items : [];
        expect(panelInboxStatusCopy(items[1]!).label).toBe("kept");
        expect(keptItemCopy(items[1]!)).toContain("inbound/b.json");
        expect(keptItemCopy(items[0]!)).toBeNull();
    });

    it("shows an Inbox the Home could not read as unavailable, not empty", () => {
        const view = panelSettingsView(pages({ unavailable: "the Inbox could not be read" }));
        expect(view.inbox).toEqual({ unavailable: "the Inbox could not be read" });
    });

    it("refuses an item in a state it does not know, so no keep button appears on it", () => {
        expect(() => panelSettingsView(pages({ pending: 0, items: [{ item_id: "a", bytes: 1, arrived_at_unix_ms: 1, status: "screening" }] })))
            .toThrow(/malformed/);
    });

    it("refuses a session missing a page", () => {
        expect(() => panelSettingsView(pages().slice(0, 2))).toThrow(/inbox page/);
    });
});
