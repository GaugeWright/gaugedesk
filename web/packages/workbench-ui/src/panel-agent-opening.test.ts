/**
 * Opening a Panel agent (PANEL-12).
 *
 * These pin the two decisions the opened surface rests on: opening shows the
 * latest edit chat rather than creating one on every click, and a placement
 * pinned to a frozen version shows its contract and deploys it, while only the
 * Library draft is edited and published.
 */

import { describe, expect, it } from "vitest";
import { editChatToOpen, panelAgentSurfacePlan } from "./panel-agent-opening";

describe("opening a Panel agent", () => {
    it("shows the latest edit chat, which the projection lists last", () => {
        expect(editChatToOpen([{ id: "chat-1" }, { id: "chat-2" }, { id: "chat-3" }])).toBe("chat-3");
    });

    it("opens no chat when there is none yet, so the opener creates one", () => {
        expect(editChatToOpen([])).toBeNull();
    });

    it("edits and publishes the Library draft", () => {
        const plan = panelAgentSurfacePlan(null);
        expect(plan.scope).toBe("draft");
        expect(plan.subtitle).toBe("Library draft");
        expect(plan.contractEditable).toBe(true);
        expect(plan.actions).toEqual(["publish"]);
    });

    it("shows a pinned placement's frozen contract and deploys it", () => {
        const plan = panelAgentSurfacePlan({ version: 3, deployments: [] }, "Customer site");
        expect(plan.scope).toBe("pinned");
        expect(plan.subtitle).toBe("Customer site · pinned v3");
        expect(plan.contractEditable).toBe(false);
        expect(plan.actions).toEqual(["deploy", "inbox"]);
        expect(plan.deployLabel).toBe("Deploy…");
    });

    it("says when a placement already has deployments to manage", () => {
        const deployed = { id: "b1", deploymentId: "intake", edgeOrigin: "https://edge.example", activeReleaseId: "sha256:1", status: "active" as const };
        expect(panelAgentSurfacePlan({ version: 3, deployments: [deployed] }, "Customer site").deployLabel).toBe("Manage deployments…");
    });
});
