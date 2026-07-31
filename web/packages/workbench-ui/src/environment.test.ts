import { describe, expect, it, vi } from "vitest";
import {
    engagementId,
    type ControlPlane,
} from "@gaugewright/control-plane-client";
import {
    Environment,
    panelManifest,
    type SessionBinding,
} from "./environment";

function controlPlane(): ControlPlane {
    return {
        setBearer: vi.fn(),
        listEngagements: vi.fn(async () => [engagementId("chat-1")]),
        createEngagement: vi.fn(async (id = engagementId("chat-new")) => ({
            id,
            branch: `engagement/${id}`,
            path: `/tmp/${id}`,
        })),
        deleteChat: vi.fn(async () => undefined),
        getTranscript: vi.fn(async () => []),
        subscribe: vi.fn(() => () => undefined),
        runTask: vi.fn(async () => ({})),
        stopTurn: vi.fn(async () => ({ stopped: true })),
        engagementDiff: vi.fn(async () => ""),
        getMerge: vi.fn(async () => ({
            phase: "Idle",
            thread_state: "idle",
            git_outcome: "Unknown",
            review_requested: false,
        })),
        mergeCommand: vi.fn(async () => ({
            phase: "Idle",
            thread_state: "idle",
            git_outcome: "Unknown",
            review_requested: false,
        })),
        getTree: vi.fn(async () => []),
        getFile: vi.fn(async () => ""),
        getFileWithCut: vi.fn(async () => ({ content: "", cut: null })),
        putFile: vi.fn(async () => undefined),
        saveFile: vi.fn(async () => ({ kind: "saved", cut: "cut-1" })),
        previewMerge: vi.fn(async () => ({ knownBase: false as const })),
        getConfig: vi.fn(async () => "{}"),
        putConfig: vi.fn(async () => undefined),
    } as ControlPlane;
}

describe("PanelManifest", () => {
    it("parses, orders, and deduplicates the shared panel ids", () => {
        expect(panelManifest("chat, files,chat").panels).toEqual(["chat", "files"]);
    });

    it("fails closed on unknown or empty panel sets", () => {
        expect(() => panelManifest("chat,other")).toThrow("unknown GaugeDesk panel");
        expect(() => panelManifest("")).toThrow("at least one panel");
    });
});

describe("Environment", () => {
    it("owns cross-engagement commands and mints a Session leaf", async () => {
        const cp = controlPlane();
        const binding = { session: {} as SessionBinding["session"], dispose: vi.fn() };
        const factory = vi.fn(() => binding);
        const environment = new Environment({
            identity: { kind: "authenticated", subject: "audience:alice" },
            controlPlane: cp,
            manifest: panelManifest(["chat", "viewer"]),
            sessionFactory: factory,
        });
        const id = engagementId("chat-1");

        await expect(environment.listEngagements()).resolves.toEqual([id]);
        await environment.createEngagement(id);
        await environment.closeEngagement(id);
        expect(environment.openSession(id)).toBe(binding);
        expect(factory).toHaveBeenCalledWith(cp, id);
        expect(environment.includes("chat")).toBe(true);
        expect(environment.includes("files")).toBe(false);
    });

    it("refuses an identity with no attributable subject", () => {
        expect(
            () =>
                new Environment({
                    identity: { kind: "anonymous", subject: "" },
                    controlPlane: controlPlane(),
                    manifest: panelManifest(["chat"]),
                    sessionFactory: vi.fn(),
                }),
        ).toThrow("requires a subject");
    });
});
