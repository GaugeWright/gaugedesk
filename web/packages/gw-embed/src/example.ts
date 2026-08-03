import { createRoot } from "solid-js";
import type {
    EngagementId,
    FileEntry,
    MergeAction,
    MergeState,
    StreamEvent,
} from "@gaugewright/control-plane-client";

import { registerEmbedElements, type GwSessionElement } from "./elements";
import { createRemoteSession } from "./remote-session";
import type { EmbedSessionApi } from "./session-api";

registerEmbedElements();

const params = new URLSearchParams(location.search);
const requestedPanels = (params.get("panels") ?? "chat,viewer,files")
    .split(",")
    .map((panel) => panel.trim())
    .filter(Boolean);
const mount = document.getElementById("mount");

function panelMarkup(): string {
    return requestedPanels
        .filter((panel) => ["chat", "viewer", "files", "chats"].includes(panel))
        .map((panel) => panel === "chat"
            ? '<gw-chat opening-message="Welcome to the embedded assistant."></gw-chat>'
            : `<gw-${panel}></gw-${panel}>`)
        .join("");
}

function mountHosted(host: string): void {
    const session = document.createElement("gw-session");
    session.setAttribute("host", host);
    session.setAttribute("panels", requestedPanels.join(","));
    const token = params.get("token");
    if (token) session.setAttribute("token", token);
    session.innerHTML = panelMarkup();
    mount?.appendChild(session);
}

function fixtureApi(): EmbedSessionApi {
    const emptyMerge = { phase: "Clean" } as MergeState;
    return {
        getTranscript: async () => [] as StreamEvent[],
        subscribe: () => () => undefined,
        engagementDiff: async () => "",
        getMerge: async () => emptyMerge,
        // Keep the hermetic browser fixture in-flight so the shared panel's
        // optimistic user projection remains visible without fabricating a
        // terminal runtime response.
        runEmbedTurn: (_id, prompt, images = []) => {
            document.body.dataset.fixtureTurn = JSON.stringify({ prompt, images });
            return new Promise<never>(() => undefined);
        },
        runTask: () => new Promise<never>(() => undefined),
        mergeCommand: async (_id: EngagementId, _action: MergeAction) =>
            emptyMerge,
        getFile: async () => "",
        putFile: async () => {
            throw new Error("fixture files are read-only");
        },
        getTree: async () => [] as FileEntry[],
        embedMyChats: async () => [],
        embedAudience: params.get("audience") !== "anonymous",
        embedNewChat: async () => {
            document.body.dataset.fixtureNewSession = "started";
        },
        embedOpenChat: async () => undefined,
        embedEraseChat: async () => undefined,
        embedGetConfig: async () => ({ white_label: false }),
    };
}

function mountFixture(): void {
    createRoot((dispose) => {
        const engagement = "embed-browser-fixture" as EngagementId;
        const binding = createRemoteSession({
            api: fixtureApi(),
            engagementId: engagement,
        });
        const session = document.createElement("gw-session") as GwSessionElement;
        session.session = binding.session;
        session.setAttribute("panels", requestedPanels.join(","));
        session.innerHTML = panelMarkup();
        mount?.appendChild(session);
        globalThis.addEventListener(
            "pagehide",
            () => {
                binding.dispose();
                dispose();
            },
            { once: true },
        );
    });
}

if (params.get("fixture") === "1") {
    mountFixture();
} else {
    const host = params.get("host");
    if (host) {
        mountHosted(host);
    } else if (mount) {
        mount.textContent =
            "Add ?host=https://panels.gaugewright.com/d/<deployment> to open a hosted agent.";
    }
}
