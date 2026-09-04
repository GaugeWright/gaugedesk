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
import type { EmbedQueuedTurn, EmbedSessionApi, TurnObservation } from "./session-api";

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
            ? '<gw-chat agent-name="Example Assistant" opening-message="Welcome to the embedded assistant."></gw-chat>'
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
    let onEvent: ((event: StreamEvent) => void) | undefined;
    // Every timer a turn schedules is held here, not just the settling one: a
    // stop has to cancel the whole turn, and a delayed turn has a tool timer and
    // one timer per streamed word still pending before streaming even begins.
    let active: { resolve: () => void; timers: ReturnType<typeof setTimeout>[] } | undefined;
    let queue: EmbedQueuedTurn[] = [];
    const queueListeners = new Set<(items: readonly EmbedQueuedTurn[]) => void>();
    let nextCommand = 1;
    const publishQueue = () => {
        for (const listener of queueListeners) listener(queue);
    };
    const recordCommand = (kind: "steer" | "follow_up", text: string) => {
        const commands = JSON.parse(document.body.dataset.fixtureCommands ?? "[]") as unknown[];
        commands.push({ kind, text });
        document.body.dataset.fixtureCommands = JSON.stringify(commands);
    };
    const enqueue = (kind: "steer" | "follow_up", text: string) => {
        const command_id = `fixture-command-${nextCommand++}`;
        recordCommand(kind, text);
        queue = [
            ...queue,
            { command_id, text, position: nextCommand * 1024 },
        ];
        publishQueue();
    };
    // The fixture's durable transcript. Without one, `settle()`'s snapshot re-read
    // replaced the streamed answer with nothing, and a turn looked like it had
    // produced no reply at all — the durable transcript is authority, so a fixture
    // standing in for the runtime has to actually be one.
    const durable: StreamEvent[] = [];
    const delayParam = params.get("delay");
    const delay = delayParam === null ? null : Number(delayParam);
    // The live-turn projection, driven exactly as the runtime drives it: the
    // states and the `tool` field mirror WhippleScript's `turn_activity` frame
    // (spec/agent-harness.md), so a fixture turn rehearses the real sequence
    // rather than a shape only this file believes in.
    let observation: TurnObservation = { state: "idle" };
    const activityListeners = new Set<(value: TurnObservation) => void>();
    const setObservation = (next: TurnObservation) => {
        observation = next;
        for (const listener of activityListeners) listener(next);
    };
    // `?tool=` rehearses a turn that runs a named tool before answering; without
    // it the turn goes straight from thinking to streaming, which is what a
    // tool-less deployment actually does.
    const fixtureTool = params.get("tool");
    const fixtureDeliverable = params.get("deliverable") === "1";
    const FIXTURE_DELIVERABLE = "deliverable/oai-readout.html";
    return {
        getTurnActivity: () => observation,
        subscribeTurnActivity: (listener: (value: TurnObservation) => void) => {
            activityListeners.add(listener);
            return () => activityListeners.delete(listener);
        },
        getTranscript: async () => [...durable],
        subscribe: (_id, listener) => {
            onEvent = listener;
            return () => { onEvent = undefined; };
        },
        engagementDiff: async () => "",
        getMerge: async () => emptyMerge,
        runEmbedTurn: (_id, prompt, images = []) => {
            document.body.dataset.fixtureTurn = JSON.stringify({ prompt, images });
            const turns = JSON.parse(document.body.dataset.fixtureTurns ?? "[]") as unknown[];
            turns.push({ prompt, images });
            document.body.dataset.fixtureTurns = JSON.stringify(turns);
            durable.push({ type: "user", text: prompt } as StreamEvent);
            setObservation({ state: "awaiting_model" });
            return new Promise<void>((resolve) => {
                const turn = { resolve, timers: [] as ReturnType<typeof setTimeout>[] };
                active = turn;
                const schedule = (fn: () => void, ms: number) => {
                    turn.timers.push(setTimeout(fn, ms));
                };
                if (delay === null || !Number.isFinite(delay) || delay < 0) return;
                const answer =
                    `Here is what I found for "${prompt}". This reply arrives as a `
                    + "sequence of deltas, the way a provider streams one, so the "
                    + "transcript fills in progressively rather than appearing whole.";
                // Roughly: think for a third, run the tool for a third, stream the
                // answer across the last third.
                const third = Math.max(1, Math.floor(delay / 3));
                if (fixtureTool) {
                    schedule(
                        () => setObservation({ state: "running_tool", tool: fixtureTool }),
                        third,
                    );
                }
                const words = answer.split(" ");
                const streamStart = fixtureTool ? third * 2 : third;
                const perWord = Math.max(16, Math.floor((delay - streamStart) / words.length));
                words.forEach((word, index) => {
                    schedule(() => {
                        if (index === 0) setObservation({ state: "streaming_output" });
                        onEvent?.({ type: "text", delta: index === 0 ? word : ` ${word}` });
                    }, streamStart + index * perWord);
                });
                schedule(() => {
                    setObservation({ state: "settling" });
                    // The durable message is what survives; the streamed copy is a
                    // projection the snapshot re-read replaces.
                    durable.push({ type: "assistant", text: answer } as StreamEvent);
                    queue = [];
                    publishQueue();
                    active = undefined;
                    setObservation({ state: "idle" });
                    resolve();
                }, streamStart + words.length * perWord + 120);
            });
        },
        runTask: () => new Promise<never>(() => undefined),
        mergeCommand: async (_id: EngagementId, _action: MergeAction) =>
            emptyMerge,
        // `?deliverable=1` rehearses a session whose agent wrote a report for
        // the visitor (ADR 0163): the card after the transcript offers it, and
        // the download fetches this HTML through the same `getFile` seam the
        // real projection answers.
        getFile: async (_id: EngagementId, path: string) =>
            fixtureDeliverable && path === FIXTURE_DELIVERABLE
                ? "<!doctype html><title>Your readout</title><h1>Your readout</h1><p>Fixture report.</p>"
                : "",
        putFile: async () => {
            throw new Error("fixture files are read-only");
        },
        getTree: async () =>
            (fixtureDeliverable
                ? [
                      { path: "oai/flow.md", isDir: false },
                      { path: "record/oai-record.json", isDir: false },
                      { path: FIXTURE_DELIVERABLE, isDir: false },
                  ]
                : []) as FileEntry[],
        embedMyChats: async () => [],
        embedAudience: params.get("audience") !== "anonymous",
        embedNewChat: async () => {
            document.body.dataset.fixtureNewSession = "started";
        },
        embedOpenChat: async () => undefined,
        embedEraseChat: async () => undefined,
        embedGetConfig: async () => ({ white_label: false }),
        stopTurn: async () => {
            if (!active) throw new Error("fixture has no active turn");
            for (const timer of active.timers) clearTimeout(timer);
            const { resolve } = active;
            active = undefined;
            document.body.dataset.fixtureStopped = "true";
            setObservation({ state: "idle" });
            resolve();
        },
        getTurnQueue: () => queue,
        subscribeTurnQueue: (listener) => {
            queueListeners.add(listener);
            listener(queue);
            return () => queueListeners.delete(listener);
        },
        followUpTurn: async (text) => enqueue("follow_up", text),
        steerTurn: async (text) => enqueue("steer", text),
        editQueuedTurn: async (commandId, text) => {
            queue = queue.map((item) => item.command_id === commandId ? { ...item, text } : item);
            publishQueue();
        },
        removeQueuedTurn: async (commandId) => {
            queue = queue.filter((item) => item.command_id !== commandId);
            publishQueue();
        },
        reorderQueuedTurns: async (commandIds) => {
            const byId = new Map(queue.map((item) => [item.command_id, item]));
            queue = commandIds.flatMap((id, index) => {
                const item = byId.get(id);
                return item ? [{ ...item, position: (index + 1) * 1024 }] : [];
            });
            publishQueue();
        },
        promoteQueuedTurn: async (commandId) => {
            const index = queue.findIndex((item) => item.command_id === commandId);
            if (index < 0) return;
            queue = [queue[index], ...queue.slice(0, index), ...queue.slice(index + 1)];
            publishQueue();
        },
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
