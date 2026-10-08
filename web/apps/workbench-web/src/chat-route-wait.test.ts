import { describe, expect, it } from "vitest";
import { createRoot, createSignal } from "solid-js";
import type { EngagementId } from "@gaugewright/control-plane-client";
import { chatRouted } from "./chat-route-wait";

const chat = (id: string) => id as EngagementId;
const settled = async (promise: Promise<void>) => {
    let done = false;
    void promise.then(() => { done = true; });
    for (let i = 0; i < 10; i++) await Promise.resolve();
    await new Promise((resolve) => setTimeout(resolve, 0));
    return done;
};

describe("a turn waits for its chat's route (WS-892)", () => {
    it("holds a turn in a just-selected chat until the route is decided from that chat", async () => {
        const [routedChat, setRoutedChat] = createRoot(() => createSignal<EngagementId | null>(chat("chat-before")));
        const [selected] = createRoot(() => createSignal<EngagementId | null>(chat("chat-new")));
        const waiting = chatRouted(chat("chat-new"), { routedChat, selected });
        expect(await settled(waiting)).toBe(false);
        // The workspace projection names the new chat's project and the route
        // effect moves the route from it.
        setRoutedChat(chat("chat-new"));
        expect(await settled(waiting)).toBe(true);
    });

    it("does not hold a turn whose chat is already routed", async () => {
        const [routedChat] = createRoot(() => createSignal<EngagementId | null>(chat("chat-a")));
        const [selected] = createRoot(() => createSignal<EngagementId | null>(chat("chat-a")));
        expect(await settled(chatRouted(chat("chat-a"), { routedChat, selected }))).toBe(true);
    });

    it("lets go when the chat is no longer selected, and after the limit", async () => {
        const [routedChat] = createRoot(() => createSignal<EngagementId | null>(null));
        const [selected, setSelected] = createRoot(() => createSignal<EngagementId | null>(chat("chat-a")));
        const away = chatRouted(chat("chat-a"), { routedChat, selected });
        setSelected(chat("chat-b"));
        expect(await settled(away)).toBe(true);
        const bounded = chatRouted(chat("chat-b"), { routedChat, selected }, 20);
        expect(await settled(bounded)).toBe(false);
        await new Promise((resolve) => setTimeout(resolve, 30));
        expect(await settled(bounded)).toBe(true);
    });
});
