import { createEffect, createRoot, type Accessor } from "solid-js";
import type { EngagementId } from "@gaugewright/control-plane-client";

/** How long a turn waits for its chat's route before it runs anyway and
 * reports whatever it meets. */
export const CHAT_ROUTE_WAIT_MS = 10_000;

/** Resolves once the work route has been decided from `chat` itself.
 *
 * A task captures the open project when it starts and refuses to run if the
 * selection moves under it (WS-459). A chat is selected before the workspace
 * projection says which project it is in, so a turn started in between ran on
 * the route the chat replaced and was refused as "Task project selection
 * changed" once the route moved (WS-892). A chat that is no longer selected
 * does not wait, since nothing will route from it. */
export function chatRouted(
    chat: EngagementId,
    state: { readonly routedChat: Accessor<EngagementId | null>; readonly selected: Accessor<EngagementId | null> },
    limitMs = CHAT_ROUTE_WAIT_MS,
): Promise<void> {
    return new Promise((resolve) => {
        createRoot((dispose) => {
            const timer = setTimeout(() => { dispose(); resolve(); }, limitMs);
            createEffect(() => {
                if (state.routedChat() !== chat && state.selected() === chat) return;
                clearTimeout(timer);
                dispose();
                resolve();
            });
        });
    });
}
