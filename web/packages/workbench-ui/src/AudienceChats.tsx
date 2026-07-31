import { createResource, createSignal, For, Show } from "solid-js";
import { type Session } from "./session-context";

export interface AudienceChatsProps {
    readonly session: Session;
    readonly standalone?: boolean;
}

/** One shared authenticated-audience chat switcher for the docked chat drawer
 * and the standalone `<gw-chats>` panel. Authority and transport remain on the
 * scoped Session API. */
export function AudienceChats(props: AudienceChatsProps) {
    const [expanded, setExpanded] = createSignal(props.standalone === true);
    const [busy, setBusy] = createSignal(false);
    const [chats, { refetch }] = createResource(
        () => props.session.api.embedAudience === true,
        () => props.session.api.embedMyChats?.() ?? Promise.resolve([]),
    );
    const current = () => props.session.engagementId();
    const run = async (command: () => Promise<void>) => {
        if (busy()) return;
        setBusy(true);
        try {
            await command();
            await refetch();
        } finally {
            setBusy(false);
        }
    };
    const erase = (chat: string) => {
        if (!globalThis.confirm?.("Delete this chat permanently?")) return;
        void run(() => props.session.api.embedEraseChat?.(chat) ?? Promise.resolve());
    };
    const body = () => (
        <div class="audience-chats-list" data-audience-chats-list>
            <div class="audience-chats-actions">
                <button
                    type="button"
                    disabled={busy()}
                    data-new-audience-chat
                    onClick={() =>
                        void run(
                            () =>
                                props.session.api.embedNewChat?.() ??
                                Promise.resolve(),
                        )
                    }
                >
                    New chat
                </button>
            </div>
            <Show when={chats()} fallback={<div class="status">loading…</div>}>
                <Show
                    when={chats()!.length}
                    fallback={
                        <div class="status" data-mychats-empty>
                            No saved chats yet.
                        </div>
                    }
                >
                    <For each={chats()}>
                        {(chat) => (
                            <div
                                class="audience-chat-row"
                                data-my-chat={chat.chat}
                                data-current-chat={current() === chat.chat ? "" : undefined}
                            >
                                <button
                                    type="button"
                                    class="audience-chat-open"
                                    disabled={busy() || current() === chat.chat}
                                    onClick={() =>
                                        void run(
                                            () =>
                                                props.session.api.embedOpenChat?.(
                                                    chat.chat,
                                                ) ?? Promise.resolve(),
                                        )
                                    }
                                >
                                    {chat.title}
                                </button>
                                <button
                                    type="button"
                                    class="audience-chat-delete"
                                    aria-label={`Delete ${chat.title}`}
                                    disabled={busy()}
                                    onClick={() => erase(chat.chat)}
                                >
                                    Delete
                                </button>
                            </div>
                        )}
                    </For>
                </Show>
            </Show>
        </div>
    );
    return (
        <Show when={props.session.api.embedAudience === true}>
            <div
                class="audience-chats"
                data-audience-chats
                data-standalone={props.standalone ? "" : undefined}
            >
                <Show
                    when={!props.standalone}
                    fallback={body()}
                >
                    <button
                        type="button"
                        class="audience-chats-toggle"
                        aria-expanded={expanded()}
                        onClick={() => setExpanded((value) => !value)}
                    >
                        Chats
                    </button>
                    <Show when={expanded()}>{body()}</Show>
                </Show>
            </div>
        </Show>
    );
}
