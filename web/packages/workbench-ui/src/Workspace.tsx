/**
 * The WORKSPACE panel (4th column, `navigation.md`): the active engagement's
 * worktree files. Selecting a file retargets the content viewer. Protected
 * method resources are marked 🔒 (visibility ≠ access, `INV-10`).
 */

import { createEffect, createMemo, createResource, createSignal, For, onCleanup, Show } from "solid-js";
import type { ChatWhipRunView } from "@gaugewright/control-plane-client";
import { useSession } from "./session-context";
import { LoadError } from "./LoadError";
import { RunDot, runsLaunched } from "./WhipRun";

// Config/plumbing artifacts (#6): dotfiles like `.agent-config.json` are
// implementation, not the user's deliverable. Hidden from the Files list by
// default. The authored package draft is the deliverable in an edit chat, so it
// is visible there even though it lives under `.whipple`.
const isInternal = (path: string, editChat: boolean) =>
    path.split("/").some((seg) => seg.startsWith("."))
    && !(editChat && (
        path.startsWith(".whipple/draft/") ||
        path.startsWith(".whipple/discipline/draft/")
    ));

export function Workspace() {
    const session = useSession();
    const [tree, { refetch }] = createResource(
        () => [session.engagementId(), session.worktreeRev()] as const,
        ([id]) => (id ? session.api.getTree(id) : Promise.resolve([])),
    );
    const [showInternal, setShowInternal] = createSignal(false);
    const editChat = () => session.chatKind() === "edit";
    const isProtected = (path: string) =>
        path.startsWith("builder_only/")
        || path.includes("/builder_only/")
        || path === ".agent-config.json"
        || path.startsWith(".whipple/versions/")
        || (!editChat() && path.startsWith(".whipple/"));
    const allFiles = () => (tree() ?? []).filter((e) => !e.isDir);
    const files = () => (showInternal() ? allFiles() : allFiles().filter((e) => !isInternal(e.path, editChat())));
    const hiddenCount = createMemo(() => allFiles().filter((e) => isInternal(e.path, editChat())).length);
    // A workflow file carries its latest run's status as a dot, so a folder
    // shows what is running without opening each file. Read while a run is
    // running, again every few seconds, since the Home steps it, not us.
    const [runsTick, setRunsTick] = createSignal(0);
    const [runs] = createResource(
        () => {
            const id = session.engagementId();
            const hasWhip = allFiles().some((e) => e.path.endsWith(".whip"));
            return id && hasWhip && session.api.listChatWhipRuns ? [id, runsTick(), runsLaunched()] as const : null;
        },
        ([id]) => session.api.listChatWhipRuns!(id).catch((): ChatWhipRunView[] => []),
    );
    const latest = createMemo(() => {
        const byPath = new Map<string, ChatWhipRunView>();
        for (const run of runs() ?? []) if (!byPath.has(run.path)) byPath.set(run.path, run);
        return byPath;
    });
    createEffect(() => {
        if (!(runs() ?? []).some((run) => run.state === "running")) return;
        const timer = setTimeout(() => setRunsTick((n) => n + 1), 4000);
        onCleanup(() => clearTimeout(timer));
    });

    return (
        <Show when={!tree.error} fallback={<LoadError what="the files" onRetry={() => void refetch()} />}>
        <Show when={tree()} fallback={<div class="status">loading…</div>}>
            <Show when={files().length} fallback={<div class="status">No files yet. Use "add files" above, or the agent will create them as it works.</div>}>
                <div class="filetree" data-worktree>
                    <For each={files()}>
                        {(e) => (
                            <div
                                class="file"
                                classList={{ active: session.selectedFile() === e.path, locked: isProtected(e.path) }}
                                onClick={() => session.selectFile(e.path)}
                            >
                                <Show when={latest().get(e.path)}>
                                    {(run) => <RunDot state={run().state} />}
                                </Show>
                                {isProtected(e.path) ? "🔒 " : ""}
                                {e.path}
                            </div>
                        )}
                    </For>
                </div>
            </Show>
            {/* Progressive disclosure (#6): the config plumbing is reachable but quiet. */}
            <Show when={hiddenCount() > 0}>
                <button
                    class="show-internal"
                    data-show-internal
                    onClick={() => setShowInternal((v) => !v)}
                >
                    {showInternal()
                        ? "hide internal files"
                        : `show ${hiddenCount()} internal file${hiddenCount() === 1 ? "" : "s"}`}
                </button>
            </Show>
        </Show>
        </Show>
    );
}
