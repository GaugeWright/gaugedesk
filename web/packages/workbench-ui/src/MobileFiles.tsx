/**
 * The mobile **Files pane** (`mobile-client.md`, MOB-015): the worktree tree
 * shown at the `files` carousel stop. It lists every handle **by name** — a
 * handle always names something — while keeping the payload behind its access
 * basis (`INV-10`, `gaugedesk_core::resource_access`: `name_visible()` is always
 * true, `payload_accessible()` only once `Granted`). Picking a *granted* file
 * advances the carousel to the `content` pane (MOB-016); a *locked* file offers
 * to request access rather than silently doing nothing.
 *
 * Like the {@link Carousel} island this is a thin renderer: every "what may I
 * show?" decision is a pure function in `mobile-files.ts` (`presentTree`), so
 * this component only wires Solid's `<For>` / events onto the derived
 * presentation and never decides access itself.
 */

import { For, Show, type JSX } from "solid-js";
import { presentTree, type FileNode } from "./mobile-files";

export interface MobileFilesProps {
    /** The worktree handles to list. Names always render; payload stays gated. */
    readonly nodes: readonly FileNode[];
    /** The currently-selected file path (boxes the row), or `null`. */
    readonly selected: string | null;
    /** Pick a *payload-open* file — the host advances to the content pane. */
    readonly onOpen: (path: string) => void;
    /** Ask for payload access on a *locked* handle (the access-request flow,
     *  MOB-030). The host raises the approval panel; this pane never grants. */
    readonly onRequestAccess: (path: string) => void;
}

export function MobileFiles(props: MobileFilesProps): JSX.Element {
    const tree = () => presentTree(props.nodes);

    return (
        <Show
            when={tree().length}
            fallback={<div class="status">empty worktree</div>}
        >
            <div class="mobile-files filetree" data-worktree>
                <For each={tree()}>
                    {(n) => (
                        <button
                            type="button"
                            class="file"
                            classList={{
                                active: props.selected === n.path,
                                locked: n.locked,
                                dir: n.isDir,
                            }}
                            title={n.accessLabel}
                            aria-label={`${n.path} — ${n.accessLabel}`}
                            // A locked handle requests access; an open one selects.
                            // A name-only, non-locked handle (e.g. dir) is inert.
                            aria-disabled={!n.payloadOpenable && !n.requestable}
                            onClick={() => {
                                if (n.payloadOpenable) props.onOpen(n.path);
                                else if (n.requestable) props.onRequestAccess(n.path);
                            }}
                        >
                            {n.locked ? "🔒 " : ""}
                            {n.path}
                        </button>
                    )}
                </For>
            </div>
        </Show>
    );
}
