/**
 * The WORKSPACE panel (4th column, `navigation.md`): the active engagement's
 * worktree files. Selecting a file retargets the content viewer. Protected
 * method resources are marked 🔒 (visibility ≠ access, `INV-10`).
 */

import { createEffect, createMemo, createResource, createSignal, For, onCleanup, Show } from "solid-js";
import type { ChatWhipRunView, FileEntry, FileManagerCommand } from "@gaugewright/control-plane-client";
import { useSession } from "./session-context";
import { ContextMenu, type MenuItem, type MenuState } from "./ContextMenu";
import { Icon } from "./icons";
import { LoadError } from "./LoadError";
import { RunDot, runsLaunched } from "./WhipRun";

// Generated packages and control files are available in the advanced view.
// The ordinary tree starts with the authored Agent files and run results.
const isInternal = (path: string) => path.split("/").some((seg) => seg.startsWith("."));

export interface WorkspaceProps {
    readonly roots?: readonly { path: string; name: string; writable: boolean }[];
    readonly creationRequest?: { chat: string; kind: "file" | "folder"; nonce: number } | null;
    readonly onCreationHandled?: () => void;
    readonly onChanged?: (message: string) => void;
}

type FileDialog =
    | { kind: "create_file" | "create_folder"; parent: string | null }
    | { kind: "rename"; path: string; isDir: boolean };

const FOLDER_MARKER = ".gaugedesk-folder";
const parentOf = (path: string) => path.includes("/") ? path.slice(0, path.lastIndexOf("/")) : "";
const leafOf = (path: string) => path.slice(path.lastIndexOf("/") + 1);
const joinPath = (parent: string, name: string) => parent ? `${parent}/${name}` : name;
const validName = (name: string) => name.length > 0
    && name !== "." && name !== ".." && name !== ".git" && name !== FOLDER_MARKER
    && !/[\\/\u0000-\u001f]/.test(name);
const actionError = (cause: unknown) => {
    const message = cause instanceof Error ? cause.message : String(cause);
    return /File exists|destination already exists/.test(message)
        ? "That name is already in use. Choose another name." : message;
};

export function Workspace(props: WorkspaceProps = {}) {
    const session = useSession();
    const [refreshTick, setRefreshTick] = createSignal(0);
    const [tree, { refetch }] = createResource(
        () => [session.engagementId(), session.worktreeRev(), refreshTick()] as const,
        ([id]) => (id ? session.api.getTree(id) : Promise.resolve([])),
    );
    const [showInternal, setShowInternal] = createSignal(false);
    const [collapsed, setCollapsed] = createSignal<ReadonlySet<string>>(new Set(["agent"]));
    const [menu, setMenu] = createSignal<MenuState | null>(null);
    const [dialog, setDialog] = createSignal<FileDialog | null>(null);
    const [name, setName] = createSignal("");
    const [rootChoice, setRootChoice] = createSignal("");
    const [error, setError] = createSignal("");
    const [saving, setSaving] = createSignal(false);
    const roots = () => props.roots?.length ? props.roots : [{ path: "", name: "Chat workspace", writable: true }];
    const writableRoots = () => roots().filter((root) => root.writable);
    const rootFor = (path: string) => roots().find((root) => root.path && (path === root.path || path.startsWith(`${root.path}/`)));
    const isRoot = (path: string) => roots().some((root) => root.path && root.path === path);
    const isProtected = (path: string) =>
        (session.chatKind() !== "edit" && (path === "agent" || path.startsWith("agent/")))
        || path === "targets" || path === ".whipple" || path.startsWith(".whipple/")
        || path === ".gaugedesk-runtime"
        || path.startsWith(".gaugedesk-runtime/") || path.includes("/.gaugedesk-runtime/")
        || path.startsWith("builder_only/")
        || path.includes("/builder_only/")
        || path === ".agent-config.json"
        || path.endsWith("/.agent-config.json")
        || path.startsWith(".whipple/versions/");
    const canManage = (path: string) => !!session.api.manageFile && !isProtected(path)
        && (rootFor(path)?.writable ?? true) && session.canEditFile?.(path) !== false;
    const allEntries = () => (tree() ?? []).filter((entry) => leafOf(entry.path) !== FOLDER_MARKER);
    const allFiles = () => allEntries().filter((entry) => !entry.isDir);
    const visibleEntries = createMemo(() => {
        const order = (path: string) => {
            const root = path.split("/", 1)[0];
            return root === "artifacts" ? 0 : root === "work" ? 1 : root === "agent" ? 2 : 3;
        };
        const ordered = (entries: readonly FileEntry[]) => [...entries].sort((a, b) =>
            order(a.path) - order(b.path) || a.path.localeCompare(b.path));
        if (showInternal()) return ordered(allEntries());
        const ordinary = allEntries().filter((entry) => !isInternal(entry.path));
        return ordered(allEntries().filter((entry) => ordinary.includes(entry)
            || (entry.isDir && ordinary.some((child) => child.path.startsWith(`${entry.path}/`)))));
    });
    const hiddenCount = createMemo(() => allFiles().filter((entry) => isInternal(entry.path)).length);
    const rows = () => visibleEntries().filter((entry) => {
        if (entry.path === "targets" && props.roots?.some((root) => root.path.startsWith("targets/"))) return false;
        let parent = parentOf(entry.path);
        while (parent) {
            if (collapsed().has(parent)) return false;
            parent = parentOf(parent);
        }
        return true;
    });
    const depth = (path: string) => {
        const root = rootFor(path);
        if (root) return path === root.path ? 0 : path.slice(root.path.length + 1).split("/").length;
        return path.split("/").length - 1;
    };
    const displayName = (path: string) => roots().find((root) => root.path === path)?.name ?? leafOf(path);
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
        const delay = (runs() ?? []).some((run) => run.state === "running") ? 4000
            : (runs() ?? []).some((run) => run.state === "waiting") ? 15000 : 0;
        if (!delay) return;
        const timer = setTimeout(() => setRunsTick((n) => n + 1), delay);
        onCleanup(() => clearTimeout(timer));
    });

    const openCreate = (kind: "file" | "folder", parent: string | null = null) => {
        if (!session.api.manageFile || (parent === null && !writableRoots().length)) return;
        setName("");
        setError("");
        setRootChoice(parent ?? writableRoots()[0]?.path ?? "");
        setDialog({ kind: kind === "file" ? "create_file" : "create_folder", parent });
    };
    createEffect(() => {
        const request = props.creationRequest;
        if (!request || request.chat !== session.engagementId()) return;
        openCreate(request.kind);
        props.onCreationHandled?.();
    });
    const openRename = (entry: FileEntry) => {
        setName(leafOf(entry.path));
        setError("");
        setDialog({ kind: "rename", path: entry.path, isDir: entry.isDir });
    };
    const apply = async (command: FileManagerCommand, selectedPath: string | null, message: string) => {
        const id = session.engagementId();
        if (!id || !session.api.manageFile) return;
        setSaving(true);
        setError("");
        try {
            await session.api.manageFile(id, command);
            setDialog(null);
            setRefreshTick((n) => n + 1);
            if (selectedPath !== null) session.selectFile(selectedPath || null);
            props.onChanged?.(message);
        } catch (cause) {
            setError(actionError(cause));
            setRefreshTick((n) => n + 1);
            if (!dialog()) props.onChanged?.(`File action failed: ${actionError(cause)}`);
        } finally {
            setSaving(false);
        }
    };
    const submitDialog = () => {
        const current = dialog();
        const trimmed = name().trim();
        if (!current || saving()) return;
        if (!validName(trimmed)) {
            setError("Use a name without slashes, control characters, or reserved names.");
            return;
        }
        if (current.kind === "rename") {
            const to = joinPath(parentOf(current.path), trimmed);
            if (to === current.path) { setDialog(null); return; }
            const selected = session.selectedFile();
            const nextSelection = selected === current.path ? to
                : current.isDir && selected?.startsWith(`${current.path}/`)
                    ? `${to}${selected.slice(current.path.length)}` : selected;
            void apply({ action: "rename", path: current.path, to },
                nextSelection,
                `renamed ${leafOf(current.path)} to ${trimmed}`);
            return;
        }
        const parent = current.parent ?? rootChoice();
        const path = joinPath(parent, trimmed);
        void apply({ action: current.kind, path }, current.kind === "create_file" ? path : session.selectedFile(),
            `created ${current.kind === "create_file" ? "file" : "folder"} ${trimmed}`);
    };
    const deleteEntry = (entry: FileEntry) => {
        const selected = session.selectedFile();
        const nextSelection = selected === entry.path || (entry.isDir && selected?.startsWith(`${entry.path}/`))
            ? "" : selected;
        void apply({ action: "delete", path: entry.path }, nextSelection, `deleted ${displayName(entry.path)}`);
    };
    const actionsFor = (entry: FileEntry): MenuItem[] => {
        const items: MenuItem[] = [];
        if (!entry.isDir) items.push({ label: "Open", run: () => session.selectFile(entry.path) });
        if (entry.isDir && canManage(entry.path)) {
            items.push({ label: "New file here", run: () => openCreate("file", entry.path) });
            items.push({ label: "New folder here", run: () => openCreate("folder", entry.path) });
        }
        if (canManage(entry.path) && !isRoot(entry.path)) {
            items.push({ label: "Rename", run: () => openRename(entry) });
            items.push({ label: "Delete", danger: true,
                confirmHint: entry.isDir ? "Removes this folder and everything inside it." : "Removes this file from the chat workspace.",
                run: () => deleteEntry(entry) });
        }
        return items;
    };
    const openMenu = (entry: FileEntry, x: number, y: number) => {
        const items = actionsFor(entry);
        if (items.length) setMenu({ x, y, items });
    };
    const showRootChoice = () => {
        const current = dialog();
        return current !== null && current.kind !== "rename"
            && current.parent === null && writableRoots().length > 1;
    };

    return <>
        <Show when={!tree.error} fallback={<LoadError what="the files" onRetry={() => void refetch()} />}>
            <Show when={tree()} fallback={<div class="status">loading…</div>}>
                <Show when={visibleEntries().length} fallback={<div class="status">No files yet. Use the Files menu to create or import one.</div>}>
                    <div class="filetree" data-worktree role="tree" aria-label="Chat files">
                        <For each={rows()}>
                            {(entry) => <div class="file-row" style={{ "--file-depth": String(depth(entry.path)) }}
                                data-file-path={entry.path}
                                onContextMenu={(event) => { event.preventDefault(); openMenu(entry, event.clientX, event.clientY); }}>
                                <button type="button" class="file" role="treeitem"
                                    aria-label={displayName(entry.path)}
                                    aria-expanded={entry.isDir ? !collapsed().has(entry.path) : undefined}
                                    classList={{ active: session.selectedFile() === entry.path, locked: isProtected(entry.path) }}
                                    title={entry.path}
                                    onClick={() => entry.isDir
                                        ? setCollapsed((current) => {
                                            const next = new Set(current);
                                            next.has(entry.path) ? next.delete(entry.path) : next.add(entry.path);
                                            return next;
                                        })
                                        : session.selectFile(entry.path)}
                                    onKeyDown={(event) => {
                                        if (event.key === "F10" && event.shiftKey) {
                                            event.preventDefault();
                                            const rect = event.currentTarget.getBoundingClientRect();
                                            openMenu(entry, rect.left, rect.bottom);
                                        }
                                    }}>
                                    <span class="file-kind" aria-hidden="true">{entry.isDir ? (collapsed().has(entry.path) ? "▸" : "▾") : "·"}</span>
                                    <Show when={latest().get(entry.path)}>{(run) => <RunDot state={run().state} />}</Show>
                                    <span class="file-name">{isProtected(entry.path) ? "🔒 " : ""}{displayName(entry.path)}</span>
                                </button>
                                <Show when={actionsFor(entry).length > 0}>
                                    <button type="button" class="file-row-menu" aria-label={`Actions for ${displayName(entry.path)}`}
                                        aria-haspopup="menu" title={`Actions for ${displayName(entry.path)}`}
                                        onClick={(event) => {
                                            const rect = event.currentTarget.getBoundingClientRect();
                                            window.setTimeout(() => openMenu(entry, rect.right, rect.bottom), 0);
                                        }}><Icon name="kebab" /></button>
                                </Show>
                            </div>}
                        </For>
                    </div>
                </Show>
                <Show when={hiddenCount() > 0}>
                    <button class="show-internal" data-show-internal onClick={() => setShowInternal((value) => !value)}>
                        {showInternal() ? "hide internal files" : `show ${hiddenCount()} internal file${hiddenCount() === 1 ? "" : "s"}`}
                    </button>
                </Show>
            </Show>
        </Show>
        <ContextMenu menu={menu()} onClose={() => setMenu(null)} />
        <Show when={dialog()}>
            {(current) => <div class="modal-overlay" data-file-dialog onClick={() => !saving() && setDialog(null)}>
                <form class="modal file-action-dialog" role="dialog" aria-modal="true"
                    aria-label={current().kind === "rename" ? "Rename" : current().kind === "create_file" ? "New file" : "New folder"}
                    onClick={(event) => event.stopPropagation()}
                    onKeyDown={(event) => event.key === "Escape" && !saving() && setDialog(null)}
                    onSubmit={(event) => { event.preventDefault(); submitDialog(); }}>
                    <div class="modal-head"><strong>{current().kind === "rename" ? "Rename" : current().kind === "create_file" ? "New file" : "New folder"}</strong></div>
                    <Show when={showRootChoice()}>
                        <label class="file-dialog-field">Location
                            <select value={rootChoice()} onChange={(event) => setRootChoice(event.currentTarget.value)}>
                                <For each={writableRoots()}>{(root) => <option value={root.path}>{root.name}</option>}</For>
                            </select>
                        </label>
                    </Show>
                    <label class="file-dialog-field">Name
                        <input ref={(element) => queueMicrotask(() => element.focus())} value={name()}
                            onInput={(event) => { setName(event.currentTarget.value); setError(""); }}
                            autocomplete="off" disabled={saving()} />
                    </label>
                    <Show when={error()}><p class="file-dialog-error" role="alert">{error()}</p></Show>
                    <div class="modal-actions">
                        <button type="button" disabled={saving()} onClick={() => setDialog(null)}>Cancel</button>
                        <button type="submit" disabled={saving() || !name().trim()}>
                            {saving() ? "Working…" : current().kind === "rename" ? "Rename" : "Create"}
                        </button>
                    </div>
                </form>
            </div>
            }</Show>
    </>;
}
