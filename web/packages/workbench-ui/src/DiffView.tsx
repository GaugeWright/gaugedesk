/**
 * The content viewer's diff (Phase 3). A pure projection of the engagement
 * branch vs `main`: the backend emits a unified `git diff`, this renders it.
 *
 * The string is the only truth — there is no client-side diffing. We split the
 * multi-file diff into per-file segments (git-diff-view is per-file) and hand
 * each to `@git-diff-view/solid`, which gives us line numbers, hunk context,
 * intra-line highlights, syntax coloring, and a side-by-side toggle.
 */

import { For, Show, createSignal, onCleanup, onMount } from "solid-js";
import { DiffView as GitDiffView, DiffModeEnum, getLang } from "@git-diff-view/solid";
import "@git-diff-view/solid/styles/diff-view.css";
import { partitionedToolTarget } from "./tool-detail";
import { isTargetNameFile, targetNameForRoot, targetRenames, type TargetName } from "./target-names";

// Below this width the side-by-side split renders each column at a few characters,
// wrapping a sentence one-syllable-per-line — illegible on the app's primary review
// surface (#2 round-4). We only offer split when there's room for it.
const SPLIT_MIN_WIDTH = 720;

/** One file's slice of the unified diff, ready for git-diff-view's `data`. */
interface FileDiff {
    /** Stable list key — the path we display. */
    key: string;
    display: string;
    targetRoot: string | null;
    targetRelativePath: string;
    oldName: string;
    newName: string;
    lang: string;
    /** The file's raw unified-diff text (header + hunks), as git-diff-view wants. */
    hunks: string[];
}

/** `--- a/path` / `+++ b/path` → `path`; preserves the `/dev/null` sentinel. */
function stripPathPrefix(raw: string): string {
    const p = raw.split("\t")[0].trim();
    if (p === "/dev/null") return p;
    return p.startsWith("a/") || p.startsWith("b/") ? p.slice(2) : p;
}

/** Resolve a segment's old/new paths, preferring the `---`/`+++` lines. */
function segmentNames(seg: string[]): { oldName: string; newName: string } {
    let oldName = "";
    let newName = "";
    for (const l of seg) {
        if (l.startsWith("--- ")) oldName = stripPathPrefix(l.slice(4));
        else if (l.startsWith("+++ ")) newName = stripPathPrefix(l.slice(4));
        else if (l.startsWith("@@")) break; // header is over once hunks start
    }
    // Pure renames / mode changes / binaries carry no ---/+++; fall back to the
    // `diff --git a/X b/Y` line.
    if (!oldName && !newName) {
        const m = seg[0].match(/^diff --git a\/(.+) b\/(.+)$/);
        if (m) {
            oldName = m[1];
            newName = m[2];
        }
    }
    return { oldName, newName };
}

/** Split a multi-file `git diff` into per-file segments. */
function splitFiles(diff: string): FileDiff[] {
    if (!diff.trim()) return [];
    const files: FileDiff[] = [];
    let cur: string[] | null = null;
    const flush = () => {
        if (!cur || cur.length === 0) return;
        const { oldName, newName } = segmentNames(cur);
        const display = newName && newName !== "/dev/null" ? newName : oldName || newName;
        const partition = partitionedToolTarget(display);
        files.push({
            key: `${display}\u0000${files.length}`,
            display,
            targetRoot: partition.targetRoot,
            targetRelativePath: partition.relativePath,
            oldName: oldName || newName,
            newName: newName || oldName,
            lang: getLang(display) || "",
            hunks: [cur.join("\n")],
        });
        cur = null;
    };
    for (const line of diff.split("\n")) {
        if (line.startsWith("diff --git ")) {
            flush();
            cur = [line];
        } else if (cur) {
            cur.push(line);
        }
    }
    flush();
    return files;
}

/** Internal/config artifacts the review shouldn't lead with (round-6 #4). The
 *  Files panel already hides `.agent-config.json` behind a "show internal file"
 *  toggle; the changed-files review must agree, or the same file the app calls
 *  "internal" becomes the headline of every review (an empty `+ {}` a layperson
 *  can't read). Dotfiles are the internal artifacts here. */
function isInternalFile(display: string): boolean {
    const name = display.split("/").pop() ?? display;
    return name.startsWith(".");
}

export function DiffView(props: { diff: string; targets?: readonly TargetName[] }) {
    // A target's name file is shown as the rename it records, not as a file.
    const allFiles = () => splitFiles(props.diff).filter((f) => !isTargetNameFile(f.display));
    const renames = () => targetRenames(props.diff);
    const targetName = (root: string | null) => root ? targetNameForRoot(root, props.targets ?? []) : null;
    // Default the review to the user's actual deliverables; fold internal config
    // artifacts under a quiet disclosure so "2 files changed" reads as the one file
    // the user cares about. If *every* changed file is internal, show them (there's
    // nothing else to review) rather than an empty list.
    const userFiles = () => allFiles().filter((f) => !isInternalFile(f.display));
    const internalFiles = () => allFiles().filter((f) => isInternalFile(f.display));
    const [showInternal, setShowInternal] = createSignal(false);
    const files = () => {
        const u = userFiles();
        if (u.length === 0) return allFiles(); // nothing but internal — show it
        return showInternal() ? allFiles() : u;
    };
    const [split, setSplit] = createSignal(false);
    // Track the panel width so we can hide split where it would be illegible (#2).
    // Start FALSE — "only offer split when there's room": the toggle stays hidden
    // until the ResizeObserver measures a panel ≥ SPLIT_MIN_WIDTH. Starting true
    // rendered the toggle for a frame (and could stick if the first measurement
    // happened to land wide), making the narrow-panel state race the observer.
    const [wide, setWide] = createSignal(false);
    let rootEl: HTMLDivElement | undefined;
    onMount(() => {
        if (!rootEl || typeof ResizeObserver === "undefined") return;
        // Round-10 #1 — the renderer-freeze bug. The previous observer watched
        // `.diff` *itself*, whose width depends on the diff body it contains:
        // toggling `wide()` flips `diffViewWrap`, which adds/removes a horizontal
        // scrollbar, which nudges `.diff`'s own contentRect back across the
        // threshold — an unbounded observe→setWide→relayout→observe loop. A
        // ResizeObserver firing every frame starves the compositor: zero frames
        // commit (the screen freezes) while synchronous JS/DOM stays responsive —
        // exactly the reported symptom on the first chat click.
        //
        // Two guards make the loop impossible: (1) measure the *outer* element via
        // its parent (the panel column, whose width is set by the layout, not by
        // the diff content), and (2) defer the state write to the next frame and
        // only ever write when the boolean actually changes, so a callback can
        // never synchronously re-mutate the layout it's observing.
        const target = rootEl.parentElement ?? rootEl;
        let raf = 0;
        const ro = new ResizeObserver((entries) => {
            const w = entries[0]?.contentRect.width ?? 0;
            const next = w >= SPLIT_MIN_WIDTH;
            if (next === wide()) return; // no boundary cross — nothing to do
            if (raf) return; // a frame is already pending
            raf = requestAnimationFrame(() => {
                raf = 0;
                setWide(next);
            });
        });
        ro.observe(target);
        onCleanup(() => {
            if (raf) cancelAnimationFrame(raf);
            ro.disconnect();
        });
    });
    // Fall back to unified whenever the panel is too narrow for split — never render
    // split below the minimum width even if it was toggled on at a wider size.
    const mode = () => (split() && wide() ? DiffModeEnum.Split : DiffModeEnum.Unified);

    return (
        <Show when={files().length || renames().length} fallback={<div class="status">no changes</div>}>
            <div class="diff" ref={rootEl}>
                <div class="diff-toolbar">
                    <span class="status">
                        {[
                            files().length ? `${files().length} file${files().length === 1 ? "" : "s"} changed` : "",
                            renames().length ? `${renames().length} folder${renames().length === 1 ? "" : "s"} renamed` : "",
                        ].filter(Boolean).join(", ")}
                    </span>
                    {/* The internal config file is folded away by default (round-6 #4);
                        a quiet toggle reveals it for the curious, matching the Files
                        panel's "show internal file" disclosure. Only shown when there
                        is something to hide (a real deliverable alongside it). */}
                    <Show when={userFiles().length > 0 && internalFiles().length > 0}>
                        <button
                            class="link-button"
                            data-diff-internal-toggle
                            onClick={() => setShowInternal((v) => !v)}
                        >
                            {/* Round-10 #6 — this used to read "show N internal file(s)",
                                which sat directly under "N file(s) changed": two adjacent
                                "1 file" counts that mean different things (the changes you're
                                reviewing vs. a hidden-dotfile disclosure) invited a misread.
                                Phrase the disclosure as what it reveals — hidden config — so
                                it can't be mistaken for the change count above it. */}
                            {showInternal()
                                ? "hide the assistant's settings file"
                                : "also show hidden config files"}
                        </button>
                    </Show>
                    {/* Split is only offered with room to render it legibly. */}
                    <Show when={wide()}>
                        <span class="diff-mode">
                            <span class="tab" classList={{ active: !split() }} onClick={() => setSplit(false)}>
                                unified
                            </span>
                            <span class="tab" classList={{ active: split() }} onClick={() => setSplit(true)}>
                                split
                            </span>
                        </span>
                    </Show>
                </div>
                <For each={renames()}>
                    {(rename) => (
                        <div class="diff-file diff-rename" data-target-rename={rename.root}>
                            <div class="diff-file-head">
                                {rename.from ? `Renamed folder ${rename.from} to ${rename.to}` : `Named folder ${rename.to}`}
                            </div>
                        </div>
                    )}
                </For>
                <For each={files()}>
                    {(f) => (
                        <div class="diff-file" data-target-root={f.targetRoot ?? undefined}>
                            <div class="diff-file-head">
                                <Show when={targetName(f.targetRoot)}>
                                    {(name) => <span class="diff-target">Target {name()} · </span>}
                                </Show>
                                {f.targetRelativePath}
                            </div>
                            <GitDiffView
                                data={{
                                    oldFile: { fileName: f.oldName, fileLang: f.lang },
                                    newFile: { fileName: f.newName, fileLang: f.lang },
                                    hunks: f.hunks,
                                }}
                                diffViewMode={mode()}
                                diffViewTheme="dark"
                                diffViewHighlight
                                /* Wrap only where there's room (round-7 #4): on a
                                   narrow panel the gutter + sign column leave ~18
                                   chars, so wrapping shatters words ("tas/k:",
                                   "campaign" → "cam/paign"). Below the threshold,
                                   stop wrapping and let the body scroll sideways
                                   (CSS) — monospace lines stay legible. */
                                diffViewWrap={wide()}
                                diffViewFontSize={12}
                            />
                        </div>
                    )}
                </For>
            </div>
        </Show>
    );
}
