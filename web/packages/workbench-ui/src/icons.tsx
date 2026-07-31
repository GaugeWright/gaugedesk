import type { JSX } from "solid-js";

/**
 * Inline, dependency-free icon set for the workbench's icon-driven controls.
 * Stroke-based on a 24px grid, drawn in `currentColor` so they inherit the
 * button's text colour (incl. hover/active). Each icon is decorative — the
 * button it sits in carries the real label via `aria-label`/`title` — so the
 * <svg> is `aria-hidden` and not focusable. Size comes from CSS (`.icon`).
 */
export type IconName =
    | "add-files"
    | "add-folder"
    | "paperclip"
    | "sources"
    | "history"
    | "pull-latest"
    | "send"
    | "queue"
    | "filter"
    | "git-branch"
    | "robot"
    | "kebab"
    | "pencil";

// Each entry is a *factory*, not a stored element: Solid evaluates JSX into real
// DOM nodes eagerly, and a node can only live under one parent. An icon used by
// two buttons (add-files, paperclip) would otherwise have its single node
// reparented to the last mounter, leaving the earlier button blank. Calling the
// factory per render mints fresh nodes for each `<Icon>`.
const PATHS: Record<IconName, () => JSX.Element> = {
    // A document with a plus — add a single file to the chat's workspace.
    "add-files": () => (
        <>
            <path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z" />
            <path d="M14 3v5h5" />
            <line x1="12" y1="12" x2="12" y2="17" />
            <line x1="9.5" y1="14.5" x2="14.5" y2="14.5" />
        </>
    ),
    // A folder with a plus — add a whole folder of files to the chat's workspace.
    "add-folder": () => (
        <>
            <path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z" />
            <line x1="12" y1="11" x2="12" y2="17" />
            <line x1="9" y1="14" x2="15" y2="14" />
        </>
    ),
    // A paperclip — attach file(s) to the message being composed (their text is
    // inlined into the turn; message-scoped, not workspace context).
    paperclip: () => (
        <path d="M21.44 11.05l-9.19 9.19a6 6 0 0 1-8.49-8.49l9.19-9.19a4 4 0 0 1 5.66 5.66l-9.2 9.19a2 2 0 0 1-2.83-2.83l8.49-8.48" />
    ),
    // Stacked layers — the context/sources the chat is working with.
    sources: () => (
        <>
            <path d="M12 2 2 7l10 5 10-5-10-5Z" />
            <path d="m2 12 10 5 10-5" />
            <path d="m2 17 10 5 10-5" />
        </>
    ),
    // A clock with a counter-clockwise arrow — the chat's timeline/history.
    history: () => (
        <>
            <path d="M3 3v5h5" />
            <path d="M3.05 13A9 9 0 1 0 6 5.3L3 8" />
            <path d="M12 7v5l4 2" />
        </>
    ),
    // Circular refresh arrows — pull in / sync the latest shared changes. (A
    // down-into-tray arrow read as "download/export", the wrong affordance for
    // "update from the shared copy" — round-11 #5.)
    "pull-latest": () => (
        <>
            <path d="M21 12a9 9 0 1 1-2.64-6.36" />
            <path d="M21 3v6h-6" />
        </>
    ),
    // A paper plane — dispatch the composed message now.
    send: () => (
        <>
            <path d="m22 2-7 20-4-9-9-4Z" />
            <path d="M22 2 11 13" />
        </>
    ),
    // A funnel — filter which event types the chat log shows.
    filter: () => (
        <path d="M22 3H2l8 9.46V19l4 2v-8.54L22 3Z" />
    ),
    // A list with a plus — add the message to the run queue.
    queue: () => (
        <>
            <path d="M11 12H3" />
            <path d="M16 6H3" />
            <path d="M16 18H3" />
            <path d="M18 9v6" />
            <path d="M21 12h-6" />
        </>
    ),
    // A branching commit graph — a workstream is a shared line of work branching
    // from, and eventually promoting back into, its project mainline.
    "git-branch": () => (
        <>
            <circle cx="6" cy="4" r="2" />
            <circle cx="18" cy="6" r="2" />
            <circle cx="6" cy="20" r="2" />
            <path d="M6 6v12" />
            <path d="M18 8c0 5.5-3.5 9-10 9" />
        </>
    ),
    // A small robot face — chats are conversations with an agent, regardless of
    // whether their root edits an archetype or works in a project placement.
    robot: () => (
        <>
            <rect x="4" y="7" width="16" height="13" rx="2" />
            <path d="M12 3v4" />
            <path d="M8 12h.01" />
            <path d="M16 12h.01" />
            <path d="M8 16h8" />
        </>
    ),
    // Three dots — a row's "more actions" menu affordance (ADR 0112). Filled,
    // not stroked: 1.6px outline circles read as specks at row size.
    kebab: () => (
        <>
            <circle cx="12" cy="5" r="1.9" fill="currentColor" stroke="none" />
            <circle cx="12" cy="12" r="1.9" fill="currentColor" stroke="none" />
            <circle cx="12" cy="19" r="1.9" fill="currentColor" stroke="none" />
        </>
    ),
    // A pencil — edit this archetype (the Library row's primary action).
    pencil: () => (
        <path d="M4 20l1.2-4.2L16.5 4.5a1.9 1.9 0 0 1 2.7 0l.3.3a1.9 1.9 0 0 1 0 2.7L8.2 18.8 4 20Z" />
    ),
};

export function Icon(props: { name: IconName; class?: string }): JSX.Element {
    return (
        <svg
            class={`icon ${props.class ?? ""}`}
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            stroke-width="2"
            stroke-linecap="round"
            stroke-linejoin="round"
            aria-hidden="true"
        >
            {PATHS[props.name]()}
        </svg>
    );
}
