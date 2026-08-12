import type { JSX } from "solid-js";

/**
 * Inline, dependency-free icon set for the workbench's icon-driven controls.
 * Stroke-based on a 24px grid, drawn in `currentColor` so they inherit the
 * button's text colour (incl. hover/active). Each icon is decorative — the
 * button it sits in carries the real label via `aria-label`/`title` — so the
 * <svg> is `aria-hidden` and not focusable. Size comes from CSS (`.icon`).
 *
 * Most glyphs are Lucide (https://lucide.dev) path data, inlined rather than
 * imported: the desktop app and the embedded panels run under a strict CSP with
 * no CDN and no runtime icon lookup, and a whole icon package would ship for the
 * two dozen marks actually used. Lucide is ISC-licensed — see LICENSES.md.
 * Hand-drawn marks (add-files, add-folder, robot, sources, …) predate the
 * switch and are kept on the same 24px / 2px-stroke grid so the set reads as
 * one hand.
 */
export type IconName =
    | "add-files"
    | "add-folder"
    | "paperclip"
    | "sources"
    | "history"
    | "pull-latest"
    | "send"
    | "fork"
    | "steer"
    | "queue"
    | "stash"
    | "stop"
    | "edit"
    | "remove"
    | "grip"
    | "chevron"
    | "more"
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
        <path d="m16 6-8.414 8.586a2 2 0 0 0 2.829 2.829l8.414-8.586a4 4 0 1 0-5.657-5.657l-8.379 8.551a6 6 0 1 0 8.485 8.485l8.379-8.551" />
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

    /* --- the composer's delivery grammar -----------------------------------
       Three families, each with one job, so nothing has to be decoded:

       - ONE primary glyph, `send` (an up arrow). It never changes, because what
         changes is *when* the message runs, and saying that is the mode's job.
       - ONE halting glyph, `stop` (a filled square), used nowhere else.
       - THREE mode glyphs naming when the next message runs: now, after this
         turn, or not until you say.

       The old rail mixed a paper plane, a play triangle and an outlined square,
       which read as three unrelated metaphors for one decision. */

    // An up arrow — dispatch the composed message. The single primary action.
    send: () => (
        <>
            <path d="m5 12 7-7 7 7" />
            <path d="M12 19V5" />
        </>
    ),
    // A double chevron — steer mode: push straight through, now, interrupting the
    // running turn. (Lucide's bolt is drawn as a filled silhouette; rendered as a
    // 2px outline at rail size it collapses into an unreadable polygon. Every
    // glyph in this set has to survive as pure stroke.)
    steer: () => (
        <>
            <path d="m6 17 5-5-5-5" />
            <path d="m13 17 5-5-5-5" />
        </>
    ),
    // A branching fork — send this message down a new line of the conversation,
    // leaving the current one where it is.
    fork: () => (
        <>
            <circle cx="12" cy="18" r="3" />
            <circle cx="6" cy="6" r="3" />
            <circle cx="18" cy="6" r="3" />
            <path d="M18 9v2c0 .6-.4 1-1 1H7c-.6 0-1-.4-1-1V9" />
            <path d="M12 12v3" />
        </>
    ),
    // A list with a plus — queue mode: the message joins the line and runs on
    // its own once the current turn finishes.
    queue: () => (
        <>
            <path d="M16 5H3" />
            <path d="M11 12H3" />
            <path d="M16 19H3" />
            <path d="M18 9v6" />
            <path d="M21 12h-6" />
        </>
    ),
    // A lidded box — stash mode: the message joins the line and stays there.
    // Nothing runs until it is released by hand.
    stash: () => (
        <>
            <rect width="20" height="5" x="2" y="3" rx="1" />
            <path d="M4 8v11a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8" />
            <path d="M10 12h4" />
        </>
    ),
    // A filled square — halt the running turn. Filled, and the only member of
    // its family: a 2px-stroked square at 15px reads as an empty box, and the
    // one irreversible control in the rail should not be ambiguous.
    stop: () => (
        <rect width="15" height="15" x="4.5" y="4.5" rx="2.5" fill="currentColor" stroke="none" />
    ),

    /* --- queued-item row controls ------------------------------------------ */

    // A pencil on a card — edit this queued message's text before it runs.
    edit: () => (
        <>
            <path d="M12 3H5a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7" />
            <path d="M18.375 2.625a1 1 0 0 1 3 3l-9.013 9.014a2 2 0 0 1-.853.505l-2.873.84a.5.5 0 0 1-.62-.62l.84-2.873a2 2 0 0 1 .506-.852z" />
        </>
    ),
    // A cross — drop this queued message.
    remove: () => (
        <>
            <path d="M18 6 6 18" />
            <path d="m6 6 12 12" />
        </>
    ),
    // Two dotted columns — the drag handle that reorders the queue.
    grip: () => (
        <>
            <circle cx="9" cy="12" r="1" fill="currentColor" />
            <circle cx="9" cy="5" r="1" fill="currentColor" />
            <circle cx="9" cy="19" r="1" fill="currentColor" />
            <circle cx="15" cy="12" r="1" fill="currentColor" />
            <circle cx="15" cy="5" r="1" fill="currentColor" />
            <circle cx="15" cy="19" r="1" fill="currentColor" />
        </>
    ),

    /* --- menus -------------------------------------------------------------- */

    // A small downward chevron — this text is a menu, not a label.
    chevron: () => (
        <path d="m6 9 6 6 6-6" />
    ),
    // A horizontal ellipsis — the one expander a narrow rail collapses its
    // non-essential controls behind, so delivery never gets crushed.
    more: () => (
        <>
            <circle cx="5" cy="12" r="1" fill="currentColor" />
            <circle cx="12" cy="12" r="1" fill="currentColor" />
            <circle cx="19" cy="12" r="1" fill="currentColor" />
        </>
    ),
    // A funnel — filter which event types the chat log shows.
    filter: () => (
        <path d="M22 3H2l8 9.46V19l4 2v-8.54L22 3Z" />
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
