/** Desktop pane geometry. Every divider owns only the panes on its two sides. */
export const PANE_RAIL = 30;
export const PANE_DIVIDER = 5;

const MIN = { nav: 120, chat: 280, content: 240, files: 150 } as const;
type Pane = keyof typeof MIN;
export type PaneDivider = "nav" | "mid" | "files";
const PANE_ORDER: readonly Pane[] = ["nav", "chat", "content", "files"];

export interface WorkbenchLayoutInput {
    width: number;
    includeFiles: boolean;
    collapsed: Record<Pane, boolean>;
    navWidth: number;
    filesWidth: number;
    chatWidth: number | null;
    chatFraction: number;
}

export interface WorkbenchLayout {
    nav: number;
    navDivider: number;
    chat: number;
    midDivider: number;
    content: number;
    filesDivider: number;
    files: number;
}

const clamp = (value: number, low: number, high: number) => Math.max(low, Math.min(high, value));

export function resolveWorkbenchLayout(input: WorkbenchLayoutInput): WorkbenchLayout {
    const { collapsed, includeFiles } = input;
    const navDivider = !collapsed.nav && !collapsed.chat ? PANE_DIVIDER : 0;
    const midDivider = !collapsed.chat && !collapsed.content ? PANE_DIVIDER : 0;
    const filesDivider = includeFiles && !collapsed.content && !collapsed.files ? PANE_DIVIDER : 0;
    const usable = Math.max(0, input.width - navDivider - midDivider - filesDivider);
    const widths = {
        nav: collapsed.nav ? PANE_RAIL : MIN.nav,
        chat: collapsed.chat ? PANE_RAIL : MIN.chat,
        content: collapsed.content ? PANE_RAIL : MIN.content,
        files: !includeFiles ? 0 : collapsed.files ? PANE_RAIL : MIN.files,
    };
    // Content normally absorbs window resizes. When it is folded, the next
    // available pane takes that role instead of leaving unclaimed grid space.
    const flexible: Pane = !collapsed.content ? "content"
        : !collapsed.chat ? "chat"
            : includeFiles && !collapsed.files ? "files" : "nav";
    let spare = Math.max(0, usable - widths.nav - widths.chat - widths.content - widths.files);
    const allocate = (pane: Pane, desired: number) => {
        if (pane === flexible || collapsed[pane] || (pane === "files" && !includeFiles)) return;
        const added = Math.min(spare, Math.max(0, desired - widths[pane]));
        widths[pane] += added;
        spare -= added;
    };
    allocate("nav", input.navWidth);
    allocate("files", input.filesWidth);
    const middle = usable - widths.nav - widths.files;
    allocate("chat", input.chatWidth ?? middle * clamp(input.chatFraction, 0, 1));
    widths[flexible] += spare;
    return { ...widths, navDivider, midDivider, filesDivider };
}

export function dragWorkbenchDivider(layout: WorkbenchLayout, divider: PaneDivider, deltaX: number): WorkbenchLayout {
    if (divider === "nav") {
        if (!layout.navDivider) return layout;
        const total = layout.nav + layout.chat;
        const nav = clamp(layout.nav + deltaX, MIN.nav, total - MIN.chat);
        return { ...layout, nav, chat: total - nav };
    }
    if (divider === "mid") {
        if (!layout.midDivider) return layout;
        const total = layout.chat + layout.content;
        const chat = clamp(layout.chat + deltaX, MIN.chat, total - MIN.content);
        return { ...layout, chat, content: total - chat };
    }
    if (!layout.filesDivider) return layout;
    const total = layout.content + layout.files;
    const content = clamp(layout.content + deltaX, MIN.content, total - MIN.files);
    return { ...layout, content, files: total - content };
}

/** A folded rail stays 30px wide. Dragging it divides space between the
 * nearest expanded panes on either side, even across several folded rails. */
export function workbenchRailResizePair(
    layout: WorkbenchLayout,
    collapsed: Record<Pane, boolean>,
    rail: Pane,
): readonly [Pane, Pane] | null {
    if (!collapsed[rail]) return null;
    const index = PANE_ORDER.indexOf(rail);
    const open = (pane: Pane) => !collapsed[pane] && (pane !== "files" || layout.files > 0);
    const left = PANE_ORDER.slice(0, index).reverse().find(open);
    const right = PANE_ORDER.slice(index + 1).find(open);
    return left && right ? [left, right] : null;
}

export function dragWorkbenchRail(
    layout: WorkbenchLayout,
    collapsed: Record<Pane, boolean>,
    rail: Pane,
    deltaX: number,
): WorkbenchLayout {
    const pair = workbenchRailResizePair(layout, collapsed, rail);
    if (!pair) return layout;
    const [left, right] = pair;
    const width = layout[left] + layout[right];
    const leftWidth = clamp(layout[left] + deltaX, MIN[left], width - MIN[right]);
    return { ...layout, [left]: leftWidth, [right]: width - leftWidth };
}
