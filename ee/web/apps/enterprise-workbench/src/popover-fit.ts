/** Space above a bottom-anchored menu, inside its actual clipping pane. */
export function availablePopoverHeight(anchorTop: number, paneTop: number): number {
    if (!Number.isFinite(anchorTop) || !Number.isFinite(paneTop)) return 0;
    return Math.min(610, Math.max(0, anchorTop - Math.max(0, paneTop) - 10));
}
