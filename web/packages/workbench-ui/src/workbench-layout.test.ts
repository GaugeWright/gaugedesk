import { describe, expect, it } from "vitest";
import { dragWorkbenchDivider, resolveWorkbenchLayout, type WorkbenchLayoutInput } from "./workbench-layout";

const base: WorkbenchLayoutInput = {
    width: 1200, includeFiles: true,
    collapsed: { nav: false, chat: false, content: false, files: false },
    navWidth: 206, filesWidth: 230, chatWidth: null, chatFraction: 0.5,
};
const total = (p: ReturnType<typeof resolveWorkbenchLayout>) =>
    p.nav + p.navDivider + p.chat + p.midDivider + p.content + p.filesDivider + p.files;

describe("workbench divider geometry", () => {
    it.each(["nav", "mid", "files"] as const)("moves only the panes beside %s", (divider) => {
        const initial = resolveWorkbenchLayout(base);
        const next = dragWorkbenchDivider(initial, divider, 40);
        expect(total(next)).toBeCloseTo(base.width);
        if (divider === "nav") {
            expect(next.nav).toBe(initial.nav + 40);
            expect(next.chat).toBe(initial.chat - 40);
            expect(next.content).toBe(initial.content);
            expect(next.files).toBe(initial.files);
        } else if (divider === "mid") {
            expect(next.chat).toBe(initial.chat + 40);
            expect(next.content).toBe(initial.content - 40);
            expect(next.nav).toBe(initial.nav);
            expect(next.files).toBe(initial.files);
        } else {
            expect(next.content).toBe(initial.content + 40);
            expect(next.files).toBe(initial.files - 40);
            expect(next.nav).toBe(initial.nav);
            expect(next.chat).toBe(initial.chat);
        }
    });

    it("stops at both adjacent minimums without creating extra width", () => {
        const initial = resolveWorkbenchLayout(base);
        for (const divider of ["nav", "mid", "files"] as const) {
            const farLeft = dragWorkbenchDivider(initial, divider, -10000);
            const farRight = dragWorkbenchDivider(initial, divider, 10000);
            expect(total(farLeft)).toBeCloseTo(base.width);
            expect(total(farRight)).toBeCloseTo(base.width);
            expect(farLeft.nav).toBeGreaterThanOrEqual(120);
            expect(farLeft.chat).toBeGreaterThanOrEqual(280);
            expect(farLeft.content).toBeGreaterThanOrEqual(240);
            expect(farLeft.files).toBeGreaterThanOrEqual(150);
            expect(farRight.nav).toBeGreaterThanOrEqual(120);
            expect(farRight.chat).toBeGreaterThanOrEqual(280);
            expect(farRight.content).toBeGreaterThanOrEqual(240);
            expect(farRight.files).toBeGreaterThanOrEqual(150);
        }
    });

    it("fits oversized saved widths into the viewport", () => {
        const layout = resolveWorkbenchLayout({ ...base, width: 1025, navWidth: 900, filesWidth: 900, chatFraction: 0.95 });
        expect(total(layout)).toBe(1025);
        expect(layout.chat).toBeGreaterThanOrEqual(280);
        expect(layout.content).toBeGreaterThanOrEqual(240);
        expect(layout.files).toBeGreaterThanOrEqual(150);
    });

    it("gives unused width to an open pane when the content pane is folded", () => {
        const layout = resolveWorkbenchLayout({
            ...base, collapsed: { ...base.collapsed, content: true },
        });
        expect(total(layout)).toBe(1200);
        expect(layout.midDivider).toBe(0);
        expect(layout.filesDivider).toBe(0);
        expect(layout.chat).toBeGreaterThan(280);
        expect(dragWorkbenchDivider(layout, "mid", 80)).toEqual(layout);
    });

    it("uses the content pane as the remaining width without a Files pane", () => {
        const layout = resolveWorkbenchLayout({ ...base, includeFiles: false });
        expect(total(layout)).toBe(1200);
        expect(layout.files).toBe(0);
        expect(layout.filesDivider).toBe(0);
    });
});
