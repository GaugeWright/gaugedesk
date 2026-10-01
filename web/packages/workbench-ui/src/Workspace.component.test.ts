// @vitest-environment happy-dom
import { createComponent, createSignal } from "solid-js";
import { render } from "solid-js/web";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { EngagementId, FileEntry } from "@gaugewright/control-plane-client";
import { SessionProvider, type Session } from "./session-context";
import { Workspace } from "./Workspace";

let dispose: (() => void) | undefined;
afterEach(() => { dispose?.(); document.body.replaceChildren(); });
function mount(getTree: (id: EngagementId) => Promise<FileEntry[]>) {
    const host = document.createElement("div");
    document.body.append(host);
    const [revision, setRevision] = createSignal(0);
    const session = {
        api: { getTree }, engagementId: () => "chat" as EngagementId,
        worktreeRev: revision, chatKind: () => "edit", selectedFile: () => null,
        selectFile: () => {},
    } as unknown as Session;
    dispose = render(() => createComponent(SessionProvider, {
        value: session, get children() { return createComponent(Workspace, {}); },
    }), host);
    return { host, setRevision };
}
const files: FileEntry[] = [{ path: "agent", isDir: true }, { path: "agent/SYSTEM.md", isDir: false }];

describe("mounted Workshop files pane", () => {
    it("replaces loading with files after the request resolves", async () => {
        let resolve!: (files: FileEntry[]) => void;
        const { host } = mount(() => new Promise((done) => { resolve = done; }));
        expect(host.textContent).toContain("loading");
        resolve(files);
        await vi.waitFor(() => expect(host.querySelector('[data-file-path="agent"]')).not.toBeNull());
        expect(host.textContent).not.toContain("loading");
    });

    it("renders a failed initial read and recovers through retry", async () => {
        const getTree = vi.fn().mockRejectedValueOnce(new Error("403 forbidden")).mockResolvedValue(files);
        const { host } = mount(getTree);
        await vi.waitFor(() => expect(host.querySelector("[data-load-error]")).not.toBeNull());
        expect(host.textContent).not.toContain("loading");
        (host.querySelector("[data-load-retry]") as HTMLButtonElement).click();
        await vi.waitFor(() => expect(host.querySelector('[data-file-path="agent"]')).not.toBeNull());
        expect(getTree).toHaveBeenCalledTimes(2);
        expect(host.querySelector("[data-load-error]")).toBeNull();
    });

    it("renders a failed refresh and recovers without remounting the pane", async () => {
        const getTree = vi.fn().mockResolvedValueOnce(files)
            .mockRejectedValueOnce(new Error("Home unavailable")).mockResolvedValue(files);
        const { host, setRevision } = mount(getTree);
        await vi.waitFor(() => expect(host.querySelector('[data-file-path="agent"]')).not.toBeNull());
        setRevision(1);
        await vi.waitFor(() => expect(host.querySelector("[data-load-error]")).not.toBeNull());
        (host.querySelector("[data-load-retry]") as HTMLButtonElement).click();
        await vi.waitFor(() => expect(host.querySelector('[data-file-path="agent"]')).not.toBeNull());
        expect(getTree).toHaveBeenCalledTimes(3);
    });
});
