// @vitest-environment happy-dom
import { createComponent, createSignal } from "solid-js";
import { render } from "solid-js/web";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { EngagementId, FileEntry } from "@gaugewright/control-plane-client";
import { SessionProvider, type Session } from "./session-context";
import { Workspace, type WorkspaceProps } from "./Workspace";

let dispose: (() => void) | undefined;
afterEach(() => { dispose?.(); document.body.replaceChildren(); });
function mount(getTree: (id: EngagementId) => Promise<FileEntry[]>, roots?: WorkspaceProps["roots"]) {
    const host = document.createElement("div");
    document.body.append(host);
    const [revision, setRevision] = createSignal(0);
    const session = {
        api: { getTree }, engagementId: () => "chat" as EngagementId,
        worktreeRev: revision, chatKind: () => "edit", selectedFile: () => null,
        selectFile: () => {},
    } as unknown as Session;
    dispose = render(() => createComponent(SessionProvider, {
        value: session, get children() { return createComponent(Workspace, { roots }); },
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

    // A chat across several targets shows each as a root folder named after
    // it, even a target that holds no file yet (DR-0248, navigation.md Files).
    it("names every selected target's root, including an empty one", async () => {
        const roots = [
            { path: "targets/main", name: "Project files", writable: true },
            { path: "targets/ref", name: "Reference target", writable: true },
        ];
        const listed: FileEntry[] = [
            { path: "targets", isDir: true },
            { path: "targets/main", isDir: true },
            { path: "targets/main/notes.md", isDir: false },
        ];
        const { host } = mount(() => Promise.resolve(listed), roots);
        await vi.waitFor(() => expect(host.querySelector('[data-file-path="targets/ref"]')).not.toBeNull());
        const names = [...host.querySelectorAll<HTMLElement>('[data-file-path^="targets/"] > .file')]
            .map((row) => row.getAttribute("aria-label"));
        expect(names).toEqual(["Project files", "notes.md", "Reference target"]);
    });

    it("keeps the empty state for a chat with one empty target", async () => {
        const { host } = mount(() => Promise.resolve([]), [{ path: "targets/main", name: "Project files", writable: true }]);
        await vi.waitFor(() => expect(host.textContent).toContain("No files yet"));
        expect(host.querySelector('[data-file-path="targets/main"]')).toBeNull();
    });
});
