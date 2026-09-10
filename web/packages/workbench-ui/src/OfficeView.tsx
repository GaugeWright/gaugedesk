/**
 * The View tab for a Word, Excel, or PowerPoint file.
 *
 * Rendered by `@silurus/ooxml` (MIT): Rust OOXML parsers compiled to WebAssembly
 * with TypeScript renderers painting onto Canvas 2D. The engine's source is
 * published, which is why it is here — a document renderer parses hostile input
 * on the workbench's own origin, and one we cannot read, patch, or rebuild is
 * not a dependency we can stand behind.
 *
 * **This view is read-only, and that is load-bearing.** Under ADR 0164 a
 * rendered page is *derived state*: a disposable materialization that creates
 * no work history and can never be authoritative. A renderer that also edited
 * would be a second write path into a document, bypassing the command →
 * WhippleScript effect → cut chain that makes the runtime log the answer to
 * "how did this project get this way". `@silurus/ooxml` puts editing, mutation
 * and round-tripping out of scope by design, so adopting it cannot open that
 * bypass. Keep it that way: if a future version grows a mutation API, it does
 * not get wired to a save.
 *
 * The bytes arrive from the worktree read the viewer already does, so nothing
 * is uploaded and nothing is fetched from a CDN — the parser wasm is emitted as
 * a local bundle asset. Untrusted documents are bounded by the engine's own
 * resource limits rather than trusted to be reasonable.
 */

import { createEffect, createSignal, lazy, onCleanup, Show, Suspense } from "solid-js";
import {
    MAX_DOCUMENT_UNCOMPRESSED_BYTES,
    MAX_DOCUMENT_ZIP_ENTRIES,
    MAX_DOCUMENT_INPUT_BYTES,
} from "./attachments";
import type { OfficeFormat } from "./file-kind";

// A deck pages rather than scrolls, so it brings its own shell — back/next, the
// position, and a present mode. Lazy like everything else on this path.
const DeckView = lazy(() => import("./DeckView").then((m) => ({ default: m.DeckView })));

/** What a hostile OOXML archive is allowed to cost. These are the bounds the
 *  composer's attachment parser already applies to a picked document
 *  (`attachments.ts`), reused deliberately: the same zip bomb should meet the
 *  same wall whether a person attaches it to a message or opens it in a pane. */
const RESOURCE_LIMITS = {
    maxArchiveEntryBytes: MAX_DOCUMENT_INPUT_BYTES,
    maxTotalInflatedBytes: MAX_DOCUMENT_UNCOMPRESSED_BYTES,
    maxArchiveEntries: MAX_DOCUMENT_ZIP_ENTRIES,
};

/** A document that has not rendered in this long is not going to. */
const WORKER_TIMEOUT_MS = 30_000;

/** The engine's viewers share the shape this view needs. */
interface MountedViewer {
    load(source: ArrayBuffer): Promise<unknown>;
    destroy(): void;
}

/** Engine options shared by every format: the archive bounds and the worker. */
const ENGINE_OPTIONS = {
    resourceLimits: RESOURCE_LIMITS,
    workerTimeoutMs: WORKER_TIMEOUT_MS,
    mode: "worker" as const,
};

async function mountViewer(
    format: Exclude<OfficeFormat, "pptx">,
    container: HTMLElement,
): Promise<MountedViewer> {
    // Imported per format so a spreadsheet never pays for the Word parser: each
    // format's wasm is its own ~1.7 MB chunk, fetched the first time one opens.
    const options = ENGINE_OPTIONS;
    switch (format) {
        case "docx": {
            const { DocxScrollViewer } = await import("@silurus/ooxml/docx");
            return new DocxScrollViewer(container, options) as unknown as MountedViewer;
        }
        case "xlsx": {
            const { XlsxViewer } = await import("@silurus/ooxml/xlsx");
            return new XlsxViewer(container, options) as unknown as MountedViewer;
        }
    }
}

export function OfficeView(props: {
    readonly format: OfficeFormat;
    readonly bytes: Uint8Array;
    readonly path: string;
}) {
    let host!: HTMLDivElement;
    const [failed, setFailed] = createSignal<string | null>(null);
    const [ready, setReady] = createSignal(false);

    createEffect(() => {
        const format = props.format;
        const bytes = props.bytes;
        if (format === "pptx") return; // the deck mounts its own viewer
        let viewer: MountedViewer | undefined;
        let dropped = false;
        setFailed(null);
        setReady(false);
        void (async () => {
            try {
                viewer = await mountViewer(format, host);
                if (dropped) {
                    viewer.destroy();
                    return;
                }
                // A copy of our own: the engine parses off the main thread and
                // may take the buffer with it.
                await viewer.load(new Uint8Array(bytes).buffer);
                if (!dropped) setReady(true);
            } catch (error) {
                if (!dropped) setFailed(messageFor(error));
            }
        })();
        onCleanup(() => {
            dropped = true;
            viewer?.destroy();
        });
    });

    return (
        <Show
            when={props.format !== "pptx" || failed()}
            fallback={
                <Suspense fallback={<div class="status">opening the deck…</div>}>
                    <DeckView
                        bytes={props.bytes}
                        path={props.path}
                        options={ENGINE_OPTIONS}
                        onFailure={(error) => setFailed(messageFor(error))}
                    />
                </Suspense>
            }
        >
            <div class="officeview" data-file-view data-file-media={props.format}>
                <Show when={failed()}>
                    <div class="status" data-office-error>{failed()}</div>
                </Show>
                <Show when={!failed() && !ready()}>
                    <div class="status">opening the document…</div>
                </Show>
                <div class="officeview-host" ref={host} />
            </div>
        </Show>
    );
}

/** A failed render is a fact about the file, so say which fact. The engine
 *  distinguishes a document that exceeds its bounds from one it cannot read,
 *  and those call for different things from the reader. */
function messageFor(error: unknown): string {
    const code = (error as { code?: unknown } | null)?.code;
    if (typeof code === "string" && code.startsWith("ooxml-")) {
        return code.includes("limit")
            ? "This document is too large to open here — its images or contents exceed what the viewer will decode."
            : "This document couldn't be opened. It may be damaged, password-protected, or use a feature the viewer doesn't read.";
    }
    return "This document couldn't be opened. It may be damaged, password-protected, or use a feature the viewer doesn't read.";
}
