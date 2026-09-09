/**
 * The View tab for a PDF.
 *
 * pdf.js is already in this tree — the composer's attachment path uses it to
 * pull text out of a picked PDF (`attachments.ts`). That path throws the
 * renderer away; this one keeps it, so a report the agent just wrote is read
 * as the document it is rather than as the text someone extracted from it.
 * Nothing new is depended on and nothing leaves the machine: the bytes come
 * from the worktree read and are drawn in the browser.
 *
 * The chunk is heavy, so {@link ContentViewer} imports this lazily and mounts
 * it keyed on the file — one document per mount, torn down when the selection
 * changes.
 *
 * Pages render as they are scrolled to. A hundred-page document otherwise
 * spends its first seconds rasterising pages nobody is looking at, and the
 * pane stays blank throughout.
 */

import {
    createEffect,
    createResource,
    createSignal,
    For,
    onCleanup,
    onMount,
    Show,
} from "solid-js";
import {
    getDocument,
    GlobalWorkerOptions,
    type PDFDocumentProxy,
    type RenderTask,
} from "pdfjs-dist";
// Emitted as a local asset by the bundler — no CDN fetch, same as the
// attachment parser's worker.
import workerSrc from "pdfjs-dist/build/pdf.worker.min.mjs?url";

GlobalWorkerOptions.workerSrc = workerSrc;

/** Zoom steps, as a multiple of fit-to-width. */
const ZOOM_STEPS = [0.5, 0.75, 1, 1.5, 2, 3] as const;
const FIT_STEP = 2;

interface LoadedPdf {
    readonly document: PDFDocumentProxy;
    readonly pages: number;
    /** Page one's height ÷ width, used to size the placeholders of pages that
     *  have not rendered yet. Mixed-orientation documents correct themselves
     *  as each page draws; the estimate only has to keep the scrollbar sane. */
    readonly aspect: number;
}

export function PdfView(props: { readonly bytes: Uint8Array; readonly path: string }) {
    let scroller!: HTMLDivElement;
    const [width, setWidth] = createSignal(0);
    const [zoom, setZoom] = createSignal(FIT_STEP);

    const [pdf] = createResource<LoadedPdf>(async () => {
        // pdf.js takes ownership of the buffer it is handed, and this one is
        // the viewer's copy of the file — hand it a copy of our own.
        const document = await getDocument({ data: props.bytes.slice() }).promise;
        const first = await document.getPage(1);
        const viewport = first.getViewport({ scale: 1 });
        return { document, pages: document.numPages, aspect: viewport.height / viewport.width };
    });
    onCleanup(() => void pdf()?.document.loadingTask.destroy());

    onMount(() => {
        const observer = new ResizeObserver(([entry]) => setWidth(entry.contentRect.width));
        observer.observe(scroller);
        setWidth(scroller.clientWidth);
        onCleanup(() => observer.disconnect());
    });

    // The CSS width one page is drawn at: the pane's width less its padding,
    // scaled by the zoom step.
    const pageWidth = () => Math.max(120, (width() - 32) * ZOOM_STEPS[zoom()]);
    const canZoom = (delta: number) => zoom() + delta >= 0 && zoom() + delta < ZOOM_STEPS.length;

    return (
        <div class="pdfview" data-file-view data-file-media="pdf">
            <div class="pdfview-bar">
                <span class="status" data-pdf-pages>
                    <Show when={pdf()} fallback="opening…">
                        {(loaded) => `${loaded().pages} page${loaded().pages === 1 ? "" : "s"}`}
                    </Show>
                </span>
                <div class="pdfview-zoom">
                    <button
                        data-pdf-zoom="out"
                        disabled={!canZoom(-1)}
                        onClick={() => setZoom((step) => step - 1)}
                        title="Show it smaller"
                    >
                        −
                    </button>
                    <span class="status" data-pdf-zoom-level>
                        {Math.round(ZOOM_STEPS[zoom()] * 100)}%
                    </span>
                    <button
                        data-pdf-zoom="in"
                        disabled={!canZoom(1)}
                        onClick={() => setZoom((step) => step + 1)}
                        title="Show it larger"
                    >
                        +
                    </button>
                </div>
            </div>
            <div class="pdfview-pages" ref={scroller}>
                <Show
                    when={pdf()}
                    fallback={
                        <div class="status">
                            <Show when={pdf.error} fallback="opening the document…">
                                This PDF couldn't be opened — it may be damaged or encrypted.
                            </Show>
                        </div>
                    }
                >
                    {(loaded) => (
                        <For each={Array.from({ length: loaded().pages }, (_, index) => index + 1)}>
                            {(pageNumber) => (
                                <PdfPage
                                    document={loaded().document}
                                    pageNumber={pageNumber}
                                    width={pageWidth}
                                    aspect={loaded().aspect}
                                />
                            )}
                        </For>
                    )}
                </Show>
            </div>
        </div>
    );
}

function PdfPage(props: {
    readonly document: PDFDocumentProxy;
    readonly pageNumber: number;
    readonly width: () => number;
    readonly aspect: number;
}) {
    let host!: HTMLDivElement;
    let canvas: HTMLCanvasElement | undefined;
    const [visible, setVisible] = createSignal(false);
    const [drawn, setDrawn] = createSignal(false);

    onMount(() => {
        // A page renders once it is within a screenful of the viewport, so
        // scrolling meets a drawn page rather than a blank one.
        const observer = new IntersectionObserver(
            (entries) => {
                if (entries.some((entry) => entry.isIntersecting)) {
                    setVisible(true);
                    observer.disconnect();
                }
            },
            { rootMargin: "400px 0px" },
        );
        observer.observe(host);
        onCleanup(() => observer.disconnect());
    });

    createEffect(() => {
        const width = props.width();
        if (!visible() || !canvas || width <= 0) return;
        let cancelled = false;
        let task: RenderTask | undefined;
        void (async () => {
            const page = await props.document.getPage(props.pageNumber);
            if (cancelled || !canvas) return;
            const base = page.getViewport({ scale: 1 });
            // Draw at the display's real pixel density, then let CSS size the
            // canvas back down — otherwise text is soft on every HiDPI screen.
            const ratio = window.devicePixelRatio || 1;
            const viewport = page.getViewport({ scale: (width / base.width) * ratio });
            canvas.width = Math.floor(viewport.width);
            canvas.height = Math.floor(viewport.height);
            canvas.style.width = `${width}px`;
            canvas.style.height = `${Math.floor(viewport.height / ratio)}px`;
            const context = canvas.getContext("2d");
            if (!context) return;
            task = page.render({ canvas, canvasContext: context, viewport });
            try {
                await task.promise;
                if (!cancelled) setDrawn(true);
            } catch {
                // A cancelled render is the ordinary case here: the pane was
                // resized or zoomed while this page was drawing.
            }
        })();
        onCleanup(() => {
            cancelled = true;
            task?.cancel();
        });
    });

    return (
        <div
            class="pdfview-page"
            classList={{ drawn: drawn() }}
            data-pdf-page={props.pageNumber}
            ref={host}
            style={{
                width: `${props.width()}px`,
                "min-height": drawn() ? undefined : `${Math.round(props.width() * props.aspect)}px`,
            }}
        >
            <canvas ref={canvas} />
        </div>
    );
}
