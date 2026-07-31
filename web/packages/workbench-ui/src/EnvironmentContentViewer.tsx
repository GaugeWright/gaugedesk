import { createEffect, createResource, createSignal, lazy, on, onCleanup, Show, Suspense, type JSX } from "solid-js";
import { EnvironmentDocumentView, type EnvironmentViewRegistry } from "./EnvironmentDocumentView";
import { useSession } from "./session-context";

const MarkdownView = lazy(() => import("./MarkdownView").then((module) => ({ default: module.MarkdownView })));

type EnvironmentContentMode = "details" | "json";

export interface EnvironmentContentViewerProps {
    readonly registry: EnvironmentViewRegistry;
    readonly refreshKey?: () => unknown;
}

/**
 * The management-document viewer. A projected document has two honest human
 * representations: its purpose-built, interactive Details surface and its
 * canonical JSON. Editing and reviewing project files remain ContentViewer
 * concerns; management commands live in the Details projection instead.
 */
export function EnvironmentContentViewer(props: EnvironmentContentViewerProps): JSX.Element {
    const session = useSession();
    const file = () => session.selectedFile();
    const [mode, setMode] = createSignal<EnvironmentContentMode>("details");
    const [helpPath, setHelpPath] = createSignal<string | null>(null);
    const [content] = createResource(
        () => {
            const id = session.engagementId();
            const path = file();
            const revision = props.refreshKey?.();
            return id && path ? ([id, path, revision] as const) : null;
        },
        ([id, path]) => session.api.getFile(id, path),
    );
    const [helpContent] = createResource(
        () => {
            const id = session.engagementId();
            const path = helpPath();
            return id && path ? ([id, path] as const) : null;
        },
        ([id, path]) => session.api.getFile(id, path),
    );

    createEffect(on(file, (path) => {
        if (!path) return;
        setMode("details");
        setHelpPath(null);
    }));
    createEffect(() => {
        if (!helpPath()) return;
        const closeOnEscape = (event: KeyboardEvent) => event.key === "Escape" && setHelpPath(null);
        window.addEventListener("keydown", closeOnEscape);
        onCleanup(() => window.removeEventListener("keydown", closeOnEscape));
    });

    const tab = (value: EnvironmentContentMode, label: string, title: string) => (
        <button
            type="button"
            class="tab environment-content-tab"
            classList={{ active: mode() === value }}
            role="tab"
            aria-selected={mode() === value}
            data-document-mode={value}
            title={title}
            onClick={() => setMode(value)}
        >
            {label}
        </button>
    );

    return <div class="viewer environment-content-viewer">
        <div class="tabs" role="tablist" aria-label="Document representation">
            {tab("details", "Details", "Interactive document details")}
            {tab("json", "JSON", "Canonical JSON document")}
            <Show when={file()}>
                <span class="status viewer-filename" title={file() ?? ""}>{file()}</span>
            </Show>
        </div>
        <Show when={file()} fallback={<div class="status">Choose an item from the navigation.</div>}>
            <Show when={!content.loading} fallback={<div class="status">loading…</div>}>
                <Show
                    when={mode() === "details"}
                    fallback={<pre class="filebody" data-file-json>{content() ?? ""}</pre>}
                >
                    <EnvironmentDocumentView
                        registry={props.registry}
                        path={file()!}
                        content={content() ?? ""}
                        onHelp={setHelpPath}
                    />
                </Show>
            </Show>
        </Show>
        <Show when={helpPath()}>
            <div class="modal-overlay" data-environment-help onClick={() => setHelpPath(null)}>
                <div
                    class="modal environment-help-dialog"
                    role="dialog"
                    aria-modal="true"
                    aria-label="Help"
                    onClick={(event) => event.stopPropagation()}
                >
                    <div class="modal-head">
                        <h3>Help</h3>
                        <button type="button" aria-label="Close help" onClick={() => setHelpPath(null)}>×</button>
                    </div>
                    <Show when={!helpContent.loading} fallback={<div class="status">loading help…</div>}>
                        <Suspense fallback={<pre class="filebody">{helpContent() ?? ""}</pre>}>
                            <MarkdownView text={helpContent() ?? ""} />
                        </Suspense>
                    </Show>
                </div>
            </div>
        </Show>
    </div>;
}
