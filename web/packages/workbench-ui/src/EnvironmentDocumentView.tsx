import { createMemo, createSignal, For, lazy, Show, Suspense, type JSX } from "solid-js";
import {
    EnvironmentViewError,
    manifestDocumentForPath,
    parseEnvironmentView,
    resolveDocumentPath,
    type EnvironmentDocumentBinding,
    type EnvironmentManifest,
    type EnvironmentViewNode,
} from "./environment-view";

const MarkdownView = lazy(() => import("./MarkdownView").then((module) => ({ default: module.MarkdownView })));

export interface EnvironmentViewCommand {
    readonly label?: string;
    readonly run: () => void | Promise<void>;
}

export interface EnvironmentComplexViewProps {
    readonly document: unknown;
    readonly attributes: Readonly<Record<string, string>>;
    readonly children: readonly EnvironmentViewNode[];
    readonly commands: Readonly<Record<string, EnvironmentViewCommand>>;
}

export type EnvironmentComplexView = (props: EnvironmentComplexViewProps) => JSX.Element;

export interface EnvironmentViewRegistry {
    readonly manifest: EnvironmentManifest;
    /** View path relative to `.environment/`, mapped to constrained MDX source. */
    readonly views: Readonly<Record<string, string>>;
    /** Every schema id in the manifest must have an explicit validator. */
    readonly schemas: Readonly<Record<string, (document: unknown) => boolean>>;
    readonly components?: Readonly<Record<string, EnvironmentComplexView>>;
    /** Authenticated server-discovered command ids only. */
    readonly commands?: Readonly<Record<string, EnvironmentViewCommand>>;
    readonly internalRoot?: string;
}

/** The components a View may use without the registry supplying one.
 *
 * Exported so a bundle carried from another repository can be held to it
 * by a test rather than by a second copy of the list, which would drift. */
export const BUILTIN_COMPONENTS: ReadonlySet<string> =
    new Set(["Field", "Table", "Metric", "Notice", "Command", "Tabs", "Grid"]);

function display(value: unknown): string {
    if (value === null) return "None";
    if (value === undefined) return "Unknown";
    if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") return String(value);
    return JSON.stringify(value);
}

function CommandElement(props: {
    readonly id: string;
    readonly label: string;
    readonly command?: EnvironmentViewCommand;
}): JSX.Element {
    const [status, setStatus] = createSignal("");
    const run = async () => {
        if (!props.command) return;
        setStatus("working…");
        try {
            await props.command.run();
            setStatus("done");
        } catch (error) {
            setStatus(error instanceof Error ? error.message : String(error));
        }
    };
    return (
        <div class="environment-command" data-environment-command={props.id}>
            <Show
                when={props.command}
                fallback={<span class="status" data-command-unavailable>Unavailable in this session</span>}
            >
                <button type="button" onClick={() => void run()}>{props.label}</button>
            </Show>
            <Show when={status()}><span class="status">{status()}</span></Show>
        </div>
    );
}

function ViewNodes(props: {
    readonly nodes: readonly EnvironmentViewNode[];
    readonly document: unknown;
    readonly components: Readonly<Record<string, EnvironmentComplexView>>;
    readonly commands: Readonly<Record<string, EnvironmentViewCommand>>;
}): JSX.Element {
    return <For each={props.nodes}>{(node) => {
        if (node.kind === "text") return <Suspense><MarkdownView text={node.value} /></Suspense>;
        const attr = node.attributes;
        const children = () => (
            <ViewNodes
                nodes={node.children}
                document={props.document}
                components={props.components}
                commands={props.commands}
            />
        );
        if (node.name === "Grid") {
            return <div class="environment-grid" style={{ "--environment-columns": attr.columns || "2" }}>{children()}</div>;
        }
        if (node.name === "Tabs") return <div class="environment-tabs">{children()}</div>;
        if (node.name === "Metric") {
            return <div class="environment-metric"><span>{attr.label || attr.value}</span><strong>{display(resolveDocumentPath(props.document, attr.value || ""))}</strong></div>;
        }
        if (node.name === "Field") {
            return <div class="environment-field"><span>{attr.label || attr.value}</span><code>{display(resolveDocumentPath(props.document, attr.value || ""))}</code></div>;
        }
        if (node.name === "Notice") {
            return <aside class="environment-notice" data-tone={attr.tone || "info"}>{attr.text || children()}</aside>;
        }
        if (node.name === "Table") {
            const rows = resolveDocumentPath(props.document, attr.value || "");
            const columns = (attr.columns || "").split(",").map((column) => column.trim()).filter(Boolean);
            return (
                <table class="environment-table">
                    <thead><tr><For each={columns}>{(column) => <th>{column}</th>}</For></tr></thead>
                    <tbody><For each={Array.isArray(rows) ? rows : []}>{(row) => <tr><For each={columns}>{(column) => <td>{display(resolveDocumentPath(row, column))}</td>}</For></tr>}</For></tbody>
                </table>
            );
        }
        if (node.name === "Command") {
            const id = attr.id || "";
            const command = props.commands[id];
            return <CommandElement id={id} label={attr.label || command?.label || id} command={command} />;
        }
        const component = props.components[node.name];
        return component ? component({ document: props.document, attributes: attr, children: node.children, commands: props.commands }) : <></>;
    }}</For>;
}

function genericJson(content: string): JSX.Element {
    return <pre class="filebody" data-file-view data-environment-view-fallback>{content}</pre>;
}

type ViewResolution =
    | { readonly kind: "none" }
    | { readonly kind: "fallback"; readonly binding: EnvironmentDocumentBinding }
    | {
        readonly kind: "view";
        readonly binding: EnvironmentDocumentBinding;
        readonly document: unknown;
        readonly nodes: readonly EnvironmentViewNode[];
    };

export function EnvironmentDocumentView(props: {
    readonly registry: EnvironmentViewRegistry;
    readonly path: string;
    readonly content: string;
    readonly onSelectFile?: (path: string) => void;
    readonly onHelp?: (path: string) => void;
}): JSX.Element {
    const resolution = createMemo<ViewResolution>(() => {
        const binding = manifestDocumentForPath(props.registry.manifest, props.path);
        if (!binding) return { kind: "none" };
        try {
            const document = JSON.parse(props.content) as unknown;
            const validate = props.registry.schemas[binding.schema];
            if (!validate || !validate(document)) return { kind: "fallback", binding };
            if (!binding.view || !props.registry.views[binding.view]) return { kind: "fallback", binding };
            const allowed = new Set([...BUILTIN_COMPONENTS, ...Object.keys(props.registry.components ?? {})]);
            const nodes = parseEnvironmentView(props.registry.views[binding.view]!, allowed);
            return { kind: "view", binding, document, nodes };
        } catch (error) {
            if (error instanceof SyntaxError || error instanceof EnvironmentViewError) {
                return { kind: "fallback", binding };
            }
            throw error;
        }
    });
    const helpPath = (binding: EnvironmentDocumentBinding): string | null => {
        if (!binding.help) return null;
        return `${props.registry.internalRoot ?? ".environment"}/${binding.help}`;
    };
    return (
        <Show when={resolution()}>{(result) => (
            <Show when={result().kind === "view"} fallback={genericJson(props.content)}>
                {(() => {
                    const view = result() as Extract<ViewResolution, { kind: "view" }>;
                    const help = helpPath(view.binding);
                    const openHelp = props.onHelp ?? props.onSelectFile;
                    return (
                        <div class="environment-document-view" data-environment-document={view.binding.id}>
                            <Show when={help && openHelp}><button class="environment-help" type="button" onClick={() => openHelp!(help!)}>help</button></Show>
                            <ViewNodes
                                nodes={view.nodes}
                                document={view.document}
                                components={props.registry.components ?? {}}
                                commands={props.registry.commands ?? {}}
                            />
                        </div>
                    );
                })()}
            </Show>
        )}</Show>
    );
}
