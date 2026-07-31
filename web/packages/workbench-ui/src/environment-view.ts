/**
 * Pure contract and parser for ADR 0107's manifest-linked document Views.
 * This is deliberately not an MDX compiler: it accepts a small declarative
 * JSX/Markdown subset and therefore never evaluates imports, expressions, or
 * tenant-supplied JavaScript.
 */

export interface EnvironmentDocumentBinding {
    readonly id: string;
    readonly path: string;
    readonly schema: string;
    readonly view?: string;
    readonly help?: string;
}

export interface EnvironmentManifest {
    readonly version: 1;
    readonly documents: readonly EnvironmentDocumentBinding[];
}

export type EnvironmentViewNode =
    | { readonly kind: "text"; readonly value: string }
    | {
        readonly kind: "element";
        readonly name: string;
        readonly attributes: Readonly<Record<string, string>>;
        readonly children: readonly EnvironmentViewNode[];
    };

export class EnvironmentViewError extends Error {}

const safeRelativePath = (value: string): boolean =>
    value.length > 0 &&
    !value.startsWith("/") &&
    !value.includes("\\") &&
    !value.split("/").includes("..") &&
    !value.includes("\0");

function record(value: unknown): Record<string, unknown> | null {
    return typeof value === "object" && value !== null && !Array.isArray(value)
        ? value as Record<string, unknown>
        : null;
}

export function parseEnvironmentManifest(value: unknown): EnvironmentManifest {
    const root = record(value);
    if (!root || root.version !== 1 || !Array.isArray(root.documents)) {
        throw new EnvironmentViewError("Environment manifest must be version 1 with a documents array.");
    }
    const ids = new Set<string>();
    const paths = new Set<string>();
    const documents = root.documents.map((candidate, index): EnvironmentDocumentBinding => {
        const item = record(candidate);
        const id = item?.id;
        const path = item?.path;
        const schema = item?.schema;
        const view = item?.view;
        const help = item?.help;
        if (typeof id !== "string" || !id.trim()) {
            throw new EnvironmentViewError(`Environment manifest document ${index} has no stable id.`);
        }
        if (typeof path !== "string" || !safeRelativePath(path)) {
            throw new EnvironmentViewError(`Environment manifest document ${id} has an unsafe path.`);
        }
        if (typeof schema !== "string" || !schema.trim()) {
            throw new EnvironmentViewError(`Environment manifest document ${id} has no schema.`);
        }
        if (view !== undefined && (typeof view !== "string" || !safeRelativePath(view))) {
            throw new EnvironmentViewError(`Environment manifest document ${id} has an unsafe View path.`);
        }
        if (help !== undefined && (typeof help !== "string" || !safeRelativePath(help))) {
            throw new EnvironmentViewError(`Environment manifest document ${id} has an unsafe Help path.`);
        }
        if (ids.has(id) || paths.has(path)) {
            throw new EnvironmentViewError(`Environment manifest document ${id} duplicates an id or path.`);
        }
        ids.add(id);
        paths.add(path);
        return { id, path, schema, ...(view ? { view } : {}), ...(help ? { help } : {}) };
    });
    return { version: 1, documents };
}

export function manifestDocumentForPath(
    manifest: EnvironmentManifest,
    path: string,
): EnvironmentDocumentBinding | undefined {
    return manifest.documents.find((document) => document.path === path);
}

function parseAttributes(source: string): Readonly<Record<string, string>> {
    const attributes: Record<string, string> = {};
    let rest = source.trim();
    const attribute = /^([A-Za-z][A-Za-z0-9_-]*)\s*=\s*"([^"{}]*)"\s*/;
    while (rest.length) {
        const match = rest.match(attribute);
        if (!match) throw new EnvironmentViewError("View attributes must be unique literal double-quoted strings.");
        if (Object.hasOwn(attributes, match[1]!)) {
            throw new EnvironmentViewError(`View attribute ${match[1]} is duplicated.`);
        }
        attributes[match[1]!] = match[2]!;
        rest = rest.slice(match[0].length);
    }
    return attributes;
}

/** Parse constrained MDX: Markdown text plus allowlisted PascalCase JSX tags. */
export function parseEnvironmentView(
    source: string,
    allowedComponents: ReadonlySet<string>,
): readonly EnvironmentViewNode[] {
    if (/\{[^}]*\}|^\s*(?:import|export)\s/m.test(source)) {
        throw new EnvironmentViewError("View expressions, imports, and exports are not allowed.");
    }

    type MutableElement = {
        kind: "element";
        name: string;
        attributes: Readonly<Record<string, string>>;
        children: EnvironmentViewNode[];
    };
    const root: EnvironmentViewNode[] = [];
    const stack: MutableElement[] = [];
    const append = (node: EnvironmentViewNode) => {
        const parent = stack.at(-1);
        if (parent) parent.children.push(node);
        else root.push(node);
    };

    const tags = /<\/?[A-Za-z][A-Za-z0-9]*(?:\s+[^<>]*?)?\s*\/?>/g;
    let offset = 0;
    for (const match of source.matchAll(tags)) {
        const index = match.index;
        if (index > offset) {
            const value = source.slice(offset, index);
            if (value.trim()) append({ kind: "text", value });
        }
        const raw = match[0];
        const closing = raw.startsWith("</");
        const selfClosing = raw.endsWith("/>");
        const body = raw.slice(closing ? 2 : 1, raw.length - (selfClosing ? 2 : 1)).trim();
        const separator = body.search(/\s/);
        const name = separator === -1 ? body : body.slice(0, separator);
        const attributeSource = separator === -1 ? "" : body.slice(separator + 1);
        if (!/^[A-Z][A-Za-z0-9]*$/.test(name) || !allowedComponents.has(name)) {
            throw new EnvironmentViewError(`View component ${name || "<unknown>"} is not allowed.`);
        }
        if (closing) {
            if (attributeSource) throw new EnvironmentViewError("Closing View tags cannot have attributes.");
            const opened = stack.pop();
            if (!opened || opened.name !== name) {
                throw new EnvironmentViewError(`View closing tag ${name} does not match its parent.`);
            }
        } else {
            const element: MutableElement = {
                kind: "element",
                name,
                attributes: parseAttributes(attributeSource),
                children: [],
            };
            append(element);
            if (!selfClosing) stack.push(element);
        }
        offset = index + raw.length;
    }
    if (offset < source.length) {
        const value = source.slice(offset);
        if (value.trim()) append({ kind: "text", value });
    }
    if (stack.length) throw new EnvironmentViewError(`View component ${stack.at(-1)!.name} is not closed.`);
    if (/<|>/.test(source.replace(tags, ""))) {
        throw new EnvironmentViewError("Raw HTML and malformed View tags are not allowed.");
    }
    return root;
}

export function resolveDocumentPath(document: unknown, path: string): unknown {
    if (!path.trim()) return document;
    return path.split(".").reduce<unknown>((value, segment) => {
        if (Array.isArray(value) && /^\d+$/.test(segment)) return value[Number(segment)];
        const object = record(value);
        return object && Object.hasOwn(object, segment) ? object[segment] : undefined;
    }, document);
}
