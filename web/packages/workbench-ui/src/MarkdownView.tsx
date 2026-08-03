/**
 * Shared rendered Markdown for document views and conversational prose.
 * Agent-written content is UNTRUSTED input, so safety comes from micromark's
 * defaults: raw HTML inside
 * the markdown is escaped (never executed) and dangerous link protocols are
 * refused — there is no sanitizer to forget because nothing dangerous is
 * emitted. GFM (tables, task lists, strikethrough, autolinks) is on because
 * agents write it constantly. The raw source stays one tab away (Edit).
 */

import { createMemo } from "solid-js";
import { micromark } from "micromark";
import { gfm, gfmHtml } from "micromark-extension-gfm";

/** File paths the viewer renders as markdown (everything else stays `<pre>`). */
export function isMarkdownPath(path: string): boolean {
    return /\.(md|markdown)$/i.test(path);
}

export function renderMarkdown(text: string): string {
    const html = micromark(text, {
        extensions: [gfm()],
        htmlExtensions: [gfmHtml()],
    });
    // A link in an embedded conversation must not navigate the host page away
    // from its current state. micromark owns all emitted markup here, so adding
    // inert browsing-context attributes to its anchor tags is safe and exact.
    return html.replaceAll(
        "<a href=",
        '<a target="_blank" rel="noopener noreferrer" href=',
    );
}

/** Safe rendered Markdown without assumptions about which surface contains it. */
export function MarkdownBody(props: { text: string; class?: string; fileView?: boolean }) {
    const html = createMemo(() => renderMarkdown(props.text));
    // innerHTML is safe here by construction: micromark escapes embedded HTML
    // and refuses javascript:/data: link destinations by default.
    return (
        <div
            class={`markdown-body${props.class ? ` ${props.class}` : ""}`}
            data-file-view={props.fileView ? "" : undefined}
            innerHTML={html()}
        />
    );
}

export function MarkdownView(props: { text: string }) {
    return <MarkdownBody text={props.text} class="filebody" fileView />;
}
