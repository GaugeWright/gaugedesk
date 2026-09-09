/**
 * The View tab for a file that is not text: a picture, or a format the viewer
 * can name but not show.
 *
 * Both views are deliberately read-only and inert. A picture is painted
 * through an `<img>` over a blob of the file's own bytes — an `<img>` renders
 * SVG without running any script the file carries, which is the whole reason
 * SVG is allowed here at all. The unshowable case paints no bytes: it says
 * what the file is and how big it is, which is the honest amount.
 *
 * Neither view offers "save a copy". Taking a worktree file out to the disk is
 * a governed act with its own route and audit trail
 * (`desktop.chat.resource.export-to-disk`); a download button here would be a
 * quiet way around it.
 */

import { createMemo, createSignal, onCleanup } from "solid-js";
import { describeSize } from "./file-kind";

/** A blob URL over the file's bytes, revoked as soon as it is replaced. */
function objectUrl(bytes: () => Uint8Array, mediaType: () => string) {
    const url = createMemo<string>((previous) => {
        if (previous) URL.revokeObjectURL(previous);
        // Copied into a buffer of its own: the viewer's Uint8Array is shared
        // with whatever else holds the read, and a Blob should not alias it.
        return URL.createObjectURL(
            new Blob([new Uint8Array(bytes()).buffer], { type: mediaType() }),
        );
    });
    onCleanup(() => URL.revokeObjectURL(url()));
    return url;
}

export interface FileMediaProps {
    readonly path: string;
    readonly bytes: Uint8Array;
    readonly mediaType: string;
}

export function ImageFileView(props: FileMediaProps) {
    const url = objectUrl(() => props.bytes, () => props.mediaType);
    const [natural, setNatural] = createSignal<{ width: number; height: number } | null>(null);
    const caption = () => {
        const size = natural();
        const bytes = describeSize(props.bytes.byteLength);
        return size ? `${size.width} × ${size.height} · ${bytes}` : bytes;
    };
    return (
        <div class="filemedia" data-file-view data-file-media="image">
            <img
                class="filemedia-image"
                src={url()}
                alt={props.path}
                onLoad={(event) =>
                    setNatural({
                        width: event.currentTarget.naturalWidth,
                        height: event.currentTarget.naturalHeight,
                    })
                }
            />
            <div class="filemedia-caption">{caption()}</div>
        </div>
    );
}

/** A real file the viewer cannot show. Saying which format it is beats both a
 *  blank pane and a screen of mojibake — and it reads nothing: fetching a
 *  200 MB archive to report that it is a 200 MB archive helps nobody. */
export function OpaqueFileView(props: {
    readonly path: string;
    readonly mediaType: string;
    /** Known only when the viewer already holds the bytes — an unrecognised
     *  file that turned out not to be text. */
    readonly byteLength?: number;
}) {
    const facts = () =>
        props.byteLength === undefined
            ? props.mediaType
            : `${props.mediaType} \u00b7 ${describeSize(props.byteLength)}`;
    // The card leads with the file's own name. Its full worktree path is a
    // target id and several segments long, and the viewer's header already
    // carries it — leading with that buries the one word the reader wants.
    const name = () => props.path.slice(props.path.lastIndexOf("/") + 1);
    return (
        <div class="filemedia" data-file-view data-file-media="opaque">
            <div class="filemedia-card">
                <div class="filemedia-name" title={props.path}>{name()}</div>
                <div class="filemedia-facts">{facts()}</div>
                <div class="filemedia-note">
                    This isn't a file the viewer can show yet. Ask the assistant about it —
                    it can read the file and tell you what's inside.
                </div>
            </div>
        </div>
    );
}
