/**
 * What the {@link ContentViewer}'s View tab should do with the selected file.
 *
 * The viewer began as a text pane, and a worktree is not a text store: a turn
 * that produces a screenshot, a scanned invoice, or a report PDF leaves a file
 * the Files panel lists and the pane could not open. This module owns the one
 * decision behind opening those — *is this file text, a picture, a PDF, or
 * something we can only hand back* — as a pure function, so the rule is
 * unit-tested rather than spread through the component.
 *
 * The decision is made from the **path**, not from sniffed bytes. The viewer
 * has to choose which read to issue before it has any bytes, and a worktree
 * file's extension is what both the person and the agent that wrote it meant.
 * A file whose extension says nothing stays text, exactly as before.
 */

/** How the View tab renders a file. `opaque` is the honest refusal: the file
 *  is real, the viewer can say what it is and how big, and no more. */
export type ViewerFileKind = "text" | "image" | "pdf" | "office" | "opaque";

/** The Office formats the OOXML engine reads. Legacy `.doc`/`.xls`/`.ppt` are
 *  a different, binary format family and are not among them. */
export type OfficeFormat = "docx" | "xlsx" | "pptx";

export interface ViewerFile {
    readonly kind: ViewerFileKind;
    /** Which engine reads it, present only for `office`. */
    readonly format?: OfficeFormat;
    /** The media type stamped on the blob the browser renders, taken from the
     *  path. The read's own content type deliberately says `attachment`, so it
     *  cannot be the source of this. */
    readonly mediaType: string;
}

/** Pictures a browser renders natively. SVG is here too — it is rendered
 *  through an `<img>`, which never runs script the file carries. */
const IMAGE_TYPES: Readonly<Record<string, string>> = {
    apng: "image/apng",
    avif: "image/avif",
    bmp: "image/bmp",
    gif: "image/gif",
    ico: "image/x-icon",
    jpeg: "image/jpeg",
    jpg: "image/jpeg",
    png: "image/png",
    svg: "image/svg+xml",
    webp: "image/webp",
};

/** Formats we know are not text, so the pane says so instead of painting
 *  mojibake. Extending this list is how a format graduates from "unopenable
 *  blob" to "named thing we cannot show yet". */
const OPAQUE_TYPES: Readonly<Record<string, string>> = {
    "7z": "application/x-7z-compressed",
    bz2: "application/x-bzip2",
    dll: "application/octet-stream",
    doc: "application/msword",
    dylib: "application/octet-stream",
    exe: "application/vnd.microsoft.portable-executable",
    flac: "audio/flac",
    gz: "application/gzip",
    jar: "application/java-archive",
    mov: "video/quicktime",
    mp3: "audio/mpeg",
    mp4: "video/mp4",
    odp: "application/vnd.oasis.opendocument.presentation",
    ods: "application/vnd.oasis.opendocument.spreadsheet",
    odt: "application/vnd.oasis.opendocument.text",
    ogg: "audio/ogg",
    otf: "font/otf",
    ppt: "application/vnd.ms-powerpoint",
    so: "application/octet-stream",
    sqlite: "application/vnd.sqlite3",
    tar: "application/x-tar",
    ttf: "font/ttf",
    wasm: "application/wasm",
    wav: "audio/wav",
    webm: "video/webm",
    woff: "font/woff",
    woff2: "font/woff2",
    xls: "application/vnd.ms-excel",
    zip: "application/zip",
};

/** Word, Excel and PowerPoint, rendered by the OOXML engine. */
const OFFICE_TYPES: Readonly<Record<string, { format: OfficeFormat; mediaType: string }>> = {
    docx: {
        format: "docx",
        mediaType: "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    },
    pptx: {
        format: "pptx",
        mediaType: "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    },
    xlsx: {
        format: "xlsx",
        mediaType: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    },
};

/** The extension, lowercased, or `""` for a path that has none. A dotfile
 *  (`.gitignore`) has no extension — its leading dot names the file. */
export function fileExtension(path: string): string {
    const name = path.slice(path.lastIndexOf("/") + 1);
    const dot = name.lastIndexOf(".");
    return dot > 0 ? name.slice(dot + 1).toLowerCase() : "";
}

/** How the View tab should open this path. */
export function viewerFileFor(path: string): ViewerFile {
    const extension = fileExtension(path);
    if (extension === "pdf") return { kind: "pdf", mediaType: "application/pdf" };
    const image = IMAGE_TYPES[extension];
    if (image) return { kind: "image", mediaType: image };
    const office = OFFICE_TYPES[extension];
    if (office) return { kind: "office", format: office.format, mediaType: office.mediaType };
    const opaque = OPAQUE_TYPES[extension];
    if (opaque) return { kind: "opaque", mediaType: opaque };
    return { kind: "text", mediaType: "text/plain" };
}

/** True when a file the viewer read as text plainly is not text.
 *
 *  The extension rules above cannot cover a worktree — an agent writes files
 *  with whatever name suits the work, and an unknown extension is read as
 *  text. A body carrying NULs, or thick with replacement characters, is a
 *  decode that failed, and saying so beats painting it. */
export function readAsTextFailed(text: string): boolean {
    const sample = text.slice(0, 4096);
    if (sample.length === 0) return false;
    if (sample.includes("\u0000")) return true;
    let replacements = 0;
    for (const character of sample) if (character === "\ufffd") replacements += 1;
    return replacements / sample.length > 0.01;
}

/** A file's size in the units a person reads it in. */
export function describeSize(bytes: number): string {
    if (bytes < 1024) return `${bytes} bytes`;
    const units = ["KiB", "MiB", "GiB", "TiB"];
    let size = bytes / 1024;
    let unit = 0;
    while (size >= 1024 && unit < units.length - 1) {
        size /= 1024;
        unit += 1;
    }
    return `${size < 10 ? size.toFixed(1) : Math.round(size)} ${units[unit]}`;
}
