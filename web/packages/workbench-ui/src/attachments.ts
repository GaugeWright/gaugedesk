/**
 * Message attachments (UX-14): the pure core behind the composer's paperclip.
 *
 * A picked file is either a **native image** (sent as a WhippleScript resource),
 * an **inline-able text file** (folded into the prompt text), a **document** whose
 * text is extracted in the browser, or unsupported binary data. `buildOutgoing`
 * assembles the neutral turn shape: text inlined into `message`, images in
 * `images[]`, and only a byte-free `[attached image: …]` note left in the durable
 * text so the transcript is honest while base64 never enters the log (`INV-10`).
 *
 * Kept here so classification, extraction limits, and turn composition are
 * unit-testable apart from the Solid component. PDF/Office bytes never cross the
 * control plane: a lazy browser parser turns them into a text `Attachment`, then
 * the existing prompt-inline pipeline takes over.
 */

import pdfWorkerSrc from "pdfjs-dist/build/pdf.worker.min.mjs?url";

/** An image clipped to a message: base64 bytes + mime. `name` is for the chip only. */
export type ImageRef = { name: string; mimeType: string; data: string };

/** A file pending in the composer before send. */
export type Attachment =
    | { kind: "text"; name: string; text: string }
    | { kind: "image"; name: string; mimeType: string; data: string };

/** Image types the current WhippleScript host resource accepts natively. */
export const IMAGE_MIMES = new Set(["image/png", "image/jpeg", "image/webp", "image/gif"]);

/** Textual `application/*` mimes worth inlining. Matched EXACTLY — a substring test
 *  would wrongly catch Office's `application/vnd.openxmlformats-…` (it contains "xml"). */
export const TEXT_MIMES = new Set([
    "application/json",
    "application/ld+json",
    "application/xml",
    "application/javascript",
    "application/x-yaml",
    "application/yaml",
    "application/toml",
    "application/csv",
]);

/** Extensions we treat as text when the browser gives no/wrong mime. */
export const TEXT_EXT =
    /\.(txt|md|markdown|mdx|json|jsonc|csv|tsv|ya?ml|toml|ini|cfg|conf|env|xml|html?|css|scss|less|js|jsx|mjs|cjs|ts|tsx|py|rs|go|rb|java|kt|c|h|cc|cpp|hpp|cs|php|swift|sh|bash|zsh|sql|log|gitignore|dockerfile|makefile)$/i;

export type DocumentFileType = "pdf" | "docx" | "xlsx" | "pptx";

const DOCUMENT_MIMES = new Map<string, DocumentFileType>([
    ["application/pdf", "pdf"],
    ["application/vnd.openxmlformats-officedocument.wordprocessingml.document", "docx"],
    ["application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "xlsx"],
    ["application/vnd.openxmlformats-officedocument.presentationml.presentation", "pptx"],
]);

const DOCUMENT_EXT = /\.(pdf|docx|xlsx|pptx)$/i;

/** Resolve the authoritative parser hint without allowing an unrelated explicit
 *  MIME (for example JSON named `report.pdf`) to masquerade as a document. Empty
 *  and generic binary MIME values may fall back to the filename because browsers
 *  commonly use those for local files. */
export function documentFileType(f: { type: string; name: string }): DocumentFileType | undefined {
    const fromMime = DOCUMENT_MIMES.get(f.type.toLowerCase());
    if (fromMime) return fromMime;
    if (f.type && f.type !== "application/octet-stream") return undefined;
    return DOCUMENT_EXT.exec(f.name)?.[1]?.toLowerCase() as DocumentFileType | undefined;
}

/** A picked file is a native image, inline-able text, a locally extractable
 *  document, or unsupported binary data. An explicit `application/*` MIME never
 *  gets reclassified as text merely because its filename has a text extension. */
export function classifyAttachment(f: { type: string; name: string }): "image" | "text" | "document" | "unsupported" {
    if (IMAGE_MIMES.has(f.type)) return "image";
    if (f.type.startsWith("text/")) return "text";
    if (TEXT_MIMES.has(f.type)) return "text";
    if (documentFileType(f)) return "document";
    if (!f.type.startsWith("application/") && TEXT_EXT.test(f.name)) return "text";
    return "unsupported";
}

/** Bound both compressed input and decompressed OOXML before invoking code that
 *  walks attacker-controlled ZIP/XML. Extracted prompt text has a separate cap so
 *  a small, repetitive document cannot silently dominate a model turn. */
export const MAX_DOCUMENT_INPUT_BYTES = 16 * 1024 * 1024;
export const MAX_DOCUMENT_UNCOMPRESSED_BYTES = 64 * 1024 * 1024;
export const MAX_DOCUMENT_ZIP_ENTRIES = 4_096;
export const MAX_DOCUMENT_TEXT_CHARS = 1_000_000;

type DocumentParser = (
    bytes: ArrayBuffer,
    config: {
        fileType: DocumentFileType;
        ocr: false;
        extractAttachments: false;
        includeRawContent: false;
        pdfWorkerSrc: string;
        decompressionLimits: { maxUncompressedBytes: number; maxZipEntries: number };
    },
) => Promise<{ toText(): string }>;

async function parseDocument(
    bytes: ArrayBuffer,
    config: Parameters<DocumentParser>[1],
): Promise<{ toText(): string }> {
    // A dynamic import keeps the sizeable Office/PDF parser out of the initial
    // workbench bundle. The PDF worker URL is emitted as a local Vite asset; no
    // CDN fetch or document upload is needed.
    const { parseOffice } = await import("officeparser/slim");
    return parseOffice(bytes, config);
}

/** Extract PDF/docx/xlsx/pptx text entirely in the client. The optional parser is
 *  a narrow test seam; production always uses the lazy `officeparser/slim` build. */
export async function extractDocumentAttachment(
    f: Blob & { name: string; type: string },
    parser: DocumentParser = parseDocument,
): Promise<Extract<Attachment, { kind: "text" }>> {
    const fileType = documentFileType(f);
    if (!fileType) throw new Error(`unsupported document type for ${f.name}`);
    if (f.size > MAX_DOCUMENT_INPUT_BYTES) {
        throw new Error(`${f.name} is larger than the 16 MiB document limit`);
    }

    const ast = await parser(await f.arrayBuffer(), {
        fileType,
        ocr: false,
        extractAttachments: false,
        includeRawContent: false,
        pdfWorkerSrc,
        decompressionLimits: {
            maxUncompressedBytes: MAX_DOCUMENT_UNCOMPRESSED_BYTES,
            maxZipEntries: MAX_DOCUMENT_ZIP_ENTRIES,
        },
    });
    const extracted = ast.toText().replace(/\r\n?/g, "\n").replaceAll("\0", "").trim();
    if (!extracted) throw new Error(`${f.name} contains no extractable text`);

    const text =
        extracted.length <= MAX_DOCUMENT_TEXT_CHARS
            ? extracted
            : `${extracted.slice(0, MAX_DOCUMENT_TEXT_CHARS)}\n\n[extracted text truncated at ${MAX_DOCUMENT_TEXT_CHARS} characters]`;
    return { kind: "text", name: f.name, text };
}

/** Read a file's bytes as base64 (no data-URL prefix) — the neutral `ImageContent`
 *  wants. Chunked so a large image doesn't blow `fromCharCode`'s argument stack. */
export async function fileToBase64(f: Blob): Promise<string> {
    const bytes = new Uint8Array(await f.arrayBuffer());
    let binary = "";
    const CHUNK = 0x8000;
    for (let i = 0; i < bytes.length; i += CHUNK) {
        binary += String.fromCharCode(...bytes.subarray(i, i + CHUNK));
    }
    return btoa(binary);
}

/** Assemble the outgoing turn from the draft body + pending attachments: text files
 *  inline as delimited blocks; images become `images[]` with only a byte-free note
 *  left in the message. Pure — the component clears the attachments after calling. */
export function buildOutgoing(body: string, atts: Attachment[]): { message: string; images: ImageRef[] } {
    const trimmed = body.trim();
    const textBlocks = atts
        .filter((a): a is Extract<Attachment, { kind: "text" }> => a.kind === "text")
        .map((a) => `--- attached: ${a.name} ---\n${a.text}\n--- end ${a.name} ---`);
    const images: ImageRef[] = atts
        .filter((a): a is Extract<Attachment, { kind: "image" }> => a.kind === "image")
        .map((a) => ({ name: a.name, mimeType: a.mimeType, data: a.data }));
    const imageNotes = images.map((i) => `[attached image: ${i.name}]`);
    const message = [trimmed, ...textBlocks, ...imageNotes].filter((s) => s.length > 0).join("\n\n");
    return { message, images };
}
