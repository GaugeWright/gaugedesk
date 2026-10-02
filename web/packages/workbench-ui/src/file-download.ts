/**
 * Saving one workspace file to the visitor's machine, from the embedded Files
 * panel (DR-0310). The bytes come through the session's own read projection,
 * so a panel can download exactly what it can open and nothing more.
 *
 * The save is an anchor click on an object URL, which every browser honours
 * from a user gesture; the media type comes from the extension, and an unknown
 * one is saved as opaque bytes, never interpreted.
 */
import type { EngagementId } from "@gaugewright/control-plane-client";
import type { SessionApi } from "./session-context";

const MEDIA_TYPES: Readonly<Record<string, string>> = {
    html: "text/html",
    htm: "text/html",
    md: "text/markdown",
    txt: "text/plain",
    json: "application/json",
    csv: "text/csv",
    pdf: "application/pdf",
    png: "image/png",
    jpg: "image/jpeg",
    jpeg: "image/jpeg",
};

export function mediaTypeFor(path: string): string {
    const leaf = path.slice(path.lastIndexOf("/") + 1);
    const dot = leaf.lastIndexOf(".");
    const extension = dot > 0 ? leaf.slice(dot + 1).toLowerCase() : "";
    return MEDIA_TYPES[extension] ?? "application/octet-stream";
}

export function filenameOf(path: string): string {
    return path.slice(path.lastIndexOf("/") + 1);
}

/** Read the file as bytes when the session can, so a PDF or an image survives
 *  the trip; otherwise as the text the session serves. */
export async function readForDownload(
    api: Pick<SessionApi, "getFile" | "getFileBytes">,
    id: EngagementId,
    path: string,
): Promise<BlobPart> {
    if (api.getFileBytes) {
        const { bytes } = await api.getFileBytes(id, path);
        return bytes as BlobPart;
    }
    return api.getFile(id, path);
}

export function saveToBrowser(path: string, content: BlobPart): void {
    const url = URL.createObjectURL(new Blob([content], { type: mediaTypeFor(path) }));
    try {
        const anchor = document.createElement("a");
        anchor.href = url;
        anchor.download = filenameOf(path);
        anchor.rel = "noopener";
        anchor.style.display = "none";
        document.body.appendChild(anchor);
        anchor.click();
        anchor.remove();
    } finally {
        // The click consumes the URL synchronously in every browser that
        // honours `download`; revoking on the next tick keeps the slow ones safe.
        setTimeout(() => URL.revokeObjectURL(url), 1_000);
    }
}
