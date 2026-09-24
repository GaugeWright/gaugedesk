/**
 * The photo a person uploads for their account (DR-0195).
 *
 * The browser shrinks the image before sending it, so a phone photograph does
 * not travel as megabytes of JSON. That is a courtesy and not a control: the
 * account authority decodes and re-encodes whatever arrives, and nothing this
 * module produces is stored as sent.
 */

/** Twice the stored edge, so the authority's own resize is a real downscale. */
export const AVATAR_UPLOAD_EDGE = 256;
export const AVATAR_UPLOAD_MAX_BYTES = 5 * 1024 * 1024;
const ACCEPTED = new Set(["image/png", "image/jpeg", "image/webp", "image/gif"]);

/** A problem with the chosen file that the person can fix by choosing another. */
export class AvatarFileError extends Error {}

export function avatarFileProblem(file: { readonly size: number; readonly type: string }): string | null {
    if (file.type && !ACCEPTED.has(file.type)) return "Choose a PNG, JPEG, WebP or GIF image.";
    if (file.size > AVATAR_UPLOAD_MAX_BYTES) return "Choose an image smaller than 5 MB.";
    return null;
}

/** The centred square of a `width` × `height` source. */
export function centreSquare(width: number, height: number): { readonly x: number; readonly y: number; readonly side: number } {
    const side = Math.min(width, height);
    return { x: (width - side) / 2, y: (height - side) / 2, side };
}

/** Up to two initials from a name, or from an address's local part. */
export function avatarInitials(name: string): string {
    const at = name.indexOf("@");
    const base = at > 0 ? name.slice(0, at) : name;
    const initials = base.split(/[\s._-]+/).filter(Boolean).slice(0, 2)
        .map((part) => part[0]?.toUpperCase() ?? "").join("");
    return initials || "?";
}

/** Read, centre-crop and shrink `file` into a `data:` URI for upload. */
export async function avatarUploadImage(file: File): Promise<string> {
    const problem = avatarFileProblem(file);
    if (problem) throw new AvatarFileError(problem);
    let bitmap: ImageBitmap;
    try {
        bitmap = await createImageBitmap(file);
    } catch {
        throw new AvatarFileError("GaugeDesk could not read that image. Choose a PNG, JPEG, WebP or GIF.");
    }
    try {
        const { x, y, side } = centreSquare(bitmap.width, bitmap.height);
        if (side <= 0) throw new AvatarFileError("That image is empty.");
        const edge = Math.min(AVATAR_UPLOAD_EDGE, side);
        const canvas = document.createElement("canvas");
        canvas.width = edge;
        canvas.height = edge;
        const context = canvas.getContext("2d");
        if (!context) throw new AvatarFileError("This browser cannot prepare the image.");
        context.imageSmoothingQuality = "high";
        context.drawImage(bitmap, x, y, side, side, 0, 0, edge, edge);
        // A JPEG stays JPEG; anything that may carry transparency goes as PNG.
        return canvas.toDataURL(file.type === "image/jpeg" ? "image/jpeg" : "image/png", 0.92);
    } finally {
        bitmap.close();
    }
}
