/**
 * Work targets as people and agents know them (DR-0248). A chat's agent sees
 * each target as a folder named after it, while storage, the Files pane and
 * the viewer address its stable-ID partition, `targets/<target-id-path-v1>/`.
 * These helpers translate between the two for display and navigation; the
 * encoded id is never shown.
 */

/** A target a conflicted chat and its line name differently (DR-0248). */
export interface NameDisagreement {
    readonly root: string;
    readonly chatName: string;
    readonly lineName: string;
}

/** One of a chat's targets: its stored root, `targets/<target-id-path-v1>`,
 *  and the name the chat and its agent know it by (DR-0248). */
export interface TargetName {
    readonly root: string;
    readonly name: string;
}

/** The name of the target stored at `targets/<rootSegment>`, or null when the
 *  chat does not know it. Never the encoded id, which is not for people. */
export function targetNameForRoot(rootSegment: string, targets: readonly TargetName[]): string | null {
    return targets.find((target) => target.root === `targets/${rootSegment}`)?.name ?? null;
}

/** The stored path for a path as the agent wrote it (DR-0248): the agent sees
 *  each target as a folder named after it, while the Files pane and the viewer
 *  address the stored `targets/<id>/` partition. Other paths are unchanged. */
export function storedTargetPath(path: string, targets: readonly TargetName[]): string {
    for (const target of targets) {
        if (path === target.name) return target.root;
        if (path.startsWith(`${target.name}/`)) return `${target.root}${path.slice(target.name.length)}`;
    }
    return path;
}

/** A target renamed on this chat's line (DR-0248). Its name is versioned in a
 *  hidden file, `.gaugedesk-names/<id>`; the review shows the rename itself. */
export interface TargetRename {
    /** The target's stored root, `targets/<id>`. */
    readonly root: string;
    /** The name before this chat's rename; empty when the line had none. */
    readonly from: string;
    readonly to: string;
}

const TARGET_NAMES_ROOT = ".gaugedesk-names/";

/** The target renames in a unified diff, one per renamed target. */
export function targetRenames(diff: string): TargetRename[] {
    const renames: TargetRename[] = [];
    let current: { root: string; from: string; to: string } | null = null;
    const flush = () => {
        if (current && current.to) renames.push(current);
        current = null;
    };
    for (const line of diff.split("\n")) {
        if (line.startsWith("diff --git ")) {
            flush();
            const m = line.match(/^diff --git a\/(.+) b\/(.+)$/);
            const path = m ? m[2] : "";
            current = path.startsWith(TARGET_NAMES_ROOT)
                ? { root: `targets/${path.slice(TARGET_NAMES_ROOT.length)}`, from: "", to: "" }
                : null;
        } else if (current && line.startsWith("-") && !line.startsWith("---")) {
            current.from = line.slice(1);
        } else if (current && line.startsWith("+") && !line.startsWith("+++")) {
            current.to = line.slice(1);
        }
    }
    flush();
    return renames;
}

export function isTargetNameFile(path: string): boolean {
    return path.startsWith(TARGET_NAMES_ROOT);
}

