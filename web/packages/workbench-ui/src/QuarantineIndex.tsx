/**
 * How an Inbox presents quarantined material (DR-0110 §7, GATE-6), shared by
 * the project's Inbox and a Panel placement's Inbox in Panel Settings.
 *
 * An Inbox is an **index**, not a document. Nothing concatenates the corpus into
 * one page — that would hand a reviewer a wall of attacker-authored text and ask
 * them to notice one line of it. Provenance leads; a payload is read only when a
 * person deliberately opens it, and a verdict carries an answer to the project's
 * gate, which is the only producer of one (DR-0117 §1). A `flag` escalates
 * rather than discarding (DR-0110 §6), so the copy says "flagged", never
 * "deleted".
 */

/** Bytes, in the units a reviewer can judge at a glance. */
export function quarantineSize(bytes: number): string {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${Math.round(bytes / 102.4) / 10} KB`;
    return `${Math.round(bytes / 104857.6) / 10} MB`;
}

/** What the gate has said about an item, in the reviewer's words. */
export function quarantineStatusCopy(status: string): { label: string; tone: string } {
    switch (status) {
        case "Approved":
            return { label: "approved", tone: "ok" };
        case "Rejected":
            return { label: "flagged", tone: "warn" };
        default:
            return { label: "awaiting review", tone: "pending" };
    }
}
