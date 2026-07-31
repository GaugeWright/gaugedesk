/**
 * The Deploy Config collection rules (ADR 0109 §5–§7, GATE-8).
 *
 * Two of these encode decisions rather than mechanics, and both are the kind a
 * later edit could quietly undo:
 *
 *  - a deployment that names no recipient collects **nothing**, rather than
 *    sealing to some ambient default;
 *  - retention is a resumption window, and the copy must not promise that it
 *    bounds how long collected material sits somewhere.
 */

import { describe, expect, it } from "vitest";
import { collectionBlockerFor, collectionInputFrom, retentionSeconds } from "./deployment-collection";

const recipient = {
    recipient_id: "tenant-a",
    recipient_ref: "recipient:collection:tenant-a",
    public_key_hex: "04" + "ab".repeat(64),
};

const declared = {
    collecting: true,
    paths: "responses.json, notes/*",
    transcript: false,
    schemaRef: "survey.v1",
    recipientClass: "collection:tenant",
    maxArtifactKb: 1000,
    recipient,
};

describe("what a deployment publishes as its collection", () => {
    it("collects nothing when collection is off", () => {
        expect(collectionInputFrom({ ...declared, collecting: false })).toBeUndefined();
    });

    it("collects nothing when no recipient is selected", () => {
        // The load-bearing one. A half-filled block would publish and be refused
        // at the edge; undefined is a deployment that plainly does not collect.
        // There is no ambient recipient to fall back to, by design.
        expect(collectionInputFrom({ ...declared, recipient: null })).toBeUndefined();
    });

    it("carries only the declared paths, split on commas or newlines", () => {
        const input = collectionInputFrom(declared);
        expect(input?.exportable_paths).toEqual(["responses.json", "notes/*"]);
    });

    it("seals to exactly the selected keyring's public half", () => {
        const input = collectionInputFrom(declared);
        expect(input?.recipient_ref).toBe("recipient:collection:tenant-a");
        expect(input?.recipient_public_keys).toEqual([recipient.public_key_hex]);
    });

    it("declares the transcript independently of the workspace paths", () => {
        // A transcript is a different disclosure: it carries everything typed,
        // not what the visitor chose to submit.
        expect(collectionInputFrom(declared)?.transcript_eligible).toBe(false);
        expect(collectionInputFrom({ ...declared, transcript: true })?.transcript_eligible).toBe(true);
    });

    it("sends the size bound in bytes, since that is what the runtime checks", () => {
        expect(collectionInputFrom(declared)?.max_artifact_bytes).toBe(1000 * 1024);
    });
});

describe("what blocks publishing a collecting deployment", () => {
    it("blocks nothing when collection is off", () => {
        expect(collectionBlockerFor({ ...declared, collecting: false })).toBe("");
    });

    it("names the missing recipient rather than failing at the edge", () => {
        expect(collectionBlockerFor({ ...declared, recipient: null })).toMatch(/keyring/i);
    });

    it("refuses a collection with no exportable path", () => {
        // Zero paths is not "collect everything" — it is a collection that can
        // never contain anything, which is worth saying before publishing.
        expect(collectionBlockerFor({ ...declared, paths: "  " })).toMatch(/path/i);
    });

    it("refuses a collection with no schema", () => {
        expect(collectionBlockerFor({ ...declared, schemaRef: "" })).toMatch(/schema/i);
    });
});

describe("retention", () => {
    it("converts the owner's units without ever reaching zero", () => {
        expect(retentionSeconds(24, 30)).toEqual({ idle: 86_400, absolute: 2_592_000 });
        // A zero or negative entry must not publish "expire immediately".
        expect(retentionSeconds(0, 0)).toEqual({ idle: 1, absolute: 1 });
    });
});
