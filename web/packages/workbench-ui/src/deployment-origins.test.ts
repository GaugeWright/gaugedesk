/**
 * The origin allowlist round trip (PANEL-11).
 *
 * Deploy Config once read `allowed_origins[0]` and published `[origin]`, so
 * reopening a deployment admitted at four origins and publishing it again cut
 * the list to one. These pin that what an active deployment admits is exactly
 * what a republish sends back, through the same two functions the panel calls
 * when it loads a deployment and when it builds the publish request.
 */

import { describe, expect, it } from "vitest";
import { originsDraftFrom, originsFromDraft } from "./deployment-origins";

// An apex and its `www` form, twice over: the edge compares `Origin` exactly,
// so each is its own entry and none may be dropped.
const ADMITTED = [
    "https://example.com",
    "https://www.example.com",
    "https://example.org",
    "https://www.example.org",
];

describe("the origin allowlist round trip", () => {
    it("a republished deployment keeps every admitted origin", () => {
        // Load: the admitted list becomes the draft. Publish: the untouched draft
        // becomes the request. Nothing in between may narrow it.
        const republished = originsFromDraft(originsDraftFrom(ADMITTED));
        expect(republished).toEqual(ADMITTED);
    });

    it("shows the owner one origin per line", () => {
        expect(originsDraftFrom(ADMITTED)).toBe(
            "https://example.com\nhttps://www.example.com\nhttps://example.org\nhttps://www.example.org",
        );
        expect(originsDraftFrom([])).toBe("");
    });

    it("treats whitespace and blank lines as editing, not as origins", () => {
        expect(originsFromDraft("  https://example.com \r\n\n\thttps://www.example.com\n\n")).toEqual([
            "https://example.com",
            "https://www.example.com",
        ]);
    });

    it("sends a repeated origin once, in first-seen order", () => {
        expect(originsFromDraft("https://example.com\nhttps://www.example.com\nhttps://example.com")).toEqual([
            "https://example.com",
            "https://www.example.com",
        ]);
    });

    it("publishes no origins from an emptied draft, so the publisher refuses it", () => {
        expect(originsFromDraft("")).toEqual([]);
        expect(originsFromDraft(" \n \n")).toEqual([]);
    });

    it("leaves what an origin is to the publisher", () => {
        // The exact-HTTPS-origin rule and its message live in the publisher; the
        // panel passes the entry through so that message, not a second one, is shown.
        expect(originsFromDraft("http://example.com/")).toEqual(["http://example.com/"]);
    });
});
