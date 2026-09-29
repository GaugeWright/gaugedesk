/**
 * The origin allowlist (PANEL-11).
 *
 * Deploy Config once read `allowed_origins[0]` and published `[origin]`, so
 * reopening a deployment admitted at four origins and publishing it again cut
 * the list to one. The panel now holds the admitted list itself; these pin that
 * adding to it never drops or reorders what is there, and that what the owner
 * types becomes the exact origin a visitor's browser sends.
 */

import { describe, expect, it } from "vitest";
import { normalizeOrigin, withOrigin, wwwCounterpart } from "./deployment-origins";

// An apex and its `www` form, twice over: the edge compares `Origin` exactly,
// so each is its own entry and none may be dropped.
const ADMITTED = [
    "https://example.com",
    "https://www.example.com",
    "https://example.org",
    "https://www.example.org",
];

describe("the origin allowlist", () => {
    it("keeps every admitted origin, in order, when one is added", () => {
        expect(withOrigin(ADMITTED, "https://example.net")).toEqual([...ADMITTED, "https://example.net"]);
    });

    it("keeps a repeated origin once", () => {
        expect(withOrigin(ADMITTED, "https://www.example.com")).toEqual(ADMITTED);
    });

    it("reads a bare host as its HTTPS origin", () => {
        expect(normalizeOrigin("  theorya.com ")).toEqual({ origin: "https://theorya.com" });
    });

    it("drops a pasted page's path, query, and trailing slash", () => {
        expect(normalizeOrigin("https://www.theorya.com/contact?ref=1")).toEqual({ origin: "https://www.theorya.com" });
        expect(normalizeOrigin("https://theorya.com/")).toEqual({ origin: "https://theorya.com" });
    });

    it("keeps a port, which is part of the origin", () => {
        expect(normalizeOrigin("https://staging.theorya.com:8443/")).toEqual({ origin: "https://staging.theorya.com:8443" });
    });

    it("refuses what a public deployment will not admit, in the owner's terms", () => {
        expect(normalizeOrigin("http://theorya.com")).toEqual({ error: "The website must use https://." });
        expect(normalizeOrigin("")).toEqual({ error: "Enter a website address." });
        expect(normalizeOrigin("localhost")).toEqual({ error: "“localhost” isn't a website address." });
        expect("error" in normalizeOrigin("https://exa mple.com")).toBe(true);
    });

    it("offers the www form of an apex and the apex of a www form", () => {
        expect(wwwCounterpart("https://theorya.com")).toBe("https://www.theorya.com");
        expect(wwwCounterpart("https://www.theorya.com")).toBe("https://theorya.com");
        expect(wwwCounterpart("https://app.theorya.com")).toBeNull();
    });
});
