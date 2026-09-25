import { describe, expect, it } from "vitest";
import { displayChatTitle, isPlaceholderTitle, PLACEHOLDER_TITLES, untitledTag } from "./chat-title";

describe("chat-title", () => {
    it("recognises every system placeholder, case-insensitively", () => {
        for (const p of PLACEHOLDER_TITLES) {
            expect(isPlaceholderTitle(p)).toBe(true);
            expect(isPlaceholderTitle(p.toUpperCase())).toBe(true);
            expect(isPlaceholderTitle(`  ${p}  `)).toBe(true);
        }
    });

    it("treats a user-chosen title as not a placeholder", () => {
        expect(isPlaceholderTitle("draft a tagline")).toBe(false);
        expect(isPlaceholderTitle("")).toBe(false);
        expect(isPlaceholderTitle(null)).toBe(false);
        expect(isPlaceholderTitle(undefined)).toBe(false);
    });

    it("shows a user-chosen title verbatim", () => {
        expect(displayChatTitle("draft a tagline")).toBe("draft a tagline");
        expect(displayChatTitle("draft a tagline", 3)).toBe("draft a tagline");
    });

    it("never leaks the raw 'new chat' placeholder — shows Untitled instead", () => {
        // This is the round-4 #4 bug: the TASKS bar showed the raw placeholder.
        expect(displayChatTitle("new chat")).toBe("Untitled");
        expect(displayChatTitle("new chat", 2)).toBe("Untitled · 2");
        expect(displayChatTitle("edit chat", 5)).toBe("Untitled · 5");
    });

    it("shows Untitled for empty/missing titles too", () => {
        expect(displayChatTitle("")).toBe("Untitled");
        expect(displayChatTitle(null, 1)).toBe("Untitled · 1");
    });

    it("accepts a stable string tag (not just a positional ordinal)", () => {
        expect(displayChatTitle("new chat", "9984")).toBe("Untitled · 9984");
        // A real title always wins — the tag is ignored once the chat is named.
        expect(displayChatTitle("draft a tagline", "9984")).toBe("draft a tagline");
        // An empty tag falls back to a bare "Untitled" (no dangling separator).
        expect(displayChatTitle("new chat", "")).toBe("Untitled");
    });
});

describe("untitledTag (stable per-chat disambiguator, round-11 #6)", () => {
    it("derives a stable token from the chat id, not list position", () => {
        // Same id ⇒ same tag, every render (the whole point — no drift).
        expect(untitledTag("chat-77bb2b4d9984")).toBe("9984");
        expect(untitledTag("chat-77bb2b4d9984")).toBe("9984");
        // Two different chats get different tags (never read identically).
        expect(untitledTag("chat-c8c3f7bd2d4b")).not.toBe(untitledTag("chat-77bb2b4d9984"));
    });

    it("tolerates a missing id and the chat:/chat- prefixes", () => {
        expect(untitledTag(null)).toBe("");
        expect(untitledTag("chat:abcd")).toBe("ABCD");
    });
});
