import { describe, expect, it } from "vitest";
import {
    ATTENTION_SIGNALS,
    parseAttentionRules,
    serializeAttentionRules,
} from "./attention";

describe("attention rules (ATTN-2)", () => {
    it("defaults queue everything but turn-settled", () => {
        const levels = parseAttentionRules(null);
        expect(levels.question).toBe("queue");
        expect(levels.conflict).toBe("queue");
        expect(levels["turn-settled"]).toBe("mute");
    });

    it("rules override per signal, first match wins, garbage ignored", () => {
        const levels = parseAttentionRules(
            JSON.stringify({
                version: 1,
                rules: [
                    { signal: "turn-settled", attention: "queue" },
                    { signal: "conflict", attention: "badge" },
                    { signal: "conflict", attention: "mute" }, // later dup loses
                    { signal: "unknown", attention: "queue" }, // ignored
                    { signal: "question", attention: "loud" }, // ignored
                ],
            }),
        );
        expect(levels["turn-settled"]).toBe("queue");
        expect(levels.conflict).toBe("badge");
        expect(levels.question).toBe("queue"); // default held
    });

    it("is total over malformed documents", () => {
        for (const raw of ["not json", "{}", '{"rules":"nope"}']) {
            expect(parseAttentionRules(raw).conflict).toBe("queue");
        }
    });

    it("serialize/parse round-trips every signal", () => {
        const chosen = Object.fromEntries(
            ATTENTION_SIGNALS.map((m, i) => [m.signal, (["queue", "badge", "mute"] as const)[i % 3]]),
        ) as Parameters<typeof serializeAttentionRules>[0];
        expect(parseAttentionRules(serializeAttentionRules(chosen))).toEqual(chosen);
    });
});
