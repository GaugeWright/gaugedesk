/**
 * The **attention policy** schema, client side (ATTN-2, ADR 0082 §3): which
 * signals a chat can raise, what each means to a human, and how the rules
 * document in the account-settings KV is read and written. The single server
 * evaluator lives in `crates/app/src/attention.rs`; this module mirrors its
 * schema and defaults so the settings surface renders from one vocabulary.
 *
 * Deliberately shallow — signal → attention, nothing else (presentation, not
 * policy; ADR 0080). Parsing is total: a missing/malformed document degrades to
 * the shipped defaults per signal.
 */

/** The account-settings key holding the rules document. */
export const ATTENTION_RULES_SETTING = "attention.rules";

/** Where a raised signal surfaces. */
export type AttentionLevel = "queue" | "badge" | "mute";

/** The signals a chat's durable state can raise, in server priority order. */
export type AttentionSignal = "question" | "conflict" | "turn-settled";

export interface AttentionSignalMeta {
    readonly signal: AttentionSignal;
    /** Settings-row label — the event, in plain language. */
    readonly label: string;
    /** What opting in means, for the row's tooltip. */
    readonly hint: string;
    readonly defaultAttention: AttentionLevel;
}

/** The schema the settings surface renders from — one row per signal. */
export const ATTENTION_SIGNALS: readonly AttentionSignalMeta[] = [
    {
        signal: "question",
        label: "The agent asks you a question",
        hint: "A turn suspended on your answer — the agent cannot continue without you.",
        defaultAttention: "queue",
    },
    {
        signal: "conflict",
        label: "A merge conflicts",
        hint: "The chat's work no longer merges cleanly and needs repair.",
        defaultAttention: "queue",
    },
    {
        signal: "turn-settled",
        label: "The agent finishes any reply",
        hint: "Every settled turn asks for your next message — the conversational cadence. Off by default so the bar only carries decisions.",
        defaultAttention: "mute",
    },
];

const LEVELS: readonly AttentionLevel[] = ["queue", "badge", "mute"];

/** Parse the rules document into a total per-signal map (defaults filled,
 *  first rule naming a signal wins, garbage ignored — mirrors the server). */
export function parseAttentionRules(
    raw: string | null | undefined,
): Record<AttentionSignal, AttentionLevel> {
    const levels = Object.fromEntries(
        ATTENTION_SIGNALS.map((m) => [m.signal, m.defaultAttention]),
    ) as Record<AttentionSignal, AttentionLevel>;
    if (!raw) return levels;
    try {
        const doc = JSON.parse(raw) as { rules?: unknown };
        if (!Array.isArray(doc.rules)) return levels;
        const seen = new Set<string>();
        for (const rule of doc.rules as { signal?: unknown; attention?: unknown }[]) {
            const signal = ATTENTION_SIGNALS.find((m) => m.signal === rule?.signal)?.signal;
            const attention = LEVELS.find((l) => l === rule?.attention);
            if (!signal || !attention || seen.has(signal)) continue;
            seen.add(signal);
            levels[signal] = attention;
        }
    } catch {
        /* malformed → defaults */
    }
    return levels;
}

/** Serialize a per-signal map as the rules document (all rules written
 *  explicitly, signal order stable, so the stored doc is self-describing). */
export function serializeAttentionRules(
    levels: Record<AttentionSignal, AttentionLevel>,
): string {
    return JSON.stringify({
        version: 1,
        rules: ATTENTION_SIGNALS.map((m) => ({
            signal: m.signal,
            attention: levels[m.signal] ?? m.defaultAttention,
        })),
    });
}
