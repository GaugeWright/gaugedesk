//! The **attention policy** (ATTN-2, ADR 0082 §3): a shallow, operator-owned
//! rules document mapping each *signal* a chat can raise to an attention level.
//!
//! Deliberately shallow — signal → attention, nothing else — and it stays that
//! way: it is presentation, not policy (ADR 0080: WhippleScript owns policy
//! language; the moment this wants predicates over labels or resources it must
//! ride the advancement path instead, ATTN-3). The document lives in the
//! account-settings KV under [`ATTENTION_RULES_SETTING`] so it syncs like every
//! other operator preference and a future LLM layer can write it against a
//! schema this module is the single evaluator of.
//!
//! Parsing is total: a missing, malformed, or partially-unknown document
//! degrades to the shipped defaults per signal — the queue never breaks because
//! a config was hand-edited (or LLM-written) badly.

use std::collections::BTreeMap;

/// The account-settings key holding the rules document.
pub const ATTENTION_RULES_SETTING: &str = "attention.rules";

/// Where a raised signal surfaces (ADR 0082 §3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Attention {
    /// A task-bar entry (and the nav badge that rides task membership).
    Queue,
    /// The chat's nav badge only — no task-bar entry.
    Badge,
    /// Transcript only — no badge, no task.
    Mute,
}

/// A signal a chat's durable state can raise, in **priority order** (a chat
/// contributes at most one task: the first signal in this order whose attention
/// is `Queue` wins; a muted/badged signal falls through to the next, so muting
/// reviews does not silence reply pings).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Signal {
    /// The agent asked a person something and it is unanswered → ask `answer`.
    /// The turn is **not** suspended (ADR 0111 §1): it settled, and the answer
    /// reaches the agent as context on a later turn.
    Question,
    /// The merge conflicted → ask `repair`.
    Conflict,
    /// A clean merge awaits keep/reject → ask `review`.
    Changes,
    /// The turn settled and the human hasn't spoken since → ask `reply`.
    /// Default **mute**: queuing every settled turn is exactly the noise
    /// ADR 0082 exists to kill — the operator opts in.
    TurnSettled,
}

impl Signal {
    /// Every signal, in priority order (see the enum docs).
    pub const ALL: [Signal; 4] = [
        Signal::Question,
        Signal::Conflict,
        Signal::Changes,
        Signal::TurnSettled,
    ];

    /// The wire/config name of this signal.
    pub fn key(self) -> &'static str {
        match self {
            Signal::Question => "question",
            Signal::Conflict => "conflict",
            Signal::Changes => "changes",
            Signal::TurnSettled => "turn-settled",
        }
    }

    /// The ask this signal raises — the task's `kind` (ADR 0082 §2).
    pub fn ask(self) -> &'static str {
        match self {
            Signal::Question => "answer",
            Signal::Conflict => "repair",
            Signal::Changes => "review",
            Signal::TurnSettled => "reply",
        }
    }

    /// The shipped default when no rule names this signal.
    pub fn default_attention(self) -> Attention {
        match self {
            Signal::TurnSettled => Attention::Mute,
            _ => Attention::Queue,
        }
    }
}

fn parse_attention(raw: &str) -> Option<Attention> {
    match raw {
        "queue" => Some(Attention::Queue),
        "badge" => Some(Attention::Badge),
        "mute" => Some(Attention::Mute),
        _ => None,
    }
}

/// The parsed, total attention policy: ask it about any signal and it answers,
/// from the operator's rule when one names the signal, else the shipped default.
#[derive(Clone, Debug, Default)]
pub struct AttentionRules {
    by_signal: BTreeMap<&'static str, Attention>,
}

impl AttentionRules {
    /// Parse the rules document. Total: `None`, malformed JSON, an unknown
    /// signal, or an unknown attention value never fail — each unusable rule is
    /// simply not adopted (forward-compatible with a newer writer). First rule
    /// naming a signal wins (first-match-wins, ADR 0082 §3).
    pub fn parse(raw: Option<&str>) -> Self {
        let mut by_signal = BTreeMap::new();
        let Some(raw) = raw else {
            return Self { by_signal };
        };
        let Ok(doc) = serde_json::from_str::<serde_json::Value>(raw) else {
            return Self { by_signal };
        };
        let Some(rules) = doc.get("rules").and_then(|r| r.as_array()) else {
            return Self { by_signal };
        };
        for rule in rules {
            let Some(signal) = rule
                .get("signal")
                .and_then(|s| s.as_str())
                .and_then(|key| Signal::ALL.into_iter().find(|s| s.key() == key))
            else {
                continue;
            };
            let Some(attention) = rule
                .get("attention")
                .and_then(|a| a.as_str())
                .and_then(parse_attention)
            else {
                continue;
            };
            by_signal.entry(signal.key()).or_insert(attention);
        }
        Self { by_signal }
    }

    /// The attention level for `signal` — the operator's rule, else the default.
    pub fn attention(&self, signal: Signal) -> Attention {
        self.by_signal
            .get(signal.key())
            .copied()
            .unwrap_or_else(|| signal.default_attention())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_queue_everything_but_turn_settled() {
        let rules = AttentionRules::parse(None);
        assert_eq!(rules.attention(Signal::Question), Attention::Queue);
        assert_eq!(rules.attention(Signal::Conflict), Attention::Queue);
        assert_eq!(rules.attention(Signal::Changes), Attention::Queue);
        assert_eq!(rules.attention(Signal::TurnSettled), Attention::Mute);
    }

    #[test]
    fn rules_override_per_signal_first_match_wins() {
        let rules = AttentionRules::parse(Some(
            r#"{"version":1,"rules":[
                {"signal":"turn-settled","attention":"queue"},
                {"signal":"changes","attention":"badge"},
                {"signal":"changes","attention":"mute"}
            ]}"#,
        ));
        assert_eq!(rules.attention(Signal::TurnSettled), Attention::Queue);
        assert_eq!(rules.attention(Signal::Changes), Attention::Badge);
        // unnamed signals keep their defaults
        assert_eq!(rules.attention(Signal::Question), Attention::Queue);
    }

    #[test]
    fn parsing_is_total_over_garbage() {
        for raw in [
            "not json",
            "{}",
            r#"{"rules":"nope"}"#,
            r#"{"rules":[{"signal":"unknown","attention":"queue"},{"signal":"changes"},{"signal":"changes","attention":"loud"}]}"#,
        ] {
            let rules = AttentionRules::parse(Some(raw));
            // every unusable rule is ignored; defaults hold
            assert_eq!(rules.attention(Signal::Changes), Attention::Queue, "{raw}");
            assert_eq!(
                rules.attention(Signal::TurnSettled),
                Attention::Mute,
                "{raw}"
            );
        }
    }
}
