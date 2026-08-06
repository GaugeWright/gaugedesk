//! The **advancement policy** (ATTN-3, ADR 0082 §4–5): operator rules deciding,
//! at settle, whether a turn's clean merge **auto-advances** to `main` or
//! **holds** for human review.
//!
//! Advancement is a governance gate, so unlike the attention policy it is
//! **fail-closed everywhere**: no rules → hold; a rule that doesn't fully cover
//! the turn → hold; a fact that can't be resolved → hold. The only rule
//! vocabulary today is `writes-within` — advance when every file the turn
//! changed falls inside the operator's named path scopes — with three safety
//! conjuncts no configuration can waive:
//!
//! - **A config-touching diff never auto-advances.** `.agent-config.json` is
//!   where a policy loosening lives; the loosening review is a human gate
//!   (this is deliberately *stricter* than detecting loosening — a tightening
//!   holds too, and that's fine: fail toward holding).
//! - **A gate-touching diff never auto-advances** (ADR 0110 §5, GATE-5).
//!   Running a gate is work; changing one is an edit act. An agent holding
//!   gate-approved content that then edits the gate is choosing what its own
//!   next release will be allowed to say, and that loop closes silently if the
//!   diff can auto-keep.
//! - **An externally-tainted turn never auto-advances.** If the engagement has
//!   read any resource whose owner is not the chat's own authority (or whose
//!   owner can't be resolved), the outputs carry someone else's stake — the
//!   read-side guard over the runtime-certified read-set (ADR 0082 §4).
//!
//! Write-side decisions prefer WhippleScript's certified DR-0036 dynamic
//! guarantee outcome, matched by exact name (ADR 0082 §5), which keeps the gate
//! placement-neutral. An older/unwitnessed runtime falls back to GaugeDesk's
//! local workspace diff; a certified violation holds without consulting that
//! fallback. GaugeDesk grows no policy language here: the document is data,
//! this module its one reader.
//!
//! Every auto-advance is admitted as ordinary merge events plus a transcript
//! citation naming the rule and the facts it matched — the audit trail says
//! *why* `main` moved without a human. Parsing is total: a malformed document
//! yields no rules, i.e. everything holds.

/// The account-settings key holding the rules document.
pub const ADVANCEMENT_RULES_SETTING: &str = "advancement.rules";

/// The envelope guarantee GaugeDesk declares from the operator's auto-keep
/// scopes (ADR 0082 §5, WhippleScript DR-0036): the runtime evaluates it per
/// turn (`held` / `violated` / `not_evaluated`) and this module matches the
/// name **verbatim** — never re-evaluating semantics. The suffix after the
/// colon is a label; the declaration's `paths` carry the actual globs.
pub const OPERATOR_WRITES_GUARANTEE: &str = "writes_within:operator-auto-keep";

/// A config/agent-policy file whose changes carry a safety meaning — mirrors
/// the web client's `CONFIG_FILE_RE` (policy-diff.ts) so both sides agree on
/// what "touches config" means.
fn is_config_path(path: &str) -> bool {
    let name = path.rsplit('/').next().unwrap_or(path);
    name.eq_ignore_ascii_case(".agent-config.json")
        || name.eq_ignore_ascii_case("agent-config.json")
}

/// The project's inbound gate: its program and its governance envelope
/// (ADR 0110 §5, GATE-5).
///
/// Running a gate is work; changing one is an edit act, and the difference is
/// the whole reason the gate lives in the workspace as an ordinary editable
/// program rather than behind a route. An agent that has just read gate-approved
/// content and then edits the gate in the same turn is the attacker steering its
/// own *future* release — a loop that closes silently if that diff can
/// auto-keep.
///
/// Matched on the path the gate is installed at rather than on a directory
/// prefix: `gates/` is the location `gate::GATE_PROGRAM_PATH` names, and tying
/// this to those constants keeps the two from drifting apart.
fn is_gate_path(path: &str) -> bool {
    let normalized = path.trim_start_matches("./");
    normalized == crate::gate::GATE_PROGRAM_PATH || normalized == crate::gate::GATE_ENVELOPE_PATH
}

/// The facts one settled turn presents to the rules — computed once at settle
/// from GaugeDesk-owned truth (the workspace diff) and the engagement's certified
/// read-set; the advance citation embeds what it matched.
#[derive(Clone, Debug, Default)]
pub struct TurnFacts {
    /// Every file the diff names (unified-diff `diff --git` headers).
    pub changed_paths: Vec<String>,
    /// Read-set stakeholders beyond the chat's owning authority (taint guard);
    /// an unresolvable owner counts as external — fail toward holding.
    pub external_read_stakeholders: Vec<String>,
}

impl TurnFacts {
    /// The unwaivable holds (ADR 0082 §4), checked before **either** decision
    /// path — local coverage or a certified guarantee. A config touch or an
    /// external read stake never auto-advances, whatever the runtime certified
    /// about write scopes: the guarantee certifies writes; these guard
    /// different axes.
    pub fn violates_safety(&self) -> Option<String> {
        if let Some(config) = self.changed_paths.iter().find(|p| is_config_path(p)) {
            return Some(format!("the turn touched the policy config `{config}`"));
        }
        // ADR 0110 §5: a gate edit is reviewed, never kept. Placed here rather
        // than left to the operator's scopes because this is the one hold an
        // operator must not be able to configure away — the scopes are the very
        // thing an agent would be steering.
        if let Some(gate) = self.changed_paths.iter().find(|p| is_gate_path(p)) {
            return Some(format!("the turn edited the project's gate `{gate}`"));
        }
        if !self.external_read_stakeholders.is_empty() {
            return Some(format!(
                "the turn read content with external stake: {}",
                self.external_read_stakeholders.join(", ")
            ));
        }
        None
    }

    /// The files a unified diff names, in first-seen order (the `b/` side of
    /// each `diff --git` header, so deletions are named too).
    pub fn changed_paths_of(diff: &str) -> Vec<String> {
        let mut paths = Vec::new();
        for line in diff.lines() {
            let Some(rest) = line.strip_prefix("diff --git a/") else {
                continue;
            };
            let Some(idx) = rest.rfind(" b/") else {
                continue;
            };
            let path = rest[idx + 3..].trim();
            if !path.is_empty() && !paths.iter().any(|p| p == path) {
                paths.push(path.to_string());
            }
        }
        paths
    }
}

/// One `writes-within` rule: the path scopes a turn must stay inside.
#[derive(Clone, Debug)]
pub struct WritesWithin {
    pub paths: Vec<String>,
}

/// A path-scope pattern, deliberately tiny (no glob engine, no new grammar):
/// `dir/**` = everything under `dir/`; `*.ext` = any file with that extension;
/// anything else = the exact path. Documented in the settings surface.
fn scope_matches(pattern: &str, path: &str) -> bool {
    if let Some(prefix) = pattern.strip_suffix("/**") {
        return path.starts_with(&format!("{prefix}/"));
    }
    if let Some(suffix) = pattern.strip_prefix("*") {
        return path.ends_with(suffix);
    }
    pattern == path
}

/// Whether an operator scope would sweep the gate into auto-keep.
///
/// Uses the same matcher the decision uses, so `gates/**` and `*.whip` are
/// caught alongside the exact path — a prefix scope is the likelier way an
/// operator pulls the gate in, and it is the one a hand-written check would
/// miss.
fn covers_the_gate(scope: &str) -> bool {
    [
        crate::gate::GATE_PROGRAM_PATH,
        crate::gate::GATE_ENVELOPE_PATH,
    ]
    .iter()
    .any(|path| scope_matches(scope, path))
}

/// The parsed advancement rules. Total parse; empty on anything unusable.
#[derive(Clone, Debug, Default)]
pub struct AdvancementRules {
    rules: Vec<WritesWithin>,
}

impl AdvancementRules {
    /// Parse `{"version":1,"rules":[{"advance":"writes-within","paths":["docs/**"]}]}`.
    /// Unknown rule kinds and malformed entries are ignored (never adopted);
    /// a rule with no usable path yields nothing — there is no "match all" shorthand.
    pub fn parse(raw: Option<&str>) -> Self {
        let mut rules = Vec::new();
        let Some(raw) = raw else {
            return Self { rules };
        };
        let Ok(doc) = serde_json::from_str::<serde_json::Value>(raw) else {
            return Self { rules };
        };
        let Some(entries) = doc.get("rules").and_then(|r| r.as_array()) else {
            return Self { rules };
        };
        for entry in entries {
            if entry.get("advance").and_then(|k| k.as_str()) != Some("writes-within") {
                continue;
            }
            let Some(paths) = entry.get("paths").and_then(|p| p.as_array()) else {
                continue;
            };
            let paths: Vec<String> = paths
                .iter()
                .filter_map(|p| p.as_str())
                .map(str::trim)
                .filter(|p| !p.is_empty() && *p != "**") // no blanket scope
                .map(str::to_string)
                .collect();
            if !paths.is_empty() {
                rules.push(WritesWithin { paths });
            }
        }
        Self { rules }
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// The scopes to declare as the [`OPERATOR_WRITES_GUARANTEE`] envelope
    /// guarantee: the first rule's paths (the one the settings surface edits).
    /// Empty when no rules — nothing is declared, the runtime evaluates
    /// nothing, and everything holds. The local matcher and the runtime's glob
    /// agree on the documented forms (`dir/**`, `*.ext`, exact).
    ///
    /// Any scope that would cover the gate is dropped (GATE-5) — `gates/**` and
    /// `*.whip` as much as the exact path, since a prefix scope is the likelier
    /// way an operator sweeps the gate in. `violates_safety` already holds a
    /// gate edit whatever this declares, so nothing turns on it for safety — but
    /// a declaration claiming `gates/inbound.whip` is auto-keepable would be an
    /// envelope stating something GaugeDesk will not honour, and an envelope
    /// that overstates is worse than one that says less.
    pub fn declared_scopes(&self) -> Vec<String> {
        self.rules
            .first()
            .map(|rule| {
                rule.paths
                    .iter()
                    .filter(|scope| !covers_the_gate(scope))
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    /// The fail-closed decision: `Some(citation)` to auto-advance, `None` to
    /// hold. Advances only when a rule's scopes cover **every** changed path
    /// and both safety conjuncts hold; the citation names rule + facts.
    pub fn decide(&self, facts: &TurnFacts) -> Option<String> {
        // Nothing changed is ATTN-1's rule (handled before rules run); nothing
        // to cover here means nothing to advance for.
        if facts.changed_paths.is_empty() {
            return None;
        }
        if facts.violates_safety().is_some() {
            return None;
        }
        for rule in &self.rules {
            let covered = facts
                .changed_paths
                .iter()
                .all(|path| rule.paths.iter().any(|scope| scope_matches(scope, path)));
            if covered {
                return Some(format!(
                    "rule writes-within({}) covered {}; no config touched, no external reads",
                    rule.paths.join(", "),
                    facts.changed_paths.join(", "),
                ));
            }
        }
        None
    }
}

/// The wire type for a certified dynamic guarantee outcome lives with the
/// harness seam (the runtime adapters produce it); re-exported here so the
/// policy vocabulary is importable from one place.
pub use gaugedesk_harness::GuaranteeOutcome;

/// What the runtime-certified guarantees say about advancing (ADR 0082 §5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GuaranteeVerdict {
    /// The operator guarantee held — advance, citing the certificate.
    AdvanceHeld(String),
    /// The runtime witnessed a write outside scope — hold **hard**: local
    /// truth is never consulted against a certified violation.
    HoldViolated(String),
    /// Not declared / not evaluated / unwitnessed — the local-truth path
    /// decides (authoritative on a local placement, where GaugeDesk owns policy).
    Unwitnessed,
}

impl AdvancementRules {
    /// Match the operator guarantee's certified outcome **by name** — this
    /// consumer never re-evaluates semantics (ADR 0080 / ADR 0082 §5). Safety
    /// conjuncts ([`TurnFacts::violates_safety`]) still apply outside this
    /// verdict; they guard axes the write guarantee does not certify.
    pub fn decide_from_guarantees(&self, outcomes: &[GuaranteeOutcome]) -> GuaranteeVerdict {
        if self.is_empty() {
            // No rules → nothing was declared under our name; whatever report
            // exists is not ours to advance on.
            return GuaranteeVerdict::Unwitnessed;
        }
        let Some(ours) = outcomes
            .iter()
            .find(|o| o.name == OPERATOR_WRITES_GUARANTEE)
        else {
            return GuaranteeVerdict::Unwitnessed;
        };
        match ours.outcome.as_str() {
            "held" => GuaranteeVerdict::AdvanceHeld(format!(
                "runtime-certified {}: {}",
                ours.name, ours.detail
            )),
            "violated" => GuaranteeVerdict::HoldViolated(format!(
                "runtime-certified violation of {}: {}",
                ours.name, ours.detail
            )),
            _ => GuaranteeVerdict::Unwitnessed,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules(raw: &str) -> AdvancementRules {
        AdvancementRules::parse(Some(raw))
    }

    fn facts(paths: &[&str]) -> TurnFacts {
        TurnFacts {
            changed_paths: paths.iter().map(|s| s.to_string()).collect(),
            external_read_stakeholders: Vec::new(),
        }
    }

    #[test]
    fn no_rules_holds_everything() {
        for raw in [
            None,
            Some("garbage"),
            Some("{}"),
            Some(r#"{"rules":[{"advance":"unknown"}]}"#),
        ] {
            let r = AdvancementRules::parse(raw);
            assert!(r.decide(&facts(&["docs/a.md"])).is_none(), "{raw:?}");
        }
    }

    #[test]
    fn covered_paths_advance_uncovered_hold() {
        let r = rules(
            r#"{"version":1,"rules":[{"advance":"writes-within","paths":["docs/**","*.md"]}]}"#,
        );
        assert!(r.decide(&facts(&["docs/a.txt", "README.md"])).is_some());
        assert!(r.decide(&facts(&["docs/a.txt", "src/main.rs"])).is_none());
        // exact-path scope
        let exact = rules(r#"{"rules":[{"advance":"writes-within","paths":["notes.txt"]}]}"#);
        assert!(exact.decide(&facts(&["notes.txt"])).is_some());
        assert!(exact.decide(&facts(&["notes2.txt"])).is_none());
    }

    #[test]
    fn safety_conjuncts_are_not_waivable() {
        let r = rules(r#"{"rules":[{"advance":"writes-within","paths":["*.json","docs/**"]}]}"#);
        // A config touch holds even when the scope would cover it.
        assert!(r.decide(&facts(&["docs/.agent-config.json"])).is_none());
        // An external read stake holds even with covered paths.
        let mut tainted = facts(&["docs/a.md"]);
        tainted.external_read_stakeholders = vec!["other-authority".into()];
        let r2 = rules(r#"{"rules":[{"advance":"writes-within","paths":["docs/**"]}]}"#);
        assert!(r2.decide(&tainted).is_none());
    }

    #[test]
    fn guarantee_verdicts_match_by_name_and_fail_toward_unwitnessed() {
        let r = rules(r#"{"rules":[{"advance":"writes-within","paths":["docs/**"]}]}"#);
        let report = serde_json::json!({
            "static": ["signed_policy_identity_verified"],
            "dynamic": [
                { "name": OPERATOR_WRITES_GUARANTEE, "outcome": "held", "detail": "1 write(s) within scope" },
                { "name": "no_reads_beyond_grant", "outcome": "held", "detail": "" }
            ]
        });
        let outcomes = GuaranteeOutcome::from_report(&report);
        assert!(matches!(
            r.decide_from_guarantees(&outcomes),
            GuaranteeVerdict::AdvanceHeld(c) if c.contains(OPERATOR_WRITES_GUARANTEE)
        ));

        // A certified violation holds hard.
        let violated = GuaranteeOutcome::from_report(&serde_json::json!({
            "dynamic": [{ "name": OPERATOR_WRITES_GUARANTEE, "outcome": "violated", "detail": "write(s) outside scope: src/x.rs" }]
        }));
        assert!(matches!(
            r.decide_from_guarantees(&violated),
            GuaranteeVerdict::HoldViolated(_)
        ));

        // Not evaluated / absent / unknown outcome / no rules → unwitnessed.
        for report in [
            serde_json::json!({}),
            serde_json::json!({ "dynamic": "nope" }),
            serde_json::json!({ "dynamic": [{ "name": OPERATOR_WRITES_GUARANTEE, "outcome": "not_evaluated" }] }),
            serde_json::json!({ "dynamic": [{ "name": "writes_within:other", "outcome": "held" }] }),
        ] {
            assert_eq!(
                r.decide_from_guarantees(&GuaranteeOutcome::from_report(&report)),
                GuaranteeVerdict::Unwitnessed,
                "{report}"
            );
        }
        assert_eq!(
            AdvancementRules::parse(None).decide_from_guarantees(&outcomes),
            GuaranteeVerdict::Unwitnessed,
            "no rules → nothing declared under our name"
        );
    }

    #[test]
    fn declared_scopes_are_the_first_rules_paths() {
        assert!(AdvancementRules::parse(None).declared_scopes().is_empty());
        let r = rules(r#"{"rules":[{"advance":"writes-within","paths":["docs/**","*.md"]}]}"#);
        assert_eq!(
            r.declared_scopes(),
            vec!["docs/**".to_string(), "*.md".to_string()]
        );
    }

    #[test]
    fn blanket_scope_is_refused_and_paths_parse_from_diffs() {
        let r = rules(r#"{"rules":[{"advance":"writes-within","paths":["**"]}]}"#);
        assert!(r.is_empty(), "a match-everything scope is not a rule");
        let diff = "diff --git a/docs/a.md b/docs/a.md\nindex 1..2 100644\n--- a/docs/a.md\n+++ b/docs/a.md\n@@\ndiff --git a/gone.txt b/gone.txt\ndeleted file mode 100644\n";
        assert_eq!(
            TurnFacts::changed_paths_of(diff),
            vec!["docs/a.md".to_string(), "gone.txt".to_string()]
        );
    }

    /// GATE-5: a gate edit is reviewed, never auto-kept (ADR 0110 §5).
    ///
    /// Placed among the unwaivable holds rather than left to the operator's
    /// scopes, because the scopes are exactly what an agent would be steering.
    /// Approved content is gate output; an agent that reads it and then edits
    /// the gate in the same turn is choosing what its *next* release will be
    /// allowed to say.
    #[test]
    fn a_gate_edit_never_auto_advances_however_wide_the_scopes() {
        let rules = AdvancementRules::parse(Some(
            r#"{"version":1,"rules":[{"advance":"writes-within","paths":["gates/**","docs/**"]}]}"#,
        ));
        let facts = TurnFacts {
            changed_paths: vec![crate::gate::GATE_PROGRAM_PATH.to_string()],
            ..Default::default()
        };
        assert!(
            facts.violates_safety().is_some(),
            "a gate edit is an unwaivable hold",
        );
        assert_eq!(
            rules.decide(&facts),
            None,
            "and no operator scope can advance it",
        );
    }

    #[test]
    fn the_gate_envelope_holds_as_hard_as_the_gate_program() {
        // The envelope is where `grant endorse` lives. Weakening it is weakening
        // the gate just as surely as rewriting the program, and it is the
        // quieter of the two edits.
        let facts = TurnFacts {
            changed_paths: vec![crate::gate::GATE_ENVELOPE_PATH.to_string()],
            ..Default::default()
        };
        assert!(facts.violates_safety().is_some());
    }

    #[test]
    fn a_certified_guarantee_does_not_rescue_a_gate_edit() {
        // `decide_from_guarantees` can return `AdvanceHeld` for a runtime that
        // certified the write was in scope. The safety conjuncts are evaluated
        // outside that verdict, so a certified gate write still holds — the
        // guarantee certifies *where* a write landed, not whether that place may
        // be auto-kept.
        let rules = AdvancementRules::parse(Some(
            r#"{"version":1,"rules":[{"advance":"writes-within","paths":["gates/**"]}]}"#,
        ));
        let certified = vec![GuaranteeOutcome {
            name: OPERATOR_WRITES_GUARANTEE.to_string(),
            outcome: "held".to_string(),
            detail: "1 write(s) within scope".to_string(),
        }];
        assert!(matches!(
            rules.decide_from_guarantees(&certified),
            GuaranteeVerdict::AdvanceHeld(_)
        ));
        let facts = TurnFacts {
            changed_paths: vec![crate::gate::GATE_PROGRAM_PATH.to_string()],
            ..Default::default()
        };
        assert!(
            facts.violates_safety().is_some(),
            "the safety conjunct is checked outside the certified verdict",
        );
    }

    #[test]
    fn the_declared_envelope_scopes_never_claim_the_gate() {
        // A prefix scope is the likelier way the gate gets swept in, so the
        // filter uses the same matcher the decision does rather than comparing
        // strings.
        for scope in ["gates/**", "*.whip", crate::gate::GATE_PROGRAM_PATH] {
            let document = format!(
                r#"{{"version":1,"rules":[{{"advance":"writes-within","paths":["{scope}","docs/**"]}}]}}"#
            );
            let declared = AdvancementRules::parse(Some(&document)).declared_scopes();
            assert_eq!(
                declared,
                vec!["docs/**".to_string()],
                "`{scope}` must not be declared auto-keepable",
            );
        }
    }

    #[test]
    fn an_ordinary_workspace_file_still_advances() {
        // The hold is narrow on purpose: it names the gate, not the project.
        let rules = AdvancementRules::parse(Some(
            r#"{"version":1,"rules":[{"advance":"writes-within","paths":["docs/**"]}]}"#,
        ));
        let facts = TurnFacts {
            changed_paths: vec!["docs/notes.md".to_string()],
            ..Default::default()
        };
        assert!(rules.decide(&facts).is_some());
    }
}
