//! Engagement-scoped taint (M1, ADR 0026). Ported from
//! `specs/models/engagement-taint.qnt`.
//!
//! Because a runtime session persists across a turn boundary, the agent *remembers*
//! what it read in an earlier run when it produces an output in a later run. So an
//! output's conservative taint is the owners of everything the **engagement** read
//! up to production — not just the producing run's reads. Egress of a tainted
//! output to a non-TCB recipient requires consent from **every stakeholder except
//! the recipient**.
//!
//! Discharges `SOUND`: no non-TCB authority holds an output unless every
//! engagement-scoped stakeholder consented (the per-run-taint teeth leaks it).

use std::collections::BTreeSet;

/// Everything the engagement has read, accumulated across all its turns. The taint
/// of any output produced in the engagement is the owners of this whole set.
#[derive(Clone, Debug, Default)]
pub struct EngagementReads {
    reads: BTreeSet<String>,
}

impl EngagementReads {
    pub fn new() -> Self {
        Self::default()
    }
    /// Record a read. Survives `new_turn` (the persistent thread remembers it).
    pub fn read(&mut self, item: impl Into<String>) {
        self.reads.insert(item.into());
    }
    /// The conservative, engagement-scoped taint of an output produced now: the
    /// owners of *everything* the engagement has read.
    pub fn taint(&self, owner_of: impl Fn(&str) -> String) -> BTreeSet<String> {
        self.reads.iter().map(|r| owner_of(r)).collect()
    }
    /// The accumulated read-set itself — the items the engagement has read. The
    /// admission shell uses it as an output's durable provenance.
    pub fn items(&self) -> &BTreeSet<String> {
        &self.reads
    }
}

/// The SOUND egress gate: may an output carrying `taint` cross to `dst`?
/// Allowed iff `dst` is in the trusted base (`tcb`) **or** every stakeholder other
/// than `dst` has consented to `dst` (a `(stakeholder, recipient)` pair in `bases`).
pub fn can_egress(
    taint: &BTreeSet<String>,
    dst: &str,
    tcb: &BTreeSet<String>,
    bases: &BTreeSet<(String, String)>,
) -> bool {
    tcb.contains(dst)
        || taint
            .iter()
            .filter(|a| a.as_str() != dst)
            .all(|a| bases.contains(&(a.clone(), dst.to_string())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    // Fixed config mirroring engagement-taint.qnt: context→B, method→A, tcb={model}.
    fn owner_of(r: &str) -> String {
        if r == "context" {
            "B".into()
        } else {
            "A".into()
        }
    }
    fn tcb() -> BTreeSet<String> {
        BTreeSet::from(["model".to_string()])
    }

    #[derive(Clone, Debug)]
    enum Op {
        Read(String),
        NewTurn,
        Produce,
        Consent(String, String),
        Egress(String),
    }

    fn arb_op() -> impl Strategy<Value = Op> {
        let auth = prop_oneof![
            Just("A".to_string()),
            Just("B".to_string()),
            Just("ext".to_string()),
            Just("model".to_string())
        ];
        let res = prop_oneof![Just("context".to_string()), Just("method".to_string())];
        prop_oneof![
            res.prop_map(Op::Read),
            Just(Op::NewTurn),
            Just(Op::Produce),
            (auth.clone(), auth.clone()).prop_map(|(by, to)| Op::Consent(by, to)),
            auth.prop_map(Op::Egress),
        ]
    }

    proptest! {
        /// SOUND over every reachable trace: any non-TCB authority that obtained the
        /// output had consent from every engagement-scoped stakeholder but itself.
        #[test]
        fn engagement_taint_sound(ops in prop::collection::vec(arb_op(), 0..40)) {
            let mut reads = EngagementReads::new();
            let mut produced = false;
            let mut tracked: BTreeSet<String> = BTreeSet::new(); // taint the boundary records
            let mut truth: BTreeSet<String> = BTreeSet::new();   // oracle, frozen at produce
            let mut bases: BTreeSet<(String, String)> = BTreeSet::new();
            let mut obtained: BTreeSet<String> = BTreeSet::new();
            let tcb = tcb();

            for op in ops {
                match op {
                    Op::Read(r) => reads.read(r),
                    // a new turn doesn't forget engagement reads — that's the point.
                    Op::NewTurn => {}
                    Op::Produce => {
                        if !produced {
                            produced = true;
                            // engagement-scoped (the correct rule), not per-run.
                            tracked = reads.taint(owner_of);
                            truth = reads.taint(owner_of); // oracle = the same set
                        }
                    }
                    Op::Consent(by, to) => { bases.insert((by, to)); }
                    Op::Egress(dst) => {
                        if produced && can_egress(&tracked, &dst, &tcb, &bases) {
                            obtained.insert(dst);
                        }
                    }
                }
                // SOUND vs the frozen oracle: no non-TCB holder lacks full consent.
                for holder in &obtained {
                    let ok = tcb.contains(holder)
                        || truth.iter().filter(|a| a.as_str() != holder)
                            .all(|a| bases.contains(&(a.clone(), holder.clone())));
                    prop_assert!(ok, "non-stakeholder {holder} holds the output without full consent");
                }
            }
        }
    }

    #[test]
    fn items_accumulate_across_turns_and_dedup() {
        let mut reads = EngagementReads::new();
        reads.read("context");
        reads.read("context"); // a repeat read is the same item
        reads.read("method");
        // a new turn does not forget prior reads (engagement-scoped).
        assert_eq!(
            reads.items(),
            &BTreeSet::from(["context".to_string(), "method".to_string()])
        );
    }

    /// The teeth: scoping taint to the *producing run* leaks across a turn — an
    /// output made in a fresh turn after an earlier turn read protected context
    /// egresses to a non-stakeholder with no consent.
    #[test]
    fn per_run_taint_would_leak() {
        // turn 1: read protected context (owner B). turn 2: produce + egress to ext.
        let mut reads = EngagementReads::new();
        reads.read("context"); // engagement remembers this across the turn
        let per_run_taint: BTreeSet<String> = BTreeSet::new(); // produced in a fresh turn → empty
        let engagement_taint = reads.taint(owner_of); // {B}
        let bases = BTreeSet::new();
        let tcb = tcb();
        // per-run taint wrongly permits egress (no stakeholders to consent)…
        assert!(can_egress(&per_run_taint, "ext", &tcb, &bases));
        // …while engagement-scoped taint correctly blocks it (B never consented).
        assert!(!can_egress(&engagement_taint, "ext", &tcb, &bases));
    }
}
