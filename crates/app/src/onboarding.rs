//! The retired v1 onboarding checklist (ADR 0075 Phase 2, retired by DR-0185).
//!
//! ADR 0075 filed a flat three-step checklist into the account-global
//! boundary's tracker and closed each step from a best-effort app hook. Nothing
//! files or advances it any more: its copy was placeholder, its hooks missed
//! every other way of doing the same thing, and the real first-run tutorial is
//! Basics (ADR 0165, `WHIP-5`), which is not yet offered.
//!
//! What remains is what a root that already carries the checklist needs. Its
//! items stay in the tracker as legacy evidence (ADR 0165 forbids rewriting
//! them) and the task bar leaves them out. The queue itself stays: it is where
//! the account-global tracker's other issues are filed.

/// The tracker queue the onboarding checklist was filed into.
pub(crate) const ONBOARDING_QUEUE: &str = "onboarding";

/// The `metadata.step` keys of the retired checklist. An item carrying one of
/// these was filed by the old producer and is legacy evidence, not work.
const RETIRED_CHECKLIST_STEPS: &[&str] = &["credential", "first_turn", "project"];

/// Whether an item with this `metadata` is a step of the retired checklist,
/// which the task bar must not show even while it is still open in an older
/// root.
pub(crate) fn is_retired_checklist_step(metadata: &serde_json::Value) -> bool {
    metadata
        .get("step")
        .and_then(|v| v.as_str())
        .is_some_and(|step| RETIRED_CHECKLIST_STEPS.contains(&step))
}
