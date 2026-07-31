//! The v1 onboarding "package" and the app→whip event bridge (ADR 0075 Phase 2).
//!
//! The onboarding tracker is a flat checklist filed into the account-global
//! boundary's [`WhipTrackerHandle`]. Each step is one `WorkItem` in the
//! `onboarding` queue, tagged with a `metadata.step` key. App events
//! (credential connected, first turn, project created) drive two things,
//! best-effort:
//!
//! 1. a provenance event ingested into the boundary's `RuntimeKernel` (the
//!    durable "why did this close" trail), and
//! 2. closing the matching open checklist item.
//!
//! v1 keeps the *advancement* logic in Rust rather than a compiled whip program
//! whose rules lower `std.tracker` effects — that (Phase 2b) is deferred with the
//! rest of the rules engine (ADR 0075 §Consequences: the tracker is the interim
//! thin row store, sufficient for a flat checklist). The `RuntimeKernel` is still
//! stood up per boundary and carries the event stream, so Phase 2b is a swap of
//! the driver, not a new surface.
//!
//! Advancement is **best-effort by contract**: seeding or advancing onboarding
//! must never fail the real operation that triggered it (saving a credential,
//! running a turn, creating a project). Every entry point swallows tracker
//! errors after logging them.

use crate::workbench_state::Workbench;

/// The tracker queue the onboarding checklist lives in.
pub(crate) const ONBOARDING_QUEUE: &str = "onboarding";

/// The label every onboarding item carries, so the projection can tag its
/// task-bar pills and a future per-user filter can find them.
pub(crate) const ONBOARDING_LABEL: &str = "onboarding";

/// Who files the checklist. Not an assignee — just provenance on the row.
const ONBOARDING_FILER: &str = "onboarding-system";

/// Whether the onboarding feature is active. Off under the scripted fake agent
/// (`GAUGEWRIGHT_FAKE_AGENT`, used in dev/e2e): that harness needs no credential
/// and isn't a real first-run, so seeding the checklist there would put phantom
/// `issue` pills in the task bar the e2e suite doesn't expect. Mirrors the
/// server's `/account/onboarding-status` gate and `harness_select`'s runtime
/// choice, so the whole feature (overlay + tracker) is coherently on or off.
fn onboarding_enabled() -> bool {
    std::env::var("GAUGEWRIGHT_FAKE_AGENT").is_err()
}

/// One step of the first-run learn-to-build checklist. `step` is the stable key
/// matched by app events; `title`/`body` are placeholder copy — the real tutorial
/// content is designed separately (ADR 0075 §Context, deferred).
pub(crate) struct OnboardingStep {
    /// Stable key matched by the app event that closes this step.
    pub step: &'static str,
    /// The event type recorded into the kernel + expected to close this step.
    pub event_type: &'static str,
    pub title: &'static str,
    pub body: &'static str,
}

/// The v1 checklist, in the order it should appear in the task bar.
pub(crate) const ONBOARDING_STEPS: &[OnboardingStep] = &[
    OnboardingStep {
        step: "credential",
        event_type: "app.credential_connected",
        title: "Connect a model",
        body: "Add an LLM credential in account settings so agents can run.",
    },
    OnboardingStep {
        step: "first_turn",
        event_type: "app.first_turn",
        title: "Send your first message",
        body: "Open a chat and send a task to watch an agent work.",
    },
    OnboardingStep {
        step: "project",
        event_type: "app.project_created",
        title: "Create a project",
        body: "Projects are your trust boundaries — create one to organize work.",
    },
];

impl Workbench {
    /// File the onboarding checklist into the account-global tracker exactly
    /// once. Called at workbench build; a no-op on every start after the first
    /// (the queue already has items). Best-effort: a tracker failure here must
    /// not abort workbench startup.
    pub(crate) fn ensure_onboarding_seeded(&mut self) {
        if !onboarding_enabled() {
            return;
        }
        let default_assignee = self.authority().as_str().to_owned();
        let tracker = match self.account_tracker() {
            Ok(tracker) => tracker,
            Err(err) => {
                tracing::warn!(error = %err, "onboarding: could not open account tracker to seed");
                return;
            }
        };
        match tracker.has_items(ONBOARDING_QUEUE) {
            Ok(true) => return, // already seeded (open or closed) — never reseed
            Ok(false) => {}
            Err(err) => {
                tracing::warn!(error = %err, "onboarding: could not check tracker; skipping seed");
                return;
            }
        }
        let labels = [ONBOARDING_LABEL.to_owned()];
        for step in ONBOARDING_STEPS {
            let metadata = serde_json::json!({ "step": step.step });
            match tracker.file_item(
                ONBOARDING_QUEUE,
                step.title,
                step.body,
                &labels,
                &metadata,
                Some(ONBOARDING_FILER),
            ) {
                Ok(item) => {
                    if let Err(err) = tracker.assign_item(&item.id, Some(&default_assignee)) {
                        tracing::warn!(step = step.step, error = %err, "onboarding: failed to assign step");
                    }
                }
                Err(err) => {
                    tracing::warn!(step = step.step, error = %err, "onboarding: failed to file step");
                }
            }
        }
    }

    /// The app→whip bridge: an app event advanced the onboarding checklist.
    /// Records the event into the boundary's kernel for provenance and closes
    /// every open item whose `metadata.step` matches `step`. Best-effort — errors
    /// are logged, never propagated, so the triggering operation is unaffected.
    ///
    /// `payload_json` must be a JSON object string; it is stored verbatim as the
    /// kernel event payload (do not put secrets in it — this is a durable log).
    pub(crate) fn advance_onboarding(&mut self, step: &str, payload_json: &str) {
        if !onboarding_enabled() {
            return;
        }
        let Some(event_type) = ONBOARDING_STEPS
            .iter()
            .find(|s| s.step == step)
            .map(|s| s.event_type)
        else {
            tracing::warn!(step, "onboarding: advance for unknown step");
            return;
        };

        let tracker = match self.account_tracker() {
            Ok(tracker) => tracker,
            Err(err) => {
                tracing::warn!(step, error = %err, "onboarding: could not open tracker to advance");
                return;
            }
        };

        if let Err(err) = tracker.record_event(event_type, payload_json) {
            tracing::warn!(step, error = %err, "onboarding: failed to record provenance event");
            // Keep going: closing the checklist item is the user-visible part.
        }

        let open = match tracker.list_items(Some(ONBOARDING_QUEUE), Some("open")) {
            Ok(items) => items,
            Err(err) => {
                tracing::warn!(step, error = %err, "onboarding: could not list items to advance");
                return;
            }
        };
        for item in open {
            let matches = item
                .metadata
                .get("step")
                .and_then(|v| v.as_str())
                .is_some_and(|s| s == step);
            if matches {
                if let Err(err) = tracker.finish_item(&item.id, Some(event_type)) {
                    tracing::warn!(step, item = %item.id, error = %err, "onboarding: failed to close item");
                }
            }
        }
    }
}
