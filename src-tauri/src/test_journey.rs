//! The release canary's journey in the window (DR-0457).
//!
//! When the test entrances are admitted (`gaugedesk_app::test_signin`) and
//! `GAUGEDESK_TEST_JOURNEY` named a plan, the shell injects [`JOURNEY_JS`] into
//! the real window with the plan before it, and the window reports each step
//! through `test_journey_report`, which `gaugedesk_app::test_signin::report`
//! refuses unless a journey was loaded. The decisions — whether the entrances
//! are open, what a plan must hold, where a report goes — live in that crate,
//! where the green bar tests them; this is the script and the line that joins
//! it to the plan.

/// The journey, run in the window. A file of its own so it reads as the
/// JavaScript it is; it is compiled into the binary.
pub const JOURNEY_JS: &str = include_str!("test_journey.js");

/// The window's initialization script for a loaded journey: the plan as a
/// JavaScript value, then the journey.
pub fn script(journey: &gaugedesk_app::test_signin::Journey) -> String {
    format!(
        "window.__gwTestJourney = {};\n{JOURNEY_JS}",
        journey.plan_json()
    )
}
