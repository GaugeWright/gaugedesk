//! Open-source public API boundary for the local control-plane app shell.
//!
//! The transitional crate root still re-exports these symbols for existing
//! callers, but open binaries and desktop shells should import this module so
//! the future open repo has a narrow, source-posture-specific API.

pub use crate::local_operator::LocalOperatorSecret;
pub use crate::open_route_stack::{open_control_plane, open_control_plane_with_native_saves};
pub use crate::open_runtime::{
    open_control_plane_root, open_prepare, open_serve, open_serve_workbench,
    open_serve_workbench_with,
};

/// Hash a small synthetic chat observation inside the native app. The desktop
/// shell only calls this app surface; it does not reach into the domain crate.
pub fn chat_acceptance_digest(text: &str) -> Result<String, String> {
    if text.len() > 1_048_576 {
        return Err("synthetic chat evidence input is too large".into());
    }
    Ok(gaugedesk_core::protected_profile::sha256_hex(
        text.as_bytes(),
    ))
}
