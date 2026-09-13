//! Open-source public API boundary for the local control-plane app shell.
//!
//! The transitional crate root still re-exports these symbols for existing
//! callers, but open binaries and desktop shells should import this module so
//! the future open repo has a narrow, source-posture-specific API.

pub use crate::open_route_stack::{open_control_plane, open_control_plane_with_native_saves};
pub use crate::open_runtime::{open_control_plane_root, open_serve};
