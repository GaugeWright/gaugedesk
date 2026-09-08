//! The pinned WhippleScript action contract consumed by GaugeDesk (ACTION-2).
//!
//! These are the runtime owner's types and verification boundaries. Decoding a
//! command, possessing a receipt, or knowing this digest grants no authority.
//! The product shell must authenticate principals, admit intent and retain exact
//! references before invoking the governed facade.

pub const REVISION: &str = "whipplescript-host-action/v1.0.0";
pub const DIGEST: &str = "17575ebb1b477d939a2bfc71bb07d866ba2ac45b4230f2b36ac6221a0886685e";

pub use whipplescript_kernel::host_action::CompiledHostAction;
pub use whipplescript_kernel::host_facade as facade;
pub use whipplescript_kernel::host_protocol::{action, action_result, execution, recovery};
