//! The exact WhippleScript host contract GaugeDesk's project-workstream code
//! is allowed to consume. `scripts/check-whipplescript-workstream-contract.mjs`
//! binds these runtime values to the public Git dependency and the pin manifest.

pub const REVISION: &str = "whipplescript-workstream-host/v1.0.3";
pub const DIGEST: &str = "079c53e8953a43c890267a6a0ad330f5b3947b973a974ae60820132c2c95d244";

pub(crate) const MIGRATABLE_PREVIOUS_REVISION: &str = "whipplescript-workstream-host/v1.0.2";
pub(crate) const MIGRATABLE_PREVIOUS_DIGEST: &str =
    "a6ac1ea8be061c728c89dd2b4b005f206e604a151260ae329f34bd1bdbcdc5b0";
