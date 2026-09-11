//! The pinned WhippleScript action contract consumed by GaugeDesk (ACTION-2).
//!
//! These are the runtime owner's types and verification boundaries. Decoding a
//! command, possessing a receipt, or knowing this digest grants no authority.
//! The product shell must authenticate principals, admit intent and retain exact
//! references before invoking the governed facade.

pub const REVISION: &str = "whipplescript-host-action/v3.0.0";
pub const DIGEST: &str = "00e082316c68f5c696663cfaef2ad6f9e4488b707d172ba4f0c1829e02877e63";

pub use whipplescript_kernel::host_action::CompiledHostAction;
pub use whipplescript_kernel::host_facade as facade;
pub use whipplescript_kernel::host_protocol::{action, action_result, execution, recovery};
pub use whipplescript_store::{log_append::LogAppend, native_stores::NativeStores, RuntimeStore};

/// Product admission carries the runtime owner's complete command. The shell
/// authenticates it before calling the product store; this alias grants no
/// authority and does not create an agent run or turn.
pub type ProductActionAdmission =
    gaugedesk_core::host_action_admission::HostActionAdmission<action::HostActionCommand>;

/// Register the runtime owner's exact native file package in one transaction.
/// This configures handlers, not product access or an action execution grant.
pub fn register_native_file_package(
    store: &whipplescript_store::SqliteStore,
) -> whipplescript_store::StoreResult<()> {
    register_native_package(store, "std.files")
}

/// Register the owner's correction capability schema without an ambient
/// recording grant. Each invocation still requires the governed bound adapter.
pub fn register_native_recording_package(
    store: &whipplescript_store::SqliteStore,
) -> whipplescript_store::StoreResult<()> {
    register_native_package(store, "std.vcs")
}

fn register_native_package(
    store: &whipplescript_store::SqliteStore,
    package: &str,
) -> whipplescript_store::StoreResult<()> {
    let manifest = whipplescript::std_manifests::EMBEDDED_STD_MANIFESTS
        .iter()
        .find_map(|(name, manifest)| (*name == package).then_some(*manifest))
        .ok_or_else(|| {
            whipplescript_store::StoreError::Conflict(format!(
                "pinned runtime has no embedded {package} package"
            ))
        })?;
    store.register_package_manifests([manifest])?;
    Ok(())
}
