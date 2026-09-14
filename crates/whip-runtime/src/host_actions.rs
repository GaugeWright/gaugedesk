//! The pinned WhippleScript action contract consumed by GaugeDesk (ACTION-2).
//!
//! These are the runtime owner's types and verification boundaries. Decoding a
//! command, possessing a receipt, or knowing this digest grants no authority.
//! The product shell must authenticate principals, admit intent and retain exact
//! references before invoking the governed facade.

pub const REVISION: &str = "whipplescript-host-action/v4.0.0";
pub const DIGEST: &str = "b468641c9ccb6d41482c2f9c5a2c5f49258611a90fd9776dec87c39546d06370";

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

/// Register the owner's native tracker package so a governed action may reach
/// the runtime's tracker door (`execute_tracker_filing`).
///
/// Registering the package is not a filing grant and not a queue binding. The
/// door still demands a `TrackerExecutionAuthority` that authorizes observation
/// before any log read and the exact filing before any target I/O, and the
/// envelope still has to bind the queue handle and admit its resource flows.
/// This only makes the handlers present; everything that decides *whether* a
/// filing may happen sits above it.
pub fn register_native_tracker_package(
    store: &whipplescript_store::SqliteStore,
) -> whipplescript_store::StoreResult<()> {
    register_native_package(store, "std.tracker")
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The tracker package registers into a native action runtime, and the
    /// registration is what the governed tracker door needs present.
    ///
    /// This asserts against the **pinned** runtime's embedded manifests rather
    /// than a copied fixture: the failure it exists to catch is a pin that no
    /// longer carries `std.tracker`, which would leave
    /// `register_native_tracker_package` returning a Conflict at runtime and
    /// the tracker door unreachable — with nothing at compile time to say so.
    #[test]
    fn the_pinned_runtime_can_register_its_tracker_package() {
        let store = whipplescript_store::SqliteStore::open_in_memory().expect("runtime store");
        register_native_tracker_package(&store).expect("pinned runtime embeds std.tracker");
    }

    /// The three native packages are distinct registrations. Registering one
    /// must not be mistaken for arranging another: the file door and the
    /// tracker door are separately authorized, and a single "register
    /// everything" call would blur exactly the boundary the doors draw.
    #[test]
    fn each_native_package_registers_separately() {
        for register in [
            register_native_file_package as fn(&whipplescript_store::SqliteStore) -> _,
            register_native_recording_package,
            register_native_tracker_package,
        ] {
            let store = whipplescript_store::SqliteStore::open_in_memory().expect("runtime store");
            register(&store).expect("each package registers on its own");
        }
    }

    /// A package the pinned runtime does not embed is refused, not silently
    /// skipped. Without this the test above could pass against a registration
    /// that quietly does nothing.
    #[test]
    fn an_unembedded_package_is_refused() {
        let store = whipplescript_store::SqliteStore::open_in_memory().expect("runtime store");
        let refusal = register_native_package(&store, "std.not_a_package")
            .expect_err("an absent package must refuse");
        assert!(
            format!("{refusal:?}").contains("std.not_a_package"),
            "the refusal names the package it could not find: {refusal:?}"
        );
    }
}
