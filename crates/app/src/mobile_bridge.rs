//! Loopback mobile bridge (MOB-006): a **device-bound remote-projection** flow,
//! driven end-to-end in one process over the same [`FederationRelay`] seam
//! (`RELAY-TRAIT-1`) every cross-authority/remote/mobile delivery rides.
//!
//! A paired mobile device reaches the owner's runtime through the federation
//! bridge: the owner declares a boundary ceiling and **binds the device** to its
//! bridge grant (`DeviceBinding`, MOB-001), pinning the typed
//! `(DeviceId, BridgeGrantId)` and the device key a later delivery must present.
//! A projection then crosses to the device as a federated message — but only the
//! resource **handle name** crosses, never the payload (`INV-10`): the device can
//! render a file tree of handle names with no granted basis, and the payload stays
//! behind the [`resource_access`](gaugedesk_core::resource_access) grant.
//!
//! The crossing is **device-bound** (MOB-004): the delivery shell runs
//! `ValidateDeviceBinding` before it routes, so only the bound, still-active device
//! projects — a foreign device key or a revoked device is stopped before
//! admission, fail-closed (`INV-21`). A revoked device cannot keep projecting.
//!
//! Loopback only: both authorities and the device share one [`Store`]. A real
//! cross-machine mobile client attaches behind the same [`FederationRelay`] seam
//! with no rearchitecture (`MOBILE-PROJECTION-1`, ADR 0020).

use gaugedesk_core::boundary_lifecycle::{BoundaryCommand, BoundaryState};
use gaugedesk_core::federated_delivery::{DeliveryCommand, DeliveryEnvelope, DeliveryState};
use gaugedesk_core::ids::{BridgeGrantId, DeviceId, Nonce, PublicKey};
use gaugedesk_core::signature::Signature;
use gaugedesk_store::{AdmitError, Store};

use crate::federation_relay::{delivery_scope, FederationRelay, Message};

/// The bound device key the default loopback delivery pins (mirrors
/// `federated_delivery`'s `DEFAULT_DEVICE_KEY`): a genuine projection presents this
/// key, a foreign one is denied.
const BOUND_DEVICE_KEY: &str = "04dev1ce0ke7";

/// A paired mobile device and the bridge grant the owner bound it to (MOB-001).
/// The device key is what a federated delivery's envelope must present to project
/// (MOB-004); `active` materializes the grant's liveness — a revoked grant denies
/// any further projection.
#[derive(Clone, Debug)]
pub struct PairedDevice {
    pub device: DeviceId,
    pub bridge_grant: BridgeGrantId,
    pub device_key: PublicKey,
    pub active: bool,
}

impl PairedDevice {
    /// The default loopback device — bound to the grant the default delivery
    /// pins, presenting the bound device key, and currently active.
    pub fn loopback() -> Self {
        Self {
            device: DeviceId::new("device:pixel-9"),
            bridge_grant: BridgeGrantId::new("grant-7"),
            device_key: PublicKey::new(BOUND_DEVICE_KEY),
            active: true,
        }
    }

    /// The envelope this device would present to project `correlation` — signed
    /// under the loopback source key, bound to the default bridge grant, and
    /// carrying this device's key + liveness (MOB-004).
    fn envelope(&self, correlation: &str) -> DeliveryEnvelope {
        DeliveryEnvelope {
            signed_bytes: correlation.as_bytes().to_vec(),
            signature: Signature::new(vec![0u8; 64]),
            source_pubkey: PublicKey::new("04loopback-source"),
            nonce: Nonce::new(format!("nonce::{correlation}")),
            bridge_grant_id: BridgeGrantId::new("bridge-grant-7"),
            device_key: self.device_key.clone(),
            device_active: self.active,
        }
    }
}

/// The boundary scope a mobile bridge is set up on.
pub fn bridge_scope(chat: &str) -> String {
    format!("mobile-bridge::{chat}")
}

/// Owner-side setup: declare a boundary ceiling and **bind the paired device** to
/// its bridge grant (MOB-001). Returns the boundary state with the device bound —
/// the `(DeviceId, BridgeGrantId)` is now pinned, so a later projection must match
/// it (MOB-004). The bridge `scope` is a ceiling-declared boundary; binding is an
/// optional refinement that does not gate the accept→active path.
pub fn bind_device(
    store: &mut Store,
    scope: &str,
    device: &PairedDevice,
) -> Result<BoundaryState, AdmitError> {
    let owner = "local-user".to_string();
    let mut required = std::collections::BTreeSet::new();
    required.insert(owner.clone());
    store.admit::<BoundaryState>(scope, BoundaryCommand::Propose(required))?;
    store.admit::<BoundaryState>(
        scope,
        BoundaryCommand::DeclareCeiling(gaugedesk_core::boundary_lifecycle::Placement::local()),
    )?;
    store.admit::<BoundaryState>(
        scope,
        BoundaryCommand::BindDevice {
            device: device.device.clone(),
            bridge_grant: device.bridge_grant.clone(),
        },
    )
}

/// Project a resource handle to the paired device over the federation bridge
/// (MOB-006). The flow is device-bound (MOB-004) and handle-only (`INV-10`):
///
/// 1. **Device-binding gate** — the delivery shell runs `ValidateDeviceBinding`
///    over the device's envelope before routing. A foreign device key or a revoked
///    device fails the gate, so projection stops before any crossing (`INV-21`).
/// 2. **Handle-only crossing** — the projection crosses to the device's projection
///    scope over the [`relay`](FederationRelay) seam as a federated message
///    carrying the resource **handle name**, never its payload (`INV-10`).
///
/// Returns `Ok(true)` when the bound, active device projected the handle, `Ok(false)`
/// when the device-binding gate denied it (foreign / revoked device).
pub fn project_to_device<R: FederationRelay + ?Sized>(
    relay: &R,
    store: &mut Store,
    device: &PairedDevice,
    correlation: &str,
    projection_scope: &str,
    resource_handle: &str,
) -> Result<bool, AdmitError> {
    let ds = delivery_scope(correlation);
    let envelope = device.envelope(correlation);

    // 1. Device-binding gate (MOB-004): the shell validates the device *before*
    //    routing. `ValidateDeviceBinding` is a pure pre-check — it admits no fact;
    //    a foreign or revoked device fails it fail-closed, so a revoked device
    //    cannot keep projecting.
    match store.admit::<DeliveryState>(
        &ds,
        DeliveryCommand::ValidateDeviceBinding {
            envelope: envelope.clone(),
        },
    ) {
        Ok(_) => {}
        Err(AdmitError::Rejected(_)) => return Ok(false),
        Err(e) => return Err(e),
    }

    // 2. Handle-only crossing (INV-10): the projection rides the relay carrying
    //    the resource handle name only. The relay is transport — the target
    //    admits, and only a handle crosses.
    let msg = Message {
        correlation: correlation.to_string(),
        source: "local-user".to_string(),
        target: projection_scope.to_string(),
        payload_handle: resource_handle.to_string(),
    };
    relay.deliver(store, projection_scope, &msg)
}

/// A two-authority loopback environment a mobile flow runs against end to end
/// (MOB-013): the **owner** authority (the local runtime + the paired device's
/// bridge) and a **remote** authority (a runtime at a non-local placement). Both
/// authorities share one [`Store`] — the M2 two-authority collapse — and every
/// crossing rides the same [`FederationRelay`] seam (`RELAY-TRAIT-1`) a real
/// cross-machine deployment attaches behind (`MOBILE-PROJECTION-1`, ADR 0020).
///
/// The fixture is the integration twin of the unit-level bridge test: it composes
/// the device-bound bridge (MOB-001/MOB-004/MOB-006) with the remote runtime's
/// observation return (`OBSERVATION-FEDERATION-1`) so a single scenario exercises
/// **a run flowing back** from the remote authority into the owner's run, then a
/// **handle-only projection** of that run out to the paired mobile device (`INV-10`).
pub struct TwoAuthorityMobileFixture<R: FederationRelay> {
    /// The relay seam both crossings ride (loopback in the collapse).
    pub relay: R,
    /// The owner's paired, device-bound mobile (MOB-001).
    pub device: PairedDevice,
    /// The boundary scope the bridge is set up on.
    pub bridge_scope: String,
    /// The owner's run scope the remote turn's observations federate back into.
    pub run_scope: String,
}

impl TwoAuthorityMobileFixture<crate::federation_relay::LoopbackRelay> {
    /// The default loopback fixture for `chat`: the loopback relay, the loopback
    /// paired device, and a bridge + run scope derived from the chat.
    pub fn loopback(chat: &str) -> Self {
        Self {
            relay: crate::federation_relay::LoopbackRelay,
            device: PairedDevice::loopback(),
            bridge_scope: bridge_scope(chat),
            run_scope: format!("mobile-run::{chat}"),
        }
    }
}

impl<R: FederationRelay> TwoAuthorityMobileFixture<R> {
    /// Owner-side setup: bind the paired device to the bridge grant (MOB-001) and
    /// open the owner's run so a remote runtime's observations have a lifecycle to
    /// federate back into. Returns the boundary state with the device bound.
    pub fn bind(&self, store: &mut Store) -> Result<BoundaryState, AdmitError> {
        let b = bind_device(store, &self.bridge_scope, &self.device)?;
        store.admit::<gaugedesk_core::run::RunState>(
            &self.run_scope,
            gaugedesk_core::run::RunCommand::RequestRun,
        )?;
        store.admit::<gaugedesk_core::run::RunState>(
            &self.run_scope,
            gaugedesk_core::run::RunCommand::AdmitRun,
        )?;
        store.admit::<gaugedesk_core::run::RunState>(
            &self.run_scope,
            gaugedesk_core::run::RunCommand::StartRun,
        )?;
        Ok(b)
    }

    /// A run flows back: drive one turn on the **remote** authority's runtime and
    /// federate its observations into the owner's run over the relay seam
    /// (`OBSERVATION-FEDERATION-1`). Each observation crosses as a handle (`INV-10`),
    /// the relay holds no payload basis (`INV-13`/`INV-14`), and only the **owner's**
    /// admission turns it into standing run truth (`INV-4`). Returns the owner's
    /// admitted-observation count.
    pub fn run_flows_back(
        &self,
        store: &mut Store,
        harness: &mut dyn gaugedesk_harness::RemoteHarness,
        gate: &dyn gaugedesk_harness::EgressGate,
        prompt: &str,
    ) -> Result<u32, crate::remote_runtime::RemoteRuntimeError> {
        crate::remote_runtime::federate_remote_turn(store, &self.run_scope, harness, gate, prompt)
    }

    /// Project a run handle out to the paired mobile device over the bridge
    /// (MOB-006): device-bound (MOB-004) and handle-only (`INV-10`). Returns whether
    /// the bound, active device projected; a foreign or revoked device is denied.
    pub fn project_run_to_device(
        &self,
        store: &mut Store,
        correlation: &str,
        run_handle: &str,
    ) -> Result<bool, AdmitError> {
        project_to_device(
            &self.relay,
            store,
            &self.device,
            correlation,
            &self.device_projection_scope(),
            run_handle,
        )
    }

    /// The device's projection scope — where handle-only views land for the device.
    pub fn device_projection_scope(&self) -> String {
        format!("device::{}::projection", self.device.device.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::federation_relay::{self, LoopbackRelay};
    use gaugedesk_core::resource_access::AccessState;

    /// MOB-006 end-to-end: the owner binds a paired device to a ceiling-declared
    /// boundary (MOB-001), then a projection crosses to the device over the relay
    /// seam carrying only the resource **handle name** (`INV-10`) — and only the
    /// bound, active device may project (MOB-004); a revoked or foreign device is
    /// stopped before any crossing.
    #[test]
    fn mobile_bridge_projects_handle_only_to_the_bound_device() {
        let relay = LoopbackRelay;
        let mut store = Store::open_in_memory().unwrap();
        let scope = bridge_scope("chat-1");
        let device = PairedDevice::loopback();

        // --- MOB-001: the owner binds the paired device to its bridge grant ----
        let b = bind_device(&mut store, &scope, &device).unwrap();
        assert_eq!(
            b.device_binding,
            Some((device.device.clone(), device.bridge_grant.clone())),
            "MOB-001: the typed (DeviceId, BridgeGrantId) is pinned on the boundary"
        );

        // --- INV-10: the resource handle's NAME is visible without payload ------
        // The projected resource starts with no granted access basis: a mobile
        // file-tree can render its handle name, but the payload stays behind the
        // grant. This is the HANDLE_HIDES_PAYLOAD split the projection relies on.
        let access = AccessState::default();
        assert!(
            access.name_visible(),
            "INV-10: the handle name is projectable"
        );
        assert!(
            !access.payload_accessible(),
            "INV-10: the payload is not — no grant yet"
        );

        // --- MOB-006: the bound, active device projects the handle -------------
        let projection_scope = "device::pixel-9::projection";
        assert!(
            project_to_device(
                &relay,
                &mut store,
                &device,
                "proj-1",
                projection_scope,
                "handle::method"
            )
            .unwrap(),
            "the bound, active device projected the handle"
        );
        // …and only the HANDLE crossed the bridge, never the payload (INV-10).
        let crossed = federation_relay::admitted(&store, projection_scope).unwrap();
        assert_eq!(crossed.len(), 1, "exactly one projection crossed");
        assert_eq!(
            crossed[0]["payload_handle"], "handle::method",
            "INV-10: the resource handle name crossed, not its payload"
        );
    }

    /// MOB-004 tooth: a **revoked** device cannot keep projecting. With its bridge
    /// grant no longer active, the device-binding gate denies the projection before
    /// any crossing — the device's projection scope stays empty (`INV-21`).
    #[test]
    fn a_revoked_device_cannot_project() {
        let relay = LoopbackRelay;
        let mut store = Store::open_in_memory().unwrap();
        let scope = bridge_scope("chat-revoked");
        let device = PairedDevice::loopback();
        bind_device(&mut store, &scope, &device).unwrap();

        let revoked = PairedDevice {
            active: false,
            ..device.clone()
        };
        let projection_scope = "device::revoked::projection";
        assert!(
            !project_to_device(
                &relay,
                &mut store,
                &revoked,
                "proj-r",
                projection_scope,
                "handle::method"
            )
            .unwrap(),
            "MOB-004: a revoked device fails the device-binding gate"
        );
        assert!(
            federation_relay::admitted(&store, projection_scope)
                .unwrap()
                .is_empty(),
            "INV-21: a revoked device's projection never crosses the bridge"
        );
    }

    /// MOB-004 tooth: a **foreign** device key (one the owner never bound) is
    /// denied at the gate — a stolen pairing ticket presenting a different device
    /// key cannot project onto a bound bridge.
    #[test]
    fn a_foreign_device_cannot_project() {
        let relay = LoopbackRelay;
        let mut store = Store::open_in_memory().unwrap();
        let scope = bridge_scope("chat-foreign");
        let device = PairedDevice::loopback();
        bind_device(&mut store, &scope, &device).unwrap();

        let foreign = PairedDevice {
            device_key: PublicKey::new("04not-the-bound-device"),
            ..device.clone()
        };
        let projection_scope = "device::foreign::projection";
        assert!(
            !project_to_device(
                &relay,
                &mut store,
                &foreign,
                "proj-f",
                projection_scope,
                "handle::method"
            )
            .unwrap(),
            "MOB-004: a foreign device key fails the device-binding gate"
        );
        assert!(
            federation_relay::admitted(&store, projection_scope)
                .unwrap()
                .is_empty(),
            "INV-21: a foreign device's projection never crosses the bridge"
        );
    }

    /// The projection rides the [`FederationRelay`] seam behind a trait object —
    /// the loopback impl and a future cross-machine mobile relay are
    /// interchangeable (`MOBILE-PROJECTION-1`, ADR 0020).
    #[test]
    fn projection_rides_the_relay_seam_behind_a_trait_object() {
        let relay: Box<dyn FederationRelay> = Box::new(LoopbackRelay);
        let mut store = Store::open_in_memory().unwrap();
        let device = PairedDevice::loopback();
        bind_device(&mut store, &bridge_scope("chat-seam"), &device).unwrap();

        let projection_scope = "device::seam::projection";
        assert!(project_to_device(
            &*relay,
            &mut store,
            &device,
            "proj-s",
            projection_scope,
            "handle::ctx"
        )
        .unwrap(),);
        assert_eq!(
            federation_relay::admitted(&store, projection_scope)
                .unwrap()
                .len(),
            1
        );
    }

    use gaugedesk_core::run::{RunPhase, RunState};
    use gaugedesk_harness::AllowAllGate;
    use gaugedesk_pi_bridge::RemoteLoopbackHarness;

    /// MOB-013 end-to-end: the [`TwoAuthorityMobileFixture`] ties the whole mobile
    /// flow together over the two-authority loopback collapse. The owner binds the
    /// paired device's bridge (MOB-001/MOB-004) and opens a run; a turn on the
    /// **remote** authority's runtime **flows its observations back** into the
    /// owner's run over the relay seam (`OBSERVATION-FEDERATION-1`, `INV-4`); then a
    /// **handle** for that run projects out to the bound device (MOB-006), never the
    /// payload (`INV-10`). Both crossings ride the one [`FederationRelay`] seam.
    #[test]
    fn two_authority_mobile_run_flows_back_then_projects_to_the_device() {
        let mut store = Store::open_in_memory().unwrap();
        let fx = TwoAuthorityMobileFixture::loopback("chat-m13");

        // --- owner authority: bind the device-bound bridge + open the run --------
        let b = fx.bind(&mut store).unwrap();
        assert_eq!(
            b.device_binding,
            Some((fx.device.device.clone(), fx.device.bridge_grant.clone())),
            "MOB-001: the device is bound to the bridge grant on the owner's boundary"
        );
        assert_eq!(
            store.fold::<RunState>(&fx.run_scope).unwrap().phase,
            RunPhase::Running,
            "the owner's run is open for the remote authority's observations"
        );

        // --- remote authority: a turn flows its observations back to the owner ---
        let mut harness = RemoteLoopbackHarness::new(
            "127.0.0.1:7799",
            [
                r#"{"type":"agent_start"}"#,
                r#"{"type":"text_delta","delta":"mobile "}"#,
                r#"{"type":"text_delta","delta":"reply"}"#,
                r#"{"type":"agent_end","messages":[]}"#,
                r#"{"type":"response","command":"get_last_assistant_text","success":true,"data":{"text":"mobile reply"}}"#,
            ],
        );
        let count = fx
            .run_flows_back(&mut store, &mut harness, &AllowAllGate, "go")
            .expect("the remote turn federated its observations into the owner's run");
        assert!(
            count >= 2,
            "OBSERVATION-FEDERATION-1: the remote turn's observations flowed back"
        );

        // The observations crossed as handles only (INV-10) and became owner truth
        // only via the owner's admission (INV-4) — the run is still Running.
        let crossed = federation_relay::admitted(&store, &fx.run_scope).unwrap();
        assert_eq!(
            crossed.len() as u32,
            count,
            "every flowed-back observation crossed the bridge"
        );
        for fact in &crossed {
            assert!(
                fact["payload_handle"]
                    .as_str()
                    .unwrap()
                    .starts_with("obs::"),
                "INV-10: a handle crossed, never the observation body"
            );
        }
        assert_eq!(
            store.fold::<RunState>(&fx.run_scope).unwrap().observations,
            count
        );
        assert_eq!(
            store.fold::<RunState>(&fx.run_scope).unwrap().phase,
            RunPhase::Running
        );

        // --- projection: a handle for the run goes out to the bound device -------
        assert!(
            fx.project_run_to_device(&mut store, "proj-m13", "handle::run::mobile")
                .unwrap(),
            "MOB-006: the bound, active device projects the run handle"
        );
        let projected = federation_relay::admitted(&store, &fx.device_projection_scope()).unwrap();
        assert_eq!(
            projected.len(),
            1,
            "exactly one projection crossed to the device"
        );
        assert_eq!(
            projected[0]["payload_handle"], "handle::run::mobile",
            "INV-10: only the run handle crossed to the device, never the payload"
        );
    }

    /// MOB-013 tooth: the device binding still gates projection in the composed
    /// fixture — a **revoked** device cannot have a run projected to it, even after
    /// the run has legitimately flowed back from the remote authority (`INV-21`).
    #[test]
    fn two_authority_mobile_denies_a_revoked_device_projection() {
        let mut store = Store::open_in_memory().unwrap();
        let mut fx = TwoAuthorityMobileFixture::loopback("chat-m13-revoked");
        fx.bind(&mut store).unwrap();

        let mut harness = RemoteLoopbackHarness::new(
            "127.0.0.1:7799",
            [
                r#"{"type":"agent_start"}"#,
                r#"{"type":"text_delta","delta":"x"}"#,
                r#"{"type":"agent_end","messages":[]}"#,
                r#"{"type":"response","command":"get_last_assistant_text","success":true,"data":{"text":"x"}}"#,
            ],
        );
        fx.run_flows_back(&mut store, &mut harness, &AllowAllGate, "go")
            .unwrap();

        // Revoke the device, then try to project the run out to it.
        fx.device.active = false;
        assert!(
            !fx.project_run_to_device(&mut store, "proj-rev", "handle::run::mobile")
                .unwrap(),
            "MOB-004: a revoked device fails the device-binding gate"
        );
        assert!(
            federation_relay::admitted(&store, &fx.device_projection_scope())
                .unwrap()
                .is_empty(),
            "INV-21: a revoked device's projection never crosses the bridge"
        );
    }
}
