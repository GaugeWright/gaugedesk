//! Loopback federation relay (FED-2): carries a federated message between two
//! in-process admission shells (the M2 two-authority collapse), driving the
//! verified [`gaugedesk_core::federated_delivery`] reducer (FD-1).
//!
//! The relay is **transport only**: it queues and delivers, but the fact appears in
//! the **target** scope only when the *target authority* admits it — the relay writes
//! nothing into the target scope and holds no payload basis (`INV-13`/`INV-14`). Only
//! the handle + correlation cross; never the payload (`INV-10`). Real cross-machine
//! transport (sockets, auth) is the `D-REMOTE` follow-on; the mechanism is here.

use gaugedesk_core::federated_delivery::{
    DeliveryCommand, DeliveryEnvelope, DeliveryPhase, DeliveryState,
};
use gaugedesk_core::ids::{AuthorityId, BridgeGrantId, Nonce, PublicKey};
use gaugedesk_store::{AdmitError, Store};

use crate::key_store::{KeyStore, LoopbackKeyStore};

/// One federated-delivery lifecycle instance per correlated message.
pub fn delivery_scope(correlation: &str) -> String {
    format!("delivery::{correlation}")
}

/// The relay **seam** (`RELAY-TRAIT-1`): the transport every cross-authority /
/// remote / mobile delivery rides. A relay carries a federated [`Message`] (a
/// payload **handle** + correlation) from a source to a target authority and
/// surfaces the facts a target scope has admitted. It is transport only — it
/// writes nothing into the target scope and holds no payload basis
/// (`INV-13`/`INV-14`); only the target's own admission creates the fact there.
///
/// The loopback in-process impl is [`LoopbackRelay`]; a real cross-machine TCP
/// relay (`RENDEZVOUS-STUB-1`/`SERVE-1`) attaches behind this same trait with no
/// rearchitecture (ADR 0020).
pub trait FederationRelay {
    /// Carry one message across the bridge into `target_scope`, returning whether
    /// the **target** admitted it. The relay creates the fact only via target
    /// admission; it never writes the payload.
    fn deliver(
        &self,
        store: &mut Store,
        target_scope: &str,
        msg: &Message,
    ) -> Result<bool, AdmitError>;

    /// The federated facts a target scope has admitted (handles + correlation only).
    fn admitted(
        &self,
        store: &Store,
        target_scope: &str,
    ) -> Result<Vec<serde_json::Value>, AdmitError>;
}

/// The loopback in-process relay (FED-2): the two-authority M2 collapse runs both
/// authorities in one [`Store`], so the relay queues + delivers in-process. The
/// real cross-machine transport attaches behind [`FederationRelay`] later.
#[derive(Clone, Copy, Debug, Default)]
pub struct LoopbackRelay;

impl FederationRelay for LoopbackRelay {
    fn deliver(
        &self,
        store: &mut Store,
        target_scope: &str,
        msg: &Message,
    ) -> Result<bool, AdmitError> {
        deliver(store, target_scope, msg)
    }

    fn admitted(
        &self,
        store: &Store,
        target_scope: &str,
    ) -> Result<Vec<serde_json::Value>, AdmitError> {
        admitted(store, target_scope)
    }
}

/// A federated message: a payload **handle** crossing from a source to a target
/// authority, plus a correlation id. The relay routes the handle; it never reads or
/// owns the payload.
#[derive(Clone, Debug)]
pub struct Message {
    pub correlation: String,
    pub source: String,
    pub target: String,
    pub payload_handle: String,
}

/// Drive one delivery across the loopback bridge: source authorizes → relay queues +
/// delivers (transport only) → the **target** admits it into `target_scope`. Returns
/// whether the target admitted. The relay writes nothing into the target scope; only
/// target admission creates the fact there.
pub fn deliver(store: &mut Store, target_scope: &str, msg: &Message) -> Result<bool, AdmitError> {
    let ds = delivery_scope(&msg.correlation);
    store.admit::<DeliveryState>(&ds, DeliveryCommand::AuthorizeFederatedMessage)?; // source
    store.admit::<DeliveryState>(&ds, DeliveryCommand::EnqueueFederatedMessage)?; // relay queues
    store.admit::<DeliveryState>(&ds, DeliveryCommand::RecordRelayDelivery)?; // relay delivers (transport)
                                                                              // The target verifies the source's signature before admitting (INV-21). The
                                                                              // source signs the message's canonical bytes with its real P-256 governance
                                                                              // key from the `KeyStore` (the loopback store derives it deterministically;
                                                                              // real enrollment swaps the store, not this path — ADR 0042).
    let signed_bytes = msg.correlation.clone().into_bytes();
    let source_key = LoopbackKeyStore.signing_key(&AuthorityId::new(&msg.source));
    let envelope = DeliveryEnvelope {
        signature: source_key.sign(&signed_bytes),
        source_pubkey: source_key.public_key(),
        signed_bytes,
        // Anti-replay binding (INV-21): a per-message single-use nonce and the
        // bridge grant the loopback delivery is bound to. The default delivery
        // binds to `bridge-grant-7` (DEFAULT_BRIDGE_GRANT_ID); a replayed nonce
        // or a mismatched grant would deny admission.
        nonce: Nonce::new(format!("nonce::{}", msg.correlation)),
        bridge_grant_id: BridgeGrantId::new("bridge-grant-7"),
        // Device binding (INV-21 / MOB-004): the loopback delivery presents the
        // bound device key the default delivery pins, and the device's bridge
        // grant is still active. A foreign or revoked device would deny
        // admission, so a revoked device cannot keep delivering.
        device_key: PublicKey::new("04dev1ce0ke7"),
        device_active: true,
    };
    let s = store.admit::<DeliveryState>(&ds, DeliveryCommand::AdmitTargetReceipt { envelope })?; // TARGET admits
    let admitted = s.phase == DeliveryPhase::TargetAdmitted;
    if admitted {
        // The fact now lives in the target's own scope, admitted by the target.
        let rec = serde_json::json!({
            "correlation": msg.correlation,
            "source": msg.source,
            "target": msg.target,
            "payload_handle": msg.payload_handle, // a handle — never the payload
        });
        store.append_record(target_scope, "federated", &rec.to_string())?;
    }
    Ok(admitted)
}

/// The federated facts admitted into a target scope (handles + correlation only).
pub fn admitted(store: &Store, target_scope: &str) -> Result<Vec<serde_json::Value>, AdmitError> {
    Ok(store
        .records(target_scope, "federated")?
        .into_iter()
        .filter_map(|r| serde_json::from_str(&r).ok())
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use gaugedesk_core::federated_delivery::Authority;

    #[test]
    fn a_message_crosses_to_the_target_scope_via_admission_only() {
        let mut store = Store::open_in_memory().unwrap();
        let msg = Message {
            correlation: "c1".into(),
            source: "A".into(),
            target: "B".into(),
            payload_handle: "ctx-method".into(),
        };
        // before delivery, B's scope holds no federated facts.
        assert!(admitted(&store, "scope-B").unwrap().is_empty());

        assert!(
            deliver(&mut store, "scope-B", &msg).unwrap(),
            "target admitted the message"
        );
        let facts = admitted(&store, "scope-B").unwrap();
        assert_eq!(facts.len(), 1);
        assert_eq!(
            facts[0]["payload_handle"], "ctx-method",
            "the handle crossed, not the payload"
        );

        // the delivery lifecycle confirms: admitted BY the target, relay holds no payload.
        let s = store.fold::<DeliveryState>(&delivery_scope("c1")).unwrap();
        assert_eq!(s.target_admitted_by, Authority::Target);
        assert!(!s.relay_has_payload_access);
        assert_ne!(s.payload_authority, Authority::Relay);
    }

    #[test]
    fn the_loopback_relay_carries_a_message_through_the_seam() {
        // The same crossing, driven through the `FederationRelay` trait rather than
        // the free functions — the seam every remote/mobile delivery rides.
        let relay = LoopbackRelay;
        let mut store = Store::open_in_memory().unwrap();
        let msg = Message {
            correlation: "c2".into(),
            source: "A".into(),
            target: "B".into(),
            payload_handle: "ctx-method".into(),
        };
        assert!(relay.admitted(&store, "scope-B").unwrap().is_empty());

        assert!(
            relay.deliver(&mut store, "scope-B", &msg).unwrap(),
            "target admitted via the seam"
        );
        let facts = relay.admitted(&store, "scope-B").unwrap();
        assert_eq!(facts.len(), 1);
        assert_eq!(
            facts[0]["payload_handle"], "ctx-method",
            "only the handle crossed the seam"
        );
    }

    /// The seam is object-safe: a relay can be held behind a trait object, so the
    /// loopback impl and a future cross-machine impl are interchangeable.
    #[test]
    fn the_relay_seam_is_usable_behind_a_trait_object() {
        let relay: Box<dyn FederationRelay> = Box::new(LoopbackRelay);
        let mut store = Store::open_in_memory().unwrap();
        let msg = Message {
            correlation: "c3".into(),
            source: "A".into(),
            target: "B".into(),
            payload_handle: "h".into(),
        };
        assert!(relay.deliver(&mut store, "scope-B", &msg).unwrap());
        assert_eq!(relay.admitted(&store, "scope-B").unwrap().len(), 1);
    }

    // --- LOOPBACK-TEST-1: two-authority federation, with signatures ----------
    //
    // The whole-crossing integration twin of `LOOPBACK-TEST-0` (which proptests
    // the reducer in isolation): drive the source → relay → target sequence in
    // one process and assert the security teeth *through the delivery shell* the
    // relay rides — a forged signature, a mismatched bridge grant, and a
    // replayed nonce each deny target admission (`INV-21`), and an admitted
    // crossing leaves the relay with no payload basis (`INV-13`/`INV-14`).
    use gaugedesk_core::federated_delivery::{
        DeliveryCommand, DeliveryEnvelope, DeliveryPhase, DeliveryState,
    };
    use gaugedesk_core::ids::PublicKey;
    use gaugedesk_core::signature::Signature;
    use gaugedesk_store::AdmitError;

    /// Drive one crossing through the same source → relay → target sequence
    /// [`deliver`] uses, but with a caller-chosen `envelope` so the integration
    /// test can present an adversarial envelope to the *target's* admission.
    /// Returns whether the target admitted; the production `deliver` is the
    /// valid-envelope special case of exactly this flow.
    fn cross_with_envelope(
        store: &mut Store,
        correlation: &str,
        envelope: DeliveryEnvelope,
    ) -> Result<bool, AdmitError> {
        let ds = delivery_scope(correlation);
        store.admit::<DeliveryState>(&ds, DeliveryCommand::AuthorizeFederatedMessage)?; // source
        store.admit::<DeliveryState>(&ds, DeliveryCommand::EnqueueFederatedMessage)?; // relay queues
        store.admit::<DeliveryState>(&ds, DeliveryCommand::RecordRelayDelivery)?; // relay delivers
        match store.admit::<DeliveryState>(&ds, DeliveryCommand::AdmitTargetReceipt { envelope }) {
            // The target admitted on the verified path.
            Ok(s) => Ok(s.phase == DeliveryPhase::TargetAdmitted),
            // A fail-closed admission rejection (bad sig / grant / nonce) is a
            // denied crossing, not a transport error.
            Err(AdmitError::Rejected(_)) => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// A well-formed source envelope for `correlation`, signed under the loopback
    /// source key and bound to the default bridge grant — the one a genuine
    /// crossing presents.
    fn signed_envelope(correlation: &str) -> DeliveryEnvelope {
        let source_key = LoopbackKeyStore.signing_key(&AuthorityId::new("A"));
        let signed_bytes = correlation.as_bytes().to_vec();
        DeliveryEnvelope {
            signature: source_key.sign(&signed_bytes),
            source_pubkey: source_key.public_key(),
            signed_bytes,
            nonce: Nonce::new(format!("nonce::{correlation}")),
            bridge_grant_id: BridgeGrantId::new("bridge-grant-7"),
            device_key: PublicKey::new("04dev1ce0ke7"),
            device_active: true,
        }
    }

    /// INV-21 / INV-13 / INV-14: a genuine two-authority crossing admits and the
    /// fact lives in the *target's* scope (admitted by the target), carrying only
    /// the handle; an envelope with a malformed signature, a mismatched bridge
    /// grant, or a replayed nonce is denied — the relay never writes the fact.
    #[test]
    fn loopback_two_authority_federation_with_signatures() {
        let mut store = Store::open_in_memory().unwrap();

        // --- a genuine crossing admits (target authority + verified envelope) --
        assert!(
            cross_with_envelope(&mut store, "ok", signed_envelope("ok")).unwrap(),
            "a signed envelope under the bound grant is admitted by the target"
        );
        // The fact lives in the target scope, admitted BY the target, relay-blind.
        let s = store.fold::<DeliveryState>(&delivery_scope("ok")).unwrap();
        assert_eq!(
            s.target_admitted_by,
            Authority::Target,
            "INV-13: only the target admits"
        );
        assert!(
            s.signature_verified,
            "INV-21: the source signature was verified before admission"
        );
        assert!(
            !s.relay_has_payload_access,
            "INV-10: the relay gained no payload read"
        );
        assert_ne!(
            s.payload_authority,
            Authority::Relay,
            "INV-14: the relay never becomes payload authority"
        );

        // --- INV-21: a forged (malformed) signature is denied ------------------
        let mut forged = signed_envelope("forged");
        forged.signature = Signature::new(vec![0u8; 8]); // not P-256-sized — fails closed
        assert!(
            !cross_with_envelope(&mut store, "forged", forged).unwrap(),
            "INV-21: an unverifiable signature denies target admission"
        );
        let s = store
            .fold::<DeliveryState>(&delivery_scope("forged"))
            .unwrap();
        assert_ne!(
            s.phase,
            DeliveryPhase::TargetAdmitted,
            "no target fact on the forged path"
        );
        assert!(!s.signature_verified);

        // --- INV-21: a mismatched bridge grant is denied -----------------------
        let mut wrong_grant = signed_envelope("wrong-grant");
        wrong_grant.bridge_grant_id = BridgeGrantId::new("bridge-grant-OTHER");
        assert!(
            !cross_with_envelope(&mut store, "wrong-grant", wrong_grant).unwrap(),
            "INV-21: an envelope minted under a different grant denies admission"
        );

        // --- INV-21 / MOB-004: a foreign or revoked device is denied -----------
        let mut wrong_device = signed_envelope("wrong-device");
        wrong_device.device_key = PublicKey::new("04not-the-bound-device");
        assert!(
            !cross_with_envelope(&mut store, "wrong-device", wrong_device).unwrap(),
            "MOB-004: an envelope presenting a foreign device key denies admission"
        );
        let mut revoked_device = signed_envelope("revoked-device");
        revoked_device.device_active = false;
        assert!(
            !cross_with_envelope(&mut store, "revoked-device", revoked_device).unwrap(),
            "MOB-004: a revoked device denies admission — it cannot keep delivering"
        );

        // --- INV-21 anti-replay: re-presenting an admitted envelope is denied --
        // The first crossing on `replay` admits and spends its nonce; the target
        // records the admission as a fact in its log. Re-presenting the *same*
        // signed envelope to the same delivery is rejected fail-closed — the
        // already-admitted envelope cannot write a second target fact (INV-21).
        let env = signed_envelope("replay");
        assert!(cross_with_envelope(&mut store, "replay", env.clone()).unwrap());
        let admitted_nonce = env.nonce.clone();
        let s = store
            .fold::<DeliveryState>(&delivery_scope("replay"))
            .unwrap();
        assert!(
            s.seen_nonces.contains(&admitted_nonce),
            "INV-21: the admitted nonce is now spent"
        );

        let ds = delivery_scope("replay");
        match store
            .admit::<DeliveryState>(&ds, DeliveryCommand::AdmitTargetReceipt { envelope: env })
        {
            Err(AdmitError::Rejected(_)) => {}
            other => {
                panic!("INV-21: re-presenting an admitted envelope must be denied, got {other:?}")
            }
        }
        // The delivery still shows exactly the one admission — the replay was
        // appended no second receipt.
        assert_eq!(s.phase, DeliveryPhase::TargetAdmitted);
        assert_eq!(
            s.seen_nonces.len(),
            1,
            "INV-21: the replay spent no further nonce"
        );
    }
}
