//! Recoverable product outbox admission into an authenticated runtime (ACTION-3).
//! The caller supplies a configured destination and current verifier/proof.
//! This bridge never executes an effect or treats an admission as its outcome.

use gaugedesk_store::command_dispatch::CommittedDispatch;
use gaugedesk_store::{AdmitError, CommandRecordFact, Store};
use gaugedesk_whip_runtime::host_actions::{
    action::{ActionAdmissionReceipt, ActionAdmissionVerifier, HostActionCommand},
    facade::{GovernedHostFacade, HostFacadeError},
    CompiledHostAction, LogAppend, ProductActionAdmission, RuntimeStore,
};

pub const ACKNOWLEDGMENT_KIND: &str = "host_action_runtime_admission_v1";

/// Product-owned causal link carrying the runtime owner's unchanged receipt.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeAcknowledgment {
    pub product_command_id: String,
    pub runtime_ref: String,
    pub receipt: ActionAdmissionReceipt,
}

#[derive(Debug)]
pub enum DeliveryError {
    Product(AdmitError),
    Runtime(HostFacadeError),
    Invalid(&'static str),
    Encoding(serde_json::Error),
}

/// Deliver only the original receipted command to the configured runtime.
/// `runtime_ref` comes from trusted destination configuration, never request
/// metadata. The facade independently verifies the signed policy and current
/// admission proof. An acknowledgment write failure leaves the outbox intact;
/// redelivery obtains the same runtime admission and retries this product write.
/// No route or scheduler uses this bridge until its authenticated factory and
/// input-retention obligations are implemented.
pub fn deliver_admitted_action<S: RuntimeStore + LogAppend>(
    product: &mut Store,
    scope: &str,
    runtime_ref: &str,
    runtime: &mut GovernedHostFacade<S>,
    action: &CompiledHostAction,
    verifier: &dyn ActionAdmissionVerifier,
    proof: &[u8],
) -> Result<RuntimeAcknowledgment, DeliveryError> {
    let command = product
        .fold::<ProductActionAdmission>(scope)
        .map_err(DeliveryError::Product)?
        .command
        .ok_or(DeliveryError::Invalid(
            "host action has no product admission",
        ))?;
    let delivery = product
        .committed_dispatch::<ProductActionAdmission>(scope, &command.request_id)
        .map_err(DeliveryError::Product)?
        .ok_or(DeliveryError::Invalid(
            "host action has no committed dispatch",
        ))?;
    if delivery.command != command
        || command.instance_ref().ok().as_deref() != Some(scope)
        || command.fingerprint().ok().as_deref() != Some(delivery.dispatch.command_ref.as_str())
        || delivery.dispatch.runtime_ref != runtime_ref
    {
        return Err(DeliveryError::Invalid(
            "host action dispatch does not match its admission",
        ));
    }
    let receipt = runtime
        .admit_action(command, action, verifier, proof)
        .map_err(DeliveryError::Runtime)?;
    record_runtime_acknowledgment(product, scope, delivery, receipt)
}

fn record_runtime_acknowledgment(
    product: &mut Store,
    scope: &str,
    delivery: CommittedDispatch<HostActionCommand>,
    receipt: ActionAdmissionReceipt,
) -> Result<RuntimeAcknowledgment, DeliveryError> {
    receipt.validate_for(&delivery.command).map_err(|_| {
        DeliveryError::Invalid("runtime acknowledgment does not match the product command")
    })?;
    let acknowledgment = RuntimeAcknowledgment {
        product_command_id: delivery.command_id,
        runtime_ref: delivery.dispatch.runtime_ref,
        receipt,
    };
    let payload = serde_json::to_string(&acknowledgment).map_err(DeliveryError::Encoding)?;
    // A distinct derived command scope avoids collisions with a caller-chosen
    // request key. The causal fact remains in the original action's order.
    product
        .admit_record_facts(
            &format!("host-action-runtime-ack:{scope}"),
            "admitted",
            &payload,
            &[CommandRecordFact {
                scope_id: scope.into(),
                kind: ACKNOWLEDGMENT_KIND.into(),
                payload: payload.clone(),
            }],
        )
        .map_err(DeliveryError::Product)?;
    Ok(acknowledgment)
}

#[cfg(test)]
mod tests {
    use super::*;
    use gaugedesk_core::ids::{AuthorityId, PublicKey};
    use gaugedesk_core::signature::{verify_signature, Signature, SigningKey};
    use gaugedesk_store::command_dispatch::{CommandDispatch, DISPATCH_KIND};
    use gaugedesk_store::ContentCodec;
    use gaugedesk_whip_runtime::host_actions::{action::HostActionCommand, NativeStores};
    use gaugedesk_whip_runtime::{
        sign_hosted_policy_envelope, GovernanceRootVerifier, ProtocolError,
    };
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };

    const SOURCE: &str = r#"workflow ReferenceAction
input content InputReference
output result Result
class InputReference { handle string version_ref string label_ref string }
class Result { handle string }
rule echo
  when InputReference as r
=> { complete result { handle r.handle } }
"#;
    const DESTINATION: &str = "home:issuer:native";

    // A cryptographically verified, exact, revocable fixture admission. The
    // live Home/device/agent grant resolver remains a separate factory task.
    struct CurrentAuthority {
        key: PublicKey,
        expected: Vec<u8>,
        revoked: AtomicBool,
    }
    impl ActionAdmissionVerifier for CurrentAuthority {
        fn verify(
            &self,
            _: &HostActionCommand,
            bytes: &[u8],
            proof: &[u8],
        ) -> Result<(), ProtocolError> {
            if self.revoked.load(Ordering::SeqCst)
                || bytes != self.expected
                || !verify_signature(bytes, &Signature::new(proof), &self.key).unwrap_or(false)
            {
                return Err(ProtocolError::Mismatch("current authenticated action"));
            }
            Ok(())
        }
    }

    struct Fixture {
        directory: tempfile::TempDir,
        signed_policy: String,
        root: GovernanceRootVerifier,
        command: HostActionCommand,
        action: CompiledHostAction,
        verifier: CurrentAuthority,
        proof: Vec<u8>,
    }
    impl Fixture {
        fn new(delegated: bool) -> Self {
            let key = SigningKey::from_seed(&[41; 32]).unwrap();
            let issuer = AuthorityId::new("home:issuer");
            let signed_policy = sign_hosted_policy_envelope(
                "grant file_store ledger -> file:/srv/ledger.db readable by Operator\n",
                &issuer,
                &key,
                7,
            )
            .unwrap();
            let root = GovernanceRootVerifier::new(issuer, key.public_key());
            let action = CompiledHostAction::compile("reference.echo", SOURCE, None).unwrap();
            let mut command = crate::host_action_admission_tests::command(delegated);
            command.operation = "reference.echo".into();
            command.program_version_ref = action.version_ref().into();
            command.input_schema_ref = action.input_schema_ref().into();
            command.inputs.get_mut("content").unwrap().handle = "ledger".into();
            command.resources.clear();
            let temporary = GovernedHostFacade::from_signed_store_with_verifier(
                NativeStores::open_in_memory().unwrap(),
                7,
                &signed_policy,
                &root,
            )
            .unwrap();
            command.policy = temporary.policy_ref().clone();
            let expected = command.signing_bytes().unwrap();
            let proof = key.sign(&expected).as_bytes().to_vec();
            Self {
                directory: tempfile::tempdir().unwrap(),
                signed_policy,
                root,
                command,
                action,
                verifier: CurrentAuthority {
                    key: key.public_key(),
                    expected,
                    revoked: AtomicBool::new(false),
                },
                proof,
            }
        }
        fn scope(&self) -> String {
            self.command.instance_ref().unwrap()
        }
        fn host(&self) -> GovernedHostFacade<NativeStores> {
            let path = self.directory.path();
            GovernedHostFacade::from_signed_store_with_verifier(
                NativeStores::open(
                    path.join("runtime.sqlite"),
                    path.join("coord.sqlite"),
                    path.join("items.sqlite"),
                )
                .unwrap(),
                7,
                &self.signed_policy,
                &self.root,
            )
            .unwrap()
        }
        fn admit_product(&self, product: &mut Store, command_ref: String) {
            product
                .admit_with_dispatch::<ProductActionAdmission>(
                    &self.scope(),
                    &self.command.request_id,
                    self.command.clone(),
                    &CommandDispatch {
                        runtime_ref: DESTINATION.into(),
                        command_ref,
                    },
                )
                .unwrap();
        }
        fn deliver(
            &self,
            product: &mut Store,
            host: &mut GovernedHostFacade<NativeStores>,
        ) -> Result<RuntimeAcknowledgment, DeliveryError> {
            deliver_admitted_action(
                product,
                &self.scope(),
                DESTINATION,
                host,
                &self.action,
                &self.verifier,
                &self.proof,
            )
        }
    }

    struct UnavailableAcknowledgment(AtomicBool);
    impl ContentCodec for UnavailableAcknowledgment {
        fn encode(&self, _: &str, kind: &str, payload: &str) -> Result<String, String> {
            if kind == ACKNOWLEDGMENT_KIND && self.0.load(Ordering::SeqCst) {
                Err("injected product acknowledgment write failure".into())
            } else {
                Ok(payload.into())
            }
        }
        fn decode(&self, _: &str, _: &str, payload: &str) -> Option<String> {
            Some(payload.into())
        }
    }

    #[test]
    fn lost_product_acknowledgment_recovers_the_same_runtime_admission_after_restart() {
        for delegated in [false, true] {
            let fixture = Fixture::new(delegated);
            let failure = Arc::new(UnavailableAcknowledgment(AtomicBool::new(true)));
            let mut product = Store::open_in_memory().unwrap().with_codec(failure.clone());
            fixture.admit_product(&mut product, fixture.command.fingerprint().unwrap());
            let mut host = fixture.host();
            assert!(matches!(
                fixture.deliver(&mut product, &mut host),
                Err(DeliveryError::Product(AdmitError::Codec(_)))
            ));
            assert_eq!(host.kernel().store().list_instances().unwrap().len(), 1);
            let runtime_events = host.kernel().store().list_events(&fixture.scope()).unwrap();
            assert!(!runtime_events.is_empty());
            assert!(host
                .kernel()
                .store()
                .list_effects(&fixture.scope())
                .unwrap()
                .is_empty());
            assert!(product
                .records(&fixture.scope(), ACKNOWLEDGMENT_KIND)
                .unwrap()
                .is_empty());
            let mut reopened = product.sibling().unwrap();
            drop(product);
            drop(host);
            failure.0.store(false, Ordering::SeqCst);
            let mut host = fixture.host();
            let first = fixture.deliver(&mut reopened, &mut host).unwrap();
            assert_eq!(fixture.deliver(&mut reopened, &mut host).unwrap(), first);
            assert_eq!(
                host.kernel().store().list_events(&fixture.scope()).unwrap(),
                runtime_events
            );
            assert_eq!(host.kernel().store().list_instances().unwrap().len(), 1);
            assert_eq!(
                reopened
                    .records(&fixture.scope(), DISPATCH_KIND)
                    .unwrap()
                    .len(),
                1
            );
            let facts = reopened
                .records(&fixture.scope(), ACKNOWLEDGMENT_KIND)
                .unwrap();
            assert_eq!(facts.len(), 1);
            assert_eq!(
                serde_json::from_str::<RuntimeAcknowledgment>(&facts[0]).unwrap(),
                first
            );
            assert_eq!(
                first.receipt.fingerprint,
                fixture.command.fingerprint().unwrap()
            );
            assert_eq!(
                first.product_command_id,
                reopened
                    .command_for_key(&fixture.scope(), &fixture.command.request_id)
                    .unwrap()
                    .unwrap()
                    .command_id
            );
        }
    }

    #[test]
    fn delivery_refuses_unadmitted_or_mismatched_commands_before_runtime_admission() {
        let fixture = Fixture::new(false);
        let mut host = fixture.host();
        let mut product = Store::open_in_memory().unwrap();
        assert!(matches!(
            fixture.deliver(&mut product, &mut host),
            Err(DeliveryError::Invalid(_))
        ));
        product
            .admit_with_dispatch::<ProductActionAdmission>(
                "wrong-product-scope",
                &fixture.command.request_id,
                fixture.command.clone(),
                &CommandDispatch {
                    runtime_ref: DESTINATION.into(),
                    command_ref: fixture.command.fingerprint().unwrap(),
                },
            )
            .unwrap();
        assert!(matches!(
            deliver_admitted_action(
                &mut product,
                "wrong-product-scope",
                DESTINATION,
                &mut host,
                &fixture.action,
                &fixture.verifier,
                &fixture.proof
            ),
            Err(DeliveryError::Invalid(_))
        ));
        fixture.admit_product(&mut product, "different-command".into());
        assert!(matches!(
            fixture.deliver(&mut product, &mut host),
            Err(DeliveryError::Invalid(_))
        ));
        let mut product = Store::open_in_memory().unwrap();
        fixture.admit_product(&mut product, fixture.command.fingerprint().unwrap());
        assert!(matches!(
            deliver_admitted_action(
                &mut product,
                &fixture.scope(),
                "another-runtime",
                &mut host,
                &fixture.action,
                &fixture.verifier,
                &fixture.proof
            ),
            Err(DeliveryError::Invalid(_))
        ));
        assert!(host.kernel().store().list_instances().unwrap().is_empty());
        assert!(product
            .records(&fixture.scope(), ACKNOWLEDGMENT_KIND)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn runtime_rechecks_authentication_and_revocation_even_after_an_acknowledged_delivery() {
        let fixture = Fixture::new(true);
        let mut product = Store::open_in_memory().unwrap();
        fixture.admit_product(&mut product, fixture.command.fingerprint().unwrap());
        let mut host = fixture.host();
        assert!(matches!(
            deliver_admitted_action(
                &mut product,
                &fixture.scope(),
                DESTINATION,
                &mut host,
                &fixture.action,
                &fixture.verifier,
                b"forged proof"
            ),
            Err(DeliveryError::Runtime(_))
        ));
        assert!(host.kernel().store().list_instances().unwrap().is_empty());
        fixture.deliver(&mut product, &mut host).unwrap();
        let events = host.kernel().store().list_events(&fixture.scope()).unwrap();
        fixture.verifier.revoked.store(true, Ordering::SeqCst);
        assert!(matches!(
            fixture.deliver(&mut product, &mut host),
            Err(DeliveryError::Runtime(_))
        ));
        assert_eq!(
            host.kernel().store().list_events(&fixture.scope()).unwrap(),
            events
        );
        assert_eq!(
            product
                .records(&fixture.scope(), ACKNOWLEDGMENT_KIND)
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn acknowledgment_refuses_foreign_or_invalid_owner_receipts() {
        let fixture = Fixture::new(false);
        let mut product = Store::open_in_memory().unwrap();
        fixture.admit_product(&mut product, fixture.command.fingerprint().unwrap());
        let mut host = fixture.host();
        let admitted = host
            .admit_action(
                fixture.command.clone(),
                &fixture.action,
                &fixture.verifier,
                &fixture.proof,
            )
            .unwrap();
        for corruption in ["fingerprint", "instance", "position", "digest"] {
            let delivery = product
                .committed_dispatch::<ProductActionAdmission>(
                    &fixture.scope(),
                    &fixture.command.request_id,
                )
                .unwrap()
                .unwrap();
            let mut receipt = admitted.clone();
            match corruption {
                "fingerprint" => receipt.fingerprint.push_str("-other"),
                "instance" => receipt.instance_ref.push_str("-other"),
                "position" => receipt.admitted_at.sequence = 0,
                "digest" => receipt.admitted_at.head_digest.clear(),
                _ => unreachable!(),
            }
            assert!(
                matches!(
                    record_runtime_acknowledgment(
                        &mut product,
                        &fixture.scope(),
                        delivery,
                        receipt
                    ),
                    Err(DeliveryError::Invalid(_))
                ),
                "{corruption}"
            );
        }
        assert!(product
            .records(&fixture.scope(), ACKNOWLEDGMENT_KIND)
            .unwrap()
            .is_empty());
        let original = fixture.deliver(&mut product, &mut host).unwrap();
        let facts = product
            .records(&fixture.scope(), ACKNOWLEDGMENT_KIND)
            .unwrap();
        assert_eq!(facts.len(), 1);
        assert_eq!(
            serde_json::from_str::<RuntimeAcknowledgment>(&facts[0]).unwrap(),
            original
        );
    }
}
