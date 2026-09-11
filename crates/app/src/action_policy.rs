//! Immutable action-owned policy preparation (ACTION-3). The host admits
//! current authority before calling this adapter; preparation is not execution.

use gaugedesk_core::{ids::AuthorityId, signature::SigningKey};
use gaugedesk_store::{CommandRecordFact, Store};
use gaugedesk_whip_runtime::{
    ifc::VerifiedEnvelope, sign_hosted_policy_envelope, GovernanceRootVerifier,
    HostGovernancePolicy, PolicyEpochRef,
};
use serde::{Deserialize, Serialize};
use whipplescript_kernel::gov::canonicalize;

const POLICY_KIND: &str = "host_action_policy_v1";
const PREPARATION_KEY: &str = "prepare";
const ACTION_EPOCH: u64 = 1;

/// Product preparation identity, not a replacement for the runtime's command
/// identity or fingerprint. Values come from the authenticated command factory.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionPolicyIdentity {
    pub issuer: String,
    pub scope: String,
    pub request_id: String,
}

impl ActionPolicyIdentity {
    pub(crate) fn storage_scope(&self) -> Result<String, String> {
        if [&self.issuer, &self.scope, &self.request_id]
            .iter()
            .any(|value| value.trim().is_empty())
        {
            return Err("action policy has incomplete identity".into());
        }
        // JSON framing avoids collisions between caller-chosen scope/request
        // strings. This is a record scope, never a filesystem path.
        Ok(format!(
            "host-action-policy:{}",
            serde_json::to_string(self).map_err(|error| error.to_string())?
        ))
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyRecord {
    identity: ActionPolicyIdentity,
    canonical_policy: String,
    signed_envelope: String,
    policy_ref: PolicyEpochRef,
}

/// Returned only after the runtime verifies the retained signed document.
/// Access to these bytes does not grant target access or dispatch permission.
pub struct RetainedActionPolicy {
    signed_envelope: String,
    policy_ref: PolicyEpochRef,
}

impl RetainedActionPolicy {
    pub fn signed_envelope(&self) -> &str {
        &self.signed_envelope
    }

    pub fn policy_ref(&self) -> &PolicyEpochRef {
        &self.policy_ref
    }
}

fn verify_record(
    record: &PolicyRecord,
    identity: &ActionPolicyIdentity,
    root: &GovernanceRootVerifier,
) -> Result<(), String> {
    if &record.identity != identity || root.expected_signer().as_str() != identity.issuer {
        return Err("retained action policy has the wrong authority or identity".into());
    }
    let envelope = VerifiedEnvelope::verify_signed_text_with(&record.signed_envelope, root)?;
    let attestation = envelope
        .attestation()
        .ok_or("retained action policy has no attestation")?;
    if attestation.epoch != Some(ACTION_EPOCH)
        || attestation.authority.as_deref() != Some(identity.issuer.as_str())
        || attestation.signer != identity.issuer
        || PolicyEpochRef::from_verified(ACTION_EPOCH, &envelope)
            .map_err(|error| format!("invalid action policy reference: {error:?}"))?
            != record.policy_ref
        || canonicalize(&record.signed_envelope)? != record.canonical_policy
    {
        return Err("retained action policy does not match its signed binding".into());
    }
    Ok(())
}

fn record(product: &Store, storage_scope: &str) -> Result<Option<PolicyRecord>, String> {
    let facts = product
        .records(storage_scope, POLICY_KIND)
        .map_err(|error| format!("cannot read action policy: {error:?}"))?;
    match facts.as_slice() {
        [] => Ok(None),
        [fact] => serde_json::from_str(fact)
            .map(Some)
            .map_err(|_| "retained action policy is malformed".into()),
        _ => Err("action policy has conflicting retained evidence".into()),
    }
}

/// Persist preparation with an exact-meaning receipt. Replays reuse the original
/// signature rather than re-signing; racing writers reload the receipted winner.
/// The product store's codec/transaction/durability posture remains in force.
pub fn prepare_action_policy(
    product: &mut Store,
    identity: &ActionPolicyIdentity,
    policy: &HostGovernancePolicy,
    signing_key: &SigningKey,
) -> Result<RetainedActionPolicy, String> {
    let storage_scope = identity.storage_scope()?;
    policy.validate()?;
    let canonical_policy = canonicalize(&policy.to_json()?)?;
    let issuer = AuthorityId::new(&identity.issuer);
    let root = GovernanceRootVerifier::new(issuer.clone(), signing_key.public_key());
    // Signature randomness is not command meaning. Root identity is: rotation
    // requires a new request, rather than replacing old signed evidence.
    let snapshot = serde_json::to_string(&(
        identity,
        &canonical_policy,
        root.expected_key().as_str(),
        ACTION_EPOCH,
    ))
    .map_err(|error| error.to_string())?;
    let candidate = match record(product, &storage_scope)? {
        Some(previous) => {
            verify_record(&previous, identity, &root)?;
            if previous.canonical_policy != canonical_policy {
                return Err("action policy request reused with different meaning".into());
            }
            previous
        }
        None => {
            let signed_envelope =
                sign_hosted_policy_envelope(&canonical_policy, &issuer, signing_key, ACTION_EPOCH)?;
            let envelope = VerifiedEnvelope::verify_signed_text_with(&signed_envelope, &root)?;
            PolicyRecord {
                identity: identity.clone(),
                canonical_policy,
                signed_envelope,
                policy_ref: PolicyEpochRef::from_verified(ACTION_EPOCH, &envelope)
                    .map_err(|error| format!("invalid action policy reference: {error:?}"))?,
            }
        }
    };
    verify_record(&candidate, identity, &root)?;
    product
        .admit_record_facts(
            &storage_scope,
            PREPARATION_KEY,
            &snapshot,
            &[CommandRecordFact {
                scope_id: storage_scope.clone(),
                kind: POLICY_KIND.into(),
                payload: serde_json::to_string(&candidate).map_err(|error| error.to_string())?,
            }],
        )
        .map_err(|error| format!("action policy preparation refused: {error:?}"))?;
    load_action_policy(product, identity, &candidate.policy_ref, &root)
}

/// Retrieve using the identity and exact reference from the admitted command.
/// This reads retained evidence only; it neither repairs missing facts nor
/// re-signs a policy under the current key. Old keys need explicit trusted roots.
pub fn load_action_policy(
    product: &Store,
    identity: &ActionPolicyIdentity,
    expected: &PolicyEpochRef,
    root: &GovernanceRootVerifier,
) -> Result<RetainedActionPolicy, String> {
    let retained = record(product, &identity.storage_scope()?)?
        .ok_or("retained action policy is unavailable")?;
    verify_record(&retained, identity, root)?;
    if &retained.policy_ref != expected {
        return Err("retained action policy differs from the admitted reference".into());
    }
    Ok(RetainedActionPolicy {
        signed_envelope: retained.signed_envelope,
        policy_ref: retained.policy_ref,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use gaugedesk_whip_runtime::host_actions::{facade::GovernedHostFacade, NativeStores};
    use std::collections::{BTreeMap, BTreeSet};
    use std::sync::{Arc, Barrier};

    fn identity() -> ActionPolicyIdentity {
        ActionPolicyIdentity {
            issuer: "home:issuer".into(),
            scope: "project:one".into(),
            request_id: "file-save-1".into(),
        }
    }

    fn policy() -> HostGovernancePolicy {
        HostGovernancePolicy {
            resources: BTreeMap::from([(
                "file:/action/input".into(),
                gaugedesk_whip_runtime::ResourcePolicy {
                    reader: BTreeSet::from(["Private".into()]),
                    writer: BTreeSet::from(["Owner".into()]),
                    principal: false,
                    internal: false,
                },
            )]),
            bindings: BTreeMap::from([("admitted_input".into(), "file:/action/input".into())]),
            capabilities: BTreeSet::from(["file.read".into()]),
            ..HostGovernancePolicy::default()
        }
    }

    #[test]
    fn restart_and_lost_response_retrieve_exact_policy_without_changing_agent_epoch() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("product.sqlite");
        let key = SigningKey::from_seed(&[41; 32]).unwrap();
        let id = identity();
        let root = GovernanceRootVerifier::new(AuthorityId::new(&id.issuer), key.public_key());
        let mut product = Store::open(path.to_str().unwrap()).unwrap();
        product
            .append_record("agent:chat", "whip_policy_epoch", "untouched")
            .unwrap();
        let prepared = prepare_action_policy(&mut product, &id, &policy(), &key).unwrap();
        let expected = prepared.policy_ref().clone();
        let signed = prepared.signed_envelope().to_owned();
        drop(prepared); // The preparation response need not reach the caller.
        drop(product);
        let mut product = Store::open(path.to_str().unwrap()).unwrap();
        let replay = prepare_action_policy(&mut product, &id, &policy(), &key).unwrap();
        assert_eq!(replay.signed_envelope(), signed);
        assert_eq!(replay.policy_ref(), &expected);
        let loaded = load_action_policy(&product, &id, &expected, &root).unwrap();
        let runtime = GovernedHostFacade::from_signed_store_with_verifier(
            NativeStores::open_in_memory().unwrap(),
            expected.epoch,
            loaded.signed_envelope(),
            &root,
        )
        .unwrap();
        assert_eq!(runtime.policy_ref(), &expected);
        assert_eq!(
            product
                .records(&id.storage_scope().unwrap(), POLICY_KIND)
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            product.records("agent:chat", "whip_policy_epoch").unwrap(),
            ["untouched"]
        );
        let mut changed = policy();
        changed.capabilities.insert("file.write".into());
        assert!(prepare_action_policy(&mut product, &id, &changed, &key).is_err());
        let other_key = SigningKey::from_seed(&[42; 32]).unwrap();
        assert!(prepare_action_policy(&mut product, &id, &policy(), &other_key).is_err());
        assert_eq!(
            load_action_policy(&product, &id, &expected, &root)
                .unwrap()
                .signed_envelope(),
            signed
        );
        let mut new_id = id.clone();
        new_id.request_id.push_str("-new");
        assert!(prepare_action_policy(&mut product, &new_id, &changed, &key).is_ok());
    }

    #[test]
    fn concurrent_preparation_converges_on_one_document_and_refuses_changed_meaning() {
        for changed in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("product.sqlite");
            // Open both actual SQLite writers before releasing the start barrier.
            let writers = [
                Store::open(path.to_str().unwrap()).unwrap(),
                Store::open(path.to_str().unwrap()).unwrap(),
            ];
            let start = Arc::new(Barrier::new(2));
            let jobs = writers
                .into_iter()
                .enumerate()
                .map(|(i, mut product)| {
                    let start = start.clone();
                    std::thread::spawn(move || {
                        let mut input = policy();
                        if changed && i == 1 {
                            input.capabilities.insert("file.write".into());
                        }
                        let key = SigningKey::from_seed(&[41; 32]).unwrap();
                        start.wait();
                        prepare_action_policy(&mut product, &identity(), &input, &key)
                            .map(|retained| (retained.signed_envelope, retained.policy_ref))
                    })
                })
                .collect::<Vec<_>>();
            let results = jobs
                .into_iter()
                .map(|job| job.join().unwrap())
                .collect::<Vec<_>>();
            assert_eq!(
                results.iter().filter(|result| result.is_ok()).count(),
                if changed { 1 } else { 2 }
            );
            if !changed {
                assert_eq!(results[0], results[1]);
            }
            let product = Store::open(path.to_str().unwrap()).unwrap();
            assert_eq!(
                product
                    .records(&identity().storage_scope().unwrap(), POLICY_KIND)
                    .unwrap()
                    .len(),
                1
            );
        }
    }

    #[test]
    fn missing_wrong_root_wrong_identity_and_changed_reference_never_resolve() {
        let mut product = Store::open_in_memory().unwrap();
        let id = identity();
        let key = SigningKey::from_seed(&[41; 32]).unwrap();
        let root = GovernanceRootVerifier::new(AuthorityId::new(&id.issuer), key.public_key());
        let prepared = prepare_action_policy(&mut product, &id, &policy(), &key).unwrap();
        let expected = prepared.policy_ref();
        for (scope, request_id) in [
            ("missing", id.request_id.as_str()),
            (id.scope.as_str(), "missing"),
            ("", ""),
        ] {
            let different = ActionPolicyIdentity {
                scope: scope.into(),
                request_id: request_id.into(),
                ..id.clone()
            };
            assert!(load_action_policy(&product, &different, expected, &root).is_err());
        }
        let other_root = GovernanceRootVerifier::new(
            AuthorityId::new(&id.issuer),
            SigningKey::from_seed(&[42; 32]).unwrap().public_key(),
        );
        assert!(load_action_policy(&product, &id, expected, &other_root).is_err());
        let other_issuer =
            GovernanceRootVerifier::new(AuthorityId::new("home:other"), key.public_key());
        assert!(load_action_policy(&product, &id, expected, &other_issuer).is_err());
        for changed in [
            PolicyEpochRef {
                epoch: 2,
                ..expected.clone()
            },
            PolicyEpochRef {
                envelope_hash: "other".into(),
                ..expected.clone()
            },
            PolicyEpochRef {
                signer: "home:other".into(),
                ..expected.clone()
            },
        ] {
            assert!(load_action_policy(&product, &id, &changed, &root).is_err());
        }
    }

    #[test]
    fn corrupted_or_substituted_policy_evidence_is_refused_before_reuse() {
        let key = SigningKey::from_seed(&[41; 32]).unwrap();
        let id = identity();
        let root = GovernanceRootVerifier::new(AuthorityId::new(&id.issuer), key.public_key());
        let mut original = Store::open_in_memory().unwrap();
        let prepared = prepare_action_policy(&mut original, &id, &policy(), &key).unwrap();
        let fact = original
            .records(&id.storage_scope().unwrap(), POLICY_KIND)
            .unwrap()
            .remove(0);
        for case in 0..6 {
            let mut retained: PolicyRecord = serde_json::from_str(&fact).unwrap();
            match case {
                0 => retained.signed_envelope = "unsigned".into(),
                1 => retained.identity.scope = "other".into(),
                2 => retained.policy_ref.epoch = 9,
                3 => retained.canonical_policy = "{}".into(),
                4 => {
                    retained.signed_envelope = sign_hosted_policy_envelope(
                        &retained.canonical_policy,
                        &AuthorityId::new(&id.issuer),
                        &key,
                        9,
                    )
                    .unwrap()
                }
                5 => {
                    retained.signed_envelope = gaugedesk_whip_runtime::sign_policy_envelope(
                        &retained.canonical_policy,
                        &AuthorityId::new(&id.issuer),
                        &key,
                    )
                    .unwrap()
                }
                _ => unreachable!(),
            }
            let mut product = Store::open_in_memory().unwrap();
            product
                .append_record(
                    &id.storage_scope().unwrap(),
                    POLICY_KIND,
                    &serde_json::to_string(&retained).unwrap(),
                )
                .unwrap();
            assert!(
                load_action_policy(&product, &id, prepared.policy_ref(), &root).is_err(),
                "case {case}"
            );
            assert!(
                prepare_action_policy(&mut product, &id, &policy(), &key).is_err(),
                "case {case}"
            );
            assert_eq!(
                product
                    .records(&id.storage_scope().unwrap(), POLICY_KIND)
                    .unwrap()
                    .len(),
                1
            );
        }
        original
            .append_record(&id.storage_scope().unwrap(), POLICY_KIND, &fact)
            .unwrap();
        assert!(load_action_policy(&original, &id, prepared.policy_ref(), &root).is_err());
    }
}
