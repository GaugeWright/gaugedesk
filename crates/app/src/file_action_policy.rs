//! Policy compilation for a fixed, confined file-save workflow (ACTION-3).
//! Callers supply already admitted product resources and authenticated claims.
//! The unsigned result is not target authorization, a retained-input receipt,
//! a signed policy epoch, or permission to dispatch an effect.

use std::collections::{BTreeMap, BTreeSet};

use gaugedesk_core::abac::{Action, AuthorityAttributes, Policy};
use gaugedesk_core::ids::AuthorityId;
use gaugedesk_core::resource::ResourceRecord;
use gaugedesk_whip_runtime::{HostGovernancePolicy, ResourcePolicy};

use crate::policy_compiler::{
    actor_clearances, authority_role, resource_reader_roles, validate_resources_for_action,
};

/// Current product facts, supplied after target-access admission. Labels are
/// derived from these records; the compiler accepts no caller-chosen label.
pub struct FileSavePolicyInput {
    pub actor: AuthorityId,
    pub actor_attributes: AuthorityAttributes,
    pub org_policy: Policy,
    pub purpose: Option<String>,
    pub ceiling_attested: bool,
    pub input: ResourceRecord,
    pub target: ResourceRecord,
}

/// Compile the two virtual file stores used by the confined versioned-save
/// workflow. Current path/write authority and exact input/base binding must
/// still be verified before signing, admission and each execution attempt.
pub fn compile_file_save_policy(
    input: &FileSavePolicyInput,
) -> Result<HostGovernancePolicy, String> {
    let mut policy = compile_file_resource_policy(input, Action::Run)?;
    policy.capabilities = BTreeSet::from(["file.read".into(), "file.write".into()]);
    policy.validate()?;
    Ok(policy)
}

/// Shared resource labels and clearance validation. No execution capability
/// is present until the owning operation adds it; inspection uses Access.
pub(crate) fn compile_file_resource_policy(
    input: &FileSavePolicyInput,
    action: Action,
) -> Result<HostGovernancePolicy, String> {
    if input.actor.as_str().trim().is_empty() {
        return Err("file action has no authenticated actor".into());
    }
    let records = [&input.input, &input.target];
    for record in records {
        if record.tombstoned
            || record.resource.id.as_str().trim().is_empty()
            || record.resource.owner.as_str().trim().is_empty()
            || record.stakeholders.is_empty()
            || record
                .stakeholders
                .iter()
                .any(|authority| authority.as_str().trim().is_empty())
        {
            return Err("file action resource is unavailable or has incomplete authority".into());
        }
    }
    validate_resources_for_action(
        &records,
        &input.actor_attributes,
        &input.org_policy,
        input.purpose.as_deref(),
        input.ceiling_attested,
        action,
    )?;
    let actor = authority_role(input.actor.as_str());
    let input_readers = resource_reader_roles(&input.input);
    let target_readers = resource_reader_roles(&input.target);
    let clearances = actor_clearances(
        &input.actor_attributes,
        input.purpose.as_deref(),
        &[input.input.clone(), input.target.clone()],
        std::iter::empty(),
    );
    // A file-to-file flow can preserve every label without involving a
    // principal sink. Its IFC proof alone therefore does not establish the
    // caller's clearance. Require that separately from target write authority.
    if !input_readers.is_subset(&clearances) || !target_readers.is_subset(&clearances) {
        return Err("file action actor does not clear the input and target compartments".into());
    }
    let evidence_readers: BTreeSet<_> = input_readers.union(&target_readers).cloned().collect();
    let labeled = |reader, writer| ResourcePolicy {
        reader,
        writer,
        principal: false,
        internal: false,
    };
    let resources = BTreeMap::from([
        (
            "file:/action/input".into(),
            labeled(input_readers, BTreeSet::from([actor.clone()])),
        ),
        // Access to a target does not endorse its existing content. This
        // profile has no retained integrity voucher for that content or any
        // remembered correction. Their contributions must remain untrusted
        // through the save and its terminal evidence, with attribution kept
        // separately in the original commands and recording receipts.
        (
            "file:/action/output".into(),
            labeled(target_readers.clone(), BTreeSet::new()),
        ),
        (
            "memory:/action/resolutions".into(),
            labeled(target_readers, BTreeSet::new()),
        ),
        (
            "result".into(),
            labeled(evidence_readers.clone(), BTreeSet::new()),
        ),
        ("error".into(), labeled(evidence_readers, BTreeSet::new())),
    ]);
    let mut parties = BTreeMap::from([(input.actor.as_str().to_owned(), actor.clone())]);
    for record in records {
        for authority in record
            .stakeholders
            .iter()
            .chain(std::iter::once(&record.resource.owner))
        {
            parties.insert(
                authority.as_str().to_owned(),
                authority_role(authority.as_str()),
            );
        }
    }
    let policy = HostGovernancePolicy {
        resources,
        parties,
        bindings: BTreeMap::from([
            ("admitted_input".into(), "file:/action/input".into()),
            ("admitted_target".into(), "file:/action/output".into()),
            (
                "admitted_resolutions".into(),
                "memory:/action/resolutions".into(),
            ),
            ("result".into(), "result".into()),
            ("error".into(), "error".into()),
        ]),
        delegations: clearances
            .into_iter()
            .filter(|clearance| clearance != &actor)
            .map(|clearance| [actor.clone(), clearance])
            .collect(),
        ..HostGovernancePolicy::default()
    };
    policy.validate()?;
    Ok(policy)
}

#[cfg(test)]
mod tests {
    use super::*;
    use gaugedesk_core::abac::{
        Action, Classification, Condition, Constraint, Purpose, Region, Role, Rule,
    };
    use gaugedesk_core::boundary::Authority;
    use gaugedesk_core::resource::{ContentLocator, Resource, ResourceId, ResourceKind};
    use gaugedesk_core::signature::SigningKey;
    use gaugedesk_whip_runtime::host_actions::CompiledHostAction;
    use gaugedesk_whip_runtime::{ifc, sign_hosted_policy_envelope, GovernanceRootVerifier};

    const SOURCE: &str = r#"use std.files
workflow FileSavePolicyFixture
input content InputReference
output result Saved
failure error SaveFailed
class InputReference { handle string version_ref string label_ref string }
class Saved { content_hash string }
class SaveFailed { reason string }
file store admitted_input {
  root "/action/input"
  allow read ["content"]
}
file store admitted_target {
  root "/action/output"
  allow write ["target"]
}
rule save
  when InputReference as reference
=> {
  read text from admitted_input at "content" as loaded
  after loaded succeeds as draft {
    write text to admitted_target at "target" {
      body draft.content
      mode upsert
    } as written
    after written succeeds as saved { complete result { content_hash saved.content_hash } }
    after written fails as failed { fail error { reason failed.reason } }
  }
  after loaded fails as unavailable { fail error { reason unavailable.reason } }
}
"#;

    fn input(actor: &str) -> FileSavePolicyInput {
        let owner = Authority::new("resource-owner");
        let record = |id| {
            ResourceRecord::new(
                Resource::input(ResourceId::new(id), ResourceKind::context(), owner.clone()),
                ContentLocator::Content {
                    handle: format!("retained:{id}"),
                },
                |_| owner.clone(),
            )
        };
        FileSavePolicyInput {
            actor: AuthorityId::new(actor),
            actor_attributes: AuthorityAttributes {
                roles: BTreeSet::from([Role::owner()]),
                ..AuthorityAttributes::default()
            },
            org_policy: Policy::default(),
            purpose: None,
            ceiling_attested: false,
            input: record("input"),
            target: record("target"),
        }
    }

    fn verified_policy(policy: &HostGovernancePolicy) -> ifc::VerifiedEnvelope {
        let key = SigningKey::from_seed(&[63; 32]).unwrap();
        let issuer = AuthorityId::new("home:policy-fixture");
        let signed =
            sign_hosted_policy_envelope(&policy.to_json().unwrap(), &issuer, &key, 1).unwrap();
        let root = GovernanceRootVerifier::new(issuer, key.public_key());
        ifc::VerifiedEnvelope::verify_signed_text_with(&signed, &root).unwrap()
    }

    fn flow_diagnostics(policy: &HostGovernancePolicy) -> Vec<String> {
        let envelope = verified_policy(policy);
        let action = CompiledHostAction::compile("file.save", SOURCE, None).unwrap();
        ifc::check_with_envelope(action.program(), &envelope)
            .into_iter()
            .map(|diagnostic| diagnostic.message)
            .collect()
    }

    fn composed_policy(policy: &HostGovernancePolicy) -> ifc::Composition {
        let verified = verified_policy(policy);
        let attestation = verified.attestation().unwrap();
        let record = ifc::CompositionEntry {
            authority: attestation.authority.clone().unwrap(),
            envelope_hash: attestation.envelope_hash.clone(),
            epoch: attestation.epoch.unwrap(),
        };
        ifc::Composition::compose(vec![verified], vec![record]).unwrap()
    }

    #[test]
    fn existing_target_content_does_not_gain_the_current_actors_integrity() {
        // Exercise the owner's actual flow algebra on verified signed policy.
        // This qualifies label construction; production adapter enforcement
        // additionally requires the scoped execution door and its raw flows.
        for actor in ["human:alice", "agent:editor"] {
            let policy = compile_file_save_policy(&input(actor)).unwrap();
            let composed = composed_policy(&policy);
            for terminal in ["file:/action/output", "result", "error"] {
                assert!(!composed.injects("file:/action/output", terminal));
                assert!(!composed.leaks("file:/action/output", terminal));
                let mut endorsed = policy.clone();
                endorsed.resources.get_mut(terminal).unwrap().writer =
                    BTreeSet::from([authority_role(actor)]);
                // When probing the target sink, retain its original source
                // label under a separate governed address.
                endorsed.resources.insert(
                    "file:/original-target".into(),
                    policy.resources["file:/action/output"].clone(),
                );
                assert!(
                    composed_policy(&endorsed).injects("file:/original-target", terminal),
                    "{actor}/{terminal} silently endorsed existing content"
                );
            }
        }
    }

    #[test]
    fn declared_failure_preserves_existing_content_labels_for_humans_and_agents() {
        let action = CompiledHostAction::compile(
            "file.save",
            r#"workflow ExistingFileFailure
input request Request
output result Saved
failure error SaveFailed
class Request { id string }
class Saved { content_hash string }
class SaveFailed { reason string }
file store admitted_target {
  root "/action/output"
  allow read ["target"]
}
rule inspect
  when Request as request
=> {
  read text from admitted_target at "target" as loaded
  after loaded succeeds as value { fail error { reason value.content } }
  after loaded fails as problem { fail error { reason problem.reason } }
}
"#,
            None,
        )
        .unwrap();
        for actor in ["human:alice", "agent:editor"] {
            let policy = compile_file_save_policy(&input(actor)).unwrap();
            let allowed = ifc::check_with_envelope(action.program(), &verified_policy(&policy));
            assert!(allowed.is_empty(), "{actor}: {allowed:?}");
            for axis in ["integrity", "flow"] {
                let mut changed = policy.clone();
                let error = changed.resources.get_mut("error").unwrap();
                if axis == "integrity" {
                    error.writer = BTreeSet::from([authority_role(actor)]);
                } else {
                    error.reader.clear();
                }
                let denied = ifc::check_with_envelope(action.program(), &verified_policy(&changed));
                assert!(
                    denied
                        .iter()
                        .any(|diagnostic| diagnostic.message.contains("error")
                            && diagnostic.message.contains(axis)),
                    "{actor}/{axis}: failed outcomes must preserve content labels: {denied:?}"
                );
            }
        }
    }

    #[test]
    fn fixed_file_actions_need_no_provider_and_keep_actor_equivalence() {
        for actor in ["human:alice", "agent:editor"] {
            let policy = compile_file_save_policy(&input(actor)).unwrap();
            assert!(policy.provider_bindings.is_empty());
            assert!(policy.placements.is_empty());
            assert_eq!(
                policy.capabilities,
                ["file.read".into(), "file.write".into()].into()
            );
            let diagnostics = flow_diagnostics(&policy);
            assert!(diagnostics.is_empty(), "{diagnostics:?}");
        }
    }

    #[test]
    fn file_policy_keeps_distinct_labels_and_cannot_declassify_a_save() {
        let mut input = input("human:alice");
        input.target.attributes.classification = Classification::Public;
        let policy = compile_file_save_policy(&input).unwrap();
        assert!(policy.resources["file:/action/input"]
            .reader
            .contains("classification:regulated"));
        assert!(!policy.resources["file:/action/output"]
            .reader
            .contains("classification:regulated"));
        assert!(policy.resources["error"]
            .reader
            .contains("classification:regulated"));
        assert_eq!(
            policy.resources["error"].reader,
            policy.resources["result"].reader
        );
        assert!(policy.declassifications.is_empty());
        assert!(!flow_diagnostics(&policy).is_empty());
    }

    #[test]
    fn file_policy_refuses_unavailable_resources_and_current_restrictions() {
        for actor in ["human:alice", "agent:editor"] {
            let original = input(actor);
            let mut denied = input(actor);
            denied.input.tombstoned = true;
            assert!(compile_file_save_policy(&denied).is_err());
            denied = input(actor);
            denied.target.tombstoned = true;
            assert!(compile_file_save_policy(&denied).is_err());
            denied = input(actor);
            denied.input.stakeholders.clear();
            assert!(compile_file_save_policy(&denied).is_err());
            denied = input(actor);
            denied.actor_attributes = AuthorityAttributes::default();
            assert!(compile_file_save_policy(&denied).is_err());
            denied = input(actor);
            denied.org_policy.rules.push(Rule {
                when: Condition::Always,
                require: Constraint::DenyAction(Action::Run),
            });
            assert!(compile_file_save_policy(&denied).is_err());
            denied = input(actor);
            denied.target.attributes.purpose = BTreeSet::from([Purpose::new("case-review")]);
            assert!(compile_file_save_policy(&denied).is_err());
            denied.purpose = Some("case-review".into());
            assert!(compile_file_save_policy(&denied).is_ok());
            denied = input(actor);
            denied.org_policy.rules.push(Rule {
                when: Condition::Always,
                require: Constraint::RequireAttestedCeiling,
            });
            assert!(compile_file_save_policy(&denied).is_err());
            denied.ceiling_attested = true;
            assert!(compile_file_save_policy(&denied).is_ok());
            denied = input(actor);
            denied.org_policy.rules.push(Rule {
                when: Condition::Always,
                require: Constraint::RequireResourceRegionMatchesActor,
            });
            assert!(compile_file_save_policy(&denied).is_err());
            denied.actor_attributes.region = Some(Region::new("us"));
            denied.input.attributes.region = Some(Region::new("us"));
            denied.target.attributes.region = Some(Region::new("eu"));
            assert!(compile_file_save_policy(&denied).is_err());
            denied.target.attributes.region = Some(Region::new("us"));
            assert!(compile_file_save_policy(&denied).is_ok());
            assert_eq!(
                compile_file_save_policy(&original)
                    .unwrap()
                    .provider_bindings
                    .len(),
                0
            );
        }
    }
}
