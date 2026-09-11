//! Policy for independently recording newly authored corrections (ACTION-4).
//! Current admission, retained read taint, input/store binding and execution
//! remain separate obligations. This compiler grants no file operation.

use std::collections::{BTreeMap, BTreeSet};

use crate::file_action_policy::{compile_file_save_policy, FileSavePolicyInput};
use gaugedesk_whip_runtime::HostGovernancePolicy;

/// The same admitted actor/input/target records used by file policy compilation.
/// Sharing this shape also shares its resource restrictions and clearance check;
/// it is not a file-save request or a claim about any prior text's provenance.
pub type ResolutionRecordingPolicyInput = FileSavePolicyInput;

pub fn compile_resolution_recording_policy(
    input: &ResolutionRecordingPolicyInput,
) -> Result<HostGovernancePolicy, String> {
    let shared = compile_file_save_policy(input)?;
    // Keep the original input label and the same unendorsed memory compartment
    // a scoped save reads. An explicit allowlist prevents a future file-policy
    // resource or binding from silently widening this recording profile.
    let resources = shared
        .resources
        .into_iter()
        .filter_map(|(address, resource)| match address.as_str() {
            "file:/action/input" => Some(("memory:/action/corrections".into(), resource)),
            "memory:/action/resolutions" | "result" | "error" => Some((address, resource)),
            _ => None,
        })
        .collect();
    let bindings = BTreeMap::from([
        (
            "admitted_corrections".into(),
            "memory:/action/corrections".into(),
        ),
        (
            "admitted_resolutions".into(),
            "memory:/action/resolutions".into(),
        ),
        ("result".into(), "result".into()),
        ("error".into(), "error".into()),
    ]);
    let policy = HostGovernancePolicy {
        resources,
        bindings,
        parties: shared.parties,
        delegations: shared.delegations,
        capabilities: BTreeSet::from(["vcs.record_resolutions".into()]),
        ..HostGovernancePolicy::default()
    };
    policy.validate()?;
    Ok(policy)
}

#[cfg(test)]
mod tests {
    use super::*;
    use gaugedesk_core::{
        abac::{
            Action, AuthorityAttributes, Classification, Condition, Constraint, Policy, Role, Rule,
        },
        boundary::Authority,
        ids::AuthorityId,
        resource::{ContentLocator, Resource, ResourceId, ResourceKind, ResourceRecord},
        signature::SigningKey,
    };
    use gaugedesk_whip_runtime::{ifc, sign_hosted_policy_envelope, GovernanceRootVerifier};

    fn input(actor: &str) -> ResolutionRecordingPolicyInput {
        let owner = Authority::new("resource-owner");
        let record = |name| {
            ResourceRecord::new(
                Resource::input(
                    ResourceId::new(name),
                    ResourceKind::context(),
                    owner.clone(),
                ),
                ContentLocator::Content {
                    handle: format!("retained:{name}"),
                },
                |_| owner.clone(),
            )
        };
        ResolutionRecordingPolicyInput {
            actor: AuthorityId::new(actor),
            actor_attributes: AuthorityAttributes {
                roles: BTreeSet::from([Role::owner()]),
                ..AuthorityAttributes::default()
            },
            org_policy: Policy::default(),
            purpose: None,
            ceiling_attested: false,
            input: record("corrections"),
            target: record("target"),
        }
    }

    fn verified(policy: &HostGovernancePolicy) -> ifc::VerifiedEnvelope {
        let issuer = AuthorityId::new("home:recording-policy");
        let key = SigningKey::from_seed(&[93; 32]).unwrap();
        let signed =
            sign_hosted_policy_envelope(&policy.to_json().unwrap(), &issuer, &key, 1).unwrap();
        ifc::VerifiedEnvelope::verify_signed_text_with(
            &signed,
            &GovernanceRootVerifier::new(issuer, key.public_key()),
        )
        .unwrap()
    }

    #[test]
    fn equivalent_callers_get_only_recording_with_the_save_memory_compartment() {
        let mut previous_memory = None;
        for actor in ["human:alice", "agent:editor"] {
            let input = input(actor);
            let policy = compile_resolution_recording_policy(&input).unwrap();
            let save = compile_file_save_policy(&input).unwrap();
            assert_eq!(
                policy.capabilities,
                BTreeSet::from(["vcs.record_resolutions".into()])
            );
            assert!(policy.provider_bindings.is_empty());
            assert!(policy.placements.is_empty());
            assert!(policy.declassifications.is_empty());
            assert!(policy.endorsements.is_empty());
            assert_eq!(policy.resources.len(), 4);
            assert_eq!(policy.bindings.len(), 4);
            assert!(!policy.resources.keys().any(|key| key.starts_with("file:")));
            assert!(!policy.bindings.contains_key("admitted_target"));
            assert!(!policy.bindings.contains_key("admitted_input"));
            let memory = &policy.resources["memory:/action/resolutions"];
            assert_eq!(memory, &save.resources["file:/action/output"]);
            if let Some(previous) = &previous_memory {
                assert_eq!(memory, previous);
            }
            previous_memory = Some(memory.clone());
            let envelope = verified(&policy);
            for source in ["admitted_corrections", "admitted_resolutions"] {
                for sink in ["admitted_resolutions", "result", "error"] {
                    envelope.check_resource_flow(source, sink).unwrap();
                }
            }
        }
    }

    #[test]
    fn a_private_correction_cannot_flow_into_less_restricted_memory() {
        for actor in ["human:alice", "agent:editor"] {
            let mut input = input(actor);
            input.target.attributes.classification = Classification::Public;
            let policy = compile_resolution_recording_policy(&input).unwrap();
            let envelope = verified(&policy);
            assert!(envelope
                .check_resource_flow("admitted_corrections", "admitted_resolutions")
                .is_err());
            // Failure and result references retain the combined restrictions.
            for terminal in ["result", "error"] {
                envelope
                    .check_resource_flow("admitted_corrections", terminal)
                    .unwrap();
                let mut widened = policy.clone();
                widened.resources.get_mut(terminal).unwrap().reader.clear();
                assert!(verified(&widened)
                    .check_resource_flow("admitted_corrections", terminal)
                    .is_err());
            }
        }
    }

    #[test]
    fn remembering_content_does_not_endorse_its_existing_winner() {
        for actor in ["human:alice", "agent:editor"] {
            let policy = compile_resolution_recording_policy(&input(actor)).unwrap();
            for terminal in ["result", "error", "memory:/action/resolutions"] {
                assert!(policy.resources[terminal].writer.is_empty());
                let mut endorsed = policy.clone();
                endorsed.resources.insert(
                    "memory:/original".into(),
                    policy.resources["memory:/action/resolutions"].clone(),
                );
                endorsed
                    .bindings
                    .insert("original".into(), "memory:/original".into());
                endorsed.resources.get_mut(terminal).unwrap().writer = policy.resources
                    ["memory:/action/corrections"]
                    .writer
                    .clone();
                let sink = if terminal == "memory:/action/resolutions" {
                    "admitted_resolutions"
                } else {
                    terminal
                };
                assert!(verified(&endorsed)
                    .check_resource_flow("original", sink)
                    .is_err());
            }
        }
    }

    #[test]
    fn recording_keeps_current_resource_and_actor_refusals() {
        for actor in ["human:alice", "agent:editor"] {
            for reason in ["input", "target", "clearance", "policy"] {
                let mut input = input(actor);
                match reason {
                    "input" => input.input.tombstoned = true,
                    "target" => input.target.tombstoned = true,
                    "clearance" => input.actor_attributes = AuthorityAttributes::default(),
                    "policy" => input.org_policy.rules.push(Rule {
                        when: Condition::Always,
                        require: Constraint::DenyAction(Action::Run),
                    }),
                    _ => unreachable!(),
                }
                assert!(
                    compile_resolution_recording_policy(&input).is_err(),
                    "{actor}/{reason}"
                );
            }
        }
    }
}
