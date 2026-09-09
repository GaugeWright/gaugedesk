//! Product persistence of the owner's typed command. Authentication and live
//! delivery are separate obligations; these tests do not manufacture either.

use std::collections::BTreeMap;

use gaugedesk_core::Lifecycle;
use gaugedesk_store::command_dispatch::{CommandDispatch, DISPATCH_KIND};
use gaugedesk_store::{AdmitError, Store};
use gaugedesk_whip_runtime::host_actions::{action::*, ProductActionAdmission};
use gaugedesk_whip_runtime::{PolicyEpochRef, ResourceRef};

pub(super) fn command(delegated: bool) -> HostActionCommand {
    HostActionCommand {
        protocol: HOST_ACTION_PROTOCOL.into(),
        issuer: "home:issuer".into(),
        scope: "project:one:chat:two".into(),
        request_id: "save-request".into(),
        operation: "file.save".into(),
        program_version_ref: "compiled-save:version".into(),
        input_schema_ref: "compiled-save:input-schema".into(),
        policy: PolicyEpochRef {
            epoch: 7,
            envelope_hash: "policy-digest".into(),
            signer: "home:issuer".into(),
            key_id: Some("home-signing-key".into()),
        },
        provenance: ActionProvenance {
            initiator: "account:person".into(),
            executor: if delegated {
                "agent:worker"
            } else {
                "account:person"
            }
            .into(),
            delegation: if delegated {
                vec![ActionDelegation {
                    grant_ref: "grant:exact-version".into(),
                    delegator: "account:person".into(),
                    delegate: "agent:worker".into(),
                }]
            } else {
                vec![]
            },
            origin: if delegated {
                "agent.tool"
            } else {
                "editor.save"
            }
            .into(),
            causes: vec![ActionCause {
                authority: "home:issuer".into(),
                record_ref: "prior-admitted-command".into(),
                digest: "prior-command-digest".into(),
            }],
        },
        inputs: BTreeMap::from([(
            "content".into(),
            ActionInput {
                handle: "admitted_input".into(),
                version_ref: "retained-draft-hash".into(),
                label_ref: "project:one:private".into(),
            },
        )]),
        resources: BTreeMap::from([(
            "target".into(),
            ActionResource {
                resource: ResourceRef {
                    handle: "admitted_target".into(),
                    kind: "file_store".into(),
                    selector: Some("note.md".into()),
                    writable: Some(true),
                },
                basis: ActionBasis::Version {
                    version_ref: "retained-base-cut".into(),
                },
                label_ref: "project:one:private".into(),
            },
        )]),
    }
}

fn dispatch(command: &HostActionCommand) -> CommandDispatch {
    CommandDispatch {
        runtime_ref: "home:issuer:native".into(),
        command_ref: command.fingerprint().expect("owner fingerprint"),
    }
}

#[test]
fn product_host_action_retains_the_complete_owner_command_across_restart() {
    for delegated in [false, true] {
        let command = command(delegated);
        command.validate().expect("owner validates the data shape");
        let scope = command.instance_ref().expect("owner instance identity");
        let mut original = Store::open_in_memory().expect("store");
        let admitted = original
            .admit_with_dispatch::<ProductActionAdmission>(
                &scope,
                &command.request_id,
                command.clone(),
                &dispatch(&command),
            )
            .expect("atomic product admission");
        assert!(!admitted.replayed);
        let mut reopened = original.sibling().expect("reopen durable store");
        drop(original);
        let replay = reopened
            .admit_with_dispatch::<ProductActionAdmission>(
                &scope,
                &command.request_id,
                command.clone(),
                &dispatch(&command),
            )
            .expect("redelivery");
        assert!(replay.replayed);
        let retained = replay.state.command.expect("original command");
        assert_eq!(retained, command);
        assert_eq!(
            retained.signing_bytes().unwrap(),
            command.signing_bytes().unwrap()
        );
        let events = reopened
            .records(&scope, ProductActionAdmission::KIND)
            .unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(
            serde_json::from_str::<HostActionCommand>(&events[0]).unwrap(),
            command
        );
        assert_eq!(reopened.records(&scope, DISPATCH_KIND).unwrap().len(), 1);
        assert!(reopened.records(&scope, "run").unwrap().is_empty());
    }
}

#[test]
fn product_host_action_cannot_replace_its_original_metadata_or_admit_again() {
    let command = command(true);
    let scope = command.instance_ref().unwrap();
    let mut store = Store::open_in_memory().unwrap();
    let state = store
        .admit_with_dispatch::<ProductActionAdmission>(
            &scope,
            &command.request_id,
            command.clone(),
            &dispatch(&command),
        )
        .unwrap()
        .state;
    let change: [fn(&mut HostActionCommand); 8] = [
        |c| c.provenance.initiator = "another-account".into(),
        |c| c.provenance.delegation[0].grant_ref = "another-grant".into(),
        |c| c.provenance.causes[0].digest = "another-cause".into(),
        |c| c.policy.epoch += 1,
        |c| c.inputs.get_mut("content").unwrap().version_ref = "another-draft".into(),
        |c| c.resources.get_mut("target").unwrap().basis = ActionBasis::Absent,
        |c| c.resources.get_mut("target").unwrap().resource.selector = Some("other.md".into()),
        |c| c.program_version_ref = "another-program".into(),
    ];
    for edit in change {
        let mut changed = command.clone();
        edit(&mut changed);
        assert!(matches!(
            store.admit_with_dispatch::<ProductActionAdmission>(
                &scope,
                &command.request_id,
                changed.clone(),
                &dispatch(&command),
            ),
            Err(AdmitError::Rejected(_))
        ));
        assert_eq!(
            ProductActionAdmission::evolve(&state, changed).command,
            Some(command.clone())
        );
    }
    assert!(matches!(
        store.admit_with_dispatch::<ProductActionAdmission>(
            &scope,
            "another-key",
            command.clone(),
            &dispatch(&command),
        ),
        Err(AdmitError::Rejected(_))
    ));
    assert!(store
        .command_for_key(&scope, "another-key")
        .unwrap()
        .is_none());
    assert_eq!(
        store
            .records(&scope, ProductActionAdmission::KIND)
            .unwrap()
            .len(),
        1
    );
    assert_eq!(store.records(&scope, DISPATCH_KIND).unwrap().len(), 1);
    assert_eq!(
        store
            .fold::<ProductActionAdmission>(&scope)
            .unwrap()
            .command,
        Some(command)
    );
}
