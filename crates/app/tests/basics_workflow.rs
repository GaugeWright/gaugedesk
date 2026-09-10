//! WHIP-2: qualify the product's ordinary tutorial source against its Cargo pin.
//! This exercises the runtime contract, not product launch/completion admission;
//! those remain the separate WHIP-3/4 integration obligations.

use serde_json::json;
use whipplescript_kernel::{
    effect_config::EffectConfig, effect_handlers::run_queue_effect_generic,
    rule_pass::step_instance_generic, tracker_wait, workflow_input::validate_workflow_start_input,
    ProgramVersionInput, RuntimeKernel,
};
use whipplescript_parser::{compile_program, IrProgram};
use whipplescript_store::{native_stores::NativeStores, RuntimeStore};

const SOURCE: &str = include_str!("../src/tutorials/basics.whip");
const LEARNER: &str = "person:learner";

fn settle(kernel: &mut RuntimeKernel<NativeStores>, program: &IrProgram, instance: &str) {
    let config = EffectConfig {
        provider: "builtin-tracker".into(),
        outcome_failed: false,
    };
    for _ in 0..24 {
        step_instance_generic(kernel, instance, program, None, None).expect("ordinary rule pass");
        let Some(effect) = kernel
            .claimable_effects(instance)
            .expect("ready effects")
            .into_iter()
            .next()
        else {
            return;
        };
        if tracker_wait::is_tracker_wait(&effect) {
            tracker_wait::run(kernel, instance, &effect, &config).expect("observe closing");
        } else {
            assert_eq!(
                effect.kind, "tracker.file",
                "Basics needs no model or product-specific effect"
            );
            run_queue_effect_generic(kernel, instance, &effect, "2026-09-10T12:00:00Z", &config)
                .expect("file assigned task");
        }
    }
    panic!("Basics did not park or complete within the fixture budget");
}

#[test]
fn pinned_runtime_runs_basics_source_across_restarts() {
    let directory = tempfile::tempdir().expect("state directory");
    let open = || {
        NativeStores::open(
            directory.path().join("runtime.sqlite"),
            directory.path().join("coord.sqlite"),
            directory.path().join("items.sqlite"),
        )
        .expect("workspace stores")
    };
    let compiled = compile_program(SOURCE);
    assert!(
        compiled.diagnostics.is_empty(),
        "{:?}",
        compiled.diagnostics
    );
    let program = compiled.ir.expect("compiled tutorial");
    let stores = open();
    // Consume the runtime owner's manifest. A copied test-only contract could
    // pass while the pinned package cannot execute the actual tutorial.
    whipplescript::std_manifests::register_all(&stores.runtime).expect("standard packages");
    let mut kernel = RuntimeKernel::new(stores);
    let source_hash = kernel.store().put_content(SOURCE).expect("retain source");
    let snapshot = whipplescript_parser::snapshot::identity_projection(&program.to_snapshot());
    let ir_hash = whipplescript_store::stable_hash_hex(&snapshot);
    let version = kernel
        .create_program_version_for_program(
            ProgramVersionInput {
                program_name: &program.workflow,
                source_hash: &source_hash,
                ir_hash: &ir_hash,
                compiler_version: "consumer-qualification",
                ir_snapshot: Some(&snapshot),
            },
            &program,
        )
        .expect("retained version");
    let input = json!({"learner": {"authority": LEARNER}});
    let instance = kernel
        .create_instance(&version, &input.to_string())
        .expect("instance");
    let started = kernel
        .ingest_external_event(
            &instance,
            "external.started",
            &input.to_string(),
            Some("start"),
        )
        .expect("start event");
    for fact in validate_workflow_start_input(&program, &input).expect("typed inputs") {
        kernel
            .derive_fact(
                &instance,
                &fact.name,
                &fact.key,
                &fact.value_json,
                Some(&started.event_id),
                None,
            )
            .expect("input fact");
    }

    for (step, title) in [
        "Create a chat in Personal",
        "Make your personal assistant",
        "Create a project",
        "Invite a colleague",
    ]
    .iter()
    .enumerate()
    {
        settle(&mut kernel, &program, &instance);
        let issues = kernel
            .store()
            .items
            .list_items(Some("tutorials"), None)
            .expect("tasks");
        assert_eq!(issues.len(), step + 1);
        let pending: Vec<_> = issues
            .iter()
            .filter(|issue| issue.status == "open")
            .collect();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].title, *title);
        assert_eq!(pending[0].assigned_to.as_deref(), Some(LEARNER));
        assert!(kernel
            .claimable_effects(&instance)
            .expect("parked wait")
            .is_empty());
        let issue = pending[0].id.clone();
        // Reopening while the learner is still working must preserve the same
        // assignment, not file another issue or release the next task.
        drop(kernel);
        kernel = RuntimeKernel::new(open());
        settle(&mut kernel, &program, &instance);
        let waiting = kernel
            .store()
            .items
            .list_items(Some("tutorials"), None)
            .expect("retained tasks");
        assert_eq!(waiting.len(), step + 1);
        assert_eq!(
            waiting
                .iter()
                .filter(|item| item.status == "open")
                .map(|item| item.id.as_str())
                .collect::<Vec<_>>(),
            vec![issue.as_str()]
        );
        kernel
            .store_mut()
            .items
            .finish_item(&issue, Some("self-reported fixture completion"), None)
            .expect("closing");
        drop(kernel);
        kernel = RuntimeKernel::new(open());
    }
    settle(&mut kernel, &program, &instance);
    assert_eq!(
        kernel
            .store()
            .get_instance(&instance)
            .expect("instance")
            .expect("retained instance")
            .status,
        "completed"
    );
    assert_eq!(
        kernel
            .store()
            .items
            .list_items(Some("tutorials"), None)
            .expect("tasks")
            .len(),
        4
    );
    assert_eq!(kernel.store().list_instances().expect("roots").len(), 1);
}
