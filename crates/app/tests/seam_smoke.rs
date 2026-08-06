//! SUB-0 seam smoke: one full turn where BOTH substrate seams are crossed only
//! as trait objects — the workspace held as `Box<dyn Workspace>` /
//! `Box<dyn ChatWorkspace>` (constructed through the provider seam) and the
//! runtime built by a registered `Arc<dyn HarnessFactory>` producing the
//! neutral [`ScriptedHarness`]. The test itself carries zero Pi and zero
//! provider-format knowledge: it never touches export bytes, a store path, or a line
//! name — the template for a future adapter conformance run.

use std::io;
use std::sync::Arc;

use gaugedesk_app::engine::run_task_streaming;
use gaugedesk_core::merge::MergePhase;
use gaugedesk_core::run::RunPhase;
use gaugedesk_harness::sandbox::SandboxPolicy;
use gaugedesk_harness::testing::ScriptedHarness;
use gaugedesk_harness::{
    AllowAllGate, ChatMode, CredentialProbe, Harness, HarnessFactory, HarnessSpec, Observation,
    TurnOutcome,
};
use gaugedesk_store::Store;
use gaugedesk_workspace::{WhippleWorkspaceProvider, WorkspaceProvider};

/// The registered test factory: builds the neutral scripted harness from a
/// [`HarnessSpec`] — the same construction seam the engine's selector serves.
struct NeutralScriptedFactory;

impl HarnessFactory for NeutralScriptedFactory {
    fn kind(&self) -> &'static str {
        "scripted-neutral"
    }

    fn create(&self, _spec: &HarnessSpec) -> io::Result<Box<dyn Harness>> {
        Ok(Box::new(ScriptedHarness::new(vec![TurnOutcome {
            assistant_text: "Wrote the summary.".into(),
            observations: vec![
                Observation {
                    kind: "text",
                    detail: "writing the summary".into(),
                    tool: None,
                },
                Observation {
                    kind: "egress",
                    detail: "write summary.txt".into(),
                    tool: None,
                },
            ],
            mediated_tool_calls: vec!["write".into()],
            ..TurnOutcome::default()
        }])))
    }

    /// A scripted turn is one-shot — never cached across turns.
    fn reuse_across_turns(&self) -> bool {
        false
    }

    fn credential_status(
        &self,
        _provider: &str,
        _capability: Option<&dyn gaugedesk_harness::CredentialCapability>,
    ) -> CredentialProbe {
        CredentialProbe::Ready
    }
}

/// A complete `run_task_streaming` turn over the trait-object path: provider →
/// `Box<dyn Workspace>` → `Box<dyn ChatWorkspace>`, factory → `Box<dyn Harness>`,
/// then run admission, observation streaming, auto-commit, diff, and the merge
/// probe — all through the seams alone.
#[test]
fn full_turn_runs_over_workspace_and_harness_trait_objects() {
    let tmp = tempfile::tempdir().unwrap();

    // Workspace side: constructed and used only through the seam.
    let provider: Arc<dyn WorkspaceProvider> = Arc::new(WhippleWorkspaceProvider);
    let workspace = provider.init_at(&tmp.path().join("inst")).unwrap();
    let chat = workspace.create_engagement("chat-1").unwrap();

    // The agent's content change arrives through the worktree facet (the test
    // stands in for the runtime's write, as the engine unit suite does).
    chat.write_file("summary.txt", "the scripted agent wrote this\n")
        .unwrap();

    // Harness side: the registered factory serves the spec the shell resolves.
    let factory: Arc<dyn HarnessFactory> = Arc::new(NeutralScriptedFactory);
    assert!(!factory.reuse_across_turns());
    let spec = HarnessSpec {
        chat_id: "chat-1".into(),
        worktree: chat.path().to_path_buf(),
        mode: ChatMode::Use,
        package_root: None,
        package_version_ref: None,
        policy_epoch: None,
        signed_policy_envelope: None,
        provider_binding_ref: None,
        credential_ref: None,
        placement_ceiling_ref: None,
        runtime_placement_id: None,
        provider: None,
        model: None,
        base_url: None,
        thinking: None,
        system_prompt: None,
        credential_capability: None,
        credentials: Vec::new(),
        sandbox: SandboxPolicy::new(vec![chat.path().to_path_buf()]),
        roster: Vec::new(),
    };
    let mut harness = factory.create(&spec).unwrap();

    let mut store = Store::open_in_memory().unwrap();
    let mut streamed = Vec::new();
    let result = run_task_streaming(
        &mut store,
        "chat-1",
        chat.as_ref(),
        harness.as_mut(),
        &AllowAllGate,
        "summarize the notes",
        &[],
        &mut |o: &Observation| streamed.push(o.detail.clone()),
    )
    .unwrap();

    // The turn completed and streamed its observations in scripted order.
    assert_eq!(result.run_phase, RunPhase::Completed);
    assert_eq!(
        streamed,
        vec![
            "writing the summary".to_string(),
            "write summary.txt".to_string()
        ]
    );
    assert_eq!(result.assistant_text, "Wrote the summary.");
    assert_eq!(result.mediated_tool_calls, vec!["write".to_string()]);

    // The content change auto-committed behind an opaque revision id, the
    // reviewer's diff renders it, and the merge probe came back clean.
    assert!(result.commit.is_some(), "the turn auto-committed");
    assert!(
        result.diff.contains("summary.txt"),
        "the diff shows the change: {}",
        result.diff
    );
    assert_eq!(result.merge_phase, MergePhase::Clean);
}
