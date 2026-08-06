//! gaugewright boundary — GaugeDesk-owned runtime selection and legacy policy.
//!
//! The host-side chokepoint every external effect passes through (`pi-rpc.md`,
//! "Egress Mediation"). It is **not** a bypass: even trust-by-default mediates
//! every effect — the posture only sets the *default decision* to
//! allow-and-record vs. block. The pure soundness of release (conjunctive
//! consent, `INV-22`) lives in [`gaugedesk_core::boundary`]; this crate is the
//! imperative policy gate that classifies an effect against the agent's declared
//! policy before it executes.
//!
//! The legacy membrane remains for scripted-fake and retired-adapter conformance.
//! Production package/tool authority is WhippleScript-owned (ADR 0081); new
//! `.agent-config.json` writes contain only GaugeDesk runtime selection.

use std::collections::BTreeSet;

use serde::Deserialize;

/// Which engagement mode a turn runs in, for the method-definition write-gate
/// (`INV-24`, ADR 0029). `Edit` may edit the agent's own definition; `Use` is
/// read-only to it. Defaults to `Use` (fail-closed: a context that forgot to
/// declare edit cannot rewrite the agent).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum AuthoringMode {
    Edit,
    #[default]
    Use,
}

/// The protected package/control surface. The WhippleScript package is editable
/// only through an authenticated edit chat; `.agent-config.json` is
/// GaugeDesk-owned provider/model selection and is never agent-authored.
pub fn is_method_surface_path(path: &str) -> bool {
    let p = path.trim_start_matches("./");
    p.starts_with(".whipple/") || p.contains("/.whipple/")
}

pub fn is_control_surface_path(path: &str) -> bool {
    let p = path.trim_start_matches("./");
    p == ".agent-config.json"
        || p.ends_with("/.agent-config.json")
        || p == definition::RUNTIME_MOUNT_ROOT
        || p.starts_with(concat!(".gaugedesk-runtime", "/"))
        || p.contains(concat!("/", ".gaugedesk-runtime", "/"))
}

/// Pi's built-in file-mutating tools. This membrane gate gives a fast, clean
/// rejection for these (defense-in-depth + audit); the load-bearing INV-24
/// enforcement is the OS sandbox, which makes the surface read-only for *every*
/// write path including a `bash` redirection ([ADR 0030]). So no tool — `bash`
/// included — is special-cased or blocked to protect the definition.
///
/// [ADR 0030]: ../../../specs/decisions/0030-sandbox-as-boundary-enforcement.md
pub fn is_write_tool(tool: &str) -> bool {
    matches!(tool, "write" | "edit")
}

/// The agent definition surface: a native authored WhippleScript package plus
/// GaugeDesk-owned runtime selection. WhippleScript parses the package manifest,
/// derives its tool surface from the capability registry, and binds all package
/// bytes into the immutable version reference. GaugeDesk owns who may edit,
/// publish, install, and select that reference.
pub mod definition {
    pub const PACKAGE_ROOT: &str = ".whipple";
    pub const DRAFT_ROOT: &str = ".whipple/draft";
    pub const VERSIONS_ROOT: &str = ".whipple/versions";
    pub const DISCIPLINE_VERSIONS_ROOT: &str = ".whipple/discipline/versions";
    pub const MANIFEST_FILE: &str = "package.json";
    pub const SOURCE_FILE: &str = "method.whip";
    pub const PERSONA_FILE: &str = "persona.md";
    /// GaugeDesk-owned provider/model/thinking selection. Authentication and
    /// credentials never enter the authored package.
    pub const CONFIG_PATH: &str = ".agent-config.json";
    /// Ephemeral, host-materialized view of immutable discipline assets. It is
    /// readable by a run, excluded from target history, and never user/model writable.
    pub const RUNTIME_MOUNT_ROOT: &str = ".gaugedesk-runtime";
    pub const DISCIPLINE_MOUNT_ROOT: &str = ".gaugedesk-runtime/discipline";
    /// Package bytes are read-only in work chats. The OS sandbox is
    /// defense-in-depth; WhippleScript package selection is the authority.
    pub const READONLY_ROOTS: &[&str] = &[PACKAGE_ROOT];
    pub const EDIT_READONLY_ROOTS: &[&str] = &[VERSIONS_ROOT, DISCIPLINE_VERSIONS_ROOT];
    /// GaugeDesk control files are never writable by a model, including in an
    /// edit chat.
    pub const CONTROL_READONLY_ROOTS: &[&str] = &[RUNTIME_MOUNT_ROOT];

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct PackageCapabilities {
        pub workspace_read: bool,
        pub workspace_write: bool,
        pub command_run: bool,
    }

    impl Default for PackageCapabilities {
        fn default() -> Self {
            Self {
                workspace_read: true,
                workspace_write: true,
                command_run: true,
            }
        }
    }

    impl PackageCapabilities {
        pub fn names(self) -> Vec<&'static str> {
            let mut names = Vec::new();
            if self.workspace_read {
                names.push("workspace.read");
            }
            if self.workspace_write {
                names.push("workspace.write");
            }
            if self.command_run {
                names.push("command.run");
            }
            names
        }
    }

    pub fn package_paths(root: &str) -> [(String, &'static str); 3] {
        [
            (format!("{root}/{MANIFEST_FILE}"), DEFAULT_MANIFEST),
            (format!("{root}/{SOURCE_FILE}"), DEFAULT_METHOD_SOURCE),
            (format!("{root}/{PERSONA_FILE}"), ""),
        ]
    }

    pub fn version_root(version: u64) -> String {
        format!("{VERSIONS_ROOT}/{version}")
    }

    pub fn package_documents(
        root: &str,
        persona: &str,
        capabilities: PackageCapabilities,
    ) -> Vec<(String, String)> {
        let names = capabilities.names();
        let json_names = names
            .iter()
            .map(|name| format!("\"{name}\""))
            .collect::<Vec<_>>()
            .join(", ");
        let manifest = format!(
            "{{\n  \"schema\": \"whipplescript.agent_package.v0\",\n  \"source\": \"method.whip\",\n  \"workflow\": \"GaugeDeskMethod\",\n  \"agent\": \"assistant\",\n  \"system_prompt\": \"persona.md\",\n  \"capabilities\": [{json_names}],\n  \"agent_abilities\": [{json_names}],\n  \"max_steps\": 32\n}}\n"
        );
        let capability_list = format!("[{}]", json_names);
        let requires = if names.is_empty() {
            String::new()
        } else {
            format!(" requires {capability_list}")
        };
        let mut resources = String::new();
        let mut grants = String::new();
        if capabilities.workspace_read {
            resources.push_str("file store project {\n  root \".\"\n  allow read [\"**\"]\n");
            if capabilities.workspace_write {
                resources.push_str("  allow write [\"**\"]\n");
            }
            resources.push_str("}\n\n");
            grants.push_str("\n      with access to project {\n        read [\"**\"]\n");
            if capabilities.workspace_write {
                grants.push_str("        write [\"**\"]\n");
            }
            grants.push_str("      }");
        }
        if capabilities.command_run {
            grants.push_str("\n      with access to command {\n        run\n      }");
        }
        let source = format!(
            "{resources}workflow GaugeDeskMethod {{\n  agent assistant {{\n    provider owned\n    profile \"repo-writer\"\n    capacity 1\n    capabilities {capability_list}\n  }}\n\n  rule converse\n    when started\n  => {{\n    tell assistant{requires}{grants}\n      \"Run the selected GaugeDesk method.\"\n  }}\n}}\n"
        );
        vec![
            (format!("{root}/{MANIFEST_FILE}"), manifest),
            (format!("{root}/{SOURCE_FILE}"), source),
            (format!("{root}/{PERSONA_FILE}"), persona.to_owned()),
        ]
    }

    pub const DEFAULT_METHOD_SOURCE: &str = r#"file store project {
  root "."
  allow read ["**"]
  allow write ["**"]
}

workflow GaugeDeskMethod {
  agent assistant {
    provider owned
    profile "repo-writer"
    capacity 1
    capabilities ["workspace.read", "workspace.write", "command.run"]
  }

  rule converse
    when started
  => {
    tell assistant requires ["workspace.read", "workspace.write", "command.run"]
      with access to project {
        read ["**"]
        write ["**"]
      }
      with access to command {
        run
      }
      "Run the selected GaugeDesk method."
  }
}
"#;

    pub const DEFAULT_MANIFEST: &str = r#"{
  "schema": "whipplescript.agent_package.v0",
  "source": "method.whip",
  "workflow": "GaugeDeskMethod",
  "agent": "assistant",
  "system_prompt": "persona.md",
  "capabilities": [
    "workspace.read",
    "workspace.write",
    "command.run"
  ],
  "agent_abilities": [
    "workspace.read",
    "workspace.write",
    "command.run"
  ],
  "max_steps": 32
}
"#;

    /// The neutral authored definition materialized as a native WhippleScript
    /// agent package.
    pub struct AgentDefinition {
        /// Persona included in the package-owned system context.
        pub system: String,
        /// Method conventions included in the same package-owned context.
        pub instructions: String,
        /// GaugeDesk runtime selection, when the definition carries one.
        pub config: Option<String>,
    }

    impl AgentDefinition {
        /// The one layout choke point for fresh archetype package source.
        pub fn seed_files(&self) -> Vec<(String, String)> {
            let persona = format!("{}\n\n{}", self.system.trim(), self.instructions.trim());
            let mut files = Vec::new();
            for root in [DRAFT_ROOT.to_owned(), version_root(1)] {
                files.extend(package_documents(
                    &root,
                    &persona,
                    PackageCapabilities::default(),
                ));
            }
            if let Some(config) = &self.config {
                files.push((CONFIG_PATH.to_string(), config.clone()));
            }
            files
        }
    }
}

/// How the membrane treats effects not explicitly named by policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Posture {
    /// In-workspace effects proceed without prompting (allow-and-record). The
    /// MVP default.
    #[default]
    TrustByDefault,
    /// Risky effects (network, out-of-workspace writes) require approval (stage).
    PromptOnRisk,
    /// Only effects explicitly allowed by policy proceed; everything else blocks.
    PolicyOnlyBlock,
}

/// GaugeDesk runtime selection plus retired policy fields retained solely for
/// one-way migration and fake/adapter conformance. New settings writes reject
/// `tools` and `policy`; production WhippleScript never consults them.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct AgentConfig {
    /// Provider to pin (e.g. `openai-codex`). M0 defaults to the user's OAuth
    /// codex endpoint when unset (see the engine).
    #[serde(default)]
    pub provider: Option<String>,
    #[serde(default)]
    pub model: Option<String>,
    /// Reasoning-effort level for this chat. Unset uses the provider default.
    #[serde(default)]
    pub thinking: Option<String>,
    #[serde(default)]
    /// Retired package-tool selection, read only by the migration converter.
    pub tools: Vec<String>,
    #[serde(default)]
    /// Retired GaugeDesk membrane policy, read only by migration/fake adapters.
    pub policy: Policy,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct Policy {
    #[serde(default)]
    pub posture: Posture,
    /// Tools always allowed (in-workspace file/read tools, etc.).
    #[serde(default)]
    pub allow_tools: BTreeSet<String>,
    /// Tools always blocked, regardless of posture.
    #[serde(default)]
    pub block_tools: BTreeSet<String>,
    /// Whether network egress is permitted at all in M0 (default: no).
    #[serde(default)]
    pub allow_network: bool,
}

impl AgentConfig {
    pub fn from_json(s: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(s)
    }
    pub fn from_file(path: &std::path::Path) -> std::io::Result<Self> {
        let s = std::fs::read_to_string(path)?;
        Self::from_json(&s).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }

    pub fn runtime_settings_from_json(s: &str) -> Result<Self, String> {
        let value: serde_json::Value =
            serde_json::from_str(s).map_err(|error| error.to_string())?;
        let object = value
            .as_object()
            .ok_or_else(|| "runtime settings must be a JSON object".to_owned())?;
        for retired in ["policy", "tools"] {
            if object.contains_key(retired) {
                return Err(format!(
                    "`{retired}` is package-owned; edit `.whipple/draft/package.json` and `method.whip`"
                ));
            }
        }
        Self::from_json(s).map_err(|error| error.to_string())
    }

    /// One-way SUB-3 migration of the legacy tool-policy shape into the native
    /// WhippleScript package capability registry. Network/provider authority is
    /// deliberately absent: GaugeDesk project policy and the signed governance
    /// envelope own those decisions.
    pub fn package_capabilities(&self) -> definition::PackageCapabilities {
        let admits = |names: &[&str]| {
            let named = |set: &BTreeSet<String>| names.iter().any(|name| set.contains(*name));
            let selected = self.tools.is_empty()
                || names
                    .iter()
                    .any(|name| self.tools.iter().any(|tool| tool == name));
            let posture_allows = match self.policy.posture {
                Posture::PolicyOnlyBlock => named(&self.policy.allow_tools),
                Posture::TrustByDefault | Posture::PromptOnRisk => selected,
            };
            posture_allows && !named(&self.policy.block_tools)
        };
        let workspace_write = admits(&["write", "edit"]);
        definition::PackageCapabilities {
            workspace_read: admits(&["read"]) || workspace_write,
            workspace_write,
            command_run: admits(&["bash", "command"]),
        }
    }
}

/// One effect the agent is about to perform, as classified by the plugin.
#[derive(Clone, Debug)]
pub struct Effect {
    pub tool: String,
    /// True if the effect leaves the workspace (network, or a write outside the
    /// admitted workspace root).
    pub leaves_workspace: bool,
    /// What the effect acts on (the file path / target), when the tool reports one.
    /// Used by the method-definition write-gate (`INV-24`).
    pub target: Option<String>,
}

impl Effect {
    /// An in-workspace tool effect (the common case: read/edit/write a file).
    pub fn in_workspace(tool: impl Into<String>) -> Self {
        Self {
            tool: tool.into(),
            leaves_workspace: false,
            target: None,
        }
    }
    /// An effect that crosses the boundary (network call, external write).
    pub fn external(tool: impl Into<String>) -> Self {
        Self {
            tool: tool.into(),
            leaves_workspace: true,
            target: None,
        }
    }
    /// Attach the target path the effect acts on.
    pub fn with_target(mut self, target: Option<String>) -> Self {
        self.target = target;
        self
    }
}

/// The membrane's decision for an effect.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Decision {
    /// Allowed under policy — execute and record (`INV` audit trail kept).
    Allow,
    /// Blocked — emit an observation; the effect does not happen.
    Block(&'static str),
    /// Held pending an explicit resource-access / resource-export grant (A5b).
    Stage(&'static str),
}

/// The egress membrane: classifies effects against a policy. Stateless and
/// deterministic — the same effect under the same policy always decides the same.
pub struct Membrane {
    policy: Policy,
    mode: AuthoringMode,
}

impl Membrane {
    pub fn new(policy: Policy) -> Self {
        Self {
            policy,
            mode: AuthoringMode::default(),
        }
    }

    /// Set the engagement's authoring mode (drives the `INV-24` write-gate).
    pub fn with_mode(mut self, mode: AuthoringMode) -> Self {
        self.mode = mode;
        self
    }

    /// The chokepoint. Every effect is classified here before it executes.
    pub fn classify(&self, effect: &Effect) -> Decision {
        // An explicit block always wins — even trust-by-default cannot override it.
        if self.policy.block_tools.contains(&effect.tool) {
            return Decision::Block("tool blocked by policy");
        }

        if is_write_tool(&effect.tool)
            && effect
                .target
                .as_deref()
                .is_some_and(is_control_surface_path)
        {
            return Decision::Block("GaugeDesk runtime configuration is host-owned");
        }

        // INV-24: the method-definition surface is edit-authored. A write to it
        // from a use-mode engagement is blocked even under trust-by-default — the
        // agent cannot rewrite its own system prompt or loosen its own policy.
        if self.mode != AuthoringMode::Edit && is_write_tool(&effect.tool) {
            if let Some(t) = &effect.target {
                if is_method_surface_path(t) {
                    return Decision::Block("method definition is read-only in use mode");
                }
            }
        }

        if effect.leaves_workspace {
            // Crossing the boundary needs an explicit basis; never the default.
            return if self.policy.allow_network {
                Decision::Allow
            } else {
                match self.policy.posture {
                    Posture::PromptOnRisk => Decision::Stage("external effect: needs approval"),
                    _ => Decision::Block("external effect not permitted (no network basis)"),
                }
            };
        }

        // In-workspace effects: explicit allow, or posture's default.
        if self.policy.allow_tools.contains(&effect.tool) {
            return Decision::Allow;
        }
        match self.policy.posture {
            Posture::TrustByDefault => Decision::Allow,
            Posture::PromptOnRisk => Decision::Stage("unlisted tool: confirm in-workspace effect"),
            Posture::PolicyOnlyBlock => Decision::Block("tool not in allow-list"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trust_by_default_allows_in_workspace_blocks_external() {
        let m = Membrane::new(Policy::default()); // posture defaults to trust-by-default
        assert_eq!(m.classify(&Effect::in_workspace("edit")), Decision::Allow);
        // even trust-by-default does NOT let payload leave the boundary by default
        assert!(matches!(
            m.classify(&Effect::external("fetch")),
            Decision::Block(_)
        ));
    }

    #[test]
    fn explicit_block_overrides_posture() {
        let policy = Policy {
            posture: Posture::TrustByDefault,
            block_tools: ["bash"].iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        };
        let m = Membrane::new(policy);
        assert!(matches!(
            m.classify(&Effect::in_workspace("bash")),
            Decision::Block(_)
        ));
        assert_eq!(m.classify(&Effect::in_workspace("read")), Decision::Allow);
    }

    #[test]
    fn policy_only_block_is_an_allowlist() {
        let policy = Policy {
            posture: Posture::PolicyOnlyBlock,
            allow_tools: ["read", "edit"].iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        };
        let m = Membrane::new(policy);
        assert_eq!(m.classify(&Effect::in_workspace("read")), Decision::Allow);
        assert!(matches!(
            m.classify(&Effect::in_workspace("write")),
            Decision::Block(_)
        ));
    }

    #[test]
    fn prompt_on_risk_stages_external() {
        let policy = Policy {
            posture: Posture::PromptOnRisk,
            ..Default::default()
        };
        let m = Membrane::new(policy);
        assert!(matches!(
            m.classify(&Effect::external("fetch")),
            Decision::Stage(_)
        ));
    }

    #[test]
    fn parses_agent_config_and_ignores_unknown_fields() {
        let cfg = AgentConfig::from_json(
            r#"{
                "model": "gpt-5.5",
                "tools": ["read","edit","write"],
                "policy": { "posture": "policy-only-block", "allow_tools": ["read"] },
                "builderOnly": ["builder_only/**"]
            }"#,
        )
        .unwrap();
        assert_eq!(cfg.model.as_deref(), Some("gpt-5.5"));
        assert_eq!(cfg.policy.posture, Posture::PolicyOnlyBlock);
        assert!(cfg.policy.allow_tools.contains("read"));
    }

    // ── Native package/control ownership ───────────────────────────────────────

    fn edit(target: &str) -> Effect {
        Effect::in_workspace("edit").with_target(Some(target.to_string()))
    }

    #[test]
    fn use_mode_blocks_writes_to_the_method_surface() {
        let m = Membrane::new(Policy::default()).with_mode(AuthoringMode::Use);
        for path in [
            ".whipple/draft/persona.md",
            ".whipple/versions/1/method.whip",
            ".agent-config.json",
            ".whipple/draft/skills/x.md",
            "/abs/wt/.whipple/versions/2/package.json",
        ] {
            assert!(
                matches!(m.classify(&edit(path)), Decision::Block(_)),
                "use mode must block writing {path}"
            );
        }
        // but use mode can still WRITE non-definition files (the actual work)…
        assert_eq!(m.classify(&edit("src/main.rs")), Decision::Allow);
        // …and can READ its own definition (read is not a write tool).
        let read_sys =
            Effect::in_workspace("read").with_target(Some(".whipple/draft/persona.md".into()));
        assert_eq!(m.classify(&read_sys), Decision::Allow);
        assert_eq!(m.classify(&edit("AGENTS.md")), Decision::Allow);
    }

    #[test]
    fn edit_mode_may_write_the_method_surface() {
        let m = Membrane::new(Policy::default()).with_mode(AuthoringMode::Edit);
        assert_eq!(
            m.classify(&edit(".whipple/draft/persona.md")),
            Decision::Allow
        );
        assert!(matches!(
            m.classify(&edit(".agent-config.json")),
            Decision::Block(_)
        ));
    }

    /// The definition layout has exactly one choke point: a mutable draft plus
    /// an immutable version-one package with identical authored bytes.
    #[test]
    fn seed_files_is_the_one_layout_choke_point() {
        let def = definition::AgentDefinition {
            system: "persona".into(),
            instructions: "conventions".into(),
            config: None,
        };
        let seeded = def.seed_files();
        assert_eq!(seeded.len(), 6);
        for root in [
            definition::DRAFT_ROOT.to_owned(),
            definition::version_root(1),
        ] {
            assert!(seeded
                .iter()
                .any(|(path, _)| path == &format!("{root}/package.json")));
            assert!(seeded
                .iter()
                .any(|(path, _)| path == &format!("{root}/method.whip")));
            assert!(seeded.iter().any(|(path, body)| {
                path == &format!("{root}/persona.md") && body == "persona\n\nconventions"
            }));
        }

        let with_config = definition::AgentDefinition {
            config: Some("{}".into()),
            ..def
        };
        assert_eq!(
            with_config.seed_files().last(),
            Some(&(".agent-config.json".to_string(), "{}".to_string()))
        );
        // every seeded file is either package-owned or GaugeDesk control.
        for (path, _) in with_config.seed_files() {
            assert!(
                is_method_surface_path(&path) || is_control_surface_path(&path),
                "{path} is on a protected surface"
            );
        }
    }

    use proptest::prelude::*;

    proptest! {
        // METHOD_WRITE_REQUIRES_EDIT (INV-24): for any tool/target/mode, an
        // *admitted* write to the method surface implies edit mode. Mirrors
        // models/method-integrity.qnt over the concrete membrane.
        #[test]
        fn method_write_requires_edit(
            tool in prop::sample::select(vec!["read", "edit", "write", "ls", "grep"]),
            is_edit in any::<bool>(),
            // a path that is sometimes on the surface, sometimes not
            surface in prop::sample::select(vec![".whipple/draft/persona.md", "AGENTS.md", ".agent-config.json",
                                                 ".whipple/versions/1/method.whip", "src/lib.rs", "notes/x.md", "data.csv"]),
        ) {
            let mode = if is_edit { AuthoringMode::Edit } else { AuthoringMode::Use };
            let m = Membrane::new(Policy::default()).with_mode(mode);
            let eff = Effect::in_workspace(tool).with_target(Some(surface.to_string()));
            let decision = m.classify(&eff);

            let is_surface_write = is_write_tool(tool) && is_method_surface_path(surface);
            if is_surface_write && !is_edit {
                prop_assert!(matches!(decision, Decision::Block(_)),
                    "use-mode write to surface must block: {tool} {surface}");
            }
            // The invariant: any ADMITTED (Allow) surface write was in edit mode.
            if matches!(decision, Decision::Allow) && is_write_tool(tool) && is_method_surface_path(surface) {
                prop_assert!(is_edit, "an admitted surface write must be edit mode");
            }
        }
    }
}
