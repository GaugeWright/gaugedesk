//! The agent/project library — the ADR-0027 data model as durable **records**.
//!
//! Archetypes, projects, placements, work targets, and chats are not lifecycle state; they are
//! durable *declarations* whose current value is the source of truth
//! (`data.md`). We store them as append-only records in one reserved scope
//! (`"library"`) and fold them **latest-wins by id** into a [`Library`]
//! projection: an `Upsert` sets/overwrites, a `Tombstone` removes. Because the
//! log is ordered, rename/config-edit/delete all fall out of "append a newer
//! record" — and the full history is preserved, leaving a seam for an
//! `agent-version` facet later (M1).
//!
//! - **agent** = a library-level reusable definition (its own authoring instance).
//! - **instance** = an archetype authoring root or a placement declaration.
//! - **work target** = the independently-authoritative files a chat changes.
//! - **project** = a grouping of placements and ordinary work targets.
//! - **chat** = an engagement binding a placement/archetype to a target and exact basis.

use std::collections::{BTreeMap, BTreeSet};

use gaugedesk_core::agent_release::{
    AttributionPolicy, CollectionPolicy, PanelManifest, ProviderPolicy, ReleaseFile,
    RetentionPolicy,
};
use gaugedesk_core::boundary_lifecycle::{BoundaryPhase, BoundaryState, Operator, Placement};
use gaugedesk_core::ids::HomeId;
use gaugedesk_store::{AdmitError, Store};
use serde::{Deserialize, Serialize};

/// The reserved store scope holding every library record.
pub const LIBRARY_SCOPE: &str = "library";

/// The record-shape schema version this build **writes** and the newest it
/// **reads** (DR-0054 Phase B, `specs/systems.md` Persistent State
/// Compatibility). Every persisted library record is stamped with it; records
/// written before the stamp read as version 1 (their implicit shape). A record
/// declaring a *newer* version fails the read closed (see
/// [`guard_record_schema`]) instead of being silently misread, and each
/// record's `extra` map round-trips fields this build does not recognize so an
/// older build's rewrite never drops a newer build's data. Bump only for a
/// non-additive shape change.
pub const LIBRARY_RECORD_SCHEMA: u32 = 1;

/// Serde default for [`LIBRARY_RECORD_SCHEMA`]-stamped records written before
/// the stamp existed: they are version 1, the implicit original shape.
fn record_schema_v1() -> u32 {
    1
}

/// Fail closed on a record stamped by a newer build (DR-0054 Phase B): reading
/// it with this build's shape would silently drop whatever the newer version
/// added or reinterpreted, so the reader errors diagnosably instead — naming
/// the record, both versions, and the remediation (a newer build, never a
/// state-root reset).
fn guard_record_schema(kind: &str, id: &str, schema: u32) -> Result<(), AdmitError> {
    if schema > LIBRARY_RECORD_SCHEMA {
        return Err(AdmitError::UnsupportedSchema(format!(
            "library {kind} record {id} declares schema version {schema}, but this build reads \
             at most {LIBRARY_RECORD_SCHEMA}: a newer GaugeDesk wrote it. Refusing to load it — \
             run that newer build against this state root (do not reset it)."
        )));
    }
    Ok(())
}

/// A record either declares the current value (`Upsert`) or retracts the id
/// (`Tombstone`). Folded latest-wins, so the last write per id wins.
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug, Default)]
#[serde(rename_all = "lowercase")]
pub enum RecordOp {
    #[default]
    Upsert,
    Tombstone,
}

/// Whether an instance's workspace is the agent's own definition repo
/// (`Authoring`) or a project binding (`Using`). Purpose is read from this,
/// not modeled as a separate kind (ADR 0027).
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "lowercase")]
pub enum InstanceKind {
    Authoring,
    Using,
}

/// Immutable product kind of an Agent lineage (ADR 0143). Records written
/// before Panel agents existed deserialize as ordinary work Agents.
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug, Default)]
#[serde(rename_all = "lowercase")]
pub enum AgentKind {
    #[default]
    Work,
    Panel,
}

/// Runtime shape of a project installation. This is stored independently of
/// [`InstanceKind`], which still distinguishes authoring roots from project
/// placements. Legacy placements are work placements.
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug, Default)]
#[serde(rename_all = "lowercase")]
pub enum PlacementKind {
    #[default]
    Work,
    Panel,
}

impl From<AgentKind> for PlacementKind {
    fn from(value: AgentKind) -> Self {
        match value {
            AgentKind::Work => Self::Work,
            AgentKind::Panel => Self::Panel,
        }
    }
}

/// Complete public contract authored with a Panel agent and frozen into each
/// numeric version. None of these fields are deployment-time choices.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct PanelPublicProfile {
    pub panels: PanelManifest,
    #[serde(default)]
    pub public_abilities: BTreeSet<String>,
    pub provider: ProviderPolicy,
    #[serde(default)]
    pub audience_inputs: BTreeSet<String>,
    #[serde(default)]
    pub initial_workspace: Vec<ReleaseFile>,
    pub retention: RetentionPolicy,
    #[serde(default)]
    pub collection: Option<CollectionPolicy>,
}

impl Default for PanelPublicProfile {
    fn default() -> Self {
        Self {
            panels: PanelManifest {
                components: ["gw-chat".to_owned()].into_iter().collect(),
                default_component: "gw-chat".to_owned(),
                attribution: AttributionPolicy::GaugeWright,
            },
            public_abilities: BTreeSet::new(),
            provider: ProviderPolicy {
                provider: "openai".to_owned(),
                model: "gpt-5-mini".to_owned(),
                // The native OpenAI Responses client appends `/v1/responses`.
                // This is therefore the provider origin, not the SDK-style
                // compat base used by `openai-generic` chat completions.
                base_url: "https://api.openai.com".to_owned(),
                credential_class: "openai-api-key".to_owned(),
                max_input_tokens: None,
                max_output_tokens: None,
            },
            audience_inputs: ["text".to_owned()].into_iter().collect(),
            initial_workspace: Vec::new(),
            retention: RetentionPolicy {
                idle_ttl_seconds: 86_400,
                absolute_ttl_seconds: 2_592_000,
                transcript_retained: true,
                workspace_retained: true,
            },
            collection: None,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct PanelCollectionRecipient {
    pub recipient_ref: String,
    #[serde(default)]
    pub recipient_public_keys: Vec<String>,
}

/// A placement's **admission state** (`APPROVE-1`, [ADR 0064](../decisions/0064-archetype-approval-two-acts.md)):
/// whether it is admitted for use. A placement hosts work chats and is offered in the
/// project's chat picker **only while `Active`**. Under an approval-required project
/// policy, an *explicitly-placed* archetype starts **`Pending`** until the project owner
/// accepts it; the frictionless default (and the built-in general placement, the eager
/// Personal placement, and older records) is **`Active`**.
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug, Default)]
#[serde(rename_all = "lowercase")]
pub enum Admission {
    #[default]
    Active,
    Pending,
}

/// The chat kind lives in the harness seam crate (SUB-0) — the runtime adapter
/// needs it to key the membrane/persona — re-exported here at its old path so
/// existing callers keep compiling unchanged.
pub use gaugedesk_harness::ChatMode;

impl InstanceKind {
    /// The chat kind a chat rooted on an instance of this kind takes (ADR 0035):
    /// an authoring instance (an archetype) ⇒ an **edit** chat; a using instance
    /// (a placement) ⇒ a **work** chat. The single source of edit-vs-work truth.
    pub fn chat_mode(self) -> ChatMode {
        match self {
            InstanceKind::Authoring => ChatMode::Edit,
            InstanceKind::Using => ChatMode::Use,
        }
    }

    /// The derived chat-kind label the projection emits (`"edit"` | `"work"`).
    pub fn chat_kind(self) -> &'static str {
        match self {
            InstanceKind::Authoring => "edit",
            InstanceKind::Using => "work",
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ArchetypeVersionRecord {
    pub package_ref: String,
    pub discipline_ref: String,
    /// Frozen only for Panel-agent versions. Legacy versions are ordinary work
    /// versions and therefore have no public profile.
    #[serde(default)]
    pub panel_profile: Option<PanelPublicProfile>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AgentRecord {
    pub id: String,
    #[serde(default)]
    pub op: RecordOp,
    pub name: String,
    /// Immutable for this lineage. A work Agent becomes public-capable only by
    /// an explicit copy into a new Panel-agent lineage.
    #[serde(default)]
    pub agent_kind: AgentKind,
    /// Mutable Panel-agent draft. Publish copies it into the numeric version.
    #[serde(default)]
    pub panel_profile: Option<PanelPublicProfile>,
    /// The logical authoring root. Its files live in the archetype-owned target.
    pub instance_id: String,
    /// The raw `.agent-config.json` seeded into each chat's worktree. Stored
    /// verbatim (validated on write); empty config is `"{}"`.
    #[serde(default = "empty_config")]
    pub config: String,
    /// The archetype's **current published version** (`UX-9`, [ADR 0063]): a monotonic
    /// counter bumped on publish. A placement whose `version` is behind this has an upgrade
    /// available. Older records default to `1`.
    #[serde(default = "one")]
    pub current_version: u64,
    /// Every numeric version atomically binds the executable WhippleScript
    /// package and workspace-discipline content references.
    #[serde(default)]
    pub versions: BTreeMap<u64, ArchetypeVersionRecord>,
    /// The **owner's** auto-upgrade preference (`UX-9`, [ADR 0063]): when set, placements of
    /// this archetype move to a newly-published version automatically — *but only where the
    /// hosting org also allows auto-updates* (`Org::allow_auto_upgrade`), else it falls back
    /// to manual. Default `false` (manual).
    #[serde(default)]
    pub auto_upgrade: bool,
    /// The source archetype this one was **forked from** (`Some(agent_id)`), or `None` for an
    /// original. A fork shares its source's cut lineage, so it can later *pull* upstream
    /// improvements (ADR 0038). Older records default to `None`.
    #[serde(default)]
    pub forked_from: Option<String>,
    /// The record-shape schema version that wrote this record (DR-0054 Phase
    /// B). Absent on records predating the stamp = version 1, the implicit
    /// original shape. Readers fail closed on a version newer than
    /// [`LIBRARY_RECORD_SCHEMA`].
    #[serde(default = "record_schema_v1")]
    pub schema: u32,
    /// Fields written by a build newer than this one, preserved verbatim so a
    /// read-modify-write here never drops them (DR-0054 Phase B).
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}

fn empty_config() -> String {
    "{}".to_string()
}

/// The default version pointer (`1`) for archetypes/placements predating `UX-9` versioning,
/// so an un-versioned record reads as "current" rather than perpetually behind.
fn one() -> u64 {
    1
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ProjectRecord {
    pub id: String,
    #[serde(default)]
    pub op: RecordOp,
    pub name: String,
    /// The default "Personal" project (ADR 0036 / ADR 0097): the explicit trust
    /// boundary the solo "just start chatting" path roots its default placement on.
    /// Defaults to `false` for older records.
    #[serde(default)]
    pub is_default: bool,
    /// The exactly-one authoritative Home that owns this project's GaugeDesk
    /// log, content, grants, and commands (`HOME-2`). Missing legacy values are
    /// migrated durably to the opening workbench's Home before it serves.
    #[serde(default = "unbound_home")]
    pub home_id: HomeId,
    /// The project's network egress posture (RF-B3). The app ships **open** —
    /// chats in this project may reach the model (and, with no per-host proxy yet,
    /// any host) — and the operator *opts into* isolation per project. `true`
    /// re-imposes the fail-closed kernel network isolation (`--unshare-net`) the
    /// core [`SandboxPolicy`](gaugedesk_harness::sandbox::SandboxPolicy) defaults to.
    /// Defaults to `false` (open) for older records.
    #[serde(default)]
    pub network_isolated: bool,
    /// The admitted business purpose for runs in this project. Resources with
    /// purpose tags may enter WhippleScript only when this value matches one of
    /// their allowed purposes. `None` denies purpose-constrained resources.
    #[serde(default)]
    pub run_purpose: Option<String>,
    /// The project's **deployment mode** (`DEPLOY-1`, [ADR 0059](../../../specs/decisions/0059-deployment-topology-headless-control-plane-policy-gated-pairing.md)):
    /// the `(operator, attested)` [`Placement`] the consultant declares for engagements on
    /// this project — the boundary `declareCeiling` input. `None` ⇒ the local default
    /// (`Placement::local`). Defaults to `None` for older records.
    #[serde(default)]
    pub deployment_mode: Option<Placement>,
    /// The record-shape schema version that wrote this record (DR-0054 Phase
    /// B). Absent on records predating the stamp = version 1, the implicit
    /// original shape. Readers fail closed on a version newer than
    /// [`LIBRARY_RECORD_SCHEMA`].
    #[serde(default = "record_schema_v1")]
    pub schema: u32,
    /// Fields written by a build newer than this one, preserved verbatim so a
    /// read-modify-write here never drops them (DR-0054 Phase B).
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}

fn unbound_home() -> HomeId {
    HomeId::new("")
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct InstanceRecord {
    pub id: String,
    #[serde(default)]
    pub op: RecordOp,
    pub kind: InstanceKind,
    /// Work versus Panel installation. Authoring instances mirror their
    /// Agent's kind; persisted placements without the field remain work.
    #[serde(default)]
    pub placement_kind: PlacementKind,
    pub agent_id: String,
    /// `Some` for a using-instance (which project it's bound into); `None` for
    /// an authoring instance.
    #[serde(default)]
    pub project_id: Option<String>,
    /// The archetype **version this placement runs** (`UX-9`, [ADR 0063]). Set to the
    /// archetype's `current_version` at placement time and advanced by an upgrade; when it is
    /// behind the archetype's `current_version`, the placement has an upgrade available. Older
    /// records default to `1` (treated as current).
    #[serde(default = "one")]
    pub version: u64,
    /// The placement's **admission state** (`APPROVE-1`, [ADR 0064]). `Active` placements
    /// host work chats and appear in the chat picker; a `Pending` placement is
    /// approved-but-not-yet-accepted under an approval-required project policy. Older
    /// records and the frictionless default read as `Active`.
    #[serde(default)]
    pub admission: Admission,
    /// Exact project-owned collection recipient admitted by a Panel
    /// placement. It is absent when the frozen profile collects nothing.
    #[serde(default)]
    pub collection_recipient: Option<PanelCollectionRecipient>,
    /// The record-shape schema version that wrote this record (DR-0054 Phase
    /// B). Absent on records predating the stamp = version 1, the implicit
    /// original shape. Readers fail closed on a version newer than
    /// [`LIBRARY_RECORD_SCHEMA`].
    #[serde(default = "record_schema_v1")]
    pub schema: u32,
    /// Fields written by a build newer than this one, preserved verbatim so a
    /// read-modify-write here never drops them (DR-0054 Phase B).
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Default)]
pub struct DeploymentAudienceOidc {
    pub issuer: String,
    pub audience: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct DeploymentAudience {
    #[serde(default = "default_true")]
    pub anonymous_allowed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oidc: Option<DeploymentAudienceOidc>,
}

impl Default for DeploymentAudience {
    fn default() -> Self {
        Self {
            anonymous_allowed: true,
            oidc: None,
        }
    }
}

fn default_true() -> bool {
    true
}

/// Operational deployment choices. Functional contract fields deliberately do
/// not appear here; they come only from the pinned Panel-agent version.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct DeploymentOperationalConfig {
    #[serde(default)]
    pub allowed_origins: Vec<String>,
    #[serde(default)]
    pub audience: DeploymentAudience,
    pub funding_ref: String,
    pub credential_class: String,
    pub credential_ref: String,
    #[serde(default)]
    pub max_spend_cents: Option<u64>,
    #[serde(default)]
    pub max_session_spend_cents: Option<u64>,
    #[serde(default)]
    pub max_turn_spend_cents: Option<u64>,
    pub per_visitor_turn_limit: u64,
    pub max_concurrent_sessions: u64,
    #[serde(default)]
    pub white_label: bool,
    pub retention_idle_ttl_seconds: u64,
    pub retention_absolute_ttl_seconds: u64,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum DeploymentBindingStatus {
    #[default]
    PendingPublish,
    Active,
    LegacyConfirmationRequired,
}

/// Local authority connecting one hosted public deployment to exactly one
/// project-owned Panel placement (ADR 0143). This record is written before the
/// hosted publish call and updated with its active immutable release afterward.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PublicDeploymentBindingRecord {
    pub id: String,
    #[serde(default)]
    pub op: RecordOp,
    pub project_id: String,
    pub placement_id: String,
    pub hosted_deployment_id: String,
    pub edge_origin: String,
    #[serde(default)]
    pub active_release_id: Option<String>,
    pub operational: DeploymentOperationalConfig,
    #[serde(default)]
    pub status: DeploymentBindingStatus,
    #[serde(default = "record_schema_v1")]
    pub schema: u32,
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ChatRecord {
    pub id: String,
    #[serde(default)]
    pub op: RecordOp,
    pub instance_id: String,
    pub title: String,
    /// The library-scope position at creation — drives "Recent" ordering.
    #[serde(default)]
    pub created_position: i64,
    /// The chat this one was forked from, if any (ADR 0038) — chats form a fork
    /// tree. `None` for an original chat.
    #[serde(default)]
    pub forked_from: Option<String>,
    /// Stable transcript entry selected for a point fork (ADR 0073). Absent
    /// for original chats and legacy whole-thread forks.
    #[serde(default)]
    pub forked_from_entry: Option<i64>,
    /// Inclusive upper bound on the parent-scope records this fork inherits
    /// (ADR 0141): the child's effective log is the parent's records with
    /// `position <= forked_from_cut` followed by its own — resolved by
    /// lineage, never copied. Absent for original chats and for forks created
    /// before ADR 0141, which inherit nothing (their durable log began empty).
    #[serde(default)]
    pub forked_from_cut: Option<i64>,
    /// The record-shape schema version that wrote this record (DR-0054 Phase
    /// B). Absent on records predating the stamp = version 1, the implicit
    /// original shape. Readers fail closed on a version newer than
    /// [`LIBRARY_RECORD_SCHEMA`].
    #[serde(default = "record_schema_v1")]
    pub schema: u32,
    /// Fields written by a build newer than this one, preserved verbatim so a
    /// read-modify-write here never drops them (DR-0054 Phase B).
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}

/// The authority scope that owns a work target (ADR 0100 / TARGET-1).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum WorkTargetOwner {
    Project { project_id: String },
    Archetype { archetype_id: String },
}

/// The target adapter family. `Managed` is authoritative WhippleScript VCS;
/// external targets retain their own VCS/folder authority.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum WorkTargetKind {
    Managed,
    ExternalVcs,
    ExternalFolder,
}

/// Which version-control authority owns the target's settled history. This is
/// deliberately separate from the adapter implementation: an adapter can use
/// WhippleScript as non-authoritative shadow history for an external folder
/// without changing that folder's `Unversioned` posture.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Default)]
#[serde(rename_all = "kebab-case")]
pub enum TargetVcsPosture {
    #[default]
    Managed,
    ExternalVcs,
    Unversioned,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum WorkTargetStatus {
    #[default]
    Available,
    Unavailable,
    Retired,
}

/// Separating these acts prevents a visible path or readable checkout from
/// silently granting mutation/publication authority (ADR 0100 §1/§2).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Default)]
pub struct TargetCapabilities {
    pub read: bool,
    pub propose: bool,
    pub apply: bool,
    pub publish: bool,
    pub release: bool,
}

impl TargetCapabilities {
    pub fn managed_default() -> Self {
        Self {
            read: true,
            propose: true,
            apply: true,
            publish: false,
            release: false,
        }
    }
}

/// Durable declaration of one repository/folder/managed body of files. The
/// `locator_handle` is opaque to runtimes and clients. Managed target storage is
/// keyed directly by the target id; placements never receive a storage alias.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct WorkTargetRecord {
    pub id: String,
    pub op: RecordOp,
    pub name: String,
    pub owner: WorkTargetOwner,
    pub kind: WorkTargetKind,
    /// Authority and stakeholder identities only. Protected target bytes and
    /// credentials remain behind the locator handle.
    pub authority: String,
    pub parties: Vec<String>,
    pub locator_handle: String,
    pub adapter: String,
    pub adapter_family: String,
    pub vcs_posture: TargetVcsPosture,
    /// The adapter's last resolved exact standing basis. Chat bindings always
    /// retain their own immutable basis even after this hint advances.
    pub current_basis: Option<String>,
    pub path_scope: Vec<String>,
    pub capabilities: TargetCapabilities,
    pub status: WorkTargetStatus,
    /// The record-shape schema version that wrote this record (DR-0054 Phase
    /// B). Absent on records predating the stamp = version 1, the implicit
    /// original shape. Readers fail closed on a version newer than
    /// [`LIBRARY_RECORD_SCHEMA`].
    #[serde(default = "record_schema_v1")]
    pub schema: u32,
    /// Fields written by a build newer than this one, preserved verbatim so a
    /// read-modify-write here never drops them (DR-0054 Phase B).
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}

/// Placement eligibility is independent from the target's own grants.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PlacementTargetsRecord {
    pub placement_id: String,
    pub op: RecordOp,
    pub target_ids: Vec<String>,
    /// The record-shape schema version that wrote this record (DR-0054 Phase
    /// B). Absent on records predating the stamp = version 1, the implicit
    /// original shape. Readers fail closed on a version newer than
    /// [`LIBRARY_RECORD_SCHEMA`].
    #[serde(default = "record_schema_v1")]
    pub schema: u32,
    /// Fields written by a build newer than this one, preserved verbatim so a
    /// read-modify-write here never drops them (DR-0054 Phase B).
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}

/// The durable chat-specific binding. `basis` is always an exact native cut,
/// VCS revision, or folder fingerprint—not a mutable branch/path.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ChatTargetBindingRecord {
    pub chat_id: String,
    pub op: RecordOp,
    pub target_id: String,
    pub basis: String,
    pub path_scope: Vec<String>,
    pub capabilities: TargetCapabilities,
    /// The record-shape schema version that wrote this record (DR-0054 Phase
    /// B). Absent on records predating the stamp = version 1, the implicit
    /// original shape. Readers fail closed on a version newer than
    /// [`LIBRARY_RECORD_SCHEMA`].
    #[serde(default = "record_schema_v1")]
    pub schema: u32,
    /// Fields written by a build newer than this one, preserved verbatim so a
    /// read-modify-write here never drops them (DR-0054 Phase B).
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}

/// Target-scoped root for a named workstream.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct WorkstreamRootRecord {
    pub workstream_id: String,
    pub op: RecordOp,
    pub placement_id: String,
    pub target_id: String,
    pub adapter_family: String,
    /// The record-shape schema version that wrote this record (DR-0054 Phase
    /// B). Absent on records predating the stamp = version 1, the implicit
    /// original shape. Readers fail closed on a version newer than
    /// [`LIBRARY_RECORD_SCHEMA`].
    #[serde(default = "record_schema_v1")]
    pub schema: u32,
    /// Fields written by a build newer than this one, preserved verbatim so a
    /// read-modify-write here never drops them (DR-0054 Phase B).
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}

/// One node in the **fork forest** (`UX-8`): a chat plus its fork children, nested. A
/// derived projection (`INV-5`) over `ChatRecord.forked_from` — read-only, never stored.
#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
pub struct ForkNode {
    pub id: String,
    pub title: String,
    pub children: Vec<ForkNode>,
}

/// A **workstream** declaration (`WS-A`/`WS-E`): a named shared auto-sync line within
/// one placement (its `instance_id`). This record carries only the stream's *existence*
/// for nav — its name and where it lives. The authoritative status (`active`/`archived`)
/// and **membership** live in the per-workstream [`WorkstreamState`] reducer
/// (`gaugedesk_core::workstream`, scope = the workstream id), folded on demand; a chat's
/// homing is the in-memory [`gaugedesk_workspace::Engagement::target`] cache rebuilt from it.
///
/// [`WorkstreamState`]: gaugedesk_core::workstream::WorkstreamState
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct WorkstreamRecord {
    pub id: String,
    #[serde(default)]
    pub op: RecordOp,
    /// The placement (using-instance) this workstream's shared line lives in.
    pub instance_id: String,
    pub name: String,
    /// The library-scope position at creation — drives stable nav ordering.
    #[serde(default)]
    pub created_position: i64,
    /// The record-shape schema version that wrote this record (DR-0054 Phase
    /// B). Absent on records predating the stamp = version 1, the implicit
    /// original shape. Readers fail closed on a version newer than
    /// [`LIBRARY_RECORD_SCHEMA`].
    #[serde(default = "record_schema_v1")]
    pub schema: u32,
    /// Fields written by a build newer than this one, preserved verbatim so a
    /// read-modify-write here never drops them (DR-0054 Phase B).
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}

/// The immutable lineage half of a [`ChatRecord`], retained across deletion
/// (ADR 0141): a deleted ancestor's records are still part of its descendants'
/// effective logs, so effective-log resolution and deferred crypto-erasure
/// must be able to walk the fork tree after the listing tombstone.
#[derive(Clone, Debug, Default)]
pub struct ChatLineage {
    pub forked_from: Option<String>,
    pub forked_from_cut: Option<i64>,
}

/// The current value of every library record id, folded latest-wins. Held in
/// the `Workbench` and mutated in place on each write (never re-folded on the
/// hot path); rebuilt from the log on startup.
#[derive(Default, Clone)]
pub struct Library {
    pub agents: BTreeMap<String, AgentRecord>,
    pub projects: BTreeMap<String, ProjectRecord>,
    pub instances: BTreeMap<String, InstanceRecord>,
    pub public_deployments: BTreeMap<String, PublicDeploymentBindingRecord>,
    pub chats: BTreeMap<String, ChatRecord>,
    /// Fork lineage of every chat ever recorded, tombstones included (ADR 0141).
    pub chat_lineage: BTreeMap<String, ChatLineage>,
    pub workstreams: BTreeMap<String, WorkstreamRecord>,
    pub work_targets: BTreeMap<String, WorkTargetRecord>,
    pub placement_targets: BTreeMap<String, PlacementTargetsRecord>,
    pub chat_targets: BTreeMap<String, ChatTargetBindingRecord>,
    pub workstream_roots: BTreeMap<String, WorkstreamRootRecord>,
}

/// Apply one record to its map: `Tombstone` removes the id, `Upsert` sets it.
fn fold_one<T>(map: &mut BTreeMap<String, T>, id: &str, op: RecordOp, rec: T) {
    match op {
        RecordOp::Tombstone => {
            map.remove(id);
        }
        RecordOp::Upsert => {
            map.insert(id.to_string(), rec);
        }
    }
}

impl Library {
    /// Rebuild the projection by folding all library records in position order.
    pub fn rebuild(store: &Store) -> Result<Library, AdmitError> {
        let mut lib = Library::default();
        for row in store.records(LIBRARY_SCOPE, "agent")? {
            let r: AgentRecord = serde_json::from_str(&row)?;
            guard_record_schema("agent", &r.id, r.schema)?;
            fold_one(&mut lib.agents, &r.id.clone(), r.op, r);
        }
        for row in store.records(LIBRARY_SCOPE, "project")? {
            let r: ProjectRecord = serde_json::from_str(&row)?;
            guard_record_schema("project", &r.id, r.schema)?;
            fold_one(&mut lib.projects, &r.id.clone(), r.op, r);
        }
        for row in store.records(LIBRARY_SCOPE, "instance")? {
            let r: InstanceRecord = serde_json::from_str(&row)?;
            guard_record_schema("instance", &r.id, r.schema)?;
            fold_one(&mut lib.instances, &r.id.clone(), r.op, r);
        }
        for row in store.records(LIBRARY_SCOPE, "public_deployment_binding")? {
            let r: PublicDeploymentBindingRecord = serde_json::from_str(&row)?;
            guard_record_schema("public_deployment_binding", &r.id, r.schema)?;
            fold_one(&mut lib.public_deployments, &r.id.clone(), r.op, r);
        }
        for row in store.records(LIBRARY_SCOPE, "chat")? {
            let r: ChatRecord = serde_json::from_str(&row)?;
            guard_record_schema("chat", &r.id, r.schema)?;
            lib.apply_chat(r);
        }
        for row in store.records(LIBRARY_SCOPE, "workstream")? {
            let r: WorkstreamRecord = serde_json::from_str(&row)?;
            guard_record_schema("workstream", &r.id, r.schema)?;
            fold_one(&mut lib.workstreams, &r.id.clone(), r.op, r);
        }
        for row in store.records(LIBRARY_SCOPE, "work_target")? {
            let r: WorkTargetRecord = serde_json::from_str(&row)?;
            guard_record_schema("work_target", &r.id, r.schema)?;
            fold_one(&mut lib.work_targets, &r.id.clone(), r.op, r);
        }
        for row in store.records(LIBRARY_SCOPE, "placement_targets")? {
            let r: PlacementTargetsRecord = serde_json::from_str(&row)?;
            guard_record_schema("placement_targets", &r.placement_id, r.schema)?;
            fold_one(&mut lib.placement_targets, &r.placement_id.clone(), r.op, r);
        }
        for row in store.records(LIBRARY_SCOPE, "chat_target")? {
            let r: ChatTargetBindingRecord = serde_json::from_str(&row)?;
            guard_record_schema("chat_target", &r.chat_id, r.schema)?;
            fold_one(&mut lib.chat_targets, &r.chat_id.clone(), r.op, r);
        }
        for row in store.records(LIBRARY_SCOPE, "workstream_root")? {
            let r: WorkstreamRootRecord = serde_json::from_str(&row)?;
            guard_record_schema("workstream_root", &r.workstream_id, r.schema)?;
            fold_one(&mut lib.workstream_roots, &r.workstream_id.clone(), r.op, r);
        }
        Ok(lib)
    }

    /// First run: no agents declared yet (so we seed the default builder).
    pub fn is_empty(&self) -> bool {
        self.agents.is_empty() && self.projects.is_empty()
    }

    /// In-memory apply mirrors of the four kinds, so a route appends a record
    /// then updates the projection without re-folding.
    pub fn apply_agent(&mut self, r: AgentRecord) {
        fold_one(&mut self.agents, &r.id.clone(), r.op, r);
    }
    pub fn apply_project(&mut self, r: ProjectRecord) {
        fold_one(&mut self.projects, &r.id.clone(), r.op, r);
    }

    pub fn project_home_id(&self, project_id: &str) -> Option<&HomeId> {
        self.projects
            .get(project_id)
            .map(|project| &project.home_id)
    }
    pub fn apply_instance(&mut self, r: InstanceRecord) {
        fold_one(&mut self.instances, &r.id.clone(), r.op, r);
    }
    pub fn apply_public_deployment(&mut self, r: PublicDeploymentBindingRecord) {
        fold_one(&mut self.public_deployments, &r.id.clone(), r.op, r);
    }
    pub fn apply_chat(&mut self, r: ChatRecord) {
        // Lineage survives the tombstone (ADR 0141): op-independent, and a
        // rename's read-modify-write carries the same immutable fields.
        self.chat_lineage.insert(
            r.id.clone(),
            ChatLineage {
                forked_from: r.forked_from.clone(),
                forked_from_cut: r.forked_from_cut,
            },
        );
        fold_one(&mut self.chats, &r.id.clone(), r.op, r);
    }
    pub fn apply_workstream(&mut self, r: WorkstreamRecord) {
        fold_one(&mut self.workstreams, &r.id.clone(), r.op, r);
    }
    pub fn apply_work_target(&mut self, r: WorkTargetRecord) {
        fold_one(&mut self.work_targets, &r.id.clone(), r.op, r);
    }
    pub fn apply_placement_targets(&mut self, r: PlacementTargetsRecord) {
        fold_one(
            &mut self.placement_targets,
            &r.placement_id.clone(),
            r.op,
            r,
        );
    }
    pub fn apply_chat_target(&mut self, r: ChatTargetBindingRecord) {
        fold_one(&mut self.chat_targets, &r.chat_id.clone(), r.op, r);
    }
    pub fn apply_workstream_root(&mut self, r: WorkstreamRootRecord) {
        fold_one(
            &mut self.workstream_roots,
            &r.workstream_id.clone(),
            r.op,
            r,
        );
    }

    pub fn target_for_chat(&self, chat_id: &str) -> Option<&WorkTargetRecord> {
        self.chat_targets
            .get(chat_id)
            .and_then(|binding| self.work_targets.get(&binding.target_id))
    }

    pub fn targets_for_project(&self, project_id: &str) -> Vec<&WorkTargetRecord> {
        self.work_targets
            .values()
            .filter(|target| {
                matches!(
                    &target.owner,
                    WorkTargetOwner::Project { project_id: owner } if owner == project_id
                )
            })
            .collect()
    }

    pub fn authoring_target_for(&self, archetype_id: &str) -> Option<&WorkTargetRecord> {
        self.work_targets.values().find(|target| {
            matches!(
                &target.owner,
                WorkTargetOwner::Archetype { archetype_id: owner } if owner == archetype_id
            )
        })
    }

    /// The deployment mode (`DEPLOY-1`) the consultant declared for `project_id` — the
    /// boundary `declareCeiling` input for engagements on it — or the **local default**
    /// (`Placement::local`) when unset or the project is unknown (fail-safe to the
    /// least-privileged placement).
    pub fn deployment_mode_of(&self, project_id: &str) -> Placement {
        self.projects
            .get(project_id)
            .and_then(|p| p.deployment_mode)
            .unwrap_or_else(Placement::local)
    }

    /// The archetype version a placement (using-instance) runs, and its archetype's current
    /// published version (`UX-9`, [ADR 0063]) — `None` if the instance/agent is unknown.
    pub fn placement_versions(&self, instance_id: &str) -> Option<(u64, u64)> {
        let inst = self.instances.get(instance_id)?;
        let agent = self.agents.get(&inst.agent_id)?;
        Some((inst.version, agent.current_version))
    }

    /// Whether a placement has an archetype **upgrade available** (`UX-9`): its version is
    /// behind the archetype's current published version. Fail-safe `false` when unknown.
    pub fn upgrade_available(&self, instance_id: &str) -> bool {
        self.placement_versions(instance_id)
            .map(|(on, current)| on < current)
            .unwrap_or(false)
    }

    /// Live (non-tombstoned) workstreams in a placement, stable order.
    pub fn workstreams_in(&self, instance_id: &str) -> Vec<&WorkstreamRecord> {
        let mut v: Vec<&WorkstreamRecord> = self
            .workstreams
            .values()
            .filter(|w| w.instance_id == instance_id)
            .collect();
        v.sort_by_key(|w| w.created_position);
        v
    }

    /// Live (non-tombstoned) chats in an instance.
    pub fn chats_in(&self, instance_id: &str) -> Vec<&ChatRecord> {
        let mut v: Vec<&ChatRecord> = self
            .chats
            .values()
            .filter(|c| c.instance_id == instance_id)
            .collect();
        v.sort_by_key(|c| c.created_position);
        v
    }

    /// The **fork forest** (`UX-8`): chats form a fork tree via `forked_from` (ADR 0038);
    /// this projects the live chats into nested roots → children. A root is a chat with no
    /// `forked_from`, or one whose parent is gone (an orphaned fork still surfaces). Pure,
    /// stable order (created-position), depth-guarded against any pathological cycle.
    pub fn fork_forest(&self) -> Vec<ForkNode> {
        let mut roots: Vec<&ChatRecord> = self
            .chats
            .values()
            .filter(|c| {
                c.forked_from
                    .as_ref()
                    .is_none_or(|f| !self.chats.contains_key(f))
            })
            .collect();
        roots.sort_by_key(|c| c.created_position);
        roots.into_iter().map(|c| self.fork_node(c, 64)).collect()
    }

    fn fork_node(&self, c: &ChatRecord, depth: usize) -> ForkNode {
        let children = if depth == 0 {
            Vec::new()
        } else {
            let mut kids: Vec<&ChatRecord> = self
                .chats
                .values()
                .filter(|k| k.forked_from.as_deref() == Some(c.id.as_str()))
                .collect();
            kids.sort_by_key(|k| k.created_position);
            kids.into_iter()
                .map(|k| self.fork_node(k, depth - 1))
                .collect()
        };
        ForkNode {
            id: c.id.clone(),
            title: c.title.clone(),
            children,
        }
    }

    /// All live chats across a **project's** placements (`UX-2`): the union of `chats_in` over
    /// the project's using-instances, **most-recent-first** (`created_position` desc; tie-break
    /// by id). The work chats whose lifecycle scopes the project-home rollup folds.
    pub fn project_chats(&self, project_id: &str) -> Vec<&ChatRecord> {
        let mut v: Vec<&ChatRecord> = self
            .using_instances_of(project_id)
            .into_iter()
            .flat_map(|i| self.chats_in(&i.id))
            .collect();
        v.sort_by(|a, b| {
            b.created_position
                .cmp(&a.created_position)
                .then_with(|| a.id.cmp(&b.id))
        });
        v
    }

    /// The network egress posture for a chat, resolved through its placement to
    /// its project (chat → instance → `project_id` → project). Defaults to **open**
    /// (`false`) when any hop is missing — an authoring/edit chat with no project or
    /// an unknown id — so the app's open-by-default
    /// posture holds and only an explicit per-project opt-in isolates.
    pub fn chat_network_isolated(&self, chat_id: &str) -> bool {
        self.chats
            .get(chat_id)
            .and_then(|c| self.instances.get(&c.instance_id))
            .and_then(|i| i.project_id.as_deref())
            .and_then(|pid| self.projects.get(pid))
            .map(|p| p.network_isolated)
            .unwrap_or(false)
    }

    pub fn chat_run_purpose(&self, chat_id: &str) -> Option<&str> {
        self.chats
            .get(chat_id)
            .and_then(|chat| self.instances.get(&chat.instance_id))
            .and_then(|instance| instance.project_id.as_deref())
            .and_then(|project_id| self.projects.get(project_id))
            .and_then(|project| project.run_purpose.as_deref())
    }

    /// The project a chat belongs to (`ENTSEC-2`): chat → its instance → the instance's
    /// `project_id`. `None` for an edit/authoring chat (no project), or any unknown id — the
    /// per-project scope gate then does not apply (the route is governed by membership alone).
    pub fn project_of_chat(&self, chat_id: &str) -> Option<&str> {
        self.chats
            .get(chat_id)
            .and_then(|c| self.instances.get(&c.instance_id))
            .and_then(|i| i.project_id.as_deref())
    }

    /// The project a using-instance (placement) is bound into (`ENTSEC-2`): its `project_id`.
    /// `None` for an archetype authoring root or an unknown id.
    pub fn project_of_instance(&self, instance_id: &str) -> Option<&str> {
        self.instances
            .get(instance_id)
            .and_then(|i| i.project_id.as_deref())
    }
    /// The using-instances bound into a project.
    pub fn using_instances_of(&self, project_id: &str) -> Vec<&InstanceRecord> {
        let mut v: Vec<&InstanceRecord> = self
            .instances
            .values()
            .filter(|i| {
                i.kind == InstanceKind::Using && i.project_id.as_deref() == Some(project_id)
            })
            .collect();
        v.sort_by(|a, b| a.id.cmp(&b.id));
        v
    }
}

/// The honest confidentiality ceiling of a boundary, as the API surfaces it
/// (ATTEST-14). Derived from the declared [`Placement`] and the attestation
/// evidence collected at acceptance — never asserted, always read back from the
/// reducer state so the value the client sees is the value the gate enforces.
///
/// `host_blind` is the one bit a client must trust: it is `true` *only* when the
/// placement is attested **and** every required participant presented trustworthy
/// [`AttestationEvidence`] (a verified quote over the very measurement it claimed,
/// `AttestationEvidence::is_trustworthy`). An attested placement whose evidence is
/// missing or failed verification is honestly reported as *not* host-blind: the
/// ceiling claim degrades to the unattested case rather than over-promising.
///
/// [`Placement`]: gaugedesk_core::boundary_lifecycle::Placement
/// [`AttestationEvidence`]: gaugedesk_core::attestation::AttestationEvidence
#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
pub struct BoundaryProjection {
    pub phase: BoundaryPhase,
    /// `true` once the boundary is live (declared + every participant accepted).
    pub active: bool,
    /// `Some` once a ceiling is declared: who operates the host.
    pub operator: Option<Operator>,
    /// Whether the *declared* placement claims attested (TEE) execution.
    pub attested: bool,
    /// The honest ceiling: is the method hidden from the host? `true` only when
    /// attested **and** the collected evidence verifies (see type docs).
    pub host_blind: bool,
    /// A one-line, client-facing description of the ceiling.
    pub ceiling_description: String,
}

impl BoundaryProjection {
    /// Project a [`BoundaryState`] into the client-facing ceiling view (ATTEST-14).
    pub fn from_state(state: &BoundaryState) -> BoundaryProjection {
        let placement = state.placement;
        let attested = placement.map(|p| p.attested).unwrap_or(false);
        // host_blind is the honest ceiling, not the declared claim: an attested
        // placement is host-blind only once every required participant has
        // presented trustworthy evidence. Missing/failed evidence degrades the
        // claim rather than over-promising (the value the key-release gate, ATTEST-5,
        // also enforces).
        let evidence_complete = attested
            && !state.required.is_empty()
            && state.required.iter().all(|p| {
                state
                    .attestation_evidence
                    .get(p)
                    .map(|e| e.is_trustworthy())
                    .unwrap_or(false)
            });
        let host_blind = attested && evidence_complete;
        let operator = placement.map(|p| p.operator);
        let ceiling_description = match placement {
            None => "ceiling not yet declared".to_string(),
            Some(p) => {
                let host = match p.operator {
                    Operator::Local => "a host you operate",
                    Operator::Counterparty => "the counterparty's host",
                    Operator::Neutral => "a neutral third-party host",
                };
                if host_blind {
                    format!("host-blind: the method stays sealed from {host} (attested)")
                } else if attested {
                    // Declared attested but evidence is not (yet) complete/trustworthy.
                    format!("attestation pending: {host} could see the method until every party's quote verifies")
                } else {
                    format!("host-visible: the method is in plaintext to {host} (unattested)")
                }
            }
        };
        BoundaryProjection {
            phase: state.phase,
            active: state.active(),
            operator,
            attested,
            host_blind,
            ceiling_description,
        }
    }
}

/// Mint a globally-unique id: `prefix-<12 hex>`. Server-generated so chat ids
/// never collide across instances (the property the whole flat-map design rests
/// on).
pub fn gen_id(prefix: &str) -> String {
    let mut bytes = [0u8; 6];
    getrandom::getrandom(&mut bytes).expect("os rng");
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    format!("{prefix}-{hex}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn panel_default_uses_the_openai_responses_origin() {
        let profile = PanelPublicProfile::default();
        assert_eq!(profile.provider.provider, "openai");
        assert_eq!(profile.provider.base_url, "https://api.openai.com");
    }

    #[test]
    fn anonymous_deployment_audience_omits_an_absent_oidc_provider() {
        let value = serde_json::to_value(DeploymentAudience::default()).unwrap();
        assert_eq!(value, serde_json::json!({ "anonymous_allowed": true }));
    }

    #[test]
    fn chat_mode_serializes_as_edit_and_reads_the_legacy_build_value() {
        // The mode renamed build→edit; records persisted before the rename store
        // "build" and must still deserialize (serde alias), so existing chats load.
        assert_eq!(serde_json::to_string(&ChatMode::Edit).unwrap(), "\"edit\"");
        assert_eq!(
            serde_json::from_str::<ChatMode>("\"edit\"").unwrap(),
            ChatMode::Edit
        );
        assert_eq!(
            serde_json::from_str::<ChatMode>("\"build\"").unwrap(),
            ChatMode::Edit
        );
        assert_eq!(
            serde_json::from_str::<ChatMode>("\"use\"").unwrap(),
            ChatMode::Use
        );
    }

    #[test]
    fn agent_reads_records_written_before_version_bindings() {
        let record: AgentRecord =
            serde_json::from_str(r#"{"id":"a1","name":"Legacy","instance_id":"inst-a1"}"#).unwrap();
        assert_eq!(record.current_version, 1);
        assert!(record.versions.is_empty());
        assert_eq!(record.schema, 1, "a pre-stamp record reads as version 1");
        assert!(record.extra.is_empty());
        assert_eq!(record.agent_kind, AgentKind::Work);
        assert!(record.panel_profile.is_none());
    }

    #[test]
    fn placement_reads_records_written_before_panel_kinds_as_work() {
        let record: InstanceRecord =
            serde_json::from_str(r#"{"id":"i1","kind":"using","agent_id":"a1"}"#).unwrap();
        assert_eq!(record.placement_kind, PlacementKind::Work);
        assert!(record.collection_recipient.is_none());
    }

    /// DR-0054 Phase B: a record stamped by a newer build (schema ahead of this
    /// one) must fail the rebuild closed with a diagnosable error — not be
    /// skipped, misread, or answered with a reset instruction.
    #[test]
    fn a_newer_schema_record_fails_rebuild_with_a_diagnosable_error() {
        let mut store = Store::open_in_memory().unwrap();
        agent(&mut store, "a-ok", RecordOp::Upsert, "fine");
        store
            .append_record(
                LIBRARY_SCOPE,
                "agent",
                r#"{"id":"a-future","name":"From the future","instance_id":"inst","schema":999}"#,
            )
            .unwrap();
        let error = match Library::rebuild(&store) {
            Ok(_) => panic!("a newer-schema record must fail the rebuild closed"),
            Err(error) => error,
        };
        match error {
            AdmitError::UnsupportedSchema(message) => {
                assert!(
                    message.contains("a-future") && message.contains("999"),
                    "the error names the record and its version: {message}"
                );
                assert!(
                    message.contains("do not reset"),
                    "the remediation is a newer build, never a reset: {message}"
                );
            }
            other => panic!("expected UnsupportedSchema, got {other:?}"),
        }
    }

    /// DR-0054 Phase B: fields this build does not recognize round-trip through
    /// a load-modify-save cycle via `extra` instead of being silently dropped —
    /// an older build's rewrite no longer destroys a newer build's data.
    #[test]
    fn unknown_fields_survive_a_load_modify_save_cycle() {
        let mut store = Store::open_in_memory().unwrap();
        store
            .append_record(
                LIBRARY_SCOPE,
                "agent",
                r#"{"id":"a1","name":"original","instance_id":"inst",
                    "future_field":{"nested":true},"schema":1}"#,
            )
            .unwrap();
        let lib = Library::rebuild(&store).unwrap();
        let mut record = lib.agents.get("a1").unwrap().clone();
        assert_eq!(
            record.extra.get("future_field"),
            Some(&serde_json::json!({"nested": true})),
            "the unrecognized field was captured, not dropped"
        );

        // The read-modify-write an older build performs: rename, save back.
        record.name = "renamed".into();
        let rewritten = serde_json::to_string(&record).unwrap();
        store
            .append_record(LIBRARY_SCOPE, "agent", &rewritten)
            .unwrap();

        let lib = Library::rebuild(&store).unwrap();
        let record = lib.agents.get("a1").unwrap();
        assert_eq!(record.name, "renamed");
        assert_eq!(record.schema, 1, "the write carries its schema stamp");
        assert_eq!(
            record.extra.get("future_field"),
            Some(&serde_json::json!({"nested": true})),
            "the unrecognized field survived the rewrite"
        );
        // And the persisted JSON itself still carries both.
        let value: serde_json::Value = serde_json::from_str(&rewritten).unwrap();
        assert_eq!(value["schema"], 1);
        assert_eq!(value["future_field"], serde_json::json!({"nested": true}));
    }

    fn agent(store: &mut Store, id: &str, op: RecordOp, name: &str) {
        let r = AgentRecord {
            schema: LIBRARY_RECORD_SCHEMA,
            extra: Default::default(),
            id: id.into(),
            op,
            name: name.into(),
            agent_kind: AgentKind::Work,
            panel_profile: None,
            instance_id: format!("inst-{id}"),
            config: "{}".into(),
            current_version: 1,
            versions: BTreeMap::new(),
            auto_upgrade: false,
            forked_from: None,
        };
        store
            .append_record(LIBRARY_SCOPE, "agent", &serde_json::to_string(&r).unwrap())
            .unwrap();
    }

    #[test]
    fn chat_network_posture_resolves_through_project_and_defaults_open() {
        // chat → instance → project. The app default is OPEN (false); only an
        // explicit per-project opt-in isolates. Build the projection by hand.
        let mut lib = Library::default();
        lib.apply_project(ProjectRecord {
            schema: LIBRARY_RECORD_SCHEMA,
            extra: Default::default(),
            id: "p-iso".into(),
            op: RecordOp::Upsert,
            name: "Locked".into(),
            is_default: false,
            home_id: HomeId::new("home:local-user"),
            network_isolated: true,
            run_purpose: None,
            deployment_mode: None,
        });
        lib.apply_project(ProjectRecord {
            schema: LIBRARY_RECORD_SCHEMA,
            extra: Default::default(),
            id: "p-open".into(),
            op: RecordOp::Upsert,
            name: "Open".into(),
            is_default: false,
            home_id: HomeId::new("home:local-user"),
            network_isolated: false,
            run_purpose: Some("support".to_owned()),
            deployment_mode: None,
        });
        let bind = |lib: &mut Library, inst: &str, project: Option<&str>| {
            lib.apply_instance(InstanceRecord {
                schema: LIBRARY_RECORD_SCHEMA,
                extra: Default::default(),
                id: inst.into(),
                op: RecordOp::Upsert,
                kind: InstanceKind::Using,
                placement_kind: PlacementKind::Work,
                agent_id: "a1".into(),
                project_id: project.map(str::to_string),
                version: 1,
                admission: Admission::Active,
                collection_recipient: None,
            });
        };
        let chat = |lib: &mut Library, id: &str, inst: &str| {
            lib.apply_chat(ChatRecord {
                schema: LIBRARY_RECORD_SCHEMA,
                extra: Default::default(),
                id: id.into(),
                op: RecordOp::Upsert,
                instance_id: inst.into(),
                title: id.into(),
                created_position: 0,
                forked_from: None,
                forked_from_entry: None,
                forked_from_cut: None,
            });
        };
        bind(&mut lib, "i-iso", Some("p-iso"));
        bind(&mut lib, "i-open", Some("p-open"));
        bind(&mut lib, "i-authoring", None); // an edit chat's instance — no project

        chat(&mut lib, "c-iso", "i-iso");
        chat(&mut lib, "c-open", "i-open");
        chat(&mut lib, "c-edit", "i-authoring");

        assert!(
            lib.chat_network_isolated("c-iso"),
            "isolated project isolates"
        );
        assert!(
            !lib.chat_network_isolated("c-open"),
            "open project stays open"
        );
        assert!(
            !lib.chat_network_isolated("c-edit"),
            "no project ⇒ open default"
        );
        assert!(
            !lib.chat_network_isolated("c-missing"),
            "unknown chat ⇒ open default"
        );
        assert_eq!(lib.chat_run_purpose("c-open"), Some("support"));
        assert_eq!(lib.chat_run_purpose("c-edit"), None);
    }

    #[test]
    fn project_of_chat_and_instance_resolve_or_none() {
        // ENTSEC-2: chat → instance → project; None for an authoring chat / unknown id.
        let mut lib = Library::default();
        lib.apply_instance(InstanceRecord {
            schema: LIBRARY_RECORD_SCHEMA,
            extra: Default::default(),
            id: "i-using".into(),
            op: RecordOp::Upsert,
            kind: InstanceKind::Using,
            placement_kind: PlacementKind::Work,
            agent_id: "a1".into(),
            project_id: Some("proj-acme".into()),
            version: 1,
            admission: Admission::Active,
            collection_recipient: None,
        });
        lib.apply_instance(InstanceRecord {
            schema: LIBRARY_RECORD_SCHEMA,
            extra: Default::default(),
            id: "i-authoring".into(),
            op: RecordOp::Upsert,
            kind: InstanceKind::Authoring,
            placement_kind: PlacementKind::Work,
            agent_id: "a1".into(),
            project_id: None,
            version: 1,
            admission: Admission::Active,
            collection_recipient: None,
        });
        let chat = |lib: &mut Library, id: &str, inst: &str| {
            lib.apply_chat(ChatRecord {
                schema: LIBRARY_RECORD_SCHEMA,
                extra: Default::default(),
                id: id.into(),
                op: RecordOp::Upsert,
                instance_id: inst.into(),
                title: id.into(),
                created_position: 0,
                forked_from: None,
                forked_from_entry: None,
                forked_from_cut: None,
            });
        };
        chat(&mut lib, "c-work", "i-using");
        chat(&mut lib, "c-edit", "i-authoring");

        assert_eq!(lib.project_of_chat("c-work"), Some("proj-acme"));
        assert_eq!(lib.project_of_chat("c-edit"), None); // authoring chat, no project
        assert_eq!(lib.project_of_chat("c-missing"), None); // unknown chat
        assert_eq!(lib.project_of_instance("i-using"), Some("proj-acme"));
        assert_eq!(lib.project_of_instance("i-authoring"), None);
        assert_eq!(lib.project_of_instance("i-missing"), None);
    }

    #[test]
    fn fork_forest_nests_chats_by_forked_from() {
        let mut lib = Library::default();
        let chat = |id: &str, pos: i64, from: Option<&str>| ChatRecord {
            schema: LIBRARY_RECORD_SCHEMA,
            extra: Default::default(),
            id: id.into(),
            op: RecordOp::Upsert,
            instance_id: "p1".into(),
            title: format!("title {id}"),
            created_position: pos,
            forked_from: from.map(str::to_string),
            forked_from_entry: None,
            forked_from_cut: None,
        };
        // c1 (root) → c2 → c3 ; c4 (root) ; c5 forked from a missing parent ⇒ surfaces as root.
        lib.apply_chat(chat("c1", 1, None));
        lib.apply_chat(chat("c2", 2, Some("c1")));
        lib.apply_chat(chat("c3", 3, Some("c2")));
        lib.apply_chat(chat("c4", 4, None));
        lib.apply_chat(chat("c5", 5, Some("gone")));

        let forest = lib.fork_forest();
        let roots: Vec<&str> = forest.iter().map(|n| n.id.as_str()).collect();
        assert_eq!(
            roots,
            vec!["c1", "c4", "c5"],
            "roots in created order, orphan surfaces"
        );

        let c1 = &forest[0];
        assert_eq!(c1.children.len(), 1);
        assert_eq!(c1.children[0].id, "c2");
        assert_eq!(c1.children[0].children[0].id, "c3"); // nested two deep
        assert!(forest[1].children.is_empty()); // c4 has no forks
    }

    #[test]
    fn deployment_mode_defaults_to_local_and_resolves_when_set() {
        let mut lib = Library::default();
        // Unset ⇒ the local default (least-privileged placement).
        lib.apply_project(ProjectRecord {
            schema: LIBRARY_RECORD_SCHEMA,
            extra: Default::default(),
            id: "p-default".into(),
            op: RecordOp::Upsert,
            name: "Default".into(),
            is_default: false,
            home_id: HomeId::new("home:local-user"),
            network_isolated: false,
            run_purpose: None,
            deployment_mode: None,
        });
        assert_eq!(lib.deployment_mode_of("p-default"), Placement::local());
        // Unknown project ⇒ also the local default (fail-safe).
        assert_eq!(lib.deployment_mode_of("p-missing"), Placement::local());
        // An explicitly-declared counterparty-attested mode resolves through.
        let mode = Placement {
            operator: Operator::Counterparty,
            attested: true,
        };
        lib.apply_project(ProjectRecord {
            schema: LIBRARY_RECORD_SCHEMA,
            extra: Default::default(),
            id: "p-attested".into(),
            op: RecordOp::Upsert,
            name: "Attested".into(),
            is_default: false,
            home_id: HomeId::new("home:local-user"),
            network_isolated: false,
            run_purpose: None,
            deployment_mode: Some(mode),
        });
        assert_eq!(lib.deployment_mode_of("p-attested"), mode);
    }

    #[test]
    fn folds_latest_wins_and_tombstones_disappear() {
        let mut store = Store::open_in_memory().unwrap();
        agent(&mut store, "a1", RecordOp::Upsert, "first");
        agent(&mut store, "a1", RecordOp::Upsert, "renamed"); // rename = newer upsert
        agent(&mut store, "a2", RecordOp::Upsert, "keep");
        agent(&mut store, "a2", RecordOp::Tombstone, "keep"); // delete a2

        let lib = Library::rebuild(&store).unwrap();
        assert_eq!(lib.agents.len(), 1);
        assert_eq!(lib.agents.get("a1").unwrap().name, "renamed");
        assert!(!lib.agents.contains_key("a2"), "tombstoned agent is gone");
    }

    #[test]
    fn created_position_orders_chats_and_using_instances_filter_by_project() {
        let mut store = Store::open_in_memory().unwrap();
        let mut lib = Library::default();
        for (id, pos) in [("chat-b", 5), ("chat-a", 2)] {
            let c = ChatRecord {
                schema: LIBRARY_RECORD_SCHEMA,
                extra: Default::default(),
                id: id.into(),
                op: RecordOp::Upsert,
                instance_id: "inst-1".into(),
                title: id.into(),
                created_position: pos,
                forked_from: None,
                forked_from_entry: None,
                forked_from_cut: None,
            };
            store
                .append_record(LIBRARY_SCOPE, "chat", &serde_json::to_string(&c).unwrap())
                .unwrap();
            lib.apply_chat(c);
        }
        let ordered: Vec<&str> = lib
            .chats_in("inst-1")
            .iter()
            .map(|c| c.id.as_str())
            .collect();
        assert_eq!(
            ordered,
            vec!["chat-a", "chat-b"],
            "sorted by created_position"
        );

        lib.apply_instance(InstanceRecord {
            schema: LIBRARY_RECORD_SCHEMA,
            extra: Default::default(),
            id: "inst-u".into(),
            op: RecordOp::Upsert,
            kind: InstanceKind::Using,
            placement_kind: PlacementKind::Work,
            agent_id: "a1".into(),
            project_id: Some("proj-1".into()),
            version: 1,
            admission: Admission::Active,
            collection_recipient: None,
        });
        assert_eq!(lib.using_instances_of("proj-1").len(), 1);
        assert_eq!(lib.using_instances_of("proj-other").len(), 0);
    }

    #[test]
    fn project_chats_unions_placements_most_recent_first() {
        // UX-2: project_chats gathers chats across ALL the project's using-instances, newest
        // first, and is empty for an unknown project.
        let mut lib = Library::default();
        for (iid, pid) in [
            ("inst-x", "proj-1"),
            ("inst-y", "proj-1"),
            ("inst-z", "proj-2"),
        ] {
            lib.apply_instance(InstanceRecord {
                schema: LIBRARY_RECORD_SCHEMA,
                extra: Default::default(),
                id: iid.into(),
                op: RecordOp::Upsert,
                kind: InstanceKind::Using,
                placement_kind: PlacementKind::Work,
                agent_id: "a1".into(),
                project_id: Some(pid.into()),
                version: 1,
                admission: Admission::Active,
                collection_recipient: None,
            });
        }
        for (id, iid, pos) in [
            ("chat-old", "inst-x", 1),
            ("chat-new", "inst-y", 9),
            ("chat-mid", "inst-x", 4),
            ("chat-other", "inst-z", 7), // proj-2 — must not appear in proj-1's rollup
        ] {
            lib.apply_chat(ChatRecord {
                schema: LIBRARY_RECORD_SCHEMA,
                extra: Default::default(),
                id: id.into(),
                op: RecordOp::Upsert,
                instance_id: iid.into(),
                title: id.into(),
                created_position: pos,
                forked_from: None,
                forked_from_entry: None,
                forked_from_cut: None,
            });
        }
        let ids: Vec<&str> = lib
            .project_chats("proj-1")
            .iter()
            .map(|c| c.id.as_str())
            .collect();
        assert_eq!(
            ids,
            vec!["chat-new", "chat-mid", "chat-old"],
            "all proj-1 chats, newest first"
        );
        assert!(lib.project_chats("proj-unknown").is_empty());
    }

    #[test]
    fn gen_id_is_prefixed_and_unique() {
        let a = gen_id("chat");
        let b = gen_id("chat");
        assert!(a.starts_with("chat-") && a.len() == 17);
        assert_ne!(a, b);
    }

    mod ceiling_description {
        use super::super::*;
        use gaugedesk_core::attestation::{
            AttestationEvidence, AttestationQuote, CodeMeasurement, QuoteRejection,
            QuoteVerificationResult,
        };
        use gaugedesk_core::boundary_lifecycle::{
            decide, evolve, BoundaryCommand, BoundaryState, Operator, Placement,
        };

        /// Drive one command through the reducer (decide → evolve), as the store
        /// does — admitting only valid transitions (a rejection is a no-op).
        fn apply(state: &BoundaryState, command: BoundaryCommand) -> BoundaryState {
            match decide(state, command) {
                Ok(events) => events.into_iter().fold(state.clone(), |s, e| evolve(&s, e)),
                Err(_) => state.clone(),
            }
        }

        fn measurement() -> CodeMeasurement {
            CodeMeasurement::new("a".repeat(64))
        }

        /// Evidence that verifies the measurement it claims (trustworthy).
        fn good_evidence() -> AttestationEvidence {
            AttestationEvidence::new(
                AttestationQuote::new(measurement(), "nonce", vec![1, 2, 3]),
                QuoteVerificationResult::Verified {
                    measurement: measurement(),
                },
            )
        }

        /// Evidence carrying a rejected verdict (not trustworthy).
        fn bad_evidence() -> AttestationEvidence {
            AttestationEvidence::new(
                AttestationQuote::new(measurement(), "nonce", vec![1, 2, 3]),
                QuoteVerificationResult::Rejected {
                    reason: QuoteRejection::StaleNonce,
                },
            )
        }

        /// Drive a boundary to active via the reducer, declaring `placement` and
        /// accepting each participant with the given evidence.
        fn active_boundary(
            placement: Placement,
            participants: &[(&str, Option<AttestationEvidence>)],
        ) -> BoundaryState {
            let names = participants.iter().map(|(p, _)| p.to_string()).collect();
            let mut s = apply(&BoundaryState::default(), BoundaryCommand::Propose(names));
            s = apply(&s, BoundaryCommand::DeclareCeiling(placement));
            for (p, ev) in participants {
                s = apply(
                    &s,
                    BoundaryCommand::Accept {
                        participant: (*p).into(),
                        evidence: ev.clone(),
                    },
                );
            }
            s
        }

        #[test]
        fn undeclared_boundary_has_no_ceiling() {
            let proj = BoundaryProjection::from_state(&BoundaryState::default());
            assert!(!proj.attested && !proj.host_blind && proj.operator.is_none());
            assert_eq!(proj.ceiling_description, "ceiling not yet declared");
        }

        #[test]
        fn unattested_placement_is_host_visible() {
            let s = active_boundary(
                Placement {
                    operator: Operator::Counterparty,
                    attested: false,
                },
                &[("expert", None)],
            );
            let proj = BoundaryProjection::from_state(&s);
            assert!(proj.active && !proj.attested && !proj.host_blind);
            assert_eq!(proj.operator, Some(Operator::Counterparty));
            assert!(
                proj.ceiling_description.contains("host-visible")
                    && proj.ceiling_description.contains("counterparty"),
                "{}",
                proj.ceiling_description
            );
        }

        #[test]
        fn attested_with_trustworthy_evidence_is_host_blind() {
            let s = active_boundary(
                Placement {
                    operator: Operator::Counterparty,
                    attested: true,
                },
                &[("expert", Some(good_evidence()))],
            );
            let proj = BoundaryProjection::from_state(&s);
            assert!(proj.active && proj.attested && proj.host_blind);
            assert!(
                proj.ceiling_description.starts_with("host-blind"),
                "{}",
                proj.ceiling_description
            );
        }

        /// An attested placement whose evidence failed verification must NOT be
        /// reported host-blind — the projection degrades the claim honestly so the
        /// client never sees a stronger ceiling than the key-release gate enforces.
        #[test]
        fn attested_with_untrustworthy_evidence_is_not_host_blind() {
            let s = active_boundary(
                Placement {
                    operator: Operator::Neutral,
                    attested: true,
                },
                &[("expert", Some(bad_evidence()))],
            );
            let proj = BoundaryProjection::from_state(&s);
            assert!(proj.attested && !proj.host_blind);
            assert!(
                proj.ceiling_description.starts_with("attestation pending"),
                "{}",
                proj.ceiling_description
            );
        }

        /// Two required participants but only one presented trustworthy evidence:
        /// the ceiling is not yet host-blind (every party's quote must verify).
        #[test]
        fn attested_is_not_host_blind_until_every_participant_verifies() {
            // Declared + one of two accepted (still in Declared phase, not active).
            let s = active_boundary(
                Placement {
                    operator: Operator::Counterparty,
                    attested: true,
                },
                &[("expert", Some(good_evidence()))],
            );
            // `expert` accepted; `client` has not — drive a second required party in.
            let mut required = s.required.clone();
            required.insert("client".to_string());
            let mut s = apply(
                &BoundaryState::default(),
                BoundaryCommand::Propose(required),
            );
            s = apply(
                &s,
                BoundaryCommand::DeclareCeiling(Placement {
                    operator: Operator::Counterparty,
                    attested: true,
                }),
            );
            s = apply(
                &s,
                BoundaryCommand::Accept {
                    participant: "expert".into(),
                    evidence: Some(good_evidence()),
                },
            );
            let proj = BoundaryProjection::from_state(&s);
            assert!(
                proj.attested && !proj.host_blind,
                "client has not attested yet"
            );
            assert!(proj.ceiling_description.starts_with("attestation pending"));
        }
    }
}
