//! Durable settle-time facts for one chat turn (ATTN-1, ADR 0082 §1).
//!
//! The engine computes these facts once, while it owns the runtime outcome and
//! workspace. Read-side projections only fold the latest record; they never walk
//! git, inspect labels, or reinterpret a runtime flow signature.

use gaugewright_core::resource::ResourceId;
use gaugewright_store::{AdmitError, Store};

pub const TURN_SUMMARY_KIND: &str = "turn_summary";

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptStatus {
    #[default]
    Completed,
    Failed,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyDiffDirection {
    #[default]
    None,
    Loosens,
    Tightens,
    Mixed,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CertifiedRead {
    pub resource_id: String,
    #[serde(default)]
    pub stakeholders: Vec<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TurnSummary {
    /// Position of the user transcript entry that began this attempt. This is
    /// the stable coordinate a future projection can compare with later speech.
    pub user_entry_id: i64,
    #[serde(default)]
    pub receipt_status: ReceiptStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default)]
    pub changed_paths: Vec<String>,
    #[serde(default)]
    pub changed_count: usize,
    #[serde(default)]
    pub policy_diff_direction: PolicyDiffDirection,
    #[serde(default)]
    pub certified_reads: Vec<CertifiedRead>,
}

pub fn append(store: &mut Store, scope: &str, summary: &TurnSummary) -> Result<i64, AdmitError> {
    let payload = serde_json::to_string(summary)?;
    store.append_record(scope, TURN_SUMMARY_KIND, &payload)
}

/// Latest-wins fold over the append-only settle records.
pub fn latest(store: &Store, scope: &str) -> Result<Option<TurnSummary>, AdmitError> {
    store
        .records(scope, TURN_SUMMARY_KIND)?
        .into_iter()
        .next_back()
        .map(|payload| serde_json::from_str(&payload).map_err(AdmitError::Json))
        .transpose()
}

/// Join runtime-certified resource identities to the resource store's durable
/// stakeholder facts. An unexpectedly missing handle remains visible and
/// fail-closed instead of silently disappearing.
pub fn join_certified_reads(
    store: &Store,
    scope: &str,
    reads: &[ResourceId],
) -> Result<Vec<CertifiedRead>, AdmitError> {
    let records = crate::resource_store::list(store, scope)?;
    Ok(reads
        .iter()
        .map(|read| {
            records
                .iter()
                .find(|record| &record.resource.id == read)
                .map(|record| CertifiedRead {
                    resource_id: read.as_str().to_string(),
                    stakeholders: record
                        .stakeholders
                        .iter()
                        .map(|authority| authority.as_str().to_string())
                        .collect(),
                })
                .unwrap_or_else(|| CertifiedRead {
                    resource_id: read.as_str().to_string(),
                    stakeholders: vec!["<unresolved>".to_string()],
                })
        })
        .collect())
}

fn is_config_path(path: &str) -> bool {
    let name = path.rsplit('/').next().unwrap_or(path);
    name.eq_ignore_ascii_case(".agent-config.json")
        || name.eq_ignore_ascii_case("agent-config.json")
}

fn known_tool(token: &str) -> bool {
    matches!(
        token.to_ascii_lowercase().as_str(),
        "bash" | "shell" | "exec" | "write" | "edit" | "delete" | "network" | "fetch" | "web"
    )
}

fn quoted_tokens(line: &str) -> impl Iterator<Item = &str> {
    line.split('"').enumerate().filter_map(|(index, part)| {
        (index % 2 == 1
            && !part.is_empty()
            && part.chars().all(|ch| ch.is_ascii_alphabetic() || ch == '_'))
        .then_some(part)
    })
}

/// Conservative server-side port of the workbench's `readPolicyDiff`: only a
/// changed policy line in an agent-config hunk, containing both a policy key and
/// a known capability token, contributes a direction.
pub fn policy_diff_direction(diff: &str) -> PolicyDiffDirection {
    let mut in_config = false;
    let mut loosens = false;
    let mut tightens = false;

    for raw in diff.lines() {
        if let Some(rest) = raw.strip_prefix("diff --git a/") {
            in_config = rest
                .rfind(" b/")
                .map(|index| is_config_path(rest[index + 3..].trim()))
                .unwrap_or(false);
            continue;
        }
        if !in_config
            || !matches!(raw.as_bytes().first(), Some(b'+') | Some(b'-'))
            || raw.starts_with("+++")
            || raw.starts_with("---")
        {
            continue;
        }
        let body = &raw[1..];
        let lower = body.to_ascii_lowercase();
        let mentions_policy = [
            "block", "deny", "allow", "permit", "tool", "policy", "sandbox", "grant",
        ]
        .iter()
        .any(|key| lower.contains(key));
        if !mentions_policy || !quoted_tokens(body).any(known_tool) {
            continue;
        }
        let blocking = lower.contains("block") || lower.contains("deny");
        let added = raw.starts_with('+');
        if blocking != added {
            loosens = true;
        } else {
            tightens = true;
        }
    }

    match (loosens, tightens) {
        (true, true) => PolicyDiffDirection::Mixed,
        (true, false) => PolicyDiffDirection::Loosens,
        (false, true) => PolicyDiffDirection::Tightens,
        (false, false) => PolicyDiffDirection::None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_direction_is_scoped_to_config_hunks_and_can_be_mixed() {
        let unrelated = "diff --git a/notes.json b/notes.json\n+\"allow_tools\": [\"bash\"]\n";
        assert_eq!(policy_diff_direction(unrelated), PolicyDiffDirection::None);

        let loosening = "diff --git a/.agent-config.json b/.agent-config.json\n--- a/.agent-config.json\n+++ b/.agent-config.json\n@@ -1 +1 @@\n-\"block_tools\": [\"bash\"]\n+\"block_tools\": []\n";
        assert_eq!(
            policy_diff_direction(loosening),
            PolicyDiffDirection::Loosens
        );

        let mixed = "diff --git a/.agent-config.json b/.agent-config.json\n@@ -1 +1 @@\n+\"allow_tools\": [\"write\"]\n+\"block_tools\": [\"network\"]\n";
        assert_eq!(policy_diff_direction(mixed), PolicyDiffDirection::Mixed);
    }

    #[test]
    fn latest_summary_folds_append_only_records() {
        let mut store = Store::open_in_memory().unwrap();
        append(
            &mut store,
            "chat",
            &TurnSummary {
                user_entry_id: 1,
                ..TurnSummary::default()
            },
        )
        .unwrap();
        append(
            &mut store,
            "chat",
            &TurnSummary {
                user_entry_id: 2,
                receipt_status: ReceiptStatus::Failed,
                ..TurnSummary::default()
            },
        )
        .unwrap();
        let latest = latest(&store, "chat").unwrap().unwrap();
        assert_eq!(latest.user_entry_id, 2);
        assert_eq!(latest.receipt_status, ReceiptStatus::Failed);
    }
}
