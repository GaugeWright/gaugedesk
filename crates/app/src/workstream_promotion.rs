//! Immutable project-collaboration promotion manifests (MTARGET-6).
//!
//! WhippleScript owns the reservation and exact Main CAS. GaugeDesk records the
//! product declaration that maps the reserved composite cut back to stable
//! native targets without treating collaboration promotion as target settlement.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::target_change_set::{
    TargetCandidateSnapshot, TargetChangeSetDeclaration, TARGET_CHANGE_SET_DECLARATION_KIND,
};
use crate::target_settlement::{snapshot_digest, RequestedSettlementMember};
use crate::Workbench;
use gaugedesk_workspace::WorkstreamPromotionReservation;

pub(crate) const WORKSTREAM_PROMOTION_MANIFEST_KIND: &str = "workstream_promotion_manifest";
const WORKSTREAM_SETTLEMENT_REF_KIND: &str = "workstream_target_settlement_ref";

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
struct WorkstreamSettlementRef {
    manifest_id: String,
    declaration_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub(crate) struct WorkstreamPromotionManifest {
    pub(crate) schema: String,
    pub(crate) id: String,
    pub(crate) workstream_id: String,
    pub(crate) project_id: String,
    pub(crate) workspace_id: String,
    pub(crate) reservation_id: String,
    pub(crate) line_branch_id: String,
    pub(crate) expected_line_cut: String,
    pub(crate) expected_main_cut: String,
    pub(crate) proposed_main_cut: String,
    pub(crate) partitions: Vec<TargetCandidateSnapshot>,
}

fn digest(value: impl AsRef<[u8]>) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(value.as_ref())))
}

impl Workbench {
    pub(crate) fn workstream_promotion_manifests(
        &self,
        workstream_id: &str,
    ) -> Result<Vec<WorkstreamPromotionManifest>, String> {
        self.store_ref()
            .records(workstream_id, WORKSTREAM_PROMOTION_MANIFEST_KIND)
            .map_err(|error| format!("{error:?}"))?
            .into_iter()
            .map(|body| serde_json::from_str(&body).map_err(|error| error.to_string()))
            .collect()
    }

    pub(crate) fn workstream_promotion_manifest(
        &self,
        workstream_id: &str,
        manifest_ref: Option<&str>,
    ) -> Result<WorkstreamPromotionManifest, String> {
        let manifests = self.workstream_promotion_manifests(workstream_id)?;
        match manifest_ref {
            Some(id) => manifests
                .into_iter()
                .find(|manifest| manifest.id == id)
                .ok_or_else(|| "promotion manifest is unavailable".to_owned()),
            None => manifests
                .into_iter()
                .last()
                .ok_or_else(|| "workstream has no promotion manifest".to_owned()),
        }
    }

    pub(crate) fn build_workstream_promotion_manifest(
        &mut self,
        workstream_id: &str,
        reservation: &WorkstreamPromotionReservation,
    ) -> Result<WorkstreamPromotionManifest, String> {
        let root = self
            .workstream_root(workstream_id)
            .ok_or_else(|| "workstream collaboration root is unresolved".to_owned())?;
        if reservation.workstream_id != workstream_id {
            return Err("promotion reservation belongs to another workstream".to_owned());
        }
        if let Some(existing) = self
            .workstream_promotion_manifests(workstream_id)?
            .into_iter()
            .find(|manifest| {
                manifest.reservation_id == reservation.reservation_id
                    && manifest.expected_line_cut == reservation.expected_line_cut
                    && manifest.expected_main_cut == reservation.expected_main_cut
            })
        {
            return Ok(existing);
        }

        let targets = self
            .library
            .targets_for_project(&root.project_id)
            .into_iter()
            .map(|target| {
                crate::library::target_id_path_v1(&target.id)
                    .map(|encoded| (encoded, target.clone()))
            })
            .collect::<Result<BTreeMap<_, _>, _>>()?;
        let mut grouped = BTreeMap::<String, Vec<(String, String)>>::new();
        for full_path in &reservation.changed_paths {
            let mut parts = full_path.splitn(3, '/');
            if parts.next() != Some("targets") {
                return Err(format!(
                    "promotion cut changes non-target path `{full_path}`"
                ));
            }
            let encoded = parts
                .next()
                .ok_or_else(|| format!("promotion path `{full_path}` has no target partition"))?;
            let relative = parts
                .next()
                .filter(|path| !path.is_empty())
                .ok_or_else(|| {
                    format!("promotion path `{full_path}` has no target-relative file")
                })?;
            let target = targets
                .get(encoded)
                .ok_or_else(|| format!("promotion path `{full_path}` names an unknown target"))?;
            grouped
                .entry(target.id.clone())
                .or_default()
                .push((full_path.clone(), relative.to_owned()));
        }

        let roots = grouped
            .keys()
            .map(|target_id| {
                crate::library::target_id_path_v1(target_id)
                    .map(|encoded| format!("targets/{encoded}"))
            })
            .collect::<Result<BTreeSet<_>, _>>()?;
        let workspace = self
            .collaboration_workspaces
            .get(&root.workspace_id)
            .ok_or_else(|| "project collaboration workspace is unavailable".to_owned())?;
        let temporary_id = crate::library::gen_id("promotion-manifest");
        let view = workspace
            .fork_engagement_subset_at(
                &temporary_id,
                &reservation.line_branch_id,
                workspace.mainline(),
                &reservation.expected_line_cut,
                &roots,
            )
            .map_err(|error| error.to_string())?;
        let materialized = (|| {
            let existing = view
                .tree()
                .map_err(|error| error.to_string())?
                .into_iter()
                .filter(|entry| !entry.is_dir)
                .map(|entry| entry.path)
                .collect::<BTreeSet<_>>();
            let mut partitions = Vec::new();
            for (target_id, paths) in &grouped {
                let target = self
                    .library
                    .work_targets
                    .get(target_id)
                    .ok_or_else(|| "promotion target disappeared".to_owned())?;
                let mut files = Vec::new();
                let mut changed_paths = Vec::new();
                for (full_path, relative) in paths {
                    let body = if existing.contains(full_path) {
                        Some(
                            view.read_file_bytes_capped(full_path, usize::MAX)
                                .map_err(|error| error.to_string())?
                                .ok_or_else(|| {
                                    "promotion candidate file exceeds addressable size".to_owned()
                                })?,
                        )
                    } else {
                        None
                    };
                    files.push((relative.clone(), body));
                    changed_paths.push(relative.clone());
                }
                files.sort_by(|left, right| left.0.cmp(&right.0));
                changed_paths.sort();
                let candidate_digest = snapshot_digest(&files);
                partitions.push(TargetCandidateSnapshot {
                    target_id: target_id.clone(),
                    native_basis: target
                        .current_basis
                        .clone()
                        .ok_or_else(|| "promotion target has no exact native basis".to_owned())?,
                    candidate_workspace_id: root.workspace_id.clone(),
                    candidate_line_ref: reservation.line_branch_id.clone(),
                    candidate_identity: format!(
                        "promotion-cut:{}:{}#target:{}",
                        workstream_id, reservation.expected_line_cut, target_id
                    ),
                    candidate_cut: reservation.expected_line_cut.clone(),
                    candidate_digest,
                    path_scope: target.path_scope.clone(),
                    adapter_family: target.adapter_family.clone(),
                    changed_paths,
                    checks: vec!["collaboration-promotion=reserved".to_owned()],
                    policy_decision_handles: vec![format!(
                        "workstream-promotion-policy:{}",
                        reservation.reservation_id
                    )],
                });
            }
            partitions.sort_by(|left, right| left.target_id.cmp(&right.target_id));
            Ok(partitions)
        })();
        drop(view);
        let cleanup = workspace
            .remove_engagement(&temporary_id)
            .map_err(|error| error.to_string());
        let partitions = match (materialized, cleanup) {
            (Ok(partitions), Ok(())) => partitions,
            (Err(error), _) | (Ok(_), Err(error)) => return Err(error),
        };
        let mut manifest = WorkstreamPromotionManifest {
            schema: "gaugedesk.workstream-promotion-manifest.v1".to_owned(),
            id: String::new(),
            workstream_id: workstream_id.to_owned(),
            project_id: root.project_id,
            workspace_id: root.workspace_id,
            reservation_id: reservation.reservation_id.clone(),
            line_branch_id: reservation.line_branch_id.clone(),
            expected_line_cut: reservation.expected_line_cut.clone(),
            expected_main_cut: reservation.expected_main_cut.clone(),
            proposed_main_cut: reservation.proposed_main_cut.clone(),
            partitions,
        };
        manifest.id = format!(
            "workstream-promotion-manifest:{}",
            digest(serde_json::to_vec(&manifest).map_err(|error| error.to_string())?)
        );
        self.store_mut()
            .append_record(
                workstream_id,
                WORKSTREAM_PROMOTION_MANIFEST_KIND,
                &serde_json::to_string(&manifest).map_err(|error| error.to_string())?,
            )
            .map_err(|error| format!("{error:?}"))?;
        Ok(manifest)
    }

    pub(crate) fn ensure_promotion_change_set(
        &mut self,
        manifest: &WorkstreamPromotionManifest,
        refresh_native_bases: bool,
    ) -> Result<TargetChangeSetDeclaration, String> {
        let mut candidates = manifest.partitions.clone();
        if refresh_native_bases {
            for candidate in &mut candidates {
                candidate.native_basis = self
                    .library
                    .work_targets
                    .get(&candidate.target_id)
                    .and_then(|target| target.current_basis.clone())
                    .ok_or_else(|| {
                        format!(
                            "detached promotion target {} has no current basis",
                            candidate.target_id
                        )
                    })?;
                candidate.policy_decision_handles.insert(
                    0,
                    format!(
                        "detached-candidate-admission:{}:{}",
                        manifest.id, candidate.native_basis
                    ),
                );
            }
        }
        let id = format!(
            "promotion-change-set:{}",
            digest(
                serde_json::to_vec(&(&manifest.id, refresh_native_bases, &candidates))
                    .map_err(|error| error.to_string())?
            )
        );
        if let Some(existing) = self
            .store_ref()
            .records(&manifest.workstream_id, TARGET_CHANGE_SET_DECLARATION_KIND)
            .map_err(|error| format!("{error:?}"))?
            .into_iter()
            .map(|body| {
                serde_json::from_str::<TargetChangeSetDeclaration>(&body)
                    .map_err(|error| error.to_string())
            })
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .find(|declaration| declaration.id == id)
        {
            return Ok(existing);
        }
        let placement_id = self
            .workstream(&manifest.workstream_id)
            .map(|workstream| workstream.instance_id)
            .ok_or_else(|| "workstream declaration is unavailable".to_owned())?;
        let declaration = TargetChangeSetDeclaration {
            schema: "gaugedesk.target-change-set.v1".to_owned(),
            id,
            chat_id: manifest.workstream_id.clone(),
            run_ref: manifest.id.clone(),
            project_id: manifest.project_id.clone(),
            placement_id,
            package_version_ref: String::new(),
            target_set_revision: 0,
            turn_process_declaration_id: format!("promotion-process:{}", manifest.id),
            candidate_snapshots: candidates,
            requested_acts: Vec::new(),
        };
        self.store_mut()
            .append_record(
                &manifest.workstream_id,
                TARGET_CHANGE_SET_DECLARATION_KIND,
                &serde_json::to_string(&declaration).map_err(|error| error.to_string())?,
            )
            .map_err(|error| format!("{error:?}"))?;
        Ok(declaration)
    }

    pub(crate) fn create_workstream_target_settlement(
        &mut self,
        manifest: &WorkstreamPromotionManifest,
        requested: Vec<RequestedSettlementMember>,
    ) -> Result<gaugedesk_core::target_settlement::TargetSettlementState, String> {
        self.create_workstream_target_settlement_with_basis(manifest, requested, false)
    }

    pub(crate) fn create_detached_workstream_target_settlement(
        &mut self,
        manifest: &WorkstreamPromotionManifest,
        requested: Vec<RequestedSettlementMember>,
    ) -> Result<gaugedesk_core::target_settlement::TargetSettlementState, String> {
        self.create_workstream_target_settlement_with_basis(manifest, requested, true)
    }

    fn create_workstream_target_settlement_with_basis(
        &mut self,
        manifest: &WorkstreamPromotionManifest,
        requested: Vec<RequestedSettlementMember>,
        refresh_native_bases: bool,
    ) -> Result<gaugedesk_core::target_settlement::TargetSettlementState, String> {
        let source = self.ensure_promotion_change_set(manifest, refresh_native_bases)?;
        let state = self.create_target_settlement(
            &manifest.workstream_id,
            &source.id,
            Some(manifest.id.clone()),
            requested,
        )?;
        let declaration_id = state
            .declaration
            .as_ref()
            .map(|declaration| declaration.declaration_id.clone())
            .ok_or_else(|| "settlement declaration is absent".to_owned())?;
        let reference = WorkstreamSettlementRef {
            manifest_id: manifest.id.clone(),
            declaration_id,
        };
        let exists = self
            .store_ref()
            .records(&manifest.workstream_id, WORKSTREAM_SETTLEMENT_REF_KIND)
            .map_err(|error| format!("{error:?}"))?
            .into_iter()
            .filter_map(|body| serde_json::from_str::<WorkstreamSettlementRef>(&body).ok())
            .any(|existing| existing == reference);
        if !exists {
            self.store_mut()
                .append_record(
                    &manifest.workstream_id,
                    WORKSTREAM_SETTLEMENT_REF_KIND,
                    &serde_json::to_string(&reference).map_err(|error| error.to_string())?,
                )
                .map_err(|error| format!("{error:?}"))?;
        }
        Ok(state)
    }

    pub(crate) fn latest_workstream_target_settlement(
        &self,
        workstream_id: &str,
    ) -> Option<gaugedesk_core::target_settlement::TargetSettlementState> {
        let reference = self
            .store_ref()
            .records(workstream_id, WORKSTREAM_SETTLEMENT_REF_KIND)
            .ok()?
            .into_iter()
            .filter_map(|body| serde_json::from_str::<WorkstreamSettlementRef>(&body).ok())
            .next_back()?;
        self.store_ref()
            .fold::<gaugedesk_core::target_settlement::TargetSettlementState>(&format!(
                "target-settlement::{}",
                reference.declaration_id
            ))
            .ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::library::{RecordOp, WorkstreamRecord, WorkstreamRootRecord};
    use crate::target_adapter::TargetActKind;
    use crate::{open_workbench, LockUnpoisoned, DEFAULT_PLACEMENT};
    use gaugedesk_core::target_settlement::SettlementPhase;
    use gaugedesk_workspace::{MergeOutcome, WorkstreamPromotionOutcome};
    use whipplescript_store::workstreams::StreamStatus;

    fn seeded_workstream(workbench: &mut Workbench) -> (String, String, String, String) {
        let chat = workbench
            .create_chat_in_instance(DEFAULT_PLACEMENT, "promotion member")
            .expect("chat");
        let chat_id = chat["id"].as_str().expect("chat id").to_owned();
        let project_id = workbench
            .library_project_of_chat(&chat_id)
            .expect("project");
        let collaboration = workbench.library.project_collaboration_workspaces[&project_id].clone();
        let workstream_id = crate::library::gen_id("ws-test");
        let line = {
            let workspace = &workbench.collaboration_workspaces[&collaboration.workspace_id];
            workspace
                .create_named_workstream(&workstream_id, Some("Promotion test"))
                .expect("workstream");
            workspace
                .transfer_engagement_to_workstream(&chat_id, &workstream_id)
                .expect("transfer");
            workspace
                .workstream(&workstream_id)
                .expect("topology")
                .expect("row")
                .line_branch_id
        };
        workbench.write_workstream_record(WorkstreamRecord {
            schema: crate::library::LIBRARY_RECORD_SCHEMA,
            extra: Default::default(),
            id: workstream_id.clone(),
            op: RecordOp::Upsert,
            instance_id: DEFAULT_PLACEMENT.to_owned(),
            name: "Promotion test".to_owned(),
            created_position: 0,
        });
        workbench.write_workstream_root_record(WorkstreamRootRecord {
            schema: crate::library::LIBRARY_RECORD_SCHEMA,
            extra: Default::default(),
            workstream_id: workstream_id.clone(),
            op: RecordOp::Upsert,
            placement_id: DEFAULT_PLACEMENT.to_owned(),
            project_id,
            workspace_id: collaboration.workspace_id.clone(),
            target_id: String::new(),
            adapter_family: String::new(),
        });
        workbench
            .engagements
            .get_mut(&chat_id)
            .expect("engagement")
            .rehome(&line)
            .expect("materialize workstream");
        let target_id =
            workbench.library.placement_targets[DEFAULT_PLACEMENT].target_ids[0].clone();
        let encoded = crate::library::target_id_path_v1(&target_id).expect("encoded target");
        let path = format!("targets/{encoded}/promoted.bin");
        workbench.engagements[&chat_id]
            .write_file_bytes(&path, b"promoted candidate")
            .expect("candidate");
        workbench.engagements[&chat_id]
            .commit_turn("promotion contribution")
            .expect("commit");
        assert_eq!(
            workbench.engagements[&chat_id]
                .merge_into_main()
                .expect("advance line"),
            MergeOutcome::Clean
        );
        (
            workstream_id,
            collaboration.workspace_id,
            chat_id,
            target_id,
        )
    }

    #[test]
    fn promotion_manifest_is_exact_and_promotion_does_not_settle_the_native_target() {
        let root = tempfile::tempdir().expect("root");
        let shared = open_workbench(root.path()).expect("workbench");
        let mut workbench = shared.lock_unpoisoned();
        let (workstream_id, workspace_id, _, target_id) = seeded_workstream(&mut workbench);
        let native_basis = workbench.library.work_targets[&target_id]
            .current_basis
            .clone();
        let reservation = workbench.collaboration_workspaces[&workspace_id]
            .reserve_workstream_promotion_boundary(&workstream_id, "reservation:test")
            .expect("reserve");
        let manifest = workbench
            .build_workstream_promotion_manifest(&workstream_id, &reservation)
            .expect("manifest");
        assert_eq!(manifest.partitions.len(), 1);
        assert_eq!(manifest.partitions[0].target_id, target_id);
        assert_eq!(manifest.partitions[0].changed_paths, ["promoted.bin"]);
        assert_eq!(
            workbench
                .workstream_promotion_manifests(&workstream_id)
                .expect("stored manifests"),
            vec![manifest.clone()]
        );
        assert!(matches!(
            workbench.collaboration_workspaces[&workspace_id]
                .promote_workstream_boundary(
                    &workstream_id,
                    &workspace_id,
                    &reservation.reservation_id,
                )
                .expect("promote"),
            WorkstreamPromotionOutcome::Promoted { .. }
        ));
        let recovered = workbench.collaboration_workspaces[&workspace_id]
            .reserve_workstream_promotion_boundary(&workstream_id, "reservation:ignored-retry")
            .expect("archived promotion reservation remains inspectable");
        assert_eq!(recovered.reservation_id, reservation.reservation_id);
        assert!(matches!(
            workbench.collaboration_workspaces[&workspace_id]
                .promote_workstream_boundary(
                    &workstream_id,
                    &workspace_id,
                    &recovered.reservation_id,
                )
                .expect("idempotent promotion recovery"),
            WorkstreamPromotionOutcome::Promoted { .. }
        ));
        assert_eq!(
            workbench.library.work_targets[&target_id].current_basis, native_basis,
            "collaboration promotion is not native target settlement"
        );
    }

    #[test]
    fn failed_combined_preflight_releases_the_line_and_moves_no_main_or_target() {
        let root = tempfile::tempdir().expect("root");
        let shared = open_workbench(root.path()).expect("workbench");
        let mut workbench = shared.lock_unpoisoned();
        let (workstream_id, workspace_id, _, target_id) = seeded_workstream(&mut workbench);
        let reservation = workbench.collaboration_workspaces[&workspace_id]
            .reserve_workstream_promotion_boundary(&workstream_id, "reservation:refuse")
            .expect("reserve");
        let manifest = workbench
            .build_workstream_promotion_manifest(&workstream_id, &reservation)
            .expect("manifest");
        let declared = workbench
            .create_workstream_target_settlement(
                &manifest,
                vec![RequestedSettlementMember {
                    target_id: target_id.clone(),
                    act: TargetActKind::Apply,
                }],
            )
            .expect("declare");
        workbench
            .library
            .work_targets
            .get_mut(&target_id)
            .unwrap()
            .current_basis = Some("basis:moved-before-combined-preflight".to_owned());
        let declaration_id = declared.declaration.unwrap().declaration_id;
        let refused = workbench
            .preflight_target_settlement(&declaration_id)
            .expect("durable refusal");
        assert_eq!(refused.phase, SettlementPhase::Refused);
        workbench.collaboration_workspaces[&workspace_id]
            .release_workstream_promotion_boundary(&workstream_id, &reservation.reservation_id)
            .expect("release");
        let topology = workbench.collaboration_workspaces[&workspace_id]
            .workstream(&workstream_id)
            .expect("topology")
            .expect("row");
        assert_eq!(topology.status, StreamStatus::Active);
        assert_eq!(topology.expected_line_cut, None);
        assert_eq!(topology.expected_main_cut, None);
    }

    #[test]
    fn combined_flow_preflights_before_cas_then_settles_from_the_same_manifest() {
        let root = tempfile::tempdir().expect("root");
        let shared = open_workbench(root.path()).expect("workbench");
        let mut workbench = shared.lock_unpoisoned();
        let (workstream_id, workspace_id, _, target_id) = seeded_workstream(&mut workbench);
        let reservation = workbench.collaboration_workspaces[&workspace_id]
            .reserve_workstream_promotion_boundary(&workstream_id, "reservation:combined")
            .expect("reserve");
        let manifest = workbench
            .build_workstream_promotion_manifest(&workstream_id, &reservation)
            .expect("manifest");
        let declared = workbench
            .create_workstream_target_settlement(
                &manifest,
                vec![RequestedSettlementMember {
                    target_id: target_id.clone(),
                    act: TargetActKind::Apply,
                }],
            )
            .expect("declare");
        let declaration_id = declared.declaration.unwrap().declaration_id;
        let ready = workbench
            .preflight_target_settlement(&declaration_id)
            .expect("all-member preflight");
        assert_eq!(ready.phase, SettlementPhase::Ready);
        assert!(matches!(
            workbench.collaboration_workspaces[&workspace_id]
                .promote_workstream_boundary(
                    &workstream_id,
                    &workspace_id,
                    &reservation.reservation_id,
                )
                .expect("promote"),
            WorkstreamPromotionOutcome::Promoted { .. }
        ));
        let member_id = ready.declaration.unwrap().members[0].member_id.clone();
        let completed = workbench
            .execute_settlement_member(&declaration_id, &member_id)
            .expect("settle target");
        assert_eq!(completed.phase, SettlementPhase::Completed);
        let target = &workbench.targets[&target_id];
        let probe_id = crate::library::gen_id("combined-probe");
        let probe = target.create_engagement(&probe_id).expect("probe");
        assert_eq!(
            probe
                .read_file_bytes_capped("promoted.bin", usize::MAX)
                .expect("read")
                .expect("file"),
            b"promoted candidate"
        );
        drop(probe);
        target.remove_engagement(&probe_id).expect("cleanup");
    }

    #[test]
    fn later_settlement_freshly_admits_a_detached_candidate_on_the_current_native_basis() {
        let root = tempfile::tempdir().expect("root");
        let shared = open_workbench(root.path()).expect("workbench");
        let mut workbench = shared.lock_unpoisoned();
        let (workstream_id, workspace_id, _, target_id) = seeded_workstream(&mut workbench);
        let reservation = workbench.collaboration_workspaces[&workspace_id]
            .reserve_workstream_promotion_boundary(&workstream_id, "reservation:later")
            .expect("reserve");
        let manifest = workbench
            .build_workstream_promotion_manifest(&workstream_id, &reservation)
            .expect("manifest");
        workbench.collaboration_workspaces[&workspace_id]
            .promote_workstream_boundary(&workstream_id, &workspace_id, &reservation.reservation_id)
            .expect("promote");

        let target = &workbench.targets[&target_id];
        let advance_id = crate::library::gen_id("native-advance");
        let advance = target.create_engagement(&advance_id).expect("candidate");
        advance
            .write_file("independent.txt", "independent advance")
            .expect("write");
        advance.commit_turn("independent advance").expect("commit");
        assert_eq!(
            advance.merge_into_main().expect("apply"),
            MergeOutcome::Clean
        );
        let current_basis = advance.standing_revision().expect("current basis").0;
        drop(advance);
        target.remove_engagement(&advance_id).expect("cleanup");
        let mut target_record = workbench.library.work_targets[&target_id].clone();
        assert_ne!(
            target_record.current_basis.as_deref(),
            Some(current_basis.as_str())
        );
        target_record.current_basis = Some(current_basis.clone());
        workbench.write_work_target_record(target_record);

        let declared = workbench
            .create_detached_workstream_target_settlement(
                &manifest,
                vec![RequestedSettlementMember {
                    target_id,
                    act: TargetActKind::Apply,
                }],
            )
            .expect("fresh detached declaration");
        let declaration_id = declared.declaration.unwrap().declaration_id;
        let ready = workbench
            .preflight_target_settlement(&declaration_id)
            .expect("fresh preflight");
        assert_eq!(ready.phase, SettlementPhase::Ready);
        assert_eq!(
            ready.declaration.unwrap().members[0].expected_basis,
            current_basis
        );
    }
}
