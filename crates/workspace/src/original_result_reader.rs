//! Observation of an existing original result, never execution or a read grant.
use super::*;
use whipplescript_store::vcs::original_candidate::OriginalWorkspaceCandidate;

/// An immutable provenance observation. The caller must independently retain
/// its current recipient, release and key basis through each publication.
pub struct NativeObservedOfficeResult {
    result: NativeWitnessedTurn,
    creation: OriginalWorkspaceCandidate,
    final_files: BTreeMap<String, NativeTurnFileWitness>,
    actor: String,
    command: String,
}

impl NativeWitnessedTurnTarget {
    /// Observe only the existing candidate selected by original sealed product
    /// evidence. No current head, mutable file or replacement witness is used.
    #[allow(clippy::too_many_arguments)] // One complete original creation subject.
    pub fn observe_saved_result_guarded(
        self,
        witness: &[NativeTurnFileWitness],
        runtime_cut: &str,
        actor: &str,
        command: &str,
        expected_cut: &str,
        expected_evidence: &WriteEvidenceRef,
        check: &mut dyn FnMut() -> Result<()>,
    ) -> Result<NativeObservedOfficeResult> {
        check()?;
        let (_, final_files) = self.plan_result(witness, runtime_cut, actor, command, true)?;
        let evidence =
            TurnResultEvidence::new(&self, witness, &final_files, runtime_cut, actor, command)?;
        if expected_cut.is_empty() || &evidence.reference != expected_evidence {
            return Err(refused("original reader creation evidence differs"));
        }
        let vcs = self.observe()?;
        let files = final_files
            .iter()
            .filter(|(_, f)| f.kind != "delete" && valid_native_action_target_path(&f.path))
            .map(|(path, f)| (path.clone(), f.sha256[..32].to_owned()))
            .collect::<BTreeMap<_, _>>();
        let removed = final_files
            .iter()
            .filter(|(_, f)| f.kind == "delete" && valid_native_action_target_path(&f.path))
            .map(|(path, _)| path.clone())
            .collect::<Vec<_>>();
        let mut native_check =
            || check().map_err(|_| StoreError::Conflict("current original reader ended".into()));
        let creation = vcs.observe_original_candidate_guarded(
            self.original_lineage()?,
            &files,
            &removed,
            expected_evidence,
            actor,
            command,
            &mut native_check,
        )?;
        if creation.cut.cut_id != expected_cut {
            return Err(refused("original reader result cut differs"));
        }
        evidence.observe(&vcs)?;
        validate_payloads(&vcs, &final_files, check)?;
        let manifest = vcs
            .cut_manifest(expected_cut)?
            .ok_or_else(|| refused("original reader complete tree unavailable"))?;
        let base_manifest = vcs
            .cut_manifest(self.base_cut())?
            .ok_or_else(|| refused("original reader base tree unavailable"))?;
        let result = NativeWitnessedTurn {
            target: self,
            cut: creation.cut.clone(),
            op: creation.operation.clone(),
            files,
            removed,
            manifest,
            base_manifest,
            result_evidence: Some(evidence),
        };
        result.observe_at(&vcs)?;
        check()?;
        Ok(NativeObservedOfficeResult {
            result,
            creation,
            final_files,
            actor: actor.into(),
            command: command.into(),
        })
    }
}

impl NativeObservedOfficeResult {
    fn observe_at(
        &self,
        vcs: &NativeWorkspaceVcs,
        check: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        self.result.observe_at(vcs)?;
        let mut native_check =
            || check().map_err(|_| StoreError::Conflict("current original reader ended".into()));
        let creation = vcs.observe_original_candidate_guarded(
            self.result.target.original_lineage()?,
            &self.result.files,
            &self.result.removed,
            &self.creation.evidence,
            &self.actor,
            &self.command,
            &mut native_check,
        )?;
        if creation != self.creation {
            return Err(refused("original reader creation changed"));
        }
        validate_payloads(vcs, &self.final_files, check)?;
        Ok(())
    }

    /// Release one recorded file while both native writers exclude changes and
    /// the embedding retains its same current product reader. The callback must
    /// not reacquire native stores. It supplies no execution or retry authority.
    pub fn publish_file_retained<T>(
        &self,
        path: &str,
        check: &mut dyn FnMut() -> Result<()>,
        publish: impl FnOnce(&[u8]) -> StoreResult<T>,
    ) -> StoreResult<T> {
        check().map_err(reader_error)?;
        self.result
            .target
            .engagement
            .ensure_selected_path(path)
            .map_err(reader_error)?;
        safe_path(&self.result.target.engagement.path, path).map_err(reader_error)?;
        if path.chars().any(char::is_control)
            || path.contains('\\')
            || path
                .split('/')
                .any(|p| matches!(p, ".git" | ".gaugedesk-folder"))
        {
            return Err(StoreError::Conflict("original reader path refused".into()));
        }
        let hash = if valid_native_action_target_path(path) {
            self.result.manifest.get(path).cloned()
        } else {
            self.final_files
                .get(path)
                .filter(|file| {
                    file.kind != "delete"
                        && (path.starts_with("artifacts/") || path.starts_with("work/"))
                })
                .map(|file| file.sha256[..32].to_owned())
        }
        .ok_or_else(|| StoreError::Conflict("original reader file unavailable".into()))?;
        let vcs = NativeWorkspaceVcs::open_for_recorded_review(
            self.result
                .target
                .engagement
                .store_root
                .join("branches.sqlite"),
            self.result
                .target
                .engagement
                .store_root
                .join("content.sqlite"),
        )?;
        let mut retained = self.result.retained();
        let original = self
            .result
            .target
            .original_lineage()
            .map_err(reader_error)?;
        if let Some(id) = &original.branch_point_cut_id {
            let cut = vcs.get_cut(id)?.ok_or_else(|| {
                StoreError::Conflict("original reader divergence unavailable".into())
            })?;
            retained.push(cut.manifest_hash);
            retained.extend(
                vcs.cut_manifest(id)?
                    .ok_or_else(|| {
                        StoreError::Conflict("original reader divergence tree unavailable".into())
                    })?
                    .into_values(),
            );
        }
        vcs.publish_retained_recorded_observation(&retained, |held| {
            self.observe_at(held, check).map_err(reader_error)?;
            let body = held
                .content_store()
                .get(&hash)?
                .ok_or_else(|| StoreError::Conflict("original reader file unavailable".into()))?;
            check().map_err(reader_error)?;
            let result = publish(&body)?;
            check().map_err(reader_error)?;
            Ok(result)
        })
    }
}

fn reader_error(_: WorkspaceError) -> StoreError {
    StoreError::Conflict("original reader custody refused".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file(path: &str, kind: &str, body: &[u8]) -> NativeTurnFileWitness {
        NativeTurnFileWitness {
            path: path.into(),
            kind: kind.into(),
            sha256: hex::encode(Sha256::digest(body)),
            bytes: body.len() as u64,
        }
    }

    struct Fixture {
        _root: tempfile::TempDir,
        eng: Engagement,
        target: NativeWitnessedTurnTarget,
        witness: Vec<NativeTurnFileWitness>,
        result: NativeWitnessedTurn,
    }
    impl Fixture {
        fn new() -> Self {
            let (root, instance) = crate::tests::instance();
            let eng = instance.create_engagement("original-reader").unwrap();
            eng.write_file("preserved.txt", "original unchanged")
                .unwrap();
            eng.write_file("removed.txt", "original deleted").unwrap();
            let base = eng.commit_turn("base").unwrap().unwrap().0;
            let target = eng
                .witnessed_turn_target_at(&base)
                .unwrap()
                .capture_original_lineage()
                .unwrap();
            let witness = vec![
                file("result.txt", "add", b"intermediate"),
                file("result.txt", "modify", b"original final"),
                file("removed.txt", "delete", b""),
                file("artifacts/result.bin", "add", b"original local\0\xff"),
            ];
            let bodies = BTreeMap::from([
                ("result.txt".into(), b"original final".to_vec()),
                ("removed.txt".into(), vec![]),
                (
                    "artifacts/result.bin".into(),
                    b"original local\0\xff".to_vec(),
                ),
            ]);
            let result = target
                .clone()
                .import_saved_result_guarded(
                    &witness,
                    "original-runtime",
                    "original-author",
                    "original-command",
                    &bodies,
                    &mut || Ok(()),
                )
                .unwrap();
            Self {
                _root: root,
                eng,
                target,
                witness,
                result,
            }
        }
        fn observe(&self) -> NativeObservedOfficeResult {
            self.target
                .clone()
                .observe_saved_result_guarded(
                    &self.witness,
                    "original-runtime",
                    "original-author",
                    "original-command",
                    self.result.cut(),
                    self.result.result_evidence().unwrap(),
                    &mut || Ok(()),
                )
                .unwrap()
        }
        fn vcs(&self) -> NativeWorkspaceVcs {
            NativeWorkspaceVcs::open_read_only(
                self.eng.store_root.join("branches.sqlite"),
                self.eng.store_root.join("content.sqlite"),
            )
            .unwrap()
        }
    }

    #[test]
    fn original_reader_uses_existing_result_after_later_work_without_projection() {
        let fixture = Fixture::new();
        fixture
            .eng
            .write_file("result.txt", "later mutable bytes")
            .unwrap();
        fixture
            .eng
            .write_file("artifacts/result.bin", "later local bytes")
            .unwrap();
        fixture.eng.commit_turn("later legitimate work").unwrap();
        let source = fixture.vcs().get_branch(fixture.eng.branch()).unwrap();
        let candidate = fixture
            .vcs()
            .get_branch(&fixture.result.cut.branch_id)
            .unwrap();
        std::fs::remove_dir_all(fixture.eng.path()).unwrap();
        let observed = fixture.observe();
        for (path, expected) in [
            ("result.txt", b"original final".as_slice()),
            ("preserved.txt", b"original unchanged".as_slice()),
            ("artifacts/result.bin", b"original local\0\xff".as_slice()),
        ] {
            observed
                .publish_file_retained::<()>(path, &mut || Ok(()), |body| {
                    assert_eq!(body, expected);
                    Ok(())
                })
                .unwrap();
        }
        for path in [
            "removed.txt",
            "artifacts/unknown.txt",
            ".gaugedesk-runtime/method",
            "../result.txt",
            "./result.txt",
        ] {
            assert!(
                observed
                    .publish_file_retained::<()>(path, &mut || Ok(()), |_| {
                        panic!("unrecorded or excluded path released")
                    })
                    .is_err(),
                "{path}"
            );
        }
        assert_eq!(
            fixture.vcs().get_branch(fixture.eng.branch()).unwrap(),
            source
        );
        assert_eq!(
            fixture
                .vcs()
                .get_branch(&fixture.result.cut.branch_id)
                .unwrap(),
            candidate
        );
        assert!(!fixture.eng.path().exists());
    }

    #[test]
    fn original_reader_refuses_changed_origin_and_missing_creation_without_repair() {
        let fixture = Fixture::new();
        let evidence = fixture.result.result_evidence().unwrap();
        for (runtime, actor, command, cut) in [
            (
                "changed",
                "original-author",
                "original-command",
                fixture.result.cut(),
            ),
            (
                "original-runtime",
                "changed",
                "original-command",
                fixture.result.cut(),
            ),
            (
                "original-runtime",
                "original-author",
                "changed",
                fixture.result.cut(),
            ),
            (
                "original-runtime",
                "original-author",
                "original-command",
                "changed",
            ),
        ] {
            assert!(fixture
                .target
                .clone()
                .observe_saved_result_guarded(
                    &fixture.witness,
                    runtime,
                    actor,
                    command,
                    cut,
                    evidence,
                    &mut || Ok(()),
                )
                .is_err());
        }
        let mut changed = fixture.witness.clone();
        changed.swap(0, 1);
        assert!(fixture
            .target
            .clone()
            .observe_saved_result_guarded(
                &changed,
                "original-runtime",
                "original-author",
                "original-command",
                fixture.result.cut(),
                evidence,
                &mut || Ok(()),
            )
            .is_err());
        let observed = fixture.observe();
        let db =
            rusqlite::Connection::open(fixture.eng.store_root.join("branches.sqlite")).unwrap();
        db.execute("DELETE FROM ops WHERE op_id=?1", [&fixture.result.op.op_id])
            .unwrap();
        assert!(fixture
            .target
            .clone()
            .observe_saved_result_guarded(
                &fixture.witness,
                "original-runtime",
                "original-author",
                "original-command",
                fixture.result.cut(),
                evidence,
                &mut || Ok(()),
            )
            .is_err());
        assert!(observed
            .publish_file_retained::<()>("result.txt", &mut || Ok(()), |_| {
                panic!("missing original operation released")
            })
            .is_err());
        assert!(fixture
            .vcs()
            .get_op(&fixture.result.op.op_id)
            .unwrap()
            .is_none());
    }

    #[test]
    fn original_reader_checks_current_recipient_inside_both_native_writers_and_erasure() {
        let fixture = Fixture::new();
        let observed = fixture.observe();
        let branch =
            rusqlite::Connection::open(fixture.eng.store_root.join("branches.sqlite")).unwrap();
        let content =
            rusqlite::Connection::open(fixture.eng.store_root.join("content.sqlite")).unwrap();
        branch.busy_timeout(std::time::Duration::ZERO).unwrap();
        content.busy_timeout(std::time::Duration::ZERO).unwrap();
        observed
            .publish_file_retained::<()>("artifacts/result.bin", &mut || Ok(()), |body| {
                assert_eq!(body, b"original local\0\xff");
                assert!(branch.execute_batch("BEGIN IMMEDIATE").is_err());
                assert!(content.execute_batch("BEGIN IMMEDIATE").is_err());
                Ok(())
            })
            .unwrap();
        let mut inside = false;
        assert!(observed
            .publish_file_retained::<()>(
                "result.txt",
                &mut || {
                    if branch.execute_batch("BEGIN IMMEDIATE").is_err() {
                        inside = true;
                        return Err(refused("recipient removed"));
                    }
                    branch.execute_batch("ROLLBACK").unwrap();
                    Ok(())
                },
                |_| panic!("ended recipient released bytes")
            )
            .is_err());
        assert!(inside);
        ContentStore::open_existing(fixture.eng.store_root.join("content.sqlite"))
            .unwrap()
            .erase(&fixture.result.base_manifest["preserved.txt"], "erased")
            .unwrap();
        assert!(observed
            .publish_file_retained::<()>("result.txt", &mut || Ok(()), |_| {
                panic!("incomplete original tree released")
            })
            .is_err());
    }

    #[test]
    fn original_reader_preserves_sparse_selection_when_complete_tree_is_verified() {
        let fixture = Fixture::new();
        let mut target = fixture.target.clone();
        target.engagement.sparse_roots = Some(std::collections::BTreeSet::from([
            "result.txt".into(),
            "removed.txt".into(),
        ]));
        let observed = target
            .observe_saved_result_guarded(
                &fixture.witness,
                "original-runtime",
                "original-author",
                "original-command",
                fixture.result.cut(),
                fixture.result.result_evidence().unwrap(),
                &mut || Ok(()),
            )
            .unwrap();
        observed
            .publish_file_retained::<()>("result.txt", &mut || Ok(()), |body| {
                assert_eq!(body, b"original final");
                Ok(())
            })
            .unwrap();
        assert!(observed
            .publish_file_retained::<()>("preserved.txt", &mut || Ok(()), |_| {
                panic!("whole candidate verification widened sparse read")
            })
            .is_err());
    }

    #[test]
    fn original_reader_rechecks_candidate_custody_instead_of_reusing_old_observation() {
        let fixture = Fixture::new();
        let observed = fixture.observe();
        let db =
            rusqlite::Connection::open(fixture.eng.store_root.join("branches.sqlite")).unwrap();
        db.execute(
            "UPDATE branches SET status='discarded' WHERE branch_id=?1",
            [&fixture.result.cut.branch_id],
        )
        .unwrap();
        assert!(observed
            .publish_file_retained::<()>("result.txt", &mut || Ok(()), |_| {
                panic!("discarded candidate released through old metadata observation")
            })
            .is_err());
    }
}
