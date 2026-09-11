//! Native file-action base publication. The caller admits target access before
//! asking for this binding. No materialized disk state is imported here.

use super::{Engagement, NativeWorkspaceVcs, Result, WorkspaceError};
use whipplescript_store::content::{ContentBlobs, ContentStore};
use whipplescript_store::vcs::resolution_scope::ResolutionMemoryScope;
use whipplescript_store::vcs_file_save::{
    RecoveredSave, SaveAttempt, SaveResultBinding, ScopedSaveReceipt,
};
use whipplescript_store::{StoreError, StoreResult};

/// An actual workspace adapter binding, never constructible from request data.
/// Store paths stay private and never enter a runtime command.
pub struct NativeFileActionTarget {
    store_root: std::path::PathBuf,
    branch: String,
    path: String,
    base: String,
}

/// A read-only locator for an original save result, not a write adapter or an
/// access grant. The caller authorizes the target and evidence label before
/// observing it, and separately retains evidence before publishing a result.
pub struct NativeFileActionEvidenceTarget {
    target: NativeFileActionTarget,
}

impl NativeFileActionEvidenceTarget {
    pub fn branch(&self) -> &str {
        self.target.branch()
    }
    pub fn path(&self) -> &str {
        self.target.path()
    }
    pub fn base(&self) -> &str {
        self.target.base()
    }

    /// Retain the exact result while publishing references under current host
    /// authority. The callback may reconcile through the runtime owner, but must
    /// not write the target or materialize files. An error cannot undo a
    /// disposition that already committed. None is never absence evidence.
    pub fn publish_committed_result<T>(
        &self,
        binding: &SaveResultBinding,
        attempt: &SaveAttempt,
        publish: impl FnOnce(&NativeWorkspaceVcs, &RecoveredSave) -> StoreResult<T>,
    ) -> StoreResult<Option<T>> {
        let Some(observed) = self.read_committed_result(binding, attempt)? else {
            return Ok(None);
        };
        let retained = [
            observed.reference.content_hash.clone(),
            whipplescript_store::stable_hash_hex(&observed.accepted_content),
        ];
        let content = ContentStore::open_for_retained_publication(
            self.target.store_root.join("content.sqlite"),
        )?;
        content.publish_retained(&retained, || {
            let workspace = self.target.observe()?;
            let current = whipplescript_store::vcs_file_save::read_committed_save(
                &workspace, binding, attempt,
            )
            .map_err(|_| {
                StoreError::Conflict("native committed save evidence is unavailable".into())
            })?
            .ok_or_else(|| {
                StoreError::Conflict("native committed save evidence is unavailable".into())
            })?;
            if current.reference != observed.reference
                || current.receipt_json != observed.receipt_json
                || current.accepted_content != observed.accepted_content
            {
                return Err(StoreError::Conflict(
                    "native committed save evidence changed before publication".into(),
                ));
            }
            publish(&workspace, &current).map(Some)
        })
    }

    /// Observe only the exact committed result. Original draft/base bytes and
    /// today's head are not reconstruction inputs. This does not retain the
    /// result for a later action, authorize reconciliation or admit a fact.
    /// `None` is an absent observation, never proof of non-application.
    pub fn read_committed_result(
        &self,
        binding: &SaveResultBinding,
        attempt: &SaveAttempt,
    ) -> StoreResult<Option<RecoveredSave>> {
        if binding.branch_id != self.branch()
            || binding.path != self.path()
            || binding.base_cut_id != self.base()
        {
            return Err(StoreError::Conflict(
                "native save result binding differs from its actual target".into(),
            ));
        }
        let workspace = self.target.observe()?;
        whipplescript_store::vcs_file_save::read_committed_save(&workspace, binding, attempt)
            .map_err(|_| {
                StoreError::Conflict("native committed save evidence is unavailable".into())
            })
    }
    /// Retain the exact result while publishing references under current host
    /// authority. The callback may reconcile through the runtime owner, but must
    /// not write the target or materialize files. An error cannot undo a
    /// disposition that already committed. None is never absence evidence.
    pub fn publish_committed_scoped_result<T>(
        &self,
        binding: &SaveResultBinding,
        scope: &ResolutionMemoryScope,
        attempt: &SaveAttempt,
        publish: impl FnOnce(&NativeWorkspaceVcs, &RecoveredSave<ScopedSaveReceipt>) -> StoreResult<T>,
    ) -> StoreResult<Option<T>> {
        let Some(observed) = self.read_committed_scoped_result(binding, scope, attempt)? else {
            return Ok(None);
        };
        let retained = [
            observed.reference.content_hash.clone(),
            whipplescript_store::stable_hash_hex(&observed.accepted_content),
        ];
        let content = ContentStore::open_for_retained_publication(
            self.target.store_root.join("content.sqlite"),
        )?;
        content.publish_retained(&retained, || {
            let workspace = self.target.observe()?;
            let current = whipplescript_store::vcs_file_save::read_committed_scoped_save(
                &workspace, binding, scope, attempt,
            )
            .map_err(|_| {
                StoreError::Conflict("native committed save evidence is unavailable".into())
            })?
            .ok_or_else(|| {
                StoreError::Conflict("native committed save evidence is unavailable".into())
            })?;
            if current.reference != observed.reference
                || current.receipt_json != observed.receipt_json
                || current.accepted_content != observed.accepted_content
            {
                return Err(StoreError::Conflict(
                    "native committed save evidence changed before publication".into(),
                ));
            }
            publish(&workspace, &current).map(Some)
        })
    }

    /// Observe only the exact committed result. Original draft/base bytes and
    /// today's head are not reconstruction inputs. This does not retain the
    /// result for a later action, authorize reconciliation or admit a fact.
    /// `None` is an absent observation, never proof of non-application.
    pub fn read_committed_scoped_result(
        &self,
        binding: &SaveResultBinding,
        scope: &ResolutionMemoryScope,
        attempt: &SaveAttempt,
    ) -> StoreResult<Option<RecoveredSave<ScopedSaveReceipt>>> {
        if binding.branch_id != self.branch()
            || binding.path != self.path()
            || binding.base_cut_id != self.base()
        {
            return Err(StoreError::Conflict(
                "native save result binding differs from its actual target".into(),
            ));
        }
        let workspace = self.target.observe()?;
        whipplescript_store::vcs_file_save::read_committed_scoped_save(
            &workspace, binding, scope, attempt,
        )
        .map_err(|_| StoreError::Conflict("native committed save evidence is unavailable".into()))
    }
}

impl NativeFileActionTarget {
    pub fn branch(&self) -> &str {
        &self.branch
    }
    pub fn path(&self) -> &str {
        &self.path
    }
    pub fn base(&self) -> &str {
        &self.base
    }

    fn observe(&self) -> StoreResult<NativeWorkspaceVcs> {
        NativeWorkspaceVcs::open_read_only(
            self.store_root.join("branches.sqlite"),
            self.store_root.join("content.sqlite"),
        )
    }

    fn check_base(&self, vcs: &NativeWorkspaceVcs) -> StoreResult<String> {
        let refused =
            || StoreError::Conflict("file action base is not retained on this line".into());
        let head = vcs
            .get_branch(&self.branch)?
            .and_then(|branch| branch.head_cut_id)
            .ok_or_else(refused)?;
        if vcs.cut_chain(&head, &self.base)?.is_none() {
            return Err(refused());
        }
        let base = vcs.get_cut(&self.base)?.ok_or_else(refused)?;
        // This owner read distinguishes an absent path from erased bytes and
        // verifies the complete keyed descent needed to reconstruct this file.
        vcs.read_at_cut(&self.base, &self.path)?;
        Ok(base.manifest_hash)
    }

    /// Open the owner's confined save handler only for a current authorized
    /// native operation. All command/resource matching belongs to the host;
    /// this adapter verifies that its actual private target matches the binding.
    /// It does not import or materialize disk state, and never holds the base
    /// publication read lock while the owner acquires its write transaction.
    pub fn open_versioned_save(
        &self,
        binding: whipplescript_store::vcs_file_save::VersionedSaveBinding,
    ) -> StoreResult<
        whipplescript_store::vcs_file_save::VersionedSaveFileStore<
            whipplescript_store::branches::BranchStore,
            ContentStore,
        >,
    > {
        if binding.branch_id != self.branch
            || binding.path != self.path
            || binding.base_cut_id != self.base
        {
            return Err(StoreError::Conflict(
                "native save binding differs from its actual target".into(),
            ));
        }
        self.check_base(&self.observe()?)?;
        let workspace = NativeWorkspaceVcs::open(
            self.store_root.join("branches.sqlite"),
            self.store_root.join("content.sqlite"),
        )?;
        whipplescript_store::vcs_file_save::VersionedSaveFileStore::new(workspace, binding)
            .map_err(|error| StoreError::Conflict(error.to_string()))
    }

    /// Open the owner's confined save handler only for a current authorized
    /// native operation. All command/resource matching belongs to the host;
    /// this adapter verifies that its actual private target matches the binding.
    /// It does not import or materialize disk state, and never holds the base
    /// publication read lock while the owner acquires its write transaction.
    pub fn open_scoped_versioned_save(
        &self,
        binding: whipplescript_store::vcs_file_save::VersionedSaveBinding,
        scope: ResolutionMemoryScope,
    ) -> StoreResult<
        whipplescript_store::vcs_file_save::VersionedSaveFileStore<
            whipplescript_store::branches::BranchStore,
            ContentStore,
        >,
    > {
        if binding.branch_id != self.branch
            || binding.path != self.path
            || binding.base_cut_id != self.base
        {
            return Err(StoreError::Conflict(
                "native save binding differs from its actual target".into(),
            ));
        }
        self.check_base(&self.observe()?)?;
        let workspace = NativeWorkspaceVcs::open(
            self.store_root.join("branches.sqlite"),
            self.store_root.join("content.sqlite"),
        )?;
        whipplescript_store::vcs_file_save::VersionedSaveFileStore::new_in_resolution_scope(
            workspace, binding, scope,
        )
        .map_err(|error| StoreError::Conflict(error.to_string()))
    }

    /// Hold the owner's content collection/erasure exclusion while publishing
    /// references. The callback must not perform target effects. A callback
    /// error cannot undo a product command which already committed.
    pub fn publish_base<T>(&self, publish: impl FnOnce() -> StoreResult<T>) -> StoreResult<T> {
        let manifest = self.check_base(&self.observe()?)?;
        let content = ContentStore::open(self.store_root.join("content.sqlite"))?;
        content.publish_retained(&[manifest], || {
            self.check_base(&self.observe()?)?;
            publish()
        })
    }
}

impl Engagement {
    pub fn native_file_action_target(
        &self,
        path: &str,
        base: &str,
    ) -> Result<NativeFileActionTarget> {
        let target = self.native_file_action_coordinates(path, base)?;
        target.check_base(&target.observe()?)?;
        Ok(target)
    }

    /// Bind an existing target's original result for an already authorized
    /// observation. The base is an expected identity from the original command;
    /// the owner's receipt verification checks it without reopening base bytes.
    pub fn native_file_action_evidence_target(
        &self,
        path: &str,
        base: &str,
    ) -> Result<NativeFileActionEvidenceTarget> {
        Ok(NativeFileActionEvidenceTarget {
            target: self.native_file_action_coordinates(path, base)?,
        })
    }

    fn native_file_action_coordinates(
        &self,
        path: &str,
        base: &str,
    ) -> Result<NativeFileActionTarget> {
        if base.trim().is_empty() || !super::valid_native_action_target_path(path) {
            return Err(WorkspaceError::msg(
                "file action requires a normalized target path and exact base",
            ));
        }
        self.ensure_selected_path(path)?;
        Ok(NativeFileActionTarget {
            store_root: self.store_root.clone(),
            branch: self.branch.clone(),
            path: path.into(),
            base: base.into(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use whipplescript_store::files::{FileStore, FileWriteContext};
    use whipplescript_store::vcs_file_save::{save_cut_id, VersionedSaveBinding, SAVE_OUTPUT_PATH};

    struct SavedFixture {
        _dir: tempfile::TempDir,
        instance: crate::Instance,
        chat: Engagement,
        binding: VersionedSaveBinding,
        attempt: SaveAttempt,
    }

    fn saved_fixture() -> SavedFixture {
        let dir = tempfile::tempdir().expect("workspace directory");
        let instance = crate::Instance::init_at(dir.path()).expect("workspace");
        let chat = instance.create_engagement("one").expect("engagement");
        chat.write_file("note.txt", "recorded base")
            .expect("base bytes");
        let base = chat
            .commit_turn("base")
            .expect("base commit")
            .expect("base cut")
            .0;
        let target = chat
            .native_file_action_target("note.txt", &base)
            .expect("write target");
        let binding = VersionedSaveBinding {
            branch_id: target.branch().into(),
            path: target.path().into(),
            base_cut_id: target.base().into(),
            draft: "replacement".into(),
            draft_hash: whipplescript_store::stable_hash_hex("replacement"),
            input_label: "private input".into(),
            executing_principal: "fixture actor".into(),
            evidence_label: "private evidence".into(),
            recorded_at: "fixture".into(),
        };
        let context = FileWriteContext {
            instance_id: "runtime-instance",
            effect_id: "save",
            run_id: "attempt",
            started_event_id: "started",
        };
        let files = target
            .open_versioned_save(binding.clone())
            .expect("owner handler");
        let accepted = files
            .write_text_with_context(
                std::path::Path::new(SAVE_OUTPUT_PATH),
                &binding.draft,
                context,
            )
            .expect("target save");
        assert!(accepted.evidence.is_some());
        drop(files);
        SavedFixture {
            _dir: dir,
            instance,
            chat,
            binding,
            attempt: context.into(),
        }
    }

    #[test]
    fn evidence_reader_recovers_an_old_result_after_base_erasure_without_importing() {
        let fixture = saved_fixture();
        fixture
            .chat
            .write_file("note.txt", "later head")
            .expect("later bytes");
        let later = fixture
            .chat
            .commit_turn("later")
            .expect("later commit")
            .expect("later cut")
            .0;
        fixture
            .chat
            .write_file("note.txt", "unobserved manual edit")
            .expect("manual edit");
        let before = fixture
            .chat
            .native_file_action_evidence_target("note.txt", &fixture.binding.base_cut_id)
            .expect("evidence target");
        let view = before.target.observe().expect("read-only workspace");
        let base_hash = view
            .cut_manifest(&fixture.binding.base_cut_id)
            .expect("base manifest")
            .expect("retained base manifest")["note.txt"]
            .clone();
        let content = ContentStore::open(before.target.store_root.join("content.sqlite"))
            .expect("content authority");
        assert!(matches!(
            content.erase(&base_hash, "erase old base").expect("erase"),
            whipplescript_store::content::EraseOutcome::Erased { .. }
        ));
        assert!(fixture
            .chat
            .native_file_action_target("note.txt", &fixture.binding.base_cut_id)
            .is_err());

        let reader = fixture
            .chat
            .native_file_action_evidence_target("note.txt", &fixture.binding.base_cut_id)
            .expect("evidence needs the original identity, not base bytes");
        let recovered = reader
            .read_committed_result(&SaveResultBinding::from(&fixture.binding), &fixture.attempt)
            .expect("retained result")
            .expect("committed result");
        assert_eq!(recovered.accepted_content, "replacement");
        assert_eq!(recovered.receipt.base_cut_id, fixture.binding.base_cut_id);
        assert_eq!(recovered.receipt.attempt, fixture.attempt);
        let published = reader
            .publish_committed_result(
                &SaveResultBinding::from(&fixture.binding),
                &fixture.attempt,
                |workspace, current| {
                    assert!(workspace
                        .content_store()
                        .put_text("unadmitted write")
                        .is_err());
                    Ok(current.receipt_json.clone())
                },
            )
            .expect("publish retained result without old base bytes");
        assert_eq!(published, Some(recovered.receipt_json));
        let saved = save_cut_id(&fixture.attempt.instance_id, &fixture.attempt.effect_id);
        assert_ne!(saved, later);
        assert_eq!(
            view.get_branch(fixture.chat.branch())
                .expect("line")
                .expect("line exists")
                .head_cut_id
                .as_deref(),
            Some(later.as_str())
        );
        assert_eq!(
            fixture.chat.read_file("note.txt").expect("materialization"),
            "unobserved manual edit"
        );
    }

    #[test]
    fn result_publication_excludes_erasure_and_releases_after_callback_failure() {
        let fixture = saved_fixture();
        let reader = fixture
            .chat
            .native_file_action_evidence_target("note.txt", &fixture.binding.base_cut_id)
            .unwrap();
        let binding = SaveResultBinding::from(&fixture.binding);
        let path = reader.target.store_root.join("content.sqlite");
        let contender = rusqlite::Connection::open(&path).unwrap();
        contender.busy_timeout(std::time::Duration::ZERO).unwrap();
        let calls = std::cell::Cell::new(0);
        let publish = |workspace: &NativeWorkspaceVcs, result: &RecoveredSave| {
            assert!(contender.execute_batch("BEGIN IMMEDIATE").is_err());
            assert_eq!(result.accepted_content, "replacement");
            assert_eq!(result.receipt.attempt, fixture.attempt);
            assert_eq!(
                workspace
                    .content_store()
                    .get(&result.reference.content_hash)?,
                Some(result.receipt_json.as_bytes().to_vec())
            );
            calls.set(calls.get() + 1);
            Err::<(), _>(StoreError::Conflict("lost publication response".into()))
        };
        for expected in 1..=2 {
            let error = reader
                .publish_committed_result(&binding, &fixture.attempt, publish)
                .unwrap_err();
            assert!(format!("{error:?}").contains("lost publication response"));
            assert_eq!(calls.get(), expected);
            contender
                .execute_batch("BEGIN IMMEDIATE; ROLLBACK")
                .unwrap();
        }
        let retained = reader
            .read_committed_result(&binding, &fixture.attempt)
            .unwrap()
            .unwrap();
        let content = ContentStore::open(&path).unwrap();
        assert!(matches!(
            content
                .erase(&retained.reference.content_hash, "later erasure")
                .unwrap(),
            whipplescript_store::content::EraseOutcome::Erased { .. }
        ));
        assert!(reader
            .publish_committed_result(&binding, &fixture.attempt, publish)
            .is_err());
        assert_eq!(calls.get(), 2);
    }

    #[test]
    fn evidence_reader_confines_a_valid_receipt_to_its_actual_target() {
        let fixture = saved_fixture();
        let binding = SaveResultBinding::from(&fixture.binding);
        let other = fixture
            .instance
            .create_engagement("other")
            .expect("other line");
        for reader in [
            other
                .native_file_action_evidence_target("note.txt", &binding.base_cut_id)
                .expect("other target"),
            fixture
                .chat
                .native_file_action_evidence_target("other.txt", &binding.base_cut_id)
                .expect("other path"),
            fixture
                .chat
                .native_file_action_evidence_target("note.txt", "other-base")
                .expect("other base identity"),
        ] {
            assert!(
                matches!(reader.read_committed_result(&binding, &fixture.attempt),
                Err(StoreError::Conflict(reason)) if reason == "native save result binding differs from its actual target")
            );
        }
        let reader = fixture
            .chat
            .native_file_action_evidence_target("note.txt", &binding.base_cut_id)
            .expect("exact target");
        for field in ["principal", "label", "draft"] {
            let mut changed = binding.clone();
            match field {
                "principal" => changed.executing_principal.push_str("-other"),
                "label" => changed.evidence_label.push_str("-other"),
                _ => changed.draft_hash.push_str("-other"),
            }
            assert!(
                reader
                    .read_committed_result(&changed, &fixture.attempt)
                    .is_err(),
                "{field}"
            );
        }
        for field in ["run", "start"] {
            let mut changed = fixture.attempt.clone();
            if field == "run" {
                changed.run_id.push_str("-other");
            } else {
                changed.started_event_id.push_str("-other");
            }
            assert!(
                reader.read_committed_result(&binding, &changed).is_err(),
                "{field}"
            );
        }
        for field in ["instance", "effect"] {
            let mut changed = fixture.attempt.clone();
            if field == "instance" {
                changed.instance_id.push_str("-other");
            } else {
                changed.effect_id.push_str("-other");
            }
            assert!(reader
                .read_committed_result(&binding, &changed)
                .expect("absent observation")
                .is_none());
            assert!(reader
                .publish_committed_result::<()>(&binding, &changed, |_, _| panic!(
                    "absent result published"
                ))
                .expect("absent observation")
                .is_none());
        }
    }

    #[test]
    fn evidence_reader_refuses_erased_result_bytes_and_never_creates_missing_stores() {
        for erased in ["receipt", "accepted body"] {
            let fixture = saved_fixture();
            let reader = fixture
                .chat
                .native_file_action_evidence_target("note.txt", &fixture.binding.base_cut_id)
                .expect("evidence target");
            let binding = SaveResultBinding::from(&fixture.binding);
            let result = reader
                .read_committed_result(&binding, &fixture.attempt)
                .expect("read")
                .expect("saved");
            let hash = if erased == "receipt" {
                result.reference.content_hash
            } else {
                whipplescript_store::stable_hash_hex(&result.accepted_content)
            };
            let content = ContentStore::open(reader.target.store_root.join("content.sqlite"))
                .expect("content authority");
            assert!(matches!(
                content.erase(&hash, "erase evidence").expect("erase"),
                whipplescript_store::content::EraseOutcome::Erased { .. }
            ));
            assert!(
                reader
                    .read_committed_result(&binding, &fixture.attempt)
                    .is_err(),
                "{erased}"
            );
            assert!(reader
                .publish_committed_result::<()>(&binding, &fixture.attempt, |_, _| panic!(
                    "erased result published"
                ))
                .is_err());
        }
        for database in ["branches.sqlite", "content.sqlite"] {
            let fixture = saved_fixture();
            let reader = fixture
                .chat
                .native_file_action_evidence_target("note.txt", &fixture.binding.base_cut_id)
                .expect("evidence target");
            let path = reader.target.store_root.join(database);
            std::fs::rename(&path, reader.target.store_root.join("removed.sqlite"))
                .expect("remove store");
            assert!(reader
                .read_committed_result(&SaveResultBinding::from(&fixture.binding), &fixture.attempt)
                .is_err());
            assert!(reader
                .publish_committed_result::<()>(
                    &SaveResultBinding::from(&fixture.binding),
                    &fixture.attempt,
                    |_, _| panic!("missing store published")
                )
                .is_err());
            assert!(!path.exists(), "an observation recreated {database}");
        }
    }

    #[test]
    fn native_save_handler_refuses_substituted_bindings_and_erased_base() {
        use whipplescript_store::vcs_file_save::VersionedSaveBinding;
        let dir = tempfile::tempdir().unwrap();
        let instance = crate::Instance::init_at(dir.path()).unwrap();
        let chat = instance.create_engagement("one").unwrap();
        chat.write_file("note.txt", "recorded base").unwrap();
        let base = chat.commit_turn("fixture").unwrap().unwrap().0;
        let target = chat.native_file_action_target("note.txt", &base).unwrap();
        let binding = VersionedSaveBinding {
            branch_id: target.branch().into(),
            path: target.path().into(),
            base_cut_id: target.base().into(),
            draft: "replacement".into(),
            draft_hash: whipplescript_store::stable_hash_hex("replacement"),
            input_label: "private".into(),
            executing_principal: "actual actor".into(),
            evidence_label: "private".into(),
            recorded_at: "fixture".into(),
        };
        assert!(target.open_versioned_save(binding.clone()).is_ok());
        for field in ["branch", "path", "base"] {
            let mut changed = binding.clone();
            match field {
                "branch" => changed.branch_id.push_str("other"),
                "path" => changed.path.push_str("other"),
                _ => changed.base_cut_id.push_str("other"),
            }
            assert!(target.open_versioned_save(changed).is_err(), "{field}");
        }
        assert_eq!(chat.read_file("note.txt").unwrap(), "recorded base");
        let observed = target.observe().unwrap();
        let hash = observed.cut_manifest(&base).unwrap().unwrap()["note.txt"].clone();
        ContentStore::open(target.store_root.join("content.sqlite"))
            .unwrap()
            .erase(&hash, "erase base")
            .unwrap();
        assert!(target.open_versioned_save(binding).is_err());
    }

    #[test]
    fn base_publication_retains_exact_history_without_importing_manual_edits() {
        let dir = tempfile::tempdir().unwrap();
        let instance = crate::Instance::init_at(dir.path()).unwrap();
        let chat = instance.create_engagement("one").unwrap();
        chat.write_file("note.txt", "recorded").unwrap();
        let base = chat.commit_turn("base").unwrap().unwrap().0;
        chat.write_file("note.txt", "unobserved manual change")
            .unwrap();
        let target = chat.native_file_action_target("note.txt", &base).unwrap();
        let contender =
            rusqlite::Connection::open(target.store_root.join("content.sqlite")).unwrap();
        contender.busy_timeout(std::time::Duration::ZERO).unwrap();
        let published = Cell::new(0);
        let response = target.publish_base(|| {
            assert!(contender.execute_batch("BEGIN IMMEDIATE").is_err());
            published.set(published.get() + 1);
            Err::<(), _>(StoreError::Conflict("lost publication response".into()))
        });
        assert!(response.is_err());
        assert_eq!(published.get(), 1);
        contender
            .execute_batch("BEGIN IMMEDIATE; ROLLBACK")
            .unwrap();
        let observed = target.observe().unwrap();
        assert_eq!(
            observed
                .get_branch(chat.branch())
                .unwrap()
                .unwrap()
                .head_cut_id
                .as_deref(),
            Some(base.as_str())
        );
        assert_eq!(
            observed.read_at_cut(&base, "note.txt").unwrap().as_deref(),
            Some("recorded")
        );
        assert_eq!(
            chat.read_file("note.txt").unwrap(),
            "unobserved manual change"
        );
        let body = observed.cut_manifest(&base).unwrap().unwrap()["note.txt"].clone();
        ContentStore::open(target.store_root.join("content.sqlite"))
            .unwrap()
            .erase(&body, "erase")
            .unwrap();
        assert!(target
            .publish_base(|| {
                published.set(2);
                Ok(())
            })
            .is_err());
        assert_eq!(published.get(), 1);
    }

    #[test]
    fn native_binding_refuses_foreign_bases_unsafe_paths_and_unselected_roots() {
        let dir = tempfile::tempdir().unwrap();
        let instance = crate::Instance::init_at(dir.path()).unwrap();
        let mut chat = instance.create_engagement("one").unwrap();
        chat.write_file("allowed/note.txt", "base").unwrap();
        let base = chat.commit_turn("base").unwrap().unwrap().0;
        let other = instance.create_engagement("two").unwrap();
        other.write_file("foreign.txt", "foreign").unwrap();
        let foreign = other.commit_turn("foreign").unwrap().unwrap().0;
        assert!(chat
            .native_file_action_target("allowed/note.txt", &foreign)
            .is_err());
        assert!(chat
            .native_file_action_target("allowed/note.txt", "missing")
            .is_err());
        for path in [
            "../escape",
            "/absolute",
            "allowed//note.txt",
            "allowed/./note.txt",
            "allowed\\note.txt",
            "allowed/nu\0l.txt",
            ".gaugedesk-runtime/config",
        ] {
            assert!(
                chat.native_file_action_target(path, &base).is_err(),
                "{path}"
            );
            assert!(
                chat.native_file_action_evidence_target(path, &base)
                    .is_err(),
                "{path}"
            );
        }
        crate::ChatWorkspace::replace_sparse_roots(&mut chat, &["allowed".into()].into()).unwrap();
        assert!(chat
            .native_file_action_target("outside.txt", &base)
            .is_err());
        assert!(chat
            .native_file_action_evidence_target("outside.txt", &base)
            .is_err());
        assert!(chat
            .native_file_action_evidence_target("allowed/note.txt", " ")
            .is_err());
        assert!(chat
            .native_file_action_target("allowed/new.txt", &base)
            .is_ok());
    }
}
