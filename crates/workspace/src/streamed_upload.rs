//! Exact native upload history and retained result publication. Product standing
//! belongs to the caller; this locator is never an authentication capability.
use super::{
    safe_read_file, valid_native_action_target_path, workspace_writer, Engagement, Result,
    WorkspaceError,
};
use sha2::{Digest, Sha256};
use std::io::Read;
use std::sync::PoisonError;
use whipplescript_store::branches::{BranchStore, CutRow, OpRow};
use whipplescript_store::content::{ContentBlobs, ContentStore};
use whipplescript_store::vcs::{NativeWorkspaceVcs, VcsWriteOutcome};
use whipplescript_store::{StoreError, StoreResult};

/// A confined actual workspace locator, constructed by the native adapter.
/// It cannot be deserialized or constructed from caller-supplied store paths.
pub struct NativeStreamedUploadTarget {
    engagement: Engagement,
    relative: String,
}

/// Exact recorded upload evidence, never a later publication grant.
pub struct NativeStreamedUpload {
    target: NativeStreamedUploadTarget,
    cut: CutRow,
    hash: String,
    op: OpRow,
}

impl Engagement {
    pub fn streamed_upload_target(&self, relative: &str) -> Result<NativeStreamedUploadTarget> {
        self.ensure_projection()?;
        self.ensure_selected_path(relative)?;
        if !valid_native_action_target_path(relative) {
            return Err(WorkspaceError::msg("invalid native upload target"));
        }
        let target = NativeStreamedUploadTarget {
            engagement: self.clone(),
            relative: relative.into(),
        };
        target.observe()?;
        Ok(target)
    }
}

impl NativeStreamedUploadTarget {
    fn observe(&self) -> StoreResult<NativeWorkspaceVcs> {
        let root = &self.engagement.store_root;
        let vcs = NativeWorkspaceVcs::open_read_only(
            root.join("branches.sqlite"),
            root.join("content.sqlite"),
        )?;
        if vcs.get_branch(&self.engagement.branch)?.is_none() {
            return Err(StoreError::Conflict(
                "native upload branch is unavailable".into(),
            ));
        }
        Ok(vcs)
    }

    pub fn planned_cut(
        &self,
        sha256: &str,
        byte_len: u64,
        actor: &str,
        command: &str,
    ) -> Result<String> {
        if actor.is_empty()
            || command.is_empty()
            || sha256.len() != 64
            || !sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(WorkspaceError::msg("native upload meaning is unavailable"));
        }
        let meaning = serde_json::to_vec(&(actor, command, &self.relative, sha256, byte_len))
            .map_err(|_| WorkspaceError::msg("native upload meaning unavailable"))?;
        Ok(format!("upload-{}", hex::encode(Sha256::digest(&meaning))))
    }

    pub fn place_guarded(
        &self,
        source: &std::path::Path,
        check: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        self.engagement
            .write_file_from_path_guarded(&self.relative, source, check)
    }

    /// Import only the placed upload. Unrelated unimported files are neither
    /// scanned nor projected. Checks use the original held product transaction.
    #[allow(clippy::too_many_arguments)]
    pub fn import_placed_file_guarded(
        self,
        sha256: &str,
        byte_len: u64,
        actor: &str,
        command: &str,
        check: &mut dyn FnMut() -> Result<()>,
    ) -> Result<NativeStreamedUpload> {
        check()?;
        if actor.is_empty()
            || command.is_empty()
            || sha256.len() != 64
            || !sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(WorkspaceError::msg("native upload meaning is unavailable"));
        }
        let writer = workspace_writer(&self.engagement.store_root, &self.engagement.branch);
        let _writing = writer.lock().unwrap_or_else(PoisonError::into_inner);
        self.observe()?;
        self.engagement.ensure_projection()?;
        let mut file = safe_read_file(&self.engagement.path, &self.relative)?;
        if file.metadata().map_err(WorkspaceError::io)?.len() != byte_len {
            return Err(WorkspaceError::msg("native upload bytes changed"));
        }
        let mut hasher = Sha256::new();
        let mut count = 0u64;
        let mut window = [0u8; 64 * 1024];
        loop {
            check()?;
            let n = file.read(&mut window).map_err(WorkspaceError::io)?;
            if n == 0 {
                break;
            }
            count = count.saturating_add(n as u64);
            if count > byte_len {
                return Err(WorkspaceError::msg("native upload bytes changed"));
            }
            hasher.update(&window[..n]);
        }
        if count != byte_len || hex::encode(hasher.finalize()) != sha256 {
            return Err(WorkspaceError::msg("native upload bytes changed"));
        }
        check()?;
        let root = &self.engagement.store_root;
        let mut vcs = NativeWorkspaceVcs::from_parts(
            BranchStore::open(root.join("branches.sqlite"))?,
            ContentStore::open_existing(root.join("content.sqlite"))?,
        );
        vcs.set_actor(Some(actor.into()));
        vcs.set_intent(Some(command.into()));
        let path = super::safe_path(&self.engagement.path, &self.relative)?;
        let hash = vcs.content_store().put_file(&path)?;
        if hash != sha256[..32] {
            return Err(WorkspaceError::msg(
                "native upload bytes changed during preparation",
            ));
        }
        let cut_id = self.planned_cut(sha256, byte_len, actor, command)?;
        let changed = std::collections::BTreeMap::from([(self.relative.clone(), hash.clone())]);
        let mut native_check =
            || check().map_err(|_| StoreError::Conflict("original upload authority ended".into()));
        match vcs.import_diff_guarded(
            &self.engagement.branch,
            &changed,
            &[],
            &cut_id,
            &super::now_at(),
            &mut native_check,
        )? {
            VcsWriteOutcome::Written { .. } => {}
            _ => return Err(WorkspaceError::msg("native upload import refused")),
        }
        let cut = vcs
            .get_cut(&cut_id)?
            .ok_or_else(|| WorkspaceError::msg("native upload cut unavailable"))?;
        if cut.actor.as_deref() != Some(actor) || cut.intent.as_deref() != Some(command) {
            return Err(WorkspaceError::msg("native upload attribution changed"));
        }
        let op = vcs
            .get_op(&format!("op-{cut_id}"))?
            .ok_or_else(|| WorkspaceError::msg("native upload receipt unavailable"))?;
        check()?;
        Ok(NativeStreamedUpload {
            target: self,
            cut,
            hash,
            op,
        })
    }
}

impl NativeStreamedUpload {
    pub fn cut(&self) -> &str {
        &self.cut.cut_id
    }
    pub fn hash(&self) -> &str {
        &self.hash
    }

    /// Hold native collection/erasure exclusion across the product reference
    /// commit. No native writes, preparation or network work belong in publish.
    /// A later callback error cannot roll back already committed product facts.
    pub fn publish_retained<T>(&self, publish: impl FnOnce() -> StoreResult<T>) -> StoreResult<T> {
        self.publish_retained_files(
            &std::collections::BTreeMap::from([(self.target.relative.clone(), self.hash.clone())]),
            publish,
        )
    }

    /// Retain the complete uploaded subset of this exact final native cut.
    /// Every submitted binding must match its recorded manifest; retaining only
    /// the last uploaded body cannot protect a multi-file resource publication.
    pub fn publish_retained_files<T>(
        &self,
        files: &std::collections::BTreeMap<String, String>,
        publish: impl FnOnce() -> StoreResult<T>,
    ) -> StoreResult<T> {
        if files.get(&self.target.relative) != Some(&self.hash) {
            return Err(StoreError::Conflict(
                "upload binding omits its exact native result".into(),
            ));
        }
        for path in files.keys() {
            if !valid_native_action_target_path(path) {
                return Err(StoreError::Conflict(
                    "invalid native upload binding path".into(),
                ));
            }
            self.target
                .engagement
                .ensure_selected_path(path)
                .map_err(|_| {
                    StoreError::Conflict("native upload binding exceeds its selected view".into())
                })?;
        }
        let content = ContentStore::open_for_retained_publication(
            self.target.engagement.store_root.join("content.sqlite"),
        )?;
        let mut retained: Vec<String> = files.values().cloned().collect();
        retained.push(self.cut.manifest_hash.clone());
        content.publish_retained(&retained, || {
            let vcs = self.target.observe()?;
            let manifest = vcs
                .cut_manifest(&self.cut.cut_id)?
                .ok_or_else(|| StoreError::Conflict("native upload manifest unavailable".into()))?;
            if vcs.get_cut(&self.cut.cut_id)?.as_ref() != Some(&self.cut)
                || files
                    .iter()
                    .any(|(path, hash)| manifest.get(path) != Some(hash))
                || vcs.get_op(&format!("op-{}", self.cut.cut_id))?.as_ref() != Some(&self.op)
            {
                return Err(StoreError::Conflict(
                    "native upload evidence changed before publication".into(),
                ));
            }
            publish()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_upload_preserves_unrelated_pending_work_and_original_attribution_on_retry() {
        let (dir, instance) = crate::tests::instance();
        let eng = instance.create_engagement("stream-upload").unwrap();
        eng.write_file("existing.txt", "recorded").unwrap();
        eng.commit_turn("base").unwrap();
        eng.write_file("existing.txt", "pending edit").unwrap();
        eng.write_file("unrelated.txt", "pending new file").unwrap();
        let source = dir.path().join("upload.bin");
        let bytes = vec![0xff; 9 * 1024 * 1024];
        let digest = hex::encode(Sha256::digest(&bytes));
        std::fs::write(&source, &bytes).unwrap();
        let target = eng.streamed_upload_target("recording.bin").unwrap();
        target.place_guarded(&source, &mut || Ok(())).unwrap();
        let evidence = target
            .import_placed_file_guarded(
                &digest,
                bytes.len() as u64,
                "human:staff",
                "original-http-command",
                &mut || Ok(()),
            )
            .unwrap();
        let vcs = eng
            .streamed_upload_target("recording.bin")
            .unwrap()
            .observe()
            .unwrap();
        let manifest = vcs.cut_manifest(evidence.cut()).unwrap().unwrap();
        assert_eq!(manifest["recording.bin"], evidence.hash());
        assert_eq!(
            manifest["existing.txt"],
            whipplescript_store::stable_hash_hex("recorded")
        );
        assert!(!manifest.contains_key("unrelated.txt"));
        assert_eq!(
            std::fs::read(eng.path().join("existing.txt")).unwrap(),
            b"pending edit"
        );
        assert_eq!(
            std::fs::read(eng.path().join("unrelated.txt")).unwrap(),
            b"pending new file"
        );
        assert_eq!(
            vcs.content_store().get(evidence.hash()).unwrap().unwrap(),
            bytes
        );
        assert_eq!(evidence.cut.actor.as_deref(), Some("human:staff"));
        assert_eq!(
            evidence.cut.intent.as_deref(),
            Some("original-http-command")
        );
        let retry = eng
            .streamed_upload_target("recording.bin")
            .unwrap()
            .import_placed_file_guarded(
                &digest,
                bytes.len() as u64,
                "human:staff",
                "original-http-command",
                &mut || Ok(()),
            )
            .unwrap();
        assert_eq!(retry.cut, evidence.cut);
        assert_eq!(retry.op, evidence.op);
    }

    #[test]
    fn upload_reference_publication_excludes_erasure_and_refuses_lost_payload_and_receipt() {
        let (_, instance) = crate::tests::instance();
        let eng = instance.create_engagement("retained-upload").unwrap();
        eng.write_file("recording.bin", "exact upload").unwrap();
        let digest = hex::encode(Sha256::digest(b"exact upload"));
        let evidence = eng
            .streamed_upload_target("recording.bin")
            .unwrap()
            .import_placed_file_guarded(&digest, 12, "human:staff", "command", &mut || Ok(()))
            .unwrap();
        let competitor = rusqlite::Connection::open(eng.store_root.join("content.sqlite")).unwrap();
        competitor.busy_timeout(std::time::Duration::ZERO).unwrap();
        let published = evidence
            .publish_retained(|| {
                assert!(competitor.execute_batch("BEGIN IMMEDIATE").is_err());
                Ok("published exact reference")
            })
            .unwrap();
        assert_eq!(published, "published exact reference");
        competitor
            .execute_batch("BEGIN IMMEDIATE; ROLLBACK")
            .unwrap();
        let vcs = NativeWorkspaceVcs::open(
            eng.store_root.join("branches.sqlite"),
            eng.store_root.join("content.sqlite"),
        )
        .unwrap();
        vcs.content_store().erase(evidence.hash(), "now").unwrap();
        assert!(evidence
            .publish_retained::<()>(|| panic!("erased upload published"))
            .is_err());
    }

    #[test]
    fn upload_binding_cannot_publish_an_unselected_recorded_path() {
        let (_dir, instance) = crate::tests::instance();
        instance
            .seed_main(&[
                ("selected/base.txt", "base"),
                ("outside/private.txt", "unselected"),
            ])
            .unwrap();
        let eng = instance
            .create_engagement_subset(
                "selected-upload",
                whipplescript_store::branches::MAINLINE_BRANCH_ID,
                &std::collections::BTreeSet::from(["selected".into()]),
            )
            .unwrap();
        eng.write_file("selected/upload.txt", "uploaded").unwrap();
        let result = eng
            .streamed_upload_target("selected/upload.txt")
            .unwrap()
            .import_placed_file_guarded(
                &hex::encode(Sha256::digest(b"uploaded")),
                8,
                "human:staff",
                "original-command",
                &mut || Ok(()),
            )
            .unwrap();
        let files = std::collections::BTreeMap::from([
            ("selected/upload.txt".into(), result.hash().to_string()),
            (
                "outside/private.txt".into(),
                whipplescript_store::stable_hash_hex("unselected"),
            ),
        ]);
        let vcs = result.target.observe().unwrap();
        assert_eq!(
            vcs.cut_manifest(result.cut()).unwrap().unwrap()["outside/private.txt"],
            files["outside/private.txt"]
        );
        assert!(result
            .publish_retained_files::<()>(&files, || panic!("unselected native path published"))
            .is_err());
    }

    #[test]
    fn complete_upload_binding_retains_earlier_files_and_refuses_substitution() {
        let (_dir, instance) = crate::tests::instance();
        let eng = instance.create_engagement("buffered-upload").unwrap();
        let mut files = std::collections::BTreeMap::new();
        let mut final_result = None;
        for (path, body) in [("first.bin", "first upload"), ("last.bin", "last upload")] {
            eng.write_file(path, body).unwrap();
            let digest = hex::encode(Sha256::digest(body.as_bytes()));
            let result = eng
                .streamed_upload_target(path)
                .unwrap()
                .import_placed_file_guarded(
                    &digest,
                    body.len() as u64,
                    "human:staff",
                    "one-original-command",
                    &mut || Ok(()),
                )
                .unwrap();
            files.insert(path.to_string(), result.hash().to_string());
            final_result = Some(result);
        }
        let result = final_result.unwrap();
        assert_eq!(
            result
                .publish_retained_files(&files, || Ok("complete binding"))
                .unwrap(),
            "complete binding"
        );
        let mut substituted = files.clone();
        substituted.insert("first.bin".into(), files["last.bin"].clone());
        assert!(result
            .publish_retained_files::<()>(&substituted, || panic!("substituted binding published"))
            .is_err());
        let mut missing = files.clone();
        missing.remove("last.bin");
        assert!(result
            .publish_retained_files::<()>(&missing, || panic!("incomplete result published"))
            .is_err());
        let vcs = eng
            .streamed_upload_target("last.bin")
            .unwrap()
            .observe()
            .unwrap();
        let content = ContentStore::open_existing(eng.store_root.join("content.sqlite")).unwrap();
        content.erase(&files["first.bin"], "now").unwrap();
        assert!(vcs
            .content_store()
            .cached_read_available(&files["last.bin"])
            .unwrap());
        assert!(result
            .publish_retained_files::<()>(&files, || panic!("erased earlier upload published"))
            .is_err());
    }

    #[test]
    fn upload_refuses_changed_bytes_or_original_guard_without_importing_any_files() {
        let (_, instance) = crate::tests::instance();
        let eng = instance.create_engagement("refused-upload").unwrap();
        eng.write_file("recording.bin", "actual bytes").unwrap();
        let wrong = hex::encode(Sha256::digest(b"other bytes!"));
        assert!(eng
            .streamed_upload_target("recording.bin")
            .unwrap()
            .import_placed_file_guarded(&wrong, 12, "human:staff", "command", &mut || Ok(()))
            .is_err());
        let right = hex::encode(Sha256::digest(b"actual bytes"));
        assert!(eng
            .streamed_upload_target("recording.bin")
            .unwrap()
            .import_placed_file_guarded(&right, 12, "human:staff", "command", &mut || Err(
                WorkspaceError::msg("removed")
            ))
            .is_err());
        let vcs = eng
            .streamed_upload_target("recording.bin")
            .unwrap()
            .observe()
            .unwrap();
        assert!(vcs
            .get_branch(eng.branch())
            .unwrap()
            .unwrap()
            .head_cut_id
            .is_none());
    }
}
