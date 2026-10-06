//! Guarded placement of completed upload bytes. History and product publication
//! each require their own final authority/retention boundary.
use super::{fresh_cut_id, safe_path, workspace_writer, Engagement, Result, WorkspaceError};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::PoisonError;

struct TemporaryFile {
    path: PathBuf,
    created: bool,
}
impl Drop for TemporaryFile {
    fn drop(&mut self) {
        if self.created {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

impl Engagement {
    /// Place a completed staging file while checking the original embedding
    /// authority at the native effect boundary. The caller holds its product
    /// writer fence; the check inspects only clocks and atomic standing.
    /// Cross-device copying stays provisional until the final checked rename.
    /// This does not import history or grant later resource publication.
    pub fn write_file_from_path_guarded(
        &self,
        relative: &str,
        source: &Path,
        check: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        let writer = workspace_writer(&self.store_root, &self.branch);
        let _writing = writer.lock().unwrap_or_else(PoisonError::into_inner);
        check()?;
        self.ensure_projection()?;
        self.ensure_selected_path(relative)?;
        let path = safe_path(&self.path, relative)?;
        if let Some(parent) = path.parent() {
            check()?;
            std::fs::create_dir_all(parent).map_err(WorkspaceError::io)?;
        }
        // Revalidate after parent preparation and check immediately before the
        // first publication syscall. Non-cross-device failures remain failures.
        let path = safe_path(&self.path, relative)?;
        check()?;
        match std::fs::rename(source, &path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::CrossesDevices => {
                copy_file_guarded(source, &path, check)
            }
            Err(error) => Err(WorkspaceError::io(error)),
        }
    }
}

fn copy_file_guarded(
    source: &Path,
    destination: &Path,
    check: &mut dyn FnMut() -> Result<()>,
) -> Result<()> {
    check()?;
    let mut input = std::fs::File::open(source).map_err(WorkspaceError::io)?;
    if !input.metadata().map_err(WorkspaceError::io)?.is_file() {
        return Err(WorkspaceError::msg(
            "upload staging source is not a regular file",
        ));
    }
    let parent = destination
        .parent()
        .ok_or_else(|| WorkspaceError::msg("upload destination has no parent"))?;
    let provisional = parent.join(format!(".gaugedesk-upload-{}", fresh_cut_id("copy")));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    check()?;
    // Arm cleanup only for a file this invocation created. Declare it before
    // the output handle so refusal closes the file before removal on Windows.
    let mut temporary = TemporaryFile {
        path: provisional,
        created: false,
    };
    let mut output = options.open(&temporary.path).map_err(WorkspaceError::io)?;
    temporary.created = true;
    let mut window = [0u8; 64 * 1024];
    loop {
        check()?;
        let read = input.read(&mut window).map_err(WorkspaceError::io)?;
        if read == 0 {
            break;
        }
        check()?;
        output
            .write_all(&window[..read])
            .map_err(WorkspaceError::io)?;
    }
    output.sync_all().map_err(WorkspaceError::io)?;
    drop(output);
    check()?;
    std::fs::rename(&temporary.path, destination).map_err(WorkspaceError::io)?;
    temporary.created = false;
    let _ = std::fs::remove_file(source);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guarded_file_move_refuses_before_effect_without_creating_history() {
        let (directory, instance) = crate::tests::instance();
        let eng = instance.create_engagement("guarded-upload").unwrap();
        let source = directory.path().join("staged.bin");
        std::fs::write(&source, [0xff, 0, 0x89]).unwrap();
        let before = crate::tests::observation_files(directory.path());
        assert!(eng
            .write_file_from_path_guarded("take.bin", &source, &mut || Err(WorkspaceError::msg(
                "original session ended"
            )))
            .is_err());
        assert_eq!(crate::tests::observation_files(directory.path()), before);
        eng.write_file_from_path_guarded("take.bin", &source, &mut || Ok(()))
            .unwrap();
        assert!(!source.exists());
        assert_eq!(
            std::fs::read(eng.path().join("take.bin")).unwrap(),
            [0xff, 0, 0x89]
        );
        let vcs = whipplescript_store::vcs::NativeWorkspaceVcs::open_read_only(
            eng.store_root.join("branches.sqlite"),
            eng.store_root.join("content.sqlite"),
        )
        .unwrap();
        assert!(
            vcs.get_branch(eng.branch())
                .unwrap()
                .unwrap()
                .head_cut_id
                .is_none(),
            "file custody is not a native history admission"
        );
    }

    #[test]
    fn guarded_copy_refuses_expiry_after_complete_bytes_before_destination_swap() {
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("source.bin");
        let destination = directory.path().join("take.bin");
        let body = vec![0x89; 128 * 1024];
        std::fs::write(&source, &body).unwrap();
        std::fs::write(&destination, b"previous bytes").unwrap();
        let mut current = true;
        let mut completed = false;
        assert!(copy_file_guarded(&source, &destination, &mut || {
            if !current {
                return Err(WorkspaceError::msg(
                    "original session expired after final read",
                ));
            }
            for entry in std::fs::read_dir(directory.path()).unwrap() {
                let entry = entry.unwrap();
                if entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".gaugedesk-upload-")
                    && entry.metadata().unwrap().len() == body.len() as u64
                {
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        assert_eq!(
                            entry.metadata().unwrap().permissions().mode() & 0o077,
                            0,
                            "provisional PHI has no group/world permission"
                        );
                    }
                    completed = true;
                    // Expiry follows a successful check after real completed
                    // copying, before the final destination publication.
                    current = false;
                }
            }
            Ok(())
        })
        .is_err());
        assert!(completed);
        assert_eq!(std::fs::read(&destination).unwrap(), b"previous bytes");
        assert_eq!(std::fs::read(&source).unwrap(), body);
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 2);
    }

    #[test]
    fn guarded_copy_refuses_after_real_progress_preserving_source_and_previous_destination() {
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("source.bin");
        let destination = directory.path().join("take.bin");
        let body = vec![0xff; 192 * 1024];
        std::fs::write(&source, &body).unwrap();
        std::fs::write(&destination, b"previous bytes").unwrap();
        let mut copied = false;
        assert!(copy_file_guarded(&source, &destination, &mut || {
            // Inject expiry after the actual provisional file received bytes.
            // Production checks use only the captured process/clock guards.
            copied = std::fs::read_dir(directory.path()).unwrap().any(|entry| {
                let entry = entry.unwrap();
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".gaugedesk-upload-")
                    && entry.metadata().unwrap().len() > 0
            });
            if copied {
                Err(WorkspaceError::msg("original session expired during copy"))
            } else {
                Ok(())
            }
        })
        .is_err());
        assert!(copied);
        assert_eq!(std::fs::read(&destination).unwrap(), b"previous bytes");
        assert_eq!(std::fs::read(&source).unwrap(), body);
        assert_eq!(
            std::fs::read_dir(directory.path()).unwrap().count(),
            2,
            "no provisional PHI remains after refusal"
        );
        copy_file_guarded(&source, &destination, &mut || Ok(())).unwrap();
        assert_eq!(std::fs::read(&destination).unwrap(), body);
        assert!(!source.exists());
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 1);
    }
}
