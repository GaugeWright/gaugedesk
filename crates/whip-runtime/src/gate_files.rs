//! Bind a gate's logical file store to its per-arrival quarantine directory.
//! The effect and its declared read policy remain the runtime's immutable input.
use std::io;
use std::path::{Component, Path, PathBuf};
use whipplescript_store::files::{FileStore, NativeFileStore};

pub(super) struct GateFiles<'a> {
    logical_root: &'a Path,
    physical_root: &'a Path,
}

impl<'a> GateFiles<'a> {
    pub(super) fn new(logical_root: &'a Path, physical_root: &'a Path) -> Self {
        Self {
            logical_root,
            physical_root,
        }
    }

    fn resolve(&self, path: &Path) -> io::Result<PathBuf> {
        let relative = path
            .strip_prefix(self.logical_root)
            .map_err(|_| denied("file is outside the bound logical store"))?;
        if relative
            .components()
            .any(|part| !matches!(part, Component::Normal(_) | Component::CurDir))
        {
            return Err(denied("file escapes the bound logical store"));
        }
        if let Some(reason) =
            NativeFileStore.path_policy_error(self.physical_root, relative, "quarantine", "read")
        {
            return Err(denied(&reason));
        }
        Ok(self.physical_root.join(relative))
    }
}

fn denied(reason: &str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, reason)
}

impl FileStore for GateFiles<'_> {
    fn read_to_string(&self, path: &Path) -> io::Result<String> {
        NativeFileStore.read_to_string(&self.resolve(path)?)
    }

    fn exists(&self, path: &Path) -> bool {
        self.resolve(path)
            .is_ok_and(|path| NativeFileStore.exists(&path))
    }

    fn path_policy_error(
        &self,
        root: &Path,
        relative: &Path,
        _store: &str,
        operation: &str,
    ) -> Option<String> {
        if root != self.logical_root || operation != "read" {
            return Some("gate file binding permits only its declared store's reads".into());
        }
        self.resolve(&root.join(relative))
            .err()
            .map(|error| error.to_string())
    }

    fn create_dir_all(&self, _: &Path) -> io::Result<()> {
        Err(denied("gate file binding is read-only"))
    }
    fn write(&self, _: &Path, _: &[u8]) -> io::Result<()> {
        Err(denied("gate file binding is read-only"))
    }
    fn append(&self, _: &Path, _: &[u8]) -> io::Result<()> {
        Err(denied("gate file binding is read-only"))
    }
    fn remove(&self, _: &Path) -> io::Result<()> {
        Err(denied("gate file binding is read-only"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_logical_store_reads_only_its_bound_arrival() {
        let first = tempfile::tempdir().unwrap();
        let second = tempfile::tempdir().unwrap();
        std::fs::write(first.path().join("item.json"), "first").unwrap();
        std::fs::write(second.path().join("item.json"), "second").unwrap();
        let logical = Path::new("./quarantine");
        let first_files = GateFiles::new(logical, first.path());
        let second_files = GateFiles::new(logical, second.path());
        let path = logical.join("item.json");
        assert_eq!(first_files.read_to_string(&path).unwrap(), "first");
        assert_eq!(second_files.read_to_string(&path).unwrap(), "second");
        for outside in [
            Path::new("other/item.json"),
            Path::new("quarantine/../item.json"),
            second.path(),
        ] {
            assert!(first_files.read_to_string(outside).is_err());
        }
        assert!(first_files
            .path_policy_error(
                Path::new("other"),
                Path::new("item.json"),
                "quarantine",
                "read"
            )
            .is_some());
        assert!(first_files
            .path_policy_error(logical, Path::new("item.json"), "quarantine", "write")
            .is_some());
        assert!(first_files.write(&path, b"changed").is_err());
        assert!(first_files.append(&path, b"changed").is_err());
        assert!(first_files.remove(&path).is_err());
        assert!(first_files.create_dir_all(&logical.join("new")).is_err());
        assert_eq!(
            std::fs::read_to_string(first.path().join("item.json")).unwrap(),
            "first"
        );
        assert!(!first.path().join("new").exists());
    }

    #[cfg(unix)]
    #[test]
    fn bound_reads_refuse_symlink_escape() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("private"), "outside").unwrap();
        std::os::unix::fs::symlink(outside.path(), root.path().join("link")).unwrap();
        let logical = Path::new("quarantine");
        let files = GateFiles::new(logical, root.path());
        assert!(files.read_to_string(&logical.join("link/private")).is_err());
        assert!(!files.exists(&logical.join("link/private")));
    }
}
