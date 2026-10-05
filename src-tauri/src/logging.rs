//! The desktop shell's persistent log (DR-0320).
//!
//! The co-resident control plane runs in this process, so its `tracing` events
//! have no subscriber unless the shell installs one, and a Finder- or
//! Start-menu-launched app discards stderr. Before this, a control plane that
//! refused to start — a store written by a newer build — left no trace anywhere,
//! and the window could only say "Load failed".
//!
//! Events go to a daily file in the platform log directory
//! (`~/Library/Logs/com.gaugewright.gaugedesk/` on macOS) and to stderr. The file
//! is written synchronously, so a fatal line is on disk before the process exits.
//! Seven files are kept. The level is `RUST_LOG` when set, otherwise `info`.
//!
//! The `audit` target never reaches either sink, whatever `RUST_LOG` says: it
//! names the actor, which can be a person's address, and the audit trail has its
//! own append-only store. Every other event is operational metadata by RF-A8, so
//! the file is ephemeral evidence in `specs/data-classification.md`.

use std::path::Path;

use tracing_appender::rolling::{InitError, RollingFileAppender, Rotation};
use tracing_subscriber::{fmt, layer::SubscriberExt, EnvFilter, Layer, Registry};

const DEFAULT_FILTER: &str = "info";
const FILE_PREFIX: &str = "gaugedesk";
const KEPT_FILES: usize = 7;

/// The filter both sinks use: `spec` (normally `RUST_LOG`) or the default, with
/// the audit target always off.
fn filter(spec: Option<&str>) -> EnvFilter {
    let spec = spec.map(str::trim).filter(|s| !s.is_empty());
    let filter = spec
        .and_then(|s| EnvFilter::try_new(s).ok())
        .unwrap_or_else(|| EnvFilter::new(DEFAULT_FILTER));
    filter.add_directive("audit=off".parse().expect("static directive"))
}

fn appender(dir: &Path) -> Result<RollingFileAppender, InitError> {
    RollingFileAppender::builder()
        .rotation(Rotation::DAILY)
        .filename_prefix(FILE_PREFIX)
        .filename_suffix("log")
        .max_log_files(KEPT_FILES)
        .build(dir)
}

fn subscriber(
    dir: &Path,
    spec: Option<&str>,
    stderr: bool,
) -> Result<impl tracing::Subscriber + Send + Sync, InitError> {
    let file = fmt::layer()
        .with_ansi(false)
        .with_writer(appender(dir)?)
        .with_filter(filter(spec));
    let stderr = stderr.then(|| {
        fmt::layer()
            .with_writer(std::io::stderr)
            .with_filter(filter(spec))
    });
    Ok(Registry::default().with(file).with(stderr))
}

/// Install the shell's subscriber and log panics through it. On failure the
/// shell runs on with stderr alone, since a missing log is no reason to refuse
/// the person their workbench.
pub fn init(dir: &Path) {
    let spec = std::env::var("RUST_LOG").ok();
    let installed = std::fs::create_dir_all(dir)
        .map_err(|e| e.to_string())
        .and_then(|()| subscriber(dir, spec.as_deref(), true).map_err(|e| e.to_string()))
        .and_then(|s| tracing::subscriber::set_global_default(s).map_err(|e| e.to_string()));
    if let Err(e) = installed {
        // Keep stderr, so a source build run from a terminal still says why.
        let _ = tracing::subscriber::set_global_default(
            Registry::default().with(
                fmt::layer()
                    .with_writer(std::io::stderr)
                    .with_filter(filter(spec.as_deref())),
            ),
        );
        tracing::warn!("no persistent log at {}: {e}", dir.display());
        return;
    }
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        tracing::error!(target: "panic", "{info}");
        previous(info);
    }));
    tracing::info!(version = env!("CARGO_PKG_VERSION"), dir = %dir.display(), "GaugeDesk started");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("gaugedesk-logging-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    fn written(dir: &Path) -> String {
        std::fs::read_dir(dir)
            .unwrap()
            .map(|entry| std::fs::read_to_string(entry.unwrap().path()).unwrap())
            .collect()
    }

    fn emit(dir: &Path, spec: Option<&str>) -> String {
        std::fs::create_dir_all(dir).unwrap();
        let subscriber = subscriber(dir, spec, false).unwrap();
        tracing::subscriber::with_default(subscriber, || {
            tracing::info!("control plane exited: store too new");
            tracing::debug!("a debug detail");
            tracing::info!(target: "audit", actor = "person@example.com", "audit entry");
        });
        let text = written(dir);
        let _ = std::fs::remove_dir_all(dir);
        text
    }

    #[test]
    fn writes_info_to_a_dated_file_and_never_the_audit_target() {
        let dir = scratch("default");
        let text = emit(&dir, None);
        assert!(
            text.contains("control plane exited: store too new"),
            "{text}"
        );
        assert!(!text.contains("a debug detail"), "{text}");
        assert!(!text.contains("person@example.com"), "{text}");
        assert!(
            !text.contains('\u{1b}'),
            "no ANSI escapes in the file: {text}"
        );
    }

    #[test]
    fn rust_log_widens_the_level_but_cannot_admit_audit() {
        let dir = scratch("widened");
        let text = emit(&dir, Some("debug,audit=info"));
        assert!(text.contains("a debug detail"), "{text}");
        assert!(!text.contains("person@example.com"), "{text}");
    }

    #[test]
    fn an_unparseable_filter_falls_back_to_the_default() {
        let dir = scratch("unparseable");
        let text = emit(&dir, Some("=[not a filter"));
        assert!(text.contains("control plane exited"), "{text}");
        assert!(!text.contains("a debug detail"), "{text}");
    }

    #[test]
    fn files_are_named_for_the_app() {
        let dir = scratch("named");
        std::fs::create_dir_all(&dir).unwrap();
        let subscriber = subscriber(&dir, None, false).unwrap();
        tracing::subscriber::with_default(subscriber, || tracing::info!("one line"));
        let names: Vec<String> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(names.len(), 1, "{names:?}");
        assert!(
            names[0].starts_with("gaugedesk.") && names[0].ends_with(".log"),
            "{names:?}"
        );
    }
}
