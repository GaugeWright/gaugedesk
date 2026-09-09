//! The exact WhippleScript host contract GaugeDesk's project-workstream code
//! is allowed to consume. `scripts/check-whipplescript-workstream-contract.mjs`
//! binds these runtime values to the public Git dependency and the pin manifest.

pub const REVISION: &str = "whipplescript-workstream-host/v1.0.3";
pub const DIGEST: &str = "079c53e8953a43c890267a6a0ad330f5b3947b973a974ae60820132c2c95d244";

/// Every superseded pin a persisted state root may still carry, newest first,
/// each with the digest it was published under.
///
/// This is a set of accepted starting points, not a sequence of steps, because
/// bringing a workspace forward rewrites the two pin fields and nothing else —
/// `workspace_id`, `home_id`, and `substrate` are validated and preserved, and
/// no workspace content is touched. What makes that sound across the whole
/// range is that every revision here is a `v1` of one contract whose
/// `normative_surface` and `authority` never changed: `v1.0.0` to `v1.0.3` adds
/// six operations and removes none, so a workspace pinned at any of them is
/// admissible under the current host, which offers a superset of what it was
/// created against. A revision that removed or altered an operation could not
/// be listed here, and a major-version change never could.
///
/// Both halves are matched. A known revision label carrying an unexpected
/// digest is not an old state root; it is one this build has no basis to
/// reason about, and it is refused rather than relabelled.
///
/// **A single previous entry is not enough.** This held only
/// `MIGRATABLE_PREVIOUS_REVISION`/`_DIGEST` — the one immediately superseded
/// pin — so a state root that skipped a release was refused outright, with an
/// error telling its owner to "repair/reset" it. That is not a repair anyone
/// should perform on live data, and on 2026-09-09 it took the production Hub
/// down: its `proj-default` workspace was still at `v1.0.0`, so every new
/// binary panicked at startup and `auth.gaugewright.com` served 502 until the
/// image was rolled back. A pin retired here must therefore stay here.
pub(crate) const MIGRATABLE_SUPERSEDED_PINS: &[(&str, &str)] = &[
    (
        "whipplescript-workstream-host/v1.0.2",
        "a6ac1ea8be061c728c89dd2b4b005f206e604a151260ae329f34bd1bdbcdc5b0",
    ),
    (
        "whipplescript-workstream-host/v1.0.1",
        "40d9dba3fd43d6ed531457ff40e0c92b1b6847ac66e799992e04685e7ff2a25d",
    ),
    (
        "whipplescript-workstream-host/v1.0.0",
        "7766b8cb9a824ae43c7523fd92295dca21f26e7c9abf156f5a46663ce9b1b0f7",
    ),
];

/// Whether a persisted pin is one this build can bring forward to [`REVISION`].
pub(crate) fn is_migratable_pin(revision: &str, digest: &str) -> bool {
    MIGRATABLE_SUPERSEDED_PINS
        .iter()
        .any(|(superseded_revision, superseded_digest)| {
            *superseded_revision == revision && *superseded_digest == digest
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn superseded_pins_are_distinct_and_exclude_the_current_one() {
        // The current pin is recognised by the equality check that precedes any
        // migration, so listing it here would make an already-current workspace
        // look like one needing a rewrite.
        for (revision, digest) in MIGRATABLE_SUPERSEDED_PINS {
            assert_ne!(
                *revision, REVISION,
                "the current revision is not superseded"
            );
            assert_ne!(*digest, DIGEST, "the current digest is not superseded");
            assert_eq!(digest.len(), 64, "{revision} digest must be a sha256");
            assert!(
                digest
                    .chars()
                    .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
                "{revision} digest must be lowercase hexadecimal",
            );
        }
        let mut seen = std::collections::BTreeSet::new();
        for (revision, _) in MIGRATABLE_SUPERSEDED_PINS {
            assert!(seen.insert(*revision), "{revision} is listed twice");
        }
    }

    #[test]
    fn a_known_revision_with_a_foreign_digest_is_not_migratable() {
        let (revision, digest) = MIGRATABLE_SUPERSEDED_PINS[0];
        assert!(is_migratable_pin(revision, digest));
        assert!(!is_migratable_pin(revision, DIGEST));
        assert!(!is_migratable_pin(REVISION, DIGEST));
        assert!(!is_migratable_pin(
            "whipplescript-workstream-host/v0.9.9",
            digest
        ));
    }
}
