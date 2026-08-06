//! Projection freshness — the explicit currentness marker every cached
//! projection carries before it is shown to a client (ADR 0037, spec 015).
//!
//! The core decision (spec 015): projection uncertainty must be *explicit*. If
//! the system lacks basis to prove a current view it must not silently show old
//! state as current, nor collapse uncertainty into success/failure. So a
//! projection never travels bare — it travels as a `Freshness` carrying a
//! `FreshnessMarker` and the basis (`generated_at`) the marker was decided
//! against. The imperative shell materializes the clock; the core decides
//! whether a marker may be presented as live.
//!
//! This slice carries the five markers the mobile projection client
//! distinguishes (ADR 0037): the wider conceptual set in spec 015
//! (`current_snapshot`/`blocked`/`unsupported`/`offline`/`compacted`) lands with
//! the projection-carriage and connection-state work that consumes it.

/// How current a projection is, relative to the requested scope's admitted
/// basis. A consumer must never render anything but `Live` as current.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FreshnessMarker {
    /// Connected to the current admitted basis for the requested scope.
    Live,
    /// Known to be behind, or unable to refresh from its last basis.
    Stale,
    /// Intentionally missing material outside the requested/allowed scope.
    Partial,
    /// Material exists but is hidden or minimized by policy (`INV-10`).
    Redacted,
    /// The authority cannot decide currentness from the available basis.
    Indeterminate,
}

impl FreshnessMarker {
    /// Whether a projection carrying this marker may be presented as the current
    /// truth. Only `Live` may — every other marker is an explicit caveat that
    /// must surface to the consumer rather than read as success.
    pub fn is_current(self) -> bool {
        matches!(self, FreshnessMarker::Live)
    }
}

/// A freshness stamp: the marker plus the basis it was decided against. A
/// projection is never shown as current without one.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Freshness {
    /// How current the projection is.
    pub marker: FreshnessMarker,
    /// The clock value the marker was decided against (the shell supplies it).
    pub generated_at: u64,
    /// An optional affordance describing how to refresh/repair a non-live view.
    pub repair_hint: Option<String>,
}

impl Freshness {
    /// A live stamp at `generated_at` with no repair hint.
    pub fn live(generated_at: u64) -> Self {
        Self {
            marker: FreshnessMarker::Live,
            generated_at,
            repair_hint: None,
        }
    }

    /// A non-live stamp at `generated_at`, optionally describing how to repair.
    pub fn stale(marker: FreshnessMarker, generated_at: u64, repair_hint: Option<String>) -> Self {
        Self {
            marker,
            generated_at,
            repair_hint,
        }
    }

    /// Whether the stamped projection may be presented as current truth.
    pub fn is_current(&self) -> bool {
        self.marker.is_current()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_live_is_current() {
        assert!(FreshnessMarker::Live.is_current());
        for m in [
            FreshnessMarker::Stale,
            FreshnessMarker::Partial,
            FreshnessMarker::Redacted,
            FreshnessMarker::Indeterminate,
        ] {
            assert!(!m.is_current(), "{m:?} must not read as current");
        }
    }

    #[test]
    fn freshness_currentness_follows_marker() {
        assert!(Freshness::live(7).is_current());
        let s = Freshness::stale(FreshnessMarker::Stale, 7, Some("refresh".into()));
        assert!(!s.is_current());
        assert_eq!(s.repair_hint.as_deref(), Some("refresh"));
    }

    #[test]
    fn marker_serializes_snake_case() {
        // The wire tag is the snake_case variant name, so the TS
        // projection-carriage types (MOB-007) and the projection API agree on
        // the string form. Probe the tag via ciborium's value model (no
        // serde_json dep in gaugedesk-core).
        let mut bytes = Vec::new();
        ciborium::into_writer(&FreshnessMarker::Indeterminate, &mut bytes).unwrap();
        let value: ciborium::value::Value = ciborium::from_reader(bytes.as_slice()).unwrap();
        assert_eq!(value.as_text(), Some("indeterminate"));

        let restored: FreshnessMarker = ciborium::from_reader(bytes.as_slice()).unwrap();
        assert_eq!(restored, FreshnessMarker::Indeterminate);
    }

    #[test]
    fn freshness_round_trips() {
        let f = Freshness::stale(FreshnessMarker::Partial, 42, None);
        let mut bytes = Vec::new();
        ciborium::into_writer(&f, &mut bytes).unwrap();
        let restored: Freshness = ciborium::from_reader(bytes.as_slice()).unwrap();
        assert_eq!(restored, f);
    }
}
