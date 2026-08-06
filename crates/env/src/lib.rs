//! Process-configuration variable names for GaugeDesk.
//!
//! This crate exists because the compatibility window below must have exactly
//! one home, and the crates that read configuration do not share an ancestor:
//! `harness` and `relay-transport` deliberately depend on nothing, so neither
//! `core` nor `store` is reachable from them. A leaf crate with no
//! dependencies of its own is the only shape every layer may use.
//!
//! GaugeWright is the company; GaugeDesk is the product this control plane
//! implements. The variables were originally named for the company, which put
//! nine of them — `ADDR`, `ROOT`, `AUTHORITY`, `HOME_ID`, `CONTENT_KEK_ID`,
//! `ALLOW_NETWORK_HTTP`, `TLS_TERMINATED`, `ATTESTATION_VERIFIER`, and
//! `SQLITE_SYNCHRONOUS` — in collision with the hosted control-plane server,
//! which reads the same names with different meanings. A reader could not tell
//! from a name which process it configured.
//!
//! The product-named `GAUGEDESK_*` form is authoritative. The company-named
//! `GAUGEWRIGHT_*` form is still read so existing scripts, harnesses, and
//! operator habits keep working, and using it prints one warning naming the
//! replacement. **The compatibility fallback is removed after 2026-11-30**;
//! after that date only `GAUGEDESK_*` is read.

use std::collections::BTreeSet;
use std::sync::Mutex;
use std::sync::OnceLock;

/// The date after which only the product-named form is read.
pub const COMPATIBILITY_ENDS: &str = "2026-11-30";

/// Resolve one control-plane variable by its suffix, for example `"ROOT"` for
/// `GAUGEDESK_ROOT`. Prefers the product-named form and falls back to the
/// company-named one until [`COMPATIBILITY_ENDS`].
pub fn var(suffix: &str) -> Option<String> {
    let desk = format!("GAUGEDESK_{suffix}");
    if let Ok(value) = std::env::var(&desk) {
        return Some(value);
    }
    let legacy = format!("GAUGEWRIGHT_{suffix}");
    match std::env::var(&legacy) {
        Ok(value) => {
            warn_once(&legacy, &desk);
            Some(value)
        }
        Err(_) => None,
    }
}

/// The same resolution for a variable whose value may not be valid Unicode,
/// such as a filesystem root.
pub fn var_os(suffix: &str) -> Option<std::ffi::OsString> {
    let desk = format!("GAUGEDESK_{suffix}");
    if let Some(value) = std::env::var_os(&desk) {
        return Some(value);
    }
    let legacy = format!("GAUGEWRIGHT_{suffix}");
    match std::env::var_os(&legacy) {
        Some(value) => {
            warn_once(&legacy, &desk);
            Some(value)
        }
        None => None,
    }
}

/// True when the variable is set to exactly `1` under either name.
pub fn enabled(suffix: &str) -> bool {
    var(suffix).as_deref() == Some("1")
}

fn warn_once(legacy: &str, replacement: &str) {
    static SEEN: OnceLock<Mutex<BTreeSet<String>>> = OnceLock::new();
    let seen = SEEN.get_or_init(|| Mutex::new(BTreeSet::new()));
    let mut seen = match seen.lock() {
        Ok(seen) => seen,
        Err(poisoned) => poisoned.into_inner(),
    };
    if seen.insert(legacy.to_string()) {
        eprintln!(
            "gaugedesk: {legacy} is deprecated; use {replacement}. \
             The compatibility name is removed after {COMPATIBILITY_ENDS}."
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The process environment is global, so these names are unique per test.
    #[test]
    fn the_product_named_form_wins_over_the_company_named_one() {
        std::env::set_var("GAUGEDESK_TEST_PRECEDENCE", "product");
        std::env::set_var("GAUGEWRIGHT_TEST_PRECEDENCE", "company");
        assert_eq!(var("TEST_PRECEDENCE").as_deref(), Some("product"));
    }

    #[test]
    fn the_company_named_form_still_resolves() {
        std::env::set_var("GAUGEWRIGHT_TEST_FALLBACK", "company");
        assert_eq!(var("TEST_FALLBACK").as_deref(), Some("company"));
    }

    #[test]
    fn an_unset_variable_resolves_to_nothing() {
        assert_eq!(var("TEST_NEVER_SET_ANYWHERE"), None);
        assert!(!enabled("TEST_NEVER_SET_ANYWHERE"));
    }

    #[test]
    fn enabled_admits_only_the_exact_opt_in() {
        std::env::set_var("GAUGEDESK_TEST_ENABLED", "1");
        std::env::set_var("GAUGEDESK_TEST_NOT_ENABLED", "true");
        assert!(enabled("TEST_ENABLED"));
        assert!(!enabled("TEST_NOT_ENABLED"));
    }
}
