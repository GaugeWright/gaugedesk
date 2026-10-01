//! A provider's default model against the shipped catalog (DR-0287).
//!
//! The default is what an unpinned turn runs and what the picker's first row
//! names, so it must be a current row of the catalog: a default the catalog
//! marks legacy, or does not list, names a model the uncurated picker does not
//! offer. This lives in its own test target because the catalog is then an
//! input of this crate's tests alone.

use serde_json::Value;

#[test]
fn every_provider_default_is_a_current_catalog_model() {
    let catalog: Vec<Value> = serde_json::from_str(include_str!(
        "../../../web/packages/workbench-ui/src/model-catalog.json"
    ))
    .unwrap();
    for provider in ["openai", "anthropic", "openai-codex", "xai"] {
        let model = gaugedesk_whip_runtime::native_provider_descriptor(provider, None, None)
            .unwrap_or_else(|e| panic!("{provider} has no default model: {e}"))
            .model;
        let row = catalog
            .iter()
            .find(|row| row["provider"] == provider && row["id"] == model.as_str())
            .unwrap_or_else(|| panic!("{provider} default {model} is not in the catalog"));
        assert_ne!(
            row["legacy"],
            Value::Bool(true),
            "{provider} default {model} is a legacy catalog row"
        );
    }
}
