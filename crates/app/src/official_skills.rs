//! GaugeDesk-owned, versioned skill guides.
//!
//! An official skill is instruction material, not an ability grant. Archetypes
//! pin these references in their discipline manifests; selected guides are then
//! frozen as ordinary read-only discipline assets.

use std::collections::BTreeSet;

use serde::Serialize;

const OFFICIAL_PREFIX: &str = "gaugedesk:official:";

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
pub struct OfficialSkill {
    pub id: &'static str,
    pub reference: &'static str,
    pub name: &'static str,
    pub description: &'static str,
    pub guide: &'static str,
}

const DOCX: OfficialSkill = OfficialSkill {
    id: "docx",
    reference: "gaugedesk:official:docx@1",
    name: "Word documents",
    description: "Create, inspect, and revise Word documents while preserving their structure.",
    guide: "# Word documents\n\nUse this guide for `.docx` files. Inspect an existing document before editing it. Preserve headings, lists, tables, comments, and tracked changes unless the task says otherwise. When creating a document, use semantic headings and styles, keep layout readable, and verify the finished file opens cleanly.\n",
};

const XLSX: OfficialSkill = OfficialSkill {
    id: "xlsx",
    reference: "gaugedesk:official:xlsx@1",
    name: "Excel workbooks",
    description: "Create, inspect, and revise spreadsheets without breaking data or formulas.",
    guide: "# Excel workbooks\n\nUse this guide for `.xlsx`, `.xls`, `.csv`, and `.tsv` files. Inspect sheets, ranges, formulas, and formats before changing a workbook. Preserve formulas and references unless replacement is requested. Make derived values reproducible with formulas where practical, format tables for scanning, and verify workbook structure after edits.\n",
};

const PPTX: OfficialSkill = OfficialSkill {
    id: "pptx",
    reference: "gaugedesk:official:pptx@1",
    name: "PowerPoint presentations",
    description: "Create, inspect, and revise slide decks while preserving layout and intent.",
    guide: "# PowerPoint presentations\n\nUse this guide for `.pptx` files, decks, slides, speaker notes, and presentation templates. Inspect layouts and existing slides before editing. Preserve the source theme and layout when revising a deck. Keep each slide focused, use readable text, and check that added content fits its slide without overlapping other elements.\n",
};

const PDF: OfficialSkill = OfficialSkill {
    id: "pdf",
    reference: "gaugedesk:official:pdf@1",
    name: "PDF files",
    description: "Read, extract, create, and revise PDF documents safely.",
    guide: "# PDF files\n\nUse this guide for `.pdf` files. Determine whether the PDF is text-based, scanned, or a form before working with it. Preserve page order, page size, and form fields unless the task asks to change them. Verify extracted text against the source where accuracy matters, and render or inspect output pages after creating or modifying a PDF.\n",
};

const CATALOG: [OfficialSkill; 4] = [DOCX, XLSX, PPTX, PDF];

pub fn catalog() -> &'static [OfficialSkill] {
    &CATALOG
}

pub fn find(id: &str) -> Option<&'static OfficialSkill> {
    CATALOG.iter().find(|skill| skill.id == id)
}

pub fn office_skill_references() -> BTreeSet<String> {
    CATALOG
        .iter()
        .map(|skill| skill.reference.to_owned())
        .collect()
}

pub fn asset_path(skill: &OfficialSkill) -> String {
    format!("official-skills/{}-v1.md", skill.id)
}

/// Resolve pinned first-party references into their exact, versioned guide
/// bytes. Third-party references remain opaque to GaugeDesk; a malformed or
/// unknown first-party reference fails closed instead of silently degrading the
/// published discipline.
pub fn assets_for(references: &BTreeSet<String>) -> Result<Vec<(String, String)>, String> {
    let mut assets = Vec::new();
    for reference in references {
        if !reference.starts_with(OFFICIAL_PREFIX) {
            continue;
        }
        let skill = CATALOG
            .iter()
            .find(|skill| skill.reference == reference)
            .ok_or_else(|| format!("unknown official skill reference: {reference}"))?;
        assets.push((asset_path(skill), skill.guide.to_owned()));
    }
    Ok(assets)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn office_skill_references_resolve_to_versioned_guides() {
        let references = office_skill_references();
        let assets = assets_for(&references).unwrap();
        assert_eq!(assets.len(), 4);
        assert!(assets.iter().all(|(path, guide)| {
            path.starts_with("official-skills/") && guide.starts_with("# ")
        }));
    }

    #[test]
    fn unknown_official_skill_fails_closed() {
        let references = BTreeSet::from(["gaugedesk:official:unknown@1".to_owned()]);
        assert!(assets_for(&references)
            .unwrap_err()
            .contains("unknown official skill"));
    }
}
