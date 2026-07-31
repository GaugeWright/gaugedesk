//! The shipped gate program is real WhippleScript (ADR 0110 §3, GATE-3).
//!
//! A gate we ship but never parse is the same class of bug as a sealing
//! construction nobody cross-checked: everything looks correct until the first
//! real run, and by then the failure is in production. So the program text in
//! `gate.rs` goes through the actual compiler here rather than being trusted
//! because it reads like the manual.
//!
//! This compiles the program. It does not run it — executing the gate needs a
//! provider binding for the `coerce`, which is the remaining half of GATE-3.

use gaugewright_app::gate::{
    COERCE_SCREEN_ENVELOPE, COERCE_SCREEN_GATE, REVIEW_BY_HAND_ENVELOPE, REVIEW_BY_HAND_GATE,
};

#[test]
fn the_shipped_screening_gate_compiles() {
    let compiled = whipplescript_parser::compile_program(COERCE_SCREEN_GATE);
    let blocking: Vec<&str> = compiled
        .diagnostics
        .iter()
        .map(|diagnostic| diagnostic.message.as_str())
        .collect();
    assert!(
        compiled.ir.is_some(),
        "the shipped gate does not compile: {blocking:#?}",
    );
}

#[test]
fn the_shipped_envelope_parses_and_authorizes_the_crossing() {
    // `from_dsl` is the real check: it accepts only a well-formed envelope, so a
    // malformed `grant endorse` clause fails here rather than at the first run.
    // That the clause is *present* is asserted beside the program text itself.
    gaugewright_whip_runtime::ifc::Envelope::from_dsl(COERCE_SCREEN_ENVELOPE)
        .expect("the shipped envelope parses");
}

/// The proof that the gate is a *gate*.
///
/// Compiling proves the program is well formed. This proves the crossing is
/// governed: with `grant endorse` the checker accepts the endorsed coercion,
/// and with the clause removed — the envelope otherwise identical — it refuses.
/// Without this, an envelope that silently lost its grant would look like a
/// working gate right up until a real run.
#[test]
fn the_endorsed_crossing_is_refused_without_its_grant() {
    use gaugewright_whip_runtime::ifc::{check_with_envelope, VerifiedEnvelope};

    let ir = whipplescript_parser::compile_program(COERCE_SCREEN_GATE)
        .ir
        .expect("the shipped gate compiles");

    let granted = VerifiedEnvelope::verify_text(COERCE_SCREEN_ENVELOPE)
        .expect("the shipped envelope verifies");
    let with_grant = check_with_envelope(&ir, &granted);
    assert!(
        with_grant.is_empty(),
        "the shipped gate must pass its own envelope: {:#?}",
        with_grant.iter().map(|d| &d.message).collect::<Vec<_>>(),
    );

    let stripped: String = COERCE_SCREEN_ENVELOPE
        .lines()
        .filter(|line| !line.starts_with("grant endorse"))
        .map(|line| format!("{line}\n"))
        .collect();
    let ungranted = VerifiedEnvelope::verify_text(&stripped).expect("still a valid envelope");
    let without_grant = check_with_envelope(&ir, &ungranted);
    assert!(
        !without_grant.is_empty(),
        "removing `grant endorse` must break the crossing; if this passes, the \
         grant is decoration and untrusted data reaches trusted state ungoverned",
    );
}

/// The default gate compiles too, and reaches its reviewer through the tracker
/// rather than a blocking ask — `askHuman` no longer exists (DR-0050), so a gate
/// still using it would fail here rather than at the first real review.
#[test]
fn the_shipped_review_gate_compiles() {
    let compiled = whipplescript_parser::compile_program(REVIEW_BY_HAND_GATE);
    let blocking: Vec<&str> = compiled
        .diagnostics
        .iter()
        .map(|diagnostic| diagnostic.message.as_str())
        .collect();
    assert!(
        compiled.ir.is_some(),
        "the shipped review gate does not compile: {blocking:#?}",
    );
    assert!(
        !REVIEW_BY_HAND_GATE.contains("askHuman"),
        "the review gate must reach its reviewer through the tracker",
    );
}

#[test]
fn the_review_gate_envelope_parses() {
    gaugewright_whip_runtime::ifc::VerifiedEnvelope::verify_text(REVIEW_BY_HAND_ENVELOPE)
        .expect("the shipped review envelope parses");
}

/// Both shipped gates go through `gate::admit` — the check the product actually
/// runs before any side effect.
///
/// The asymmetry this closes is why the defect survived: `coerce-screen` had a
/// full `check_with_envelope` test, `review-by-hand` had only "compiles" and
/// "envelope parses". So the one gate that never had its flows checked is the
/// one whose flows did not check, and it is the default every project is seeded
/// with.
///
/// Both admit now. `review-by-hand` used to be asserted here as a deliberate
/// *refusal*, because a rule guarded by a public fact could not record an
/// Operator-integrity fact and the only crossing the language sanctioned was a
/// source-marked `endorsed` coerce — which a human gate has none of by design.
/// WhippleScript DR-0051 gave a person's decision a crossing of its own, and the
/// gate now carries it.
#[test]
fn the_shipped_gates_admit() {
    gaugewright_app::gate::admit(COERCE_SCREEN_GATE, COERCE_SCREEN_ENVELOPE)
        .expect("the screening gate admits: its endorsed coerce is the sanctioned crossing");
    gaugewright_app::gate::admit(REVIEW_BY_HAND_GATE, REVIEW_BY_HAND_ENVELOPE)
        .expect("the human gate admits: a reviewer's claim on a vouched queue is the crossing");
}

/// The human gate's crossing is governed, not decorative.
///
/// Drop the tracker grant and the endorsement has no vouched queue to draw
/// authority from — an agent could otherwise file its own verdict and claim it.
/// Without this, an envelope that silently lost that grant would look like a
/// working gate right up until a real review.
#[test]
fn the_human_crossing_is_refused_without_a_vouched_queue() {
    let stripped: String = REVIEW_BY_HAND_ENVELOPE
        .lines()
        .filter(|line| !line.starts_with("grant tracker verdicts"))
        .map(|line| format!("{line}\n"))
        .collect();
    let refusal = gaugewright_app::gate::admit(REVIEW_BY_HAND_GATE, &stripped)
        .expect_err("an unvouched queue may not endorse");
    let message = refusal.to_string();
    assert!(
        message.contains("nobody vouches"),
        "refused for the right reason: {message}"
    );
}

/// `coerce-screen` escalates what it distrusts instead of dropping it.
///
/// ADR 0110 §6 promises "`flag` escalates to a human rather than being
/// discarded", and the shipped program recorded the screener's `flag` as the
/// final verdict — which `apply_verdict` turns into `Rejected`, the item never
/// seen again. Asserted structurally because the difference is invisible to
/// `admit`: a gate that discards compiles and satisfies its envelope perfectly.
#[test]
fn the_screening_gate_escalates_rather_than_discarding() {
    assert!(
        COERCE_SCREEN_GATE.contains("file issue into review"),
        "a flagged item reaches a person",
    );
    assert!(
        COERCE_SCREEN_GATE.contains("claim v as hold endorsed"),
        "and their verdict comes back through the endorsement crossing",
    );
    // The screener's own verdict must not be the final word for a flagged item:
    // the only unconditional `Screening` record is in the `keep` arm.
    let flag_arm = COERCE_SCREEN_GATE
        .split("\"flag\" => {")
        .nth(1)
        .expect("the gate has a flag arm");
    let flag_arm = &flag_arm[..flag_arm.find("      }").unwrap_or(flag_arm.len())];
    assert!(
        !flag_arm.contains("record Screening"),
        "a flagged item is not settled by the screener: {flag_arm}",
    );
}

/// GATE-4's last clause: the crossing is *visible* to an audit, not merely legal.
///
/// A gate is the one program in the product whose whole job is to raise
/// untrusted material to trusted, so "which crossings does this gate contain"
/// is the question an operator reviewing a project's gate actually has — and
/// after ADR 0110 §5 the gate is an author-editable program, so the answer can
/// change without anyone shipping a release.
///
/// Discharging this found a real defect, in WhippleScript rather than here:
/// DR-0051 §2 promised an endorsed *claim* prints in the trusted surface
/// "exactly as an endorsed coerce is", and it never did — the surface is built
/// by walking a rule's effects for the `endorsed` flag, and a claim is not an
/// effect. So `review-by-hand`, whose only crossing is a person's adopted
/// decision, rendered a report with no source crossing on it at all. Fixed in
/// 0.4.1; this is the test that would have caught it.
#[test]
fn both_gates_print_their_crossings_in_the_guarantee_report() {
    for (name, program, envelope) in [
        (
            "review-by-hand",
            REVIEW_BY_HAND_GATE,
            REVIEW_BY_HAND_ENVELOPE,
        ),
        ("coerce-screen", COERCE_SCREEN_GATE, COERCE_SCREEN_ENVELOPE),
    ] {
        let verified = gaugewright_whip_runtime::ifc::VerifiedEnvelope::verify_text(envelope)
            .expect("the shipped envelope verifies");
        let ir = gaugewright_whip_runtime::compile_whip_program(program)
            .ir
            .expect("the shipped gate compiles");
        let surface =
            gaugewright_whip_runtime::ifc::governance_report(&ir, &verified).trusted_surface;

        // The governance half: the envelope names who may endorse.
        assert!(
            surface
                .iter()
                .any(|crossing| crossing.starts_with("endorse ")),
            "{name}: the envelope's endorse grant is on the audit surface: {surface:#?}",
        );
        // The source half: where the program claims the crossing. Every gate has
        // the human one, because `coerce-screen` escalates what it distrusts to
        // the same `settle` rule review-by-hand parks on.
        assert!(
            surface.iter().any(|crossing| {
                crossing.contains("endorsed (source)")
                    && crossing.contains("settle")
                    && crossing.contains("verdicts")
            }),
            "{name}: the reviewer's claim on `verdicts` is on the audit surface: {surface:#?}",
        );
    }

    // And the screener's own crossing, which only the screening gate has.
    let verified =
        gaugewright_whip_runtime::ifc::VerifiedEnvelope::verify_text(COERCE_SCREEN_ENVELOPE)
            .expect("verifies");
    let ir = gaugewright_whip_runtime::compile_whip_program(COERCE_SCREEN_GATE)
        .ir
        .expect("compiles");
    let surface = gaugewright_whip_runtime::ifc::governance_report(&ir, &verified).trusted_surface;
    assert!(
        surface.iter().any(|crossing| {
            crossing.contains("endorsed (source)") && crossing.contains("screen_item")
        }),
        "the classifier's crossing is on the audit surface: {surface:#?}",
    );
    // What it carries is stated, not left to the reader: the screener's verdict
    // is shaped by quarantined bytes, which is the whole reason it is a crossing.
    assert!(
        surface.iter().any(|crossing| {
            crossing.contains("screen_item") && crossing.contains("quarantine")
        }),
        "and names quarantine as what it carries: {surface:#?}",
    );
}

/// The crossing is narrow by construction, which is why no `redact` is needed.
///
/// GATE-4 was written expecting the crossing to be narrowed with `redact` so
/// only `disposition` crosses. DR-0051 §4 replaced that with something better: a
/// kernel predicate refusing any endorsed-claim-shaped field that can hold a
/// sentence. So the narrowing is enforced rather than remembered — an author who
/// widens `Screening` to carry the reviewer's prose is refused at admit.
///
/// Asserted on the shipped classes so the property is pinned where a gate edit
/// would break it.
#[test]
fn the_endorsed_verdict_cannot_carry_prose() {
    for (name, program) in [
        ("review-by-hand", REVIEW_BY_HAND_GATE),
        ("coerce-screen", COERCE_SCREEN_GATE),
    ] {
        assert!(
            program.contains(r#"class Screening { disposition "keep" | "flag" }"#),
            "{name}: the endorsed verdict is a closed union, so nothing a \
             reviewer or a classifier quoted can cross with it",
        );
        // The item's own bytes are a separate, public fact. That is the split
        // ADR 0117 §3 settled: the reviewer vouched for a decision, not for the
        // filing metadata around it.
        assert!(
            program.contains("class Settled { item string request string }"),
            "{name}: correlation stays public rather than riding the endorsement",
        );
    }
}
