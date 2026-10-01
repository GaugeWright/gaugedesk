//! Running a project's gate: the production caller `GATE-3` never had.
//!
//! `gate.rs` holds the programs and `gate_runner` drives one, but nothing in the
//! product reached either — `run_gate` and `GateCoercionConfig` were constructed
//! only in tests, so no gate had ever executed outside a harness. This module is
//! the seam between them.
//!
//! **One state directory per project, not per item** (ADR 0117 §2). That is the
//! part worth stating, because the alternative is the obvious one and it is
//! wrong: an instance per arrival puts each run's `review` and `verdicts`
//! trackers in its own store, so a reviewer's queue fragments across as many
//! stores as there are pending items and ADR 0110 §7's single index has nothing
//! single to project from. Sharing the directory gives one queue, which is the
//! property that decision was actually about.
//!
//! Each arrival still stages into its **own** root directory, so two concurrent
//! screenings on one project cannot overwrite each other's item (GATE-3i).

use std::cell::RefCell;
use std::io;
use std::path::{Path, PathBuf};

use gaugedesk_store::home_reference_journal::{
    ReferenceCompletion, ReferenceEvidence, ReferenceOperation, ReferenceUseEvidence,
    RevalidatedReferenceEvidence,
};
use gaugedesk_store::Store;
use gaugedesk_whip_runtime::gate_runner::{
    deliver_verdict_with_use_check, run_gate, run_gate_with_home_admission,
    verify_gate_import_operation, CoerceBackend, Disposition, GateCoercionConfig,
    GateImportEvidence, GateNewAdmissionBasis, GateProgram, GateRunError, GateTransport,
    GateVersionUse,
};
use gaugedesk_whip_runtime::sansio_types::{HttpRequest, HttpResponse, TransportError};
use sha2::{Digest, Sha256};

use crate::app_support::LockUnpoisoned;
use crate::workbench_state::SharedWorkbench;

/// The gate's HTTP leg.
///
/// A gate reaches exactly one outside thing — the coercion provider — so this is
/// the whole transport. It is deliberately not the workbench's general client:
/// a gate runs untrusted material past a model, and giving that path its own
/// narrow door keeps it obvious in the code what a gate can talk to.
pub struct HttpGateTransport;

impl GateTransport for HttpGateTransport {
    fn fetch(&self, request: &HttpRequest) -> Result<HttpResponse, TransportError> {
        let mut call = ureq::post(&request.url);
        for (name, value) in &request.headers {
            call = call.set(name, value);
        }
        let result = call.send_json(request.body.clone());
        let (status, body) = match result {
            Ok(response) => status_and_body(response),
            // A 4xx/5xx is an answer, not a transport failure. The coercion's
            // own error handling decides what a refusal means; turning it into a
            // transport error here would make a provider's "no" indistinguishable
            // from the network being down.
            Err(ureq::Error::Status(_, response)) => status_and_body(response),
            Err(error) => return Err(TransportError::Transport(error.to_string())),
        };
        Ok(HttpResponse { status, body })
    }
}

fn status_and_body(response: ureq::Response) -> (u16, serde_json::Value) {
    let status = response.status();
    // A body that is not JSON is still a fact about the call. Carrying it as a
    // string keeps the coercion's parse failure legible instead of collapsing
    // every malformed reply into `null`.
    let body = match response.into_string() {
        Ok(text) => serde_json::from_str(&text).unwrap_or(serde_json::Value::String(text)),
        Err(error) => serde_json::Value::String(error.to_string()),
    };
    (status, body)
}

/// Build the coercion config from this account's own credential store.
///
/// `GATE-3b` scoped this and never delivered it, which is why `coerce-screen`
/// had never run against a real provider. Only the screening gate needs it;
/// review-by-hand reaches a person and needs no model at all, which is what lets
/// it be the seedable default (ADR 0117 §7).
pub fn gate_coercion_config(
    workbench: &SharedWorkbench,
    actor: &str,
    model: &str,
) -> io::Result<GateCoercionConfig> {
    let scope = crate::account::account_scope(actor);
    let (records, token) = {
        let guard = workbench.lock_unpoisoned();
        let records = crate::account::credentials_in_scope(guard.store_ref(), &scope);
        let record = records.get("openai").cloned();
        let token = record
            .as_ref()
            .and_then(|record| guard.unseal_account_secret(&record.sealed_token));
        (record, token)
    };
    if records.is_none() {
        return Err(io::Error::other(
            "screening needs a linked OpenAI credential; review-by-hand needs none",
        ));
    }
    let api_key = token
        .filter(|token| !token.trim().is_empty())
        .ok_or_else(|| io::Error::other("linked OpenAI credential could not be unsealed"))?;
    Ok(GateCoercionConfig {
        backend: CoerceBackend::OpenAi,
        provider_id: "openai".to_owned(),
        base_url: "https://api.openai.com/v1/responses".to_owned(),
        api_key,
        model: model.to_owned(),
        max_tokens: 256,
    })
}

/// A coercion config for a gate that does not coerce.
///
/// review-by-hand reaches a person and never calls a model, so a project using
/// it must not be blocked by a missing provider credential. The values are
/// deliberately unreachable rather than plausible: if a screening gate ever runs
/// on this, the failure is an obvious refusal from an invalid host, not a
/// mysterious call to somewhere real.
pub fn unusable_coercion_config() -> GateCoercionConfig {
    GateCoercionConfig {
        backend: CoerceBackend::OpenAi,
        provider_id: "none".to_owned(),
        base_url: "https://gate.invalid/no-provider-linked".to_owned(),
        api_key: String::new(),
        model: String::new(),
        max_tokens: 1,
    }
}

/// Where a project's gate keeps its durable stores and its reviewer queue.
///
/// Shared across every arrival in the project — see the module note.
pub fn gate_state_dir(state_root: &Path, project_id: &str) -> PathBuf {
    state_root.join("gates").join(slug(project_id))
}

/// Where one arrival is staged for the gate to read.
///
/// Its own directory, so the fixed `item.json` the program reads cannot collide
/// with another arrival's.
pub fn arrival_root(state_root: &Path, project_id: &str, item_id: &str) -> PathBuf {
    gate_state_dir(state_root, project_id)
        .join("arrivals")
        .join(slug(item_id))
}

fn slug(value: &str) -> String {
    let slug: String = value
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect();
    slug.trim_matches('-').to_owned()
}

fn gate_target_store(project_id: &str) -> String {
    format!("project-gate:{project_id}")
}

fn gate_basis_digest(home_id: &str, project_id: &str, evidence: &GateImportEvidence) -> String {
    let encoded = serde_json::to_vec(&(
        "gaugedesk.project-gate-home-basis.v1",
        home_id,
        project_id,
        &evidence.program_name,
        &evidence.source_digest,
        &evidence.ir_digest,
        &evidence.compiler_artifact_digest,
        &evidence.lock_digest,
        &evidence.envelope_digest,
    ))
    .expect("a fixed tuple of strings serializes");
    hex::encode(Sha256::digest(encoded))
}

fn registration_basis_digest(
    home_id: &str,
    project_id: &str,
    basis: &GateNewAdmissionBasis<'_>,
) -> String {
    let encoded = serde_json::to_vec(&(
        "gaugedesk.project-gate-home-basis.v1",
        home_id,
        project_id,
        basis.program_name,
        basis.source_digest,
        basis.ir_digest,
        basis.compiler_artifact_digest,
        basis.lock_digest,
        basis.envelope_digest,
    ))
    .expect("a fixed tuple of strings serializes");
    hex::encode(Sha256::digest(encoded))
}

fn gate_evidence(
    program: &GateProgram,
    state: &Path,
    operation: &ReferenceOperation,
) -> Result<GateImportEvidence, String> {
    let evidence = verify_gate_import_operation(program, state, &operation.operation_id)
        .map_err(|error| error.to_string())?;
    if evidence.operation_id != operation.operation_id {
        return Err("gate target returned a different import operation".into());
    }
    if operation.target_store_incarnation.as_deref() != Some(&evidence.target_store_incarnation) {
        return Err("gate runtime store incarnation differs from its Home registration".into());
    }
    Ok(evidence)
}

#[allow(clippy::too_many_arguments)] // Home, project, target and selected item are separate authority keys.
fn home_gate_use(
    store: &mut Store,
    home_id: &str,
    project_id: &str,
    item_id: &str,
    program: &GateProgram,
    targets_dir: &Path,
    state: &Path,
    selected: GateVersionUse<'_>,
) -> Result<(), GateRunError> {
    let target = gate_target_store(project_id);
    let (operation_id, version_id, newly_admitted) = match selected {
        GateVersionUse::NewlyAdmitted {
            operation_id,
            version_id,
            ..
        } => (operation_id.to_owned(), version_id.to_owned(), true),
        GateVersionUse::Retained { version_id } => {
            let pinned = store
                .reference_use_pin(home_id, &target, item_id)
                .map_err(|error| GateRunError::NoDisposition(error.to_string()))?;
            let operation_id = if let Some(pinned) = pinned {
                if pinned.version_id != version_id {
                    return Err(GateRunError::NoDisposition(
                        "gate item has a different immutable Home version pin".into(),
                    ));
                }
                pinned.operation_id.ok_or_else(|| {
                    GateRunError::NoDisposition(
                        "legacy gate item has no exact Home operation; preserve it for explicit readmission".into(),
                    )
                })?
            } else {
                let origin = store
                    .exact_reference_origin_for_version(home_id, &target, version_id)
                    .map_err(|error| GateRunError::NoDisposition(error.to_string()))?;
                match origin {
                    Some(operation_id) => operation_id,
                    None => {
                        store
                            .classify_legacy_reference_use_unknown(
                                home_id, &target, item_id, version_id,
                            )
                            .map_err(|error| GateRunError::NoDisposition(error.to_string()))?;
                        return Err(GateRunError::NoDisposition(
                            "retained gate version has no exact Home origin; item recorded as legacy unknown".into(),
                        ));
                    }
                }
            };
            (operation_id, version_id.to_owned(), false)
        }
    };

    if newly_admitted {
        let completion = store
            .complete_reference_operation(home_id, &operation_id, |operation| {
                if operation.target_store != target || operation.kind != "checked-program" {
                    return Err("Home gate operation has a different target or kind".into());
                }
                let evidence = gate_evidence(program, state, operation)?;
                if gate_basis_digest(home_id, project_id, &evidence) != operation.basis_digest {
                    return Err("gate target differs from registered Home basis".into());
                }
                Ok(ReferenceEvidence {
                    target_store_incarnation: evidence.target_store_incarnation,
                    evidence_ref: evidence.operation_id,
                    witness_digest: evidence.witness_digest,
                })
            })
            .map_err(|error| GateRunError::NoDisposition(error.to_string()))?;
        if matches!(completion, ReferenceCompletion::NeedsRevalidation { .. }) {
            // A seal may race a target write. Re-read the project's current
            // envelope and the exact retained target before completing in the
            // later epoch. Repeated seals keep the operation pending.
            let current = project_gate(targets_dir, project_id)
                .map_err(|error| GateRunError::NoDisposition(error.to_string()))?;
            let completed = store
                .complete_revalidated_reference_operation(
                    home_id,
                    &operation_id,
                    |operation, _epoch| {
                        let evidence = gate_evidence(&current, state, operation)?;
                        Ok(RevalidatedReferenceEvidence {
                            evidence: ReferenceEvidence {
                                target_store_incarnation: evidence.target_store_incarnation.clone(),
                                evidence_ref: evidence.operation_id.clone(),
                                witness_digest: evidence.witness_digest.clone(),
                            },
                            current_basis_digest: gate_basis_digest(home_id, project_id, &evidence),
                        })
                    },
                )
                .map_err(|error| GateRunError::NoDisposition(error.to_string()))?;
            if matches!(completed, ReferenceCompletion::NeedsRevalidation { .. }) {
                return Err(GateRunError::NoDisposition(
                    "Home epoch advanced during gate revalidation; retry the same item".into(),
                ));
            }
        }
    }

    let current = project_gate(targets_dir, project_id)
        .map_err(|error| GateRunError::NoDisposition(error.to_string()))?;
    store
        .bind_exact_reference_use(
            home_id,
            &target,
            item_id,
            &version_id,
            &operation_id,
            |operation| {
                let evidence = gate_evidence(&current, state, operation)?;
                let current_basis = gate_basis_digest(home_id, project_id, &evidence);
                let admitted_basis = operation
                    .revalidated_basis_digest
                    .as_deref()
                    .unwrap_or(&operation.basis_digest);
                if current_basis != admitted_basis {
                    return Err(
                        "current gate basis differs from its completed Home admission".into(),
                    );
                }
                Ok(ReferenceUseEvidence {
                    target_store_incarnation: evidence.target_store_incarnation,
                    version_id: evidence.version_id,
                    evidence_ref: evidence.operation_id,
                    witness_digest: evidence.witness_digest,
                })
            },
        )
        .map_err(|error| GateRunError::NoDisposition(error.to_string()))?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn screen_item_with_home<T: GateTransport>(
    store: &mut Store,
    home_id: &str,
    ir: &GateProgram,
    coerce: &GateCoercionConfig,
    state_root: &Path,
    targets_dir: &Path,
    project_id: &str,
    item_id: &str,
    payload: &[u8],
    transport: &T,
) -> io::Result<Option<Disposition>> {
    let root = arrival_root(state_root, project_id, item_id);
    std::fs::create_dir_all(&root)?;
    std::fs::write(root.join("item.json"), payload)?;
    let state = gate_state_dir(state_root, project_id);
    let target = gate_target_store(project_id);
    let request = format!("gate-item:{project_id}:{item_id}");
    let shared = RefCell::new(store);
    match run_gate_with_home_admission(
        ir,
        coerce,
        item_id,
        &root,
        &state,
        transport,
        |basis| {
            let digest = registration_basis_digest(home_id, project_id, &basis);
            shared
                .borrow_mut()
                .register_checked_program_request(
                    home_id,
                    &target,
                    basis.target_store_incarnation,
                    &request,
                    &digest,
                )
                .map(|operation| operation.operation_id)
                .map_err(|error| GateRunError::NoDisposition(error.to_string()))
        },
        |selected| {
            home_gate_use(
                &mut shared.borrow_mut(),
                home_id,
                project_id,
                item_id,
                ir,
                targets_dir,
                &state,
                selected,
            )
        },
    ) {
        Ok(disposition) => Ok(Some(disposition)),
        Err(GateRunError::AwaitingReview) => Ok(None),
        Err(error) => Err(io::Error::other(error)),
    }
}

/// Run an unjournaled gate fixture over one quarantined item.
///
/// Production callers use `Workbench::run_project_gate`, which registers and
/// verifies the Home operation before any version is used. This narrow helper
/// remains for runtime fixtures and pre-journal migration tests.
pub fn screen_item<T: GateTransport>(
    ir: &GateProgram,
    coerce: &GateCoercionConfig,
    state_root: &Path,
    project_id: &str,
    item_id: &str,
    payload: &[u8],
    transport: &T,
) -> io::Result<Option<Disposition>> {
    let root = arrival_root(state_root, project_id, item_id);
    std::fs::create_dir_all(&root)?;
    // The program reads a literal `item.json`; identity is this directory and
    // the ingested signal, never the filename (GATE-3i).
    std::fs::write(root.join("item.json"), payload)?;
    let state = gate_state_dir(state_root, project_id);
    match run_gate(ir, coerce, item_id, &root, &state, transport) {
        Ok(disposition) => Ok(Some(disposition)),
        // A gate that reaches a person settles nothing on this pass. Reporting
        // that as an error would make every human review look like a failure.
        Err(GateRunError::AwaitingReview) => Ok(None),
        Err(error) => Err(io::Error::other(error)),
    }
}

/// Read a project's own gate off its files target.
///
/// The gate lives in the target's mainline (ADR 0110 §5, `GATE-3l`), so this is
/// where "the project's gate" becomes a concrete program rather than a phrase.
/// A project whose gate does not compile or does not satisfy its envelope gets a
/// refusal here, before any side effect — which is the whole point of admitting
/// separately from running.
pub fn project_gate(
    targets_dir: &Path,
    project_id: &str,
) -> Result<GateProgram, crate::gate::GateRefusal> {
    let repo = targets_dir
        .join(crate::library_state::managed_project_target_id(project_id))
        .join("repo");
    let source = std::fs::read_to_string(repo.join(crate::gate::GATE_PROGRAM_PATH))
        .map_err(|error| crate::gate::GateRefusal::Malformed(vec![error.to_string()]))?;
    let envelope = std::fs::read_to_string(repo.join(crate::gate::GATE_ENVELOPE_PATH))
        .map_err(|error| crate::gate::GateRefusal::Envelope(error.to_string()))?;
    // Admit and retain the SAME read, not a second read racing a file edit.
    crate::gate::admit(&source, &envelope)?;
    GateProgram::compile(&source, &envelope)
        .map_err(|error| crate::gate::GateRefusal::Malformed(vec![error.to_string()]))
}

impl crate::Workbench {
    /// Run this project's gate over one quarantined item and apply what it ruled.
    ///
    /// The production path `GATE-3` never had. Returns the workspace path an
    /// approved item landed at, `None` when the gate parked on a person, and an
    /// error only when the gate itself is unusable.
    ///
    /// A parked gate is the ordinary case for review-by-hand and is deliberately
    /// not an error: the item stays `Pending` and its question waits in the
    /// project's `review` tracker for someone to answer.
    pub fn run_project_gate<T: GateTransport>(
        &mut self,
        project_id: &str,
        item_id: &str,
        chat_id: &str,
        coerce: &GateCoercionConfig,
        transport: &T,
    ) -> io::Result<Option<String>> {
        let ir = project_gate(&self.targets_dir(), project_id).map_err(io::Error::other)?;
        let payload = self.read_quarantined_item(project_id, item_id)?;
        let state_root = self.root_path();
        let targets_dir = self.targets_dir();
        let home_id = self.home_id().as_str().to_owned();
        let Some(disposition) = screen_item_with_home(
            self.store_mut(),
            &home_id,
            &ir,
            coerce,
            &state_root,
            &targets_dir,
            project_id,
            item_id,
            &payload,
            transport,
        )?
        else {
            return Ok(None);
        };
        let verdict = match disposition {
            Disposition::Keep => crate::gate::Verdict::Keep,
            Disposition::Flag => crate::gate::Verdict::Flag,
        };
        self.apply_gate_verdict(project_id, item_id, chat_id, verdict)
    }

    /// Deliver a person's review decision to this project's gate.
    ///
    /// The reviewer's answer becomes a claim on the queue the gate is parked
    /// against; the gate rules, and only then does anything move. That is
    /// ADR 0117 §1 — the gate is the only producer of a verdict — and it is what
    /// makes ADR 0110 §2's "nothing else reads quarantine" true of the shipped
    /// product rather than only of its design.
    ///
    /// Returns the workspace path an approved item landed at, or `None` when the
    /// gate did not settle on this pass.
    pub fn review_through_gate<T: GateTransport>(
        &mut self,
        project_id: &str,
        item_id: &str,
        chat_id: &str,
        verdict: crate::gate::Verdict,
        coerce: &GateCoercionConfig,
        transport: &T,
    ) -> io::Result<Option<String>> {
        let ir = project_gate(&self.targets_dir(), project_id).map_err(io::Error::other)?;
        let state_root = self.root_path();
        let targets_dir = self.targets_dir();
        let home_id = self.home_id().as_str().to_owned();
        let root = arrival_root(&state_root, project_id, item_id);
        let state = gate_state_dir(&state_root, project_id);
        // `screen_item` creates these on the screening path; review-by-hand
        // reached the same stores without ever creating them, so a project
        // whose first ruling came from a person failed on an unopenable
        // `runtime.sqlite` instead of ruling. Both paths now arrive at a
        // directory that exists.
        std::fs::create_dir_all(&root)?;
        std::fs::create_dir_all(&state)?;
        let disposition = match verdict {
            crate::gate::Verdict::Keep => Disposition::Keep,
            crate::gate::Verdict::Flag => Disposition::Flag,
        };
        let ruled = deliver_verdict_with_use_check(
            &ir,
            coerce,
            item_id,
            disposition,
            &root,
            &state,
            transport,
            |selected| {
                home_gate_use(
                    self.store_mut(),
                    &home_id,
                    project_id,
                    item_id,
                    &ir,
                    &targets_dir,
                    &state,
                    selected,
                )
            },
        )
        .map_err(io::Error::other)?;
        // An answer needs a question. `deliver_verdict` finds none when nothing
        // has screened this project yet — no instance, so no parked request the
        // verdict could correlate against — and returns `None`, which the caller
        // cannot distinguish from a gate that considered the item and declined
        // to move it. Every verdict from the review surface hit exactly that: the
        // item stayed pending and nothing said why.
        //
        // So screen on first review. The pass may rule outright, in which case
        // **the gate's ruling stands and the reviewer's answer does not override
        // it** — the gate is the only producer of a verdict (ADR 0117 §1), and a
        // person answering a question it never asked cannot outvote it. If it
        // parks, the answer now has its question and is delivered.
        let ruled = match ruled {
            Some(ruled) => Some(ruled),
            None => {
                let payload = self.read_quarantined_item(project_id, item_id)?;
                match screen_item_with_home(
                    self.store_mut(),
                    &home_id,
                    &ir,
                    coerce,
                    &state_root,
                    &targets_dir,
                    project_id,
                    item_id,
                    &payload,
                    transport,
                )? {
                    Some(screened) => Some(screened),
                    None => deliver_verdict_with_use_check(
                        &ir,
                        coerce,
                        item_id,
                        disposition,
                        &root,
                        &state,
                        transport,
                        |selected| {
                            home_gate_use(
                                self.store_mut(),
                                &home_id,
                                project_id,
                                item_id,
                                &ir,
                                &targets_dir,
                                &state,
                                selected,
                            )
                        },
                    )
                    .map_err(io::Error::other)?,
                }
            }
        };
        let Some(ruled) = ruled else {
            return Ok(None);
        };
        let verdict = match ruled {
            Disposition::Keep => crate::gate::Verdict::Keep,
            Disposition::Flag => crate::gate::Verdict::Flag,
        };
        self.apply_gate_verdict(project_id, item_id, chat_id, verdict)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use gaugedesk_whip_runtime::sansio_types::TransportError;

    #[test]
    fn one_project_shares_a_state_dir_and_arrivals_do_not() {
        let root = Path::new("/state");
        let a = gate_state_dir(root, "proj-1");
        let b = gate_state_dir(root, "proj-1");
        assert_eq!(a, b, "one queue per project, so one store per project");
        assert_ne!(gate_state_dir(root, "proj-2"), a);

        let one = arrival_root(root, "proj-1", "sess-1:1");
        let two = arrival_root(root, "proj-1", "sess-1:2");
        assert_ne!(one, two, "two arrivals never share a staging root");
        assert!(one.starts_with(&a), "arrivals live under the project's dir");
    }

    #[test]
    fn a_slug_cannot_climb_out_of_its_directory() {
        let root = Path::new("/state");
        let escaped = arrival_root(root, "proj-1", "../../etc/passwd");
        assert!(
            escaped.starts_with(gate_state_dir(root, "proj-1")),
            "a traversal-shaped id stays inside: {escaped:?}",
        );
        assert!(!escaped.to_string_lossy().contains(".."));
    }

    #[test]
    fn a_seal_between_registration_and_target_write_revalidates_before_use() {
        struct NoTransport;
        impl GateTransport for NoTransport {
            fn fetch(&self, _: &HttpRequest) -> Result<HttpResponse, TransportError> {
                panic!("review-by-hand cannot call a provider")
            }
        }

        let dir = tempfile::tempdir().unwrap();
        let targets = dir.path().join("targets");
        let project = "project-one";
        let item = "item-one";
        let repo = targets
            .join(crate::library_state::managed_project_target_id(project))
            .join("repo");
        crate::gate::install(&repo, crate::gate::GateKind::ReviewByHand).unwrap();
        let program = project_gate(&targets, project).unwrap();
        let state = gate_state_dir(dir.path(), project);
        let arrival = arrival_root(dir.path(), project, item);
        std::fs::create_dir_all(&arrival).unwrap();
        std::fs::write(arrival.join("item.json"), br#"{"text":"review me"}"#).unwrap();
        let home = "home-one";
        let target = gate_target_store(project);
        let store = RefCell::new(Store::open_in_memory().unwrap());
        let result = run_gate_with_home_admission(
            &program,
            &unusable_coercion_config(),
            item,
            &arrival,
            &state,
            &NoTransport,
            |basis| {
                let digest = registration_basis_digest(home, project, &basis);
                let mut store = store.borrow_mut();
                let operation = store
                    .register_checked_program_request(
                        home,
                        &target,
                        basis.target_store_incarnation,
                        "gate-item:project-one:item-one",
                        &digest,
                    )
                    .unwrap();
                store
                    .seal_reference_epoch(home, "registry:1", "policy:1", "tree:1")
                    .unwrap();
                Ok(operation.operation_id)
            },
            |selected| {
                home_gate_use(
                    &mut store.borrow_mut(),
                    home,
                    project,
                    item,
                    &program,
                    &targets,
                    &state,
                    selected,
                )
            },
        );
        assert!(matches!(result, Err(GateRunError::AwaitingReview)));
        let pin = store
            .borrow()
            .reference_use_pin(home, &target, item)
            .unwrap()
            .unwrap();
        let operation = store
            .borrow()
            .reference_operation(pin.operation_id.as_deref().unwrap())
            .unwrap()
            .unwrap();
        assert_eq!(operation.registered_epoch, 0);
        assert_eq!(operation.completed_epoch, Some(1));
        assert!(operation.revalidated_basis_digest.is_some());
    }
}
