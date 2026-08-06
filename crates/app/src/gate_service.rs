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

use std::io;
use std::path::{Path, PathBuf};

use gaugedesk_whip_runtime::gate_runner::{
    deliver_verdict, run_gate, CoerceBackend, Disposition, GateCoercionConfig, GateProgram,
    GateTransport,
};
use gaugedesk_whip_runtime::sansio_types::{HttpRequest, HttpResponse, TransportError};

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

/// Run the project's own gate over one quarantined item.
///
/// Returns the disposition when the gate ruled, and `None` when it parked on a
/// person — which is not a failure but the review-by-hand path working. The
/// caller applies a ruling; a parked item stays `Pending` and its question waits
/// in the project's `review` tracker.
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
        Err(_) => Ok(None),
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
    crate::gate::admit_installed(&repo)?;
    let source = std::fs::read_to_string(repo.join(crate::gate::GATE_PROGRAM_PATH))
        .map_err(|error| crate::gate::GateRefusal::Malformed(vec![error.to_string()]))?;
    gaugedesk_whip_runtime::compile_whip_program(&source)
        .ir
        .ok_or_else(|| {
            crate::gate::GateRefusal::Malformed(vec!["the gate does not compile".into()])
        })
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
        let Some(disposition) = screen_item(
            &ir,
            coerce,
            &state_root,
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
        let ruled = deliver_verdict(&ir, coerce, item_id, disposition, &root, &state, transport)
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
                match screen_item(
                    &ir,
                    coerce,
                    &state_root,
                    project_id,
                    item_id,
                    &payload,
                    transport,
                )? {
                    Some(screened) => Some(screened),
                    None => {
                        deliver_verdict(&ir, coerce, item_id, disposition, &root, &state, transport)
                            .map_err(io::Error::other)?
                    }
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
}
