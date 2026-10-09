//! DR-0464 over the account plane's own routes: a hand-over away from a
//! proven root waits, with notice, and only an enrolled, active computer
//! submits one.

use std::sync::atomic::AtomicBool;
use std::sync::Mutex;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use gaugedesk_core::delegation::DeviceDelegation;
use gaugedesk_core::signature::SigningKey;
use http_body_util::BodyExt;
use serde_json::Value;
use tower::ServiceExt;

use super::*;
use crate::account::{account_scope, DeviceKind, DeviceRecord, ACCOUNT_SCOPE};

const PERSON: &str = "acct-hand-over";
const ADDRESS: &str = "owner@example.test";
const STUDIO: &str = "device:studio";
const LAPTOP: &str = "device:laptop";

fn key(seed: u8) -> SigningKey {
    SigningKey::from_seed(&[seed; 32]).unwrap()
}

fn public(key: &SigningKey) -> String {
    key.public_key().as_str().to_owned()
}

/// The device subkey every computer here proves with, under whichever root
/// delegates to it.
fn subkey() -> SigningKey {
    key(9)
}

/// The account mail, recorded, and refused while `refusing`.
#[derive(Default)]
struct Outbox {
    sent: Mutex<Vec<(String, RootHandOverNotice)>>,
    refusing: AtomicBool,
}

impl Outbox {
    fn kinds(&self) -> Vec<NoticeKind> {
        self.sent
            .lock()
            .unwrap()
            .iter()
            .map(|(_, notice)| notice.kind)
            .collect()
    }
}

impl EmailChallengeSender for Outbox {
    fn send_verification(&self, _email: &str, _code: &str, _expires: u64) -> Result<(), String> {
        Err("not a verification outbox".to_owned())
    }

    fn send_root_hand_over_notice(
        &self,
        to: &str,
        notice: &RootHandOverNotice,
    ) -> Result<(), String> {
        if self.refusing.load(Ordering::SeqCst) {
            return Err("the relay is down".to_owned());
        }
        self.sent
            .lock()
            .unwrap()
            .push((to.to_owned(), notice.clone()));
        Ok(())
    }
}

/// An enrolled computer of the account in `scope`, signed in over a session
/// bound to it. Returns that session's bearer.
fn enrolled_computer(wb: &mut Workbench, scope: &str, id: &str, label: &str) -> String {
    wb.upsert_account_device_in(
        scope,
        &DeviceRecord {
            id: id.to_owned(),
            op: RecordOp::Upsert,
            label: label.to_owned(),
            kind: DeviceKind::Computer,
            subkey_pubkey: String::new(),
            status: DeviceStatus::Active,
            enrolled_at: 1,
        },
    )
    .unwrap();
    let token = wb.mint_account_session(PERSON, "passkey", 3600).unwrap();
    let session = crate::account_session::session_id(&token);
    assert!(wb.bind_account_session_device(&session, PERSON, id));
    token
}

struct Hub {
    _dir: tempfile::TempDir,
    wb: SharedWorkbench,
    app: Router,
    studio: String,
}

/// A Hub-mode account with a verified address and one enrolled computer.
///
/// The sweeper the routes start uses the deployment's relay, which a test has
/// none of, so it can record no notice and never races the sweeps a test runs.
fn hub() -> Hub {
    let hub = hub_without_address();
    verify_address(&hub.wb);
    hub
}

fn verify_address(wb: &SharedWorkbench) {
    crate::account_auth::append_facts(
        wb.lock_unpoisoned().store_mut(),
        &[crate::account_auth::AccountAuthFact::Email(
            crate::account_auth::VerifiedEmailRecord::new(PERSON, ADDRESS, 1).unwrap(),
        )],
    )
    .unwrap();
}

fn hub_without_address() -> Hub {
    let dir = tempfile::tempdir().unwrap();
    let wb = crate::open_workbench(dir.path()).unwrap();
    let studio = {
        let mut guard = wb.lock_unpoisoned();
        guard.enable_hosted_home_mode();
        enrolled_computer(&mut guard, &account_scope(PERSON), STUDIO, "Studio Mac")
    };
    let app = crate::account_routes::routes().with_state(wb.clone());
    Hub {
        _dir: dir,
        wb,
        app,
        studio,
    }
}

async fn call(
    app: &Router,
    method: &str,
    path: &str,
    bearer: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header("authorization", format!("Bearer {bearer}"));
    let body = match body {
        Some(body) => {
            request = request.header("content-type", "application/json");
            Body::from(body.to_string())
        }
        None => Body::empty(),
    };
    let response = app
        .clone()
        .oneshot(request.body(body).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let value = serde_json::from_slice(&bytes)
        .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into_owned()));
    (status, value)
}

/// Publish `root` from the session `bearer`'s computer, proving with its
/// subkey under `root`'s delegation unless `prove` is false.
async fn publish(
    app: &Router,
    bearer: &str,
    root: &SigningKey,
    transition: Option<&RootTransition>,
    prove: bool,
) -> (StatusCode, Value) {
    let root_key = public(root);
    let mut body = json!({ "root_pubkey": root_key });
    if prove {
        let (status, challenge) = call(
            app,
            "POST",
            "/account/directory/challenge",
            bearer,
            Some(json!({})),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let delegation = DeviceDelegation::issue(
            root,
            subkey().public_key(),
            crate::account::device_enrolled_at_now() + 600,
        );
        let proof = crate::root_publication::prove(
            challenge["challenge"].as_str().unwrap(),
            &root_key,
            &subkey(),
            &delegation,
        );
        body["proof"] = serde_json::to_value(proof).unwrap();
    }
    if let Some(transition) = transition {
        body["transition"] = serde_json::to_value(transition).unwrap();
    }
    call(app, "POST", "/account/directory", bearer, Some(body)).await
}

fn hand_over(from: &SigningKey, to: &SigningKey) -> RootTransition {
    gaugedesk_directory_protocol::sign_root_transition(&public(to), 5, from).unwrap()
}

async fn projected(app: &Router, bearer: &str) -> Value {
    let (status, body) = call(app, "GET", "/account/directory", bearer, None).await;
    assert_eq!(status, StatusCode::OK);
    body
}

fn account(wb: &SharedWorkbench) -> Account {
    Account::rebuild_in(wb.lock_unpoisoned().store_ref(), &account_scope(PERSON)).unwrap()
}

/// An account whose computer proved root A, with a hand-over to B pending.
/// Returns B's pending view.
async fn pending_hand_over(hub: &Hub) -> Value {
    let (status, _) = publish(&hub.app, &hub.studio, &key(1), None, true).await;
    assert_eq!(status, StatusCode::CREATED);
    assert!(account(&hub.wb).directory.unwrap().proven);
    let (status, body) = publish(
        &hub.app,
        &hub.studio,
        &key(2),
        Some(&hand_over(&key(1), &key(2))),
        true,
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    body["pending"].clone()
}

fn at(view: &Value, field: &str) -> u64 {
    view[field].as_u64().unwrap()
}

const HOUR_MS: u64 = 60 * 60 * 1000;

/// DR-0464 §6, ADR 0133 §2: a live session alone never replaces a projected
/// root. Without its computer's proof the replacement is refused, and without
/// the projected root's own signed hand-over it conflicts.
#[tokio::test]
async fn replacing_a_projected_root_needs_a_computers_proof_and_the_roots_hand_over() {
    let hub = hub();
    let (status, _) = publish(&hub.app, &hub.studio, &key(1), None, true).await;
    assert_eq!(status, StatusCode::CREATED);

    let signed = hand_over(&key(1), &key(2));
    let (status, _) = publish(&hub.app, &hub.studio, &key(2), Some(&signed), false).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "no proof");
    let (status, _) = publish(&hub.app, &hub.studio, &key(2), None, true).await;
    assert_eq!(status, StatusCode::CONFLICT, "no hand-over");
    let forged = hand_over(&key(3), &key(2));
    let (status, _) = publish(&hub.app, &hub.studio, &key(2), Some(&forged), true).await;
    assert_eq!(status, StatusCode::CONFLICT, "not the projected root's");

    let served = projected(&hub.app, &hub.studio).await;
    assert_eq!(served["root_pubkey"], public(&key(1)));
    assert!(account(&hub.wb).root_hand_over.is_none());
}

/// DR-0464 §7: a revoked computer cannot submit a hand-over. On the Hub its
/// session stops authenticating at all; on a desktop's single account scope
/// the session can outlive its device's standing, so the route checks the
/// device itself.
#[tokio::test]
async fn a_revoked_computer_cannot_hand_over_the_root() {
    let dir = tempfile::tempdir().unwrap();
    let wb = crate::open_workbench(dir.path()).unwrap();
    let studio = enrolled_computer(
        &mut wb.lock_unpoisoned(),
        ACCOUNT_SCOPE,
        STUDIO,
        "Studio Mac",
    );
    let app = crate::account_routes::routes().with_state(wb.clone());
    let (status, _) = publish(&app, &studio, &key(1), None, true).await;
    assert_eq!(status, StatusCode::CREATED);
    {
        let mut guard = wb.lock_unpoisoned();
        let mut device = Account::rebuild_in(guard.store_ref(), ACCOUNT_SCOPE)
            .unwrap()
            .devices
            .remove(STUDIO)
            .unwrap();
        device.status = DeviceStatus::Revoked;
        guard
            .upsert_account_device_in(ACCOUNT_SCOPE, &device)
            .unwrap();
    }

    let (status, body) = publish(
        &app,
        &studio,
        &key(2),
        Some(&hand_over(&key(1), &key(2))),
        true,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(body.as_str().unwrap().contains("revoked"), "{body}");
    let directory = Account::rebuild_in(wb.lock_unpoisoned().store_ref(), ACCOUNT_SCOPE)
        .unwrap()
        .directory
        .unwrap();
    assert_eq!(directory.root_pubkey, public(&key(1)));
}

/// DR-0464 §1–§2: away from a proven root the hand-over waits. The outgoing
/// root stays projected and the hand-over is not among the transitions served.
/// The wait runs 72 hours from when the account was told, so a notice that is
/// late — here by 100 hours — never shortens the owner's window.
#[tokio::test]
async fn a_hand_over_away_from_a_proven_root_waits_72_hours_from_its_notice() {
    let hub = hub();
    let pending = pending_hand_over(&hub).await;
    assert_eq!(pending["computer"], "Studio Mac");
    assert_eq!(pending["device_id"], STUDIO);
    assert_eq!(pending["root_pubkey"], public(&key(2)));
    assert_eq!(
        pending["effective_at_ms"],
        Value::Null,
        "unknown until told"
    );
    let submitted = at(&pending, "submitted_at_ms");

    let served = projected(&hub.app, &hub.studio).await;
    assert_eq!(served["root_pubkey"], public(&key(1)));
    assert_eq!(
        served["transitions"],
        json!([]),
        "a pending hand-over is not served"
    );
    let (status, shown) = call(
        &hub.app,
        "GET",
        "/account/directory/pending",
        &hub.studio,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(shown["pending"], pending);

    // Nobody can be told: however long it waits, it does not take effect.
    let outbox = Outbox::default();
    outbox.refusing.store(true, Ordering::SeqCst);
    let told = submitted + 100 * HOUR_MS;
    sweep(&hub.wb, Some(&outbox), told);
    assert_eq!(
        projected(&hub.app, &hub.studio).await["root_pubkey"],
        public(&key(1))
    );
    let held = account(&hub.wb).root_hand_over.unwrap();
    assert_eq!(held.notice, NoticeState::default());
    assert_eq!(held.effective_at_ms, None);

    // Told at last; the wait starts now.
    outbox.refusing.store(false, Ordering::SeqCst);
    sweep(&hub.wb, Some(&outbox), told);
    let effective = told + HAND_OVER_WAIT_MS;
    assert_eq!(
        outbox.sent.lock().unwrap().clone(),
        vec![(
            ADDRESS.to_owned(),
            RootHandOverNotice {
                kind: NoticeKind::Submitted,
                computer: "Studio Mac".to_owned(),
                effective_at_ms: effective,
            }
        )]
    );
    assert_eq!(
        account(&hub.wb).root_hand_over.unwrap().effective_at_ms,
        Some(effective)
    );
    sweep(&hub.wb, Some(&outbox), effective - 1);
    assert_eq!(
        projected(&hub.app, &hub.studio).await["root_pubkey"],
        public(&key(1))
    );

    sweep(&hub.wb, Some(&outbox), effective);
    let served = projected(&hub.app, &hub.studio).await;
    assert_eq!(served["root_pubkey"], public(&key(2)));
    let chain: Vec<RootTransition> = serde_json::from_value(served["transitions"].clone()).unwrap();
    assert!(gaugedesk_directory_protocol::root_chain_reaches(
        &public(&key(1)),
        &public(&key(2)),
        &chain
    ));
    let account = account(&hub.wb);
    assert!(account.directory.unwrap().proven);
    assert_eq!(
        account.root_hand_over.unwrap().settled_at_ms,
        Some(effective)
    );
    let (status, _) = call(
        &hub.app,
        "GET",
        "/account/directory/pending",
        &hub.studio,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
}

/// DR-0464 §2, failing closed: an account the Hub has no channel to — no
/// verified address — is not told, so its hand-over stays pending and shown,
/// never taken, until a channel exists.
#[tokio::test]
async fn a_hand_over_nobody_can_be_told_of_stays_pending() {
    let hub = hub_without_address();
    let pending = pending_hand_over(&hub).await;
    let submitted = at(&pending, "submitted_at_ms");
    let outbox = Outbox::default();
    for later in [1, 72 * HOUR_MS, 1000 * HOUR_MS] {
        sweep(&hub.wb, Some(&outbox), submitted + later);
    }
    assert!(outbox.kinds().is_empty());
    assert_eq!(
        projected(&hub.app, &hub.studio).await["root_pubkey"],
        public(&key(1))
    );
    let (status, shown) = call(
        &hub.app,
        "GET",
        "/account/directory/pending",
        &hub.studio,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        shown["pending"]["notice"]["submitted_sent_at_ms"],
        Value::Null
    );
    assert_eq!(shown["pending"]["effective_at_ms"], Value::Null);

    // An address arrives, and the account is told; the wait starts then.
    verify_address(&hub.wb);
    let told = submitted + 1001 * HOUR_MS;
    sweep(&hub.wb, Some(&outbox), told);
    assert_eq!(outbox.kinds(), vec![NoticeKind::Submitted]);
    assert_eq!(
        account(&hub.wb).root_hand_over.unwrap().effective_at_ms,
        Some(told + HAND_OVER_WAIT_MS)
    );
}

/// DR-0464 §1, clarified: a root no device proved — a claimed computer's
/// install-derived key — is not one the account rotates away from, so a
/// hand-over away from it gives the account its first root at once. Its
/// statement is kept and served, across later writes of the same root, so a
/// client that pinned the old root follows it (ADR 0133 §3).
#[tokio::test]
async fn a_hand_over_away_from_an_unproven_root_is_taken_at_once_and_kept() {
    let hub = hub();
    let (status, _) = publish(&hub.app, &hub.studio, &key(1), None, false).await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "the first root is taken on first use"
    );
    assert!(!account(&hub.wb).directory.unwrap().proven);

    let (status, body) = publish(
        &hub.app,
        &hub.studio,
        &key(2),
        Some(&hand_over(&key(1), &key(2))),
        true,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let (status, _) = publish(&hub.app, &hub.studio, &key(2), None, false).await;
    assert_eq!(status, StatusCode::CREATED, "the same root again");

    let served = projected(&hub.app, &hub.studio).await;
    assert_eq!(served["root_pubkey"], public(&key(2)));
    let chain: Vec<RootTransition> = serde_json::from_value(served["transitions"].clone()).unwrap();
    assert_eq!(chain.len(), 1);
    assert!(gaugedesk_directory_protocol::root_chain_reaches(
        &public(&key(1)),
        &public(&key(2)),
        &chain
    ));
    let account = account(&hub.wb);
    assert!(account.directory.unwrap().proven);
    assert!(account.root_hand_over.is_none());
}

/// DR-0464 §7: revoking the computer that submitted a hand-over withdraws it,
/// so it never takes effect.
#[tokio::test]
async fn revoking_the_submitting_computer_withdraws_its_hand_over() {
    let hub = hub();
    let laptop = enrolled_computer(
        &mut hub.wb.lock_unpoisoned(),
        &account_scope(PERSON),
        LAPTOP,
        "Laptop",
    );
    let pending = pending_hand_over(&hub).await;

    let (status, _) = call(
        &hub.app,
        "POST",
        &format!("/account/devices/{STUDIO}/revoke"),
        &laptop,
        Some(json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = call(&hub.app, "GET", "/account/directory/pending", &laptop, None).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let withdrawn = account(&hub.wb).root_hand_over.unwrap();
    assert_eq!(withdrawn.withdrawn_reason, "revoked");
    assert!(withdrawn.withdrawn_at_ms.is_some());

    let outbox = Outbox::default();
    sweep(
        &hub.wb,
        Some(&outbox),
        at(&pending, "submitted_at_ms") + 100 * HOUR_MS,
    );
    assert!(
        outbox.kinds().is_empty(),
        "a withdrawn hand-over is not announced"
    );
    assert_eq!(
        projected(&hub.app, &laptop).await["root_pubkey"],
        public(&key(1))
    );
}

/// Until the freeze lands (DR-0464 §4, WS-984), a second, different hand-over
/// while one is pending is refused; submitting the pending one again changes
/// nothing.
#[tokio::test]
async fn a_second_hand_over_is_refused_while_one_is_pending_and_the_same_one_is_idempotent() {
    let hub = hub();
    let pending = pending_hand_over(&hub).await;

    let (status, again) = publish(
        &hub.app,
        &hub.studio,
        &key(2),
        Some(&hand_over(&key(1), &key(2))),
        true,
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    assert_eq!(again["pending"], pending, "the wait does not restart");

    let (status, body) = publish(
        &hub.app,
        &hub.studio,
        &key(3),
        Some(&hand_over(&key(1), &key(3))),
        true,
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert!(body.as_str().unwrap().contains("already pending"), "{body}");
    assert_eq!(
        account(&hub.wb).root_hand_over.unwrap().transition.to,
        public(&key(2))
    );
}

/// DR-0464 §2: the account is reminded once, 24 hours before the hand-over
/// takes effect.
#[tokio::test]
async fn a_reminder_goes_once_a_day_before_the_hand_over_takes_effect() {
    let hub = hub();
    let pending = pending_hand_over(&hub).await;
    let told = at(&pending, "submitted_at_ms") + 1;
    let effective = told + HAND_OVER_WAIT_MS;
    let outbox = Outbox::default();
    sweep(&hub.wb, Some(&outbox), told);
    sweep(&hub.wb, Some(&outbox), effective - REMINDER_BEFORE_MS - 1);
    assert_eq!(outbox.kinds(), vec![NoticeKind::Submitted]);

    sweep(&hub.wb, Some(&outbox), effective - REMINDER_BEFORE_MS);
    sweep(&hub.wb, Some(&outbox), effective - HOUR_MS);
    assert_eq!(
        outbox.kinds(),
        vec![NoticeKind::Submitted, NoticeKind::Reminder]
    );
    let reminder = outbox.sent.lock().unwrap()[1].clone();
    assert_eq!(reminder.0, ADDRESS);
    assert_eq!(reminder.1.effective_at_ms, effective);
    assert_eq!(
        account(&hub.wb)
            .root_hand_over
            .unwrap()
            .notice
            .reminder_sent_at_ms,
        Some(effective - REMINDER_BEFORE_MS)
    );
}

/// Whoever reads the directory once a hand-over is due takes it; the sweeper
/// is not the only way it takes effect.
#[tokio::test]
async fn reading_the_directory_takes_a_hand_over_that_is_due() {
    let hub = hub();
    pending_hand_over(&hub).await;
    {
        let mut guard = hub.wb.lock_unpoisoned();
        let scope = account_scope(PERSON);
        let mut due = Account::rebuild_in(guard.store_ref(), &scope)
            .unwrap()
            .root_hand_over
            .unwrap();
        due.effective_at_ms = Some(1);
        due.notice.submitted_sent_at_ms = Some(1);
        guard
            .write_account_record_in(&scope, ROOT_HAND_OVER_RECORD_KIND, &due.id, &due)
            .unwrap();
    }
    assert_eq!(
        projected(&hub.app, &hub.studio).await["root_pubkey"],
        public(&key(2))
    );
}
