//! Machine-scoped mobile controller enrollment and session shell (ADR 0109).
//!
//! Work APIs stay unchanged. This module only turns a one-use invitation and a
//! native device-key proof into a durable, revocable controller grant, then a
//! short-lived session accepted by the ordinary work-route middleware.

use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use gaugewright_core::{
    ids::{DeviceId, HomeId, PublicKey},
    mobile_machine_session::{
        enrollment_challenge_bytes, session_challenge_bytes, ControllerCommand, ControllerPhase,
        ControllerState,
    },
    signature::{verify_signature, Signature},
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::{account::RecordOp, session::random_bytes, LockUnpoisoned, SharedWorkbench};

pub const MACHINE_SESSION_HEADER: &str = "x-gaugewright-machine-session";
const SCOPE: &str = "machine-controllers";
const KIND: &str = "controller-grant";
const INVITATION_TTL_SECS: u64 = 10 * 60;
const CHALLENGE_TTL_SECS: u64 = 5 * 60;
const SESSION_TTL_SECS: u64 = 15 * 60;

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default()
}

fn random_secret() -> String {
    URL_SAFE_NO_PAD.encode(random_bytes::<32>())
}

fn random_id(prefix: &str) -> String {
    format!("{prefix}-{}", URL_SAFE_NO_PAD.encode(random_bytes::<18>()))
}

fn secret_hash(secret: &str) -> String {
    hex::encode(Sha256::digest(secret.as_bytes()))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ControllerGrantStatus {
    Active,
    Revoked,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ControllerGrantRecord {
    pub id: String,
    #[serde(default)]
    pub op: RecordOp,
    pub machine: HomeId,
    pub device: DeviceId,
    pub public_key: PublicKey,
    pub label: String,
    pub credential_hash: String,
    pub status: ControllerGrantStatus,
    pub enrolled_at: u64,
}

#[derive(Clone, Debug)]
struct Invitation {
    machine: HomeId,
    endpoint: String,
    secret_hash: String,
    expires_at: u64,
    consumed: bool,
}

#[derive(Clone, Debug)]
struct EnrollmentRequest {
    state: ControllerState,
    label: String,
    pickup_hash: String,
    challenge: String,
    expires_at: u64,
    credential: Option<String>,
    grant_id: Option<String>,
}

#[derive(Clone, Debug)]
struct ResumeChallenge {
    grant_id: String,
    challenge: String,
    expires_at: u64,
}

#[derive(Clone, Debug)]
struct ActiveSession {
    grant_id: String,
    expires_at: u64,
}

#[derive(Default)]
pub struct MachineControllerRuntime {
    invitations: BTreeMap<String, Invitation>,
    requests: BTreeMap<String, EnrollmentRequest>,
    resume_challenges: BTreeMap<String, ResumeChallenge>,
    sessions: BTreeMap<String, ActiveSession>,
}

impl MachineControllerRuntime {
    fn sweep(&mut self, now: u64) {
        self.invitations
            .retain(|_, invitation| invitation.expires_at > now && !invitation.consumed);
        self.requests.retain(|_, request| {
            request.expires_at > now
                || matches!(
                    request.state.phase,
                    ControllerPhase::Granted | ControllerPhase::Active
                )
        });
        self.resume_challenges
            .retain(|_, challenge| challenge.expires_at > now);
        self.sessions.retain(|_, session| session.expires_at > now);
    }
}

pub fn routes() -> Router<SharedWorkbench> {
    Router::new()
        .route("/mobile/enrollment/invitations", post(post_invitation))
        .route("/mobile/enrollment/claim", post(post_claim))
        .route("/mobile/enrollment/prove", post(post_proof))
        .route("/mobile/enrollment/status", post(post_status))
        .route("/mobile/enrollment/requests", get(get_pending_requests))
        .route(
            "/mobile/enrollment/requests/:id/approve",
            post(post_approve),
        )
        .route("/mobile/enrollment/requests/:id/reject", post(post_reject))
        .route("/mobile/sessions/challenge", post(post_session_challenge))
        .route("/mobile/sessions", post(post_session))
        .route("/mobile/controllers", get(get_controllers))
        .route("/mobile/controllers/:id/revoke", post(post_revoke))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct InvitationRequest {
    endpoint: String,
}

async fn post_invitation(
    State(wb): State<SharedWorkbench>,
    Json(body): Json<InvitationRequest>,
) -> axum::response::Response {
    let endpoint = body.endpoint.trim().trim_end_matches('/').to_string();
    let endpoint_uri = endpoint.parse::<axum::http::Uri>().ok();
    let endpoint_valid = endpoint_uri.as_ref().is_some_and(|uri| {
        uri.scheme_str() == Some("https") && uri.host().is_some() && uri.query().is_none()
    });
    if !endpoint_valid {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "Machine controller invitations require an HTTPS Home endpoint without a query"
            })),
        )
            .into_response();
    }
    let now = now_secs();
    let id = random_id("invite");
    let secret = random_secret();
    let mut wb = wb.lock_unpoisoned();
    let machine = wb.home_id().clone();
    wb.machine_controllers.sweep(now);
    wb.machine_controllers.invitations.insert(
        id.clone(),
        Invitation {
            machine: machine.clone(),
            endpoint: endpoint.clone(),
            secret_hash: secret_hash(&secret),
            expires_at: now + INVITATION_TTL_SECS,
            consumed: false,
        },
    );
    (
        StatusCode::CREATED,
        Json(json!({
            "version": 1,
            "invitationId": id,
            "secret": secret,
            "machine": machine,
            "endpoint": endpoint,
            "expiresAt": now + INVITATION_TTL_SECS,
        })),
    )
        .into_response()
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ClaimRequest {
    invitation_id: String,
    secret: String,
    machine: HomeId,
    endpoint: String,
    device: DeviceId,
    public_key: PublicKey,
    #[serde(default)]
    label: String,
}

async fn post_claim(
    State(wb): State<SharedWorkbench>,
    Json(body): Json<ClaimRequest>,
) -> axum::response::Response {
    let now = now_secs();
    let mut wb = wb.lock_unpoisoned();
    let serving_machine = wb.home_id().clone();
    if body.machine != serving_machine {
        return (
            StatusCode::MISDIRECTED_REQUEST,
            Json(json!({ "error": "invitation belongs to another Machine" })),
        )
            .into_response();
    }
    wb.machine_controllers.sweep(now);
    let Some(invitation) = wb
        .machine_controllers
        .invitations
        .get_mut(&body.invitation_id)
    else {
        return (
            StatusCode::GONE,
            Json(json!({ "error": "invitation is unknown, spent, or expired" })),
        )
            .into_response();
    };
    if invitation.consumed
        || invitation.expires_at <= now
        || invitation.machine != body.machine
        || invitation.endpoint != body.endpoint
        || invitation.secret_hash != secret_hash(&body.secret)
    {
        return (
            StatusCode::GONE,
            Json(json!({ "error": "invitation is unknown, spent, or expired" })),
        )
            .into_response();
    }
    invitation.consumed = true;
    let request_id = random_id("controller-request");
    let nonce = hex::encode(random_bytes::<24>());
    let challenge_bytes = enrollment_challenge_bytes(
        &body.machine,
        &body.endpoint,
        &request_id,
        &body.device,
        &body.public_key,
        &nonce,
    );
    let challenge = String::from_utf8(challenge_bytes).expect("canonical challenge is UTF-8");
    wb.machine_controllers.requests.insert(
        request_id.clone(),
        EnrollmentRequest {
            state: ControllerState::challenged(body.machine, body.device, body.public_key),
            label: body.label,
            pickup_hash: secret_hash(&body.secret),
            challenge: challenge.clone(),
            expires_at: now + CHALLENGE_TTL_SECS,
            credential: None,
            grant_id: None,
        },
    );
    wb.machine_controllers
        .invitations
        .remove(&body.invitation_id);
    (
        StatusCode::CREATED,
        Json(json!({
            "requestId": request_id,
            "challenge": challenge,
            "expiresAt": now + CHALLENGE_TTL_SECS,
        })),
    )
        .into_response()
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProofRequest {
    request_id: String,
    signature: String,
}

async fn post_proof(
    State(wb): State<SharedWorkbench>,
    Json(body): Json<ProofRequest>,
) -> axum::response::Response {
    let now = now_secs();
    let mut wb = wb.lock_unpoisoned();
    wb.machine_controllers.sweep(now);
    let Some(request) = wb.machine_controllers.requests.get_mut(&body.request_id) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    if request.expires_at <= now {
        return StatusCode::GONE.into_response();
    }
    let Ok(signature) = URL_SAFE_NO_PAD.decode(&body.signature) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "signature is not base64url" })),
        )
            .into_response();
    };
    let valid = verify_signature(
        request.challenge.as_bytes(),
        &Signature::new(signature),
        &request.state.public_key,
    )
    .unwrap_or(false);
    match request.state.apply(ControllerCommand::Prove {
        signature_valid: valid,
    }) {
        Ok(state) => {
            request.state = state;
            (
                StatusCode::OK,
                Json(json!({ "status": "awaiting-owner-approval" })),
            )
                .into_response()
        }
        Err(_) => (
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "device key proof was refused" })),
        )
            .into_response(),
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct StatusRequest {
    request_id: String,
    secret: String,
}

async fn post_status(
    State(wb): State<SharedWorkbench>,
    Json(body): Json<StatusRequest>,
) -> axum::response::Response {
    let now = now_secs();
    let mut wb = wb.lock_unpoisoned();
    wb.machine_controllers.sweep(now);
    let Some(request) = wb.machine_controllers.requests.get_mut(&body.request_id) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    if request.pickup_hash != secret_hash(&body.secret) {
        return StatusCode::FORBIDDEN.into_response();
    }
    // Retry returns the same memory-only credential until the device proves it
    // by opening its first session. A dropped HTTP response must not strand an
    // already-approved grant.
    let credential = request.credential.clone();
    (
        StatusCode::OK,
        Json(json!({
            "status": request.state.phase,
            "grantId": request.grant_id,
            "credential": credential,
        })),
    )
        .into_response()
}

async fn get_pending_requests(State(wb): State<SharedWorkbench>) -> impl IntoResponse {
    let now = now_secs();
    let mut wb = wb.lock_unpoisoned();
    wb.machine_controllers.sweep(now);
    let pending = wb
        .machine_controllers
        .requests
        .iter()
        .filter(|(_, request)| request.state.phase == ControllerPhase::Proved)
        .map(|(id, request)| {
            json!({
                "requestId": id,
                "device": request.state.device,
                "publicKey": request.state.public_key,
                "label": request.label,
                "proved": true,
                "expiresAt": request.expires_at,
            })
        })
        .collect::<Vec<_>>();
    Json(json!({ "requests": pending }))
}

async fn post_approve(
    State(wb): State<SharedWorkbench>,
    Path(request_id): Path<String>,
) -> axum::response::Response {
    let now = now_secs();
    let mut wb = wb.lock_unpoisoned();
    wb.machine_controllers.sweep(now);
    let Some(mut request) = wb.machine_controllers.requests.remove(&request_id) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let state = match request.state.apply(ControllerCommand::Approve) {
        Ok(state) => state,
        Err(_) => {
            wb.machine_controllers.requests.insert(request_id, request);
            return (
                StatusCode::CONFLICT,
                Json(json!({ "error": "request has not proved its device key" })),
            )
                .into_response();
        }
    };
    let grant_id = random_id("controller");
    let credential = random_secret();
    let record = ControllerGrantRecord {
        id: grant_id.clone(),
        op: RecordOp::Upsert,
        machine: state.machine.clone(),
        device: state.device.clone(),
        public_key: state.public_key.clone(),
        label: request.label.clone(),
        credential_hash: secret_hash(&credential),
        status: ControllerGrantStatus::Active,
        enrolled_at: now,
    };
    if let Err(error) =
        wb.store_mut()
            .append_record(SCOPE, KIND, &serde_json::to_string(&record).unwrap())
    {
        wb.machine_controllers.requests.insert(request_id, request);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": format!("could not persist controller grant: {error:?}") })),
        )
            .into_response();
    }
    request.state = state;
    request.credential = Some(credential);
    request.grant_id = Some(grant_id.clone());
    request.expires_at = now + INVITATION_TTL_SECS;
    wb.machine_controllers.requests.insert(request_id, request);
    (
        StatusCode::OK,
        Json(json!({ "grantId": grant_id, "status": "granted" })),
    )
        .into_response()
}

async fn post_reject(
    State(wb): State<SharedWorkbench>,
    Path(request_id): Path<String>,
) -> axum::response::Response {
    let mut wb = wb.lock_unpoisoned();
    let Some(request) = wb.machine_controllers.requests.get_mut(&request_id) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    match request.state.apply(ControllerCommand::Reject) {
        Ok(state) => {
            request.state = state;
            StatusCode::NO_CONTENT.into_response()
        }
        Err(_) => StatusCode::CONFLICT.into_response(),
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SessionChallengeRequest {
    grant_id: String,
    device: DeviceId,
}

async fn post_session_challenge(
    State(wb): State<SharedWorkbench>,
    Json(body): Json<SessionChallengeRequest>,
) -> axum::response::Response {
    let now = now_secs();
    let mut wb = wb.lock_unpoisoned();
    let Some(grant) = active_grant(wb.store_ref(), &body.grant_id) else {
        return StatusCode::FORBIDDEN.into_response();
    };
    if grant.device != body.device || grant.machine != *wb.home_id() {
        return StatusCode::FORBIDDEN.into_response();
    }
    let challenge_id = random_id("session-challenge");
    let nonce = hex::encode(random_bytes::<24>());
    let challenge = String::from_utf8(session_challenge_bytes(
        &grant.machine,
        &grant.id,
        &grant.device,
        &grant.public_key,
        &nonce,
    ))
    .expect("canonical challenge is UTF-8");
    wb.machine_controllers.resume_challenges.insert(
        challenge_id.clone(),
        ResumeChallenge {
            grant_id: grant.id,
            challenge: challenge.clone(),
            expires_at: now + CHALLENGE_TTL_SECS,
        },
    );
    (
        StatusCode::CREATED,
        Json(json!({
            "challengeId": challenge_id,
            "challenge": challenge,
            "expiresAt": now + CHALLENGE_TTL_SECS,
        })),
    )
        .into_response()
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct OpenSessionRequest {
    challenge_id: String,
    grant_id: String,
    device: DeviceId,
    credential: String,
    signature: String,
}

async fn post_session(
    State(wb): State<SharedWorkbench>,
    Json(body): Json<OpenSessionRequest>,
) -> axum::response::Response {
    let now = now_secs();
    let mut wb = wb.lock_unpoisoned();
    wb.machine_controllers.sweep(now);
    let Some(challenge) = wb
        .machine_controllers
        .resume_challenges
        .remove(&body.challenge_id)
    else {
        return (
            StatusCode::GONE,
            Json(json!({ "error": "session challenge is unknown, spent, or expired" })),
        )
            .into_response();
    };
    if challenge.grant_id != body.grant_id || challenge.expires_at <= now {
        return StatusCode::FORBIDDEN.into_response();
    }
    let Some(grant) = active_grant(wb.store_ref(), &body.grant_id) else {
        return StatusCode::FORBIDDEN.into_response();
    };
    let Ok(signature) = URL_SAFE_NO_PAD.decode(&body.signature) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let signature_valid = verify_signature(
        challenge.challenge.as_bytes(),
        &Signature::new(signature),
        &grant.public_key,
    )
    .unwrap_or(false);
    let state = ControllerState {
        machine: grant.machine.clone(),
        device: grant.device.clone(),
        public_key: grant.public_key.clone(),
        phase: ControllerPhase::Granted,
        credential_issued: true,
        grant_active: true,
        session_active: false,
    };
    if state
        .apply(ControllerCommand::OpenSession {
            machine: wb.home_id().clone(),
            device: body.device,
            public_key: grant.public_key,
            credential_valid: grant.credential_hash == secret_hash(&body.credential),
            signature_valid,
        })
        .is_err()
    {
        return StatusCode::FORBIDDEN.into_response();
    }
    let token = random_secret();
    let expires_at = now + SESSION_TTL_SECS;
    wb.machine_controllers.sessions.insert(
        secret_hash(&token),
        ActiveSession {
            grant_id: grant.id,
            expires_at,
        },
    );
    for request in wb.machine_controllers.requests.values_mut() {
        if request.grant_id.as_deref() == Some(body.grant_id.as_str()) {
            request.credential = None;
        }
    }
    (
        StatusCode::CREATED,
        Json(json!({
            "session": token,
            "expiresAt": expires_at,
            "machine": wb.home_id(),
        })),
    )
        .into_response()
}

async fn get_controllers(State(wb): State<SharedWorkbench>) -> impl IntoResponse {
    let wb = wb.lock_unpoisoned();
    Json(json!({ "controllers": folded_grants(wb.store_ref()) }))
}

async fn post_revoke(
    State(wb): State<SharedWorkbench>,
    Path(grant_id): Path<String>,
) -> axum::response::Response {
    let mut wb = wb.lock_unpoisoned();
    let Some(mut grant) = active_grant(wb.store_ref(), &grant_id) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    grant.status = ControllerGrantStatus::Revoked;
    if let Err(error) =
        wb.store_mut()
            .append_record(SCOPE, KIND, &serde_json::to_string(&grant).unwrap())
    {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": format!("could not revoke controller: {error:?}") })),
        )
            .into_response();
    }
    wb.machine_controllers
        .sessions
        .retain(|_, session| session.grant_id != grant_id);
    StatusCode::NO_CONTENT.into_response()
}

fn folded_grants(store: &gaugewright_store::Store) -> Vec<ControllerGrantRecord> {
    let mut grants = BTreeMap::<String, ControllerGrantRecord>::new();
    for payload in store.records(SCOPE, KIND).unwrap_or_default() {
        if let Ok(record) = serde_json::from_str::<ControllerGrantRecord>(&payload) {
            match record.op {
                RecordOp::Upsert => {
                    grants.insert(record.id.clone(), record);
                }
                RecordOp::Tombstone => {
                    grants.remove(&record.id);
                }
            }
        }
    }
    grants.into_values().collect()
}

fn active_grant(store: &gaugewright_store::Store, grant_id: &str) -> Option<ControllerGrantRecord> {
    folded_grants(store)
        .into_iter()
        .find(|grant| grant.id == grant_id && grant.status == ControllerGrantStatus::Active)
}

/// Validate a short-lived Machine session and its still-active durable grant.
/// Every request rechecks the durable grant, so revocation invalidates already
/// issued sessions immediately.
pub fn authorize_session(wb: &mut crate::Workbench, token: &str) -> Option<ControllerGrantRecord> {
    let now = now_secs();
    wb.machine_controllers.sweep(now);
    let session = wb
        .machine_controllers
        .sessions
        .get(&secret_hash(token))?
        .clone();
    if session.expires_at <= now {
        return None;
    }
    let grant = active_grant(wb.store_ref(), &session.grant_id)?;
    (grant.machine == *wb.home_id()).then_some(grant)
}

pub fn session_token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(MACHINE_SESSION_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request};
    use http_body_util::BodyExt;
    use p256::ecdsa::{
        signature::Signer as _, Signature as P256Signature, SigningKey as P256SigningKey,
    };
    use tower::ServiceExt;

    use crate::{open_route_stack::open_control_plane, open_workbench};

    async fn json_call(
        app: &Router,
        method: &str,
        path: &str,
        body: serde_json::Value,
    ) -> (StatusCode, serde_json::Value) {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(path)
                    .header("content-type", "application/json")
                    .header("idempotency-key", random_id("test"))
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let value = if bytes.is_empty() {
            json!(null)
        } else {
            serde_json::from_slice(&bytes).unwrap()
        };
        (status, value)
    }

    async fn get_with_session(app: &Router, path: &str, token: &str) -> StatusCode {
        request_with_session(app, "GET", path, token).await
    }

    async fn request_with_session(
        app: &Router,
        method: &str,
        path: &str,
        token: &str,
    ) -> StatusCode {
        app.clone()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(path)
                    .header(MACHINE_SESSION_HEADER, token)
                    .header("idempotency-key", random_id("test"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap()
            .status()
    }

    fn raw_signature(key: &P256SigningKey, challenge: &str) -> String {
        let signature: P256Signature = key.sign(challenge.as_bytes());
        URL_SAFE_NO_PAD.encode(signature.to_bytes())
    }

    #[tokio::test]
    async fn enrollment_restart_session_and_revocation_are_device_bound() {
        let root = tempfile::tempdir().unwrap();
        let wb = open_workbench(root.path()).unwrap();
        let app = open_control_plane(wb.clone());
        let key = P256SigningKey::from_slice(&[7u8; 32]).unwrap();
        let public_key = PublicKey::new(hex::encode(key.verifying_key().to_sec1_bytes()));

        let (status, invitation) = json_call(
            &app,
            "POST",
            "/mobile/enrollment/invitations",
            json!({ "endpoint": "https://machine.example.test" }),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        let secret = invitation["secret"].as_str().unwrap();
        let (status, claim) = json_call(
            &app,
            "POST",
            "/mobile/enrollment/claim",
            json!({
                "invitationId": invitation["invitationId"],
                "secret": secret,
                "machine": invitation["machine"],
                "endpoint": invitation["endpoint"],
                "device": "device:android",
                "publicKey": public_key,
                "label": "Pixel"
            }),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        let request_id = claim["requestId"].as_str().unwrap();
        let challenge = claim["challenge"].as_str().unwrap();
        let (status, _) = json_call(
            &app,
            "POST",
            "/mobile/enrollment/prove",
            json!({
                "requestId": request_id,
                "signature": raw_signature(&key, challenge)
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let (status, approved) = json_call(
            &app,
            "POST",
            &format!("/mobile/enrollment/requests/{request_id}/approve"),
            json!({}),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let grant_id = approved["grantId"].as_str().unwrap().to_string();
        let (status, pickup) = json_call(
            &app,
            "POST",
            "/mobile/enrollment/status",
            json!({ "requestId": request_id, "secret": secret }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let credential = pickup["credential"].as_str().unwrap().to_string();
        let (status, pickup_retry) = json_call(
            &app,
            "POST",
            "/mobile/enrollment/status",
            json!({ "requestId": request_id, "secret": secret }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(pickup_retry["credential"], credential);

        // A Machine restart retains the hashed grant; the raw credential stays
        // only in the simulated Android vault (`credential` here).
        drop(app);
        drop(wb);
        let reopened = open_workbench(root.path()).unwrap();
        let reopened_app = open_control_plane(reopened.clone());
        let (status, resume) = json_call(
            &reopened_app,
            "POST",
            "/mobile/sessions/challenge",
            json!({ "grantId": grant_id, "device": "device:android" }),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        let (status, opened) = json_call(
            &reopened_app,
            "POST",
            "/mobile/sessions",
            json!({
                "challengeId": resume["challengeId"],
                "grantId": grant_id,
                "device": "device:android",
                "credential": credential,
                "signature": raw_signature(&key, resume["challenge"].as_str().unwrap())
            }),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        let token = opened["session"].as_str().unwrap().to_string();
        assert!(authorize_session(&mut reopened.lock_unpoisoned(), &token).is_some());
        let guarded_work = Router::new()
            .merge(crate::local_routes::routes(false))
            .merge(routes())
            .route_layer(axum::middleware::from_fn_with_state(
                reopened.clone(),
                crate::home_routes::require_home_admission,
            ))
            .with_state(reopened.clone());
        assert_eq!(
            get_with_session(&guarded_work, "/workspace", &token).await,
            StatusCode::OK
        );
        assert_eq!(
            get_with_session(&guarded_work, "/mobile/controllers", &token).await,
            StatusCode::UNAUTHORIZED,
            "a controller session must not authorize owner controller-management routes"
        );

        assert_eq!(
            request_with_session(
                &guarded_work,
                "POST",
                "/mobile/controllers/another-grant/revoke",
                &token,
            )
            .await,
            StatusCode::FORBIDDEN,
        );
        assert_eq!(
            request_with_session(
                &guarded_work,
                "POST",
                &format!("/mobile/controllers/{grant_id}/revoke"),
                &token,
            )
            .await,
            StatusCode::NO_CONTENT,
        );
        assert!(authorize_session(&mut reopened.lock_unpoisoned(), &token).is_none());
        assert_eq!(
            get_with_session(&guarded_work, "/workspace", &token).await,
            StatusCode::UNAUTHORIZED
        );
    }

    #[tokio::test]
    async fn invitation_and_challenge_replay_fail_closed() {
        let root = tempfile::tempdir().unwrap();
        let wb = open_workbench(root.path()).unwrap();
        let app = open_control_plane(wb);
        let key = P256SigningKey::from_slice(&[8u8; 32]).unwrap();
        let public_key = hex::encode(key.verifying_key().to_sec1_bytes());
        let (_, invitation) = json_call(
            &app,
            "POST",
            "/mobile/enrollment/invitations",
            json!({ "endpoint": "https://machine.example.test/" }),
        )
        .await;
        assert_eq!(invitation["endpoint"], "https://machine.example.test");
        let (path_endpoint, path_invitation) = json_call(
            &app,
            "POST",
            "/mobile/enrollment/invitations",
            json!({ "endpoint": "https://machine.example.test/control-plane" }),
        )
        .await;
        assert_eq!(path_endpoint, StatusCode::CREATED);
        assert_eq!(
            path_invitation["endpoint"],
            "https://machine.example.test/control-plane"
        );
        let (invalid_endpoint, _) = json_call(
            &app,
            "POST",
            "/mobile/enrollment/invitations",
            json!({ "endpoint": "https://machine.example.test/control-plane?wrong=route" }),
        )
        .await;
        assert_eq!(invalid_endpoint, StatusCode::BAD_REQUEST);
        let claim_body = json!({
            "invitationId": invitation["invitationId"],
            "secret": invitation["secret"],
            "machine": invitation["machine"],
            "endpoint": invitation["endpoint"],
            "device": "device:android",
            "publicKey": public_key
        });
        let (first, claim) =
            json_call(&app, "POST", "/mobile/enrollment/claim", claim_body.clone()).await;
        let (replay, _) = json_call(&app, "POST", "/mobile/enrollment/claim", claim_body).await;
        assert_eq!(first, StatusCode::CREATED);
        assert_eq!(replay, StatusCode::GONE);

        let proof = json!({
            "requestId": claim["requestId"],
            "signature": raw_signature(&key, claim["challenge"].as_str().unwrap())
        });
        let (first, _) = json_call(&app, "POST", "/mobile/enrollment/prove", proof.clone()).await;
        let (replay, _) = json_call(&app, "POST", "/mobile/enrollment/prove", proof).await;
        assert_eq!(first, StatusCode::OK);
        assert_eq!(replay, StatusCode::FORBIDDEN);
    }
}
