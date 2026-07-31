//! Authenticated carrier-neutral wake service and hermetic mock carrier.
//!
//! Provider tokens remain in this imperative adapter; reducer state and mock
//! payloads contain only opaque handles and target references (ADR 0116).

use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{delete, get, post},
    Json, Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use gaugewright_core::{
    ids::{AuthorityId, PublicKey},
    mobile_wake::{
        decide_installation, decide_wake, evolve_installation, evolve_wake,
        installation_proof_bytes, CarrierPlatform, InstallationCommand, InstallationEvent,
        InstallationState, WakeCommand, WakeEvent, WakeState,
    },
    signature::{verify_signature, Signature},
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::{net_http, LockUnpoisoned, SharedWorkbench};

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct MockNotification {
    notification_id: String,
    device: String,
    installation_epoch: u64,
    target_reference: String,
    expires_at: u64,
}

#[derive(Default)]
pub struct MobileWakeRuntime {
    installations: BTreeMap<(String, String), InstallationState>,
    /// Raw provider tokens belong only to the carrier adapter. The mock never
    /// serializes this map and production adapters replace it with their vault.
    provider_tokens: BTreeMap<(String, String), String>,
    wakes: BTreeMap<(String, String), WakeState>,
    mock_notifications: BTreeMap<String, Vec<MockNotification>>,
}

const INSTALLATION_KIND: &str = "mobile-wake-installation";
const WAKE_KIND: &str = "mobile-wake";

#[derive(Serialize, Deserialize)]
struct StoredInstallationEvent {
    device: String,
    event: InstallationEvent,
}

#[derive(Serialize, Deserialize)]
struct StoredWakeEvent {
    notification_id: String,
    event: WakeEvent,
}

fn load_installation(
    store: &gaugewright_store::Store,
    account: &str,
    device: &str,
) -> InstallationState {
    store
        .records(account, INSTALLATION_KIND)
        .unwrap_or_default()
        .into_iter()
        .filter_map(|row| serde_json::from_str::<StoredInstallationEvent>(&row).ok())
        .filter(|record| record.device == device)
        .fold(InstallationState::default(), |state, record| {
            evolve_installation(&state, record.event)
        })
}

fn load_wake(store: &gaugewright_store::Store, account: &str, notification_id: &str) -> WakeState {
    store
        .records(account, WAKE_KIND)
        .unwrap_or_default()
        .into_iter()
        .filter_map(|row| serde_json::from_str::<StoredWakeEvent>(&row).ok())
        .filter(|record| record.notification_id == notification_id)
        .fold(WakeState::default(), |state, record| {
            evolve_wake(&state, record.event)
        })
}

pub fn hub_routes() -> Router<SharedWorkbench> {
    Router::new()
        .route("/account/mobile/installations", post(post_installation))
        .route(
            "/account/mobile/installations/:device",
            delete(delete_installation),
        )
        .route("/account/mobile/wakes", get(get_mock_notifications))
}

pub fn home_routes() -> Router<SharedWorkbench> {
    Router::new().route("/mobile/wakes", post(post_wake))
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default()
}

#[allow(clippy::result_large_err)]
fn authenticated_account(headers: &HeaderMap) -> Result<&str, axum::response::Response> {
    net_http::bearer(headers).ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "account authentication required" })),
        )
            .into_response()
    })
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct InstallationBody {
    device: String,
    platform: CarrierPlatform,
    provider_token: String,
    epoch: u64,
    proof: String,
}

async fn post_installation(
    State(wb): State<SharedWorkbench>,
    headers: HeaderMap,
    Json(body): Json<InstallationBody>,
) -> axum::response::Response {
    let bearer = match authenticated_account(&headers) {
        Ok(bearer) => bearer,
        Err(response) => return response,
    };
    if body.provider_token.trim().is_empty() {
        return StatusCode::UNPROCESSABLE_ENTITY.into_response();
    }
    let mut wb = wb.lock_unpoisoned();
    let account = wb.account_scope_for(Some(bearer));
    let Ok(projection) = crate::account::Account::rebuild_in(wb.store_ref(), &account) else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    let Some(device) = projection
        .devices
        .get(&body.device)
        .filter(|device| device.status == crate::account::DeviceStatus::Active)
    else {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "wake installation requires an active enrolled Device" })),
        )
            .into_response();
    };
    let token_handle = hex::encode(Sha256::digest(body.provider_token.as_bytes()));
    let proof = URL_SAFE_NO_PAD.decode(&body.proof).ok();
    let proof_verified = proof.is_some_and(|proof| {
        verify_signature(
            &installation_proof_bytes(
                &account,
                &body.device,
                body.platform,
                &token_handle,
                body.epoch,
            ),
            &Signature::new(proof),
            &PublicKey::new(device.subkey_pubkey.clone()),
        )
        .unwrap_or(false)
    });
    let key = (account.clone(), body.device.clone());
    let state = load_installation(wb.store_ref(), &account, &body.device);
    let event = match decide_installation(
        &state,
        InstallationCommand::Register {
            account: account.clone(),
            device: body.device.clone(),
            platform: body.platform,
            token_handle: token_handle.clone(),
            epoch: body.epoch,
            device_proof_verified: proof_verified,
        },
    ) {
        Ok(mut events) => events.remove(0),
        Err(rejection) => {
            return (
                StatusCode::FORBIDDEN,
                Json(json!({ "error": rejection.reason })),
            )
                .into_response()
        }
    };
    let stored = StoredInstallationEvent {
        device: body.device.clone(),
        event: event.clone(),
    };
    if wb
        .store_mut()
        .append_record(
            &account,
            INSTALLATION_KIND,
            &serde_json::to_string(&stored).unwrap(),
        )
        .is_err()
    {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    wb.mobile_wakes
        .installations
        .insert(key.clone(), evolve_installation(&state, event));
    wb.mobile_wakes
        .provider_tokens
        .insert(key, body.provider_token);
    (
        StatusCode::CREATED,
        Json(json!({ "tokenHandle": token_handle, "epoch": body.epoch })),
    )
        .into_response()
}

#[derive(Deserialize)]
struct DisableQuery {
    epoch: u64,
}

async fn delete_installation(
    State(wb): State<SharedWorkbench>,
    headers: HeaderMap,
    Path(device): Path<String>,
    Json(body): Json<DisableQuery>,
) -> axum::response::Response {
    let bearer = match authenticated_account(&headers) {
        Ok(bearer) => bearer,
        Err(response) => return response,
    };
    let mut wb = wb.lock_unpoisoned();
    let account = wb.account_scope_for(Some(bearer));
    let key = (account.clone(), device.clone());
    let state = load_installation(wb.store_ref(), &account, &device);
    if state.account.is_empty() {
        return StatusCode::NOT_FOUND.into_response();
    }
    let event = match decide_installation(
        &state,
        InstallationCommand::Disable {
            account: account.clone(),
            device: device.clone(),
            epoch: body.epoch,
        },
    ) {
        Ok(mut events) => events.remove(0),
        Err(rejection) => {
            return (
                StatusCode::CONFLICT,
                Json(json!({ "error": rejection.reason })),
            )
                .into_response()
        }
    };
    let stored = StoredInstallationEvent {
        device,
        event: event.clone(),
    };
    if wb
        .store_mut()
        .append_record(
            &account,
            INSTALLATION_KIND,
            &serde_json::to_string(&stored).unwrap(),
        )
        .is_err()
    {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    wb.mobile_wakes
        .installations
        .insert(key.clone(), evolve_installation(&state, event));
    wb.mobile_wakes.provider_tokens.remove(&key);
    StatusCode::NO_CONTENT.into_response()
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct WakeBody {
    notification_id: String,
    device: String,
    installation_epoch: u64,
    target_reference: String,
    expires_at: u64,
}

async fn post_wake(
    State(wb): State<SharedWorkbench>,
    headers: HeaderMap,
    Json(body): Json<WakeBody>,
) -> axum::response::Response {
    let bearer = match authenticated_account(&headers) {
        Ok(bearer) => bearer,
        Err(response) => return response,
    };
    let Some(admission) = headers
        .get(crate::home_admission::HOME_ADMISSION_HEADER)
        .and_then(|value| value.to_str().ok())
        .and_then(crate::home_admission::HomeAdmissionToken::parse)
    else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "authenticated Home admission required" })),
        )
            .into_response();
    };
    let mut wb = wb.lock_unpoisoned();
    let actor = match wb.admit_data_request(Some(bearer), None) {
        Ok(actor) => AuthorityId::new(actor),
        Err((status, message)) => {
            return (status, Json(json!({ "error": message }))).into_response()
        }
    };
    if wb
        .home_admissions
        .authorize(wb.home_id(), &actor, &admission)
        .is_err()
    {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "Home admission does not match this identity" })),
        )
            .into_response();
    }
    let account = wb.account_scope_for(Some(bearer));
    let installation = load_installation(wb.store_ref(), &account, &body.device);
    let key = (account.clone(), body.notification_id.clone());
    let mut state = load_wake(wb.store_ref(), &account, &body.notification_id);
    let event = match decide_wake(
        &state,
        WakeCommand::Submit {
            notification_id: body.notification_id.clone(),
            installation_epoch: body.installation_epoch,
            target_reference: body.target_reference.clone(),
            expires_at: body.expires_at,
            now: now_secs(),
            home_authenticated: true,
            protected_payload_present: false,
            installation,
        },
    ) {
        Ok(mut events) => events.remove(0),
        Err(rejection) => {
            return (
                StatusCode::CONFLICT,
                Json(json!({ "error": rejection.reason })),
            )
                .into_response()
        }
    };
    let queued = StoredWakeEvent {
        notification_id: body.notification_id.clone(),
        event: event.clone(),
    };
    if wb
        .store_mut()
        .append_record(
            &account,
            WAKE_KIND,
            &serde_json::to_string(&queued).unwrap(),
        )
        .is_err()
    {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    state = evolve_wake(&state, event);
    // Mock carrier: accept a generic reference-only payload immediately.
    let accepted = decide_wake(&state, WakeCommand::RecordCarrierAccepted)
        .expect("a newly queued wake accepts carrier evidence")
        .remove(0);
    let stored = StoredWakeEvent {
        notification_id: body.notification_id.clone(),
        event: accepted.clone(),
    };
    if wb
        .store_mut()
        .append_record(
            &account,
            WAKE_KIND,
            &serde_json::to_string(&stored).unwrap(),
        )
        .is_err()
    {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    state = evolve_wake(&state, accepted);
    wb.mobile_wakes.wakes.insert(key, state);
    wb.mobile_wakes
        .mock_notifications
        .entry(account)
        .or_default()
        .push(MockNotification {
            notification_id: body.notification_id,
            device: body.device,
            installation_epoch: body.installation_epoch,
            target_reference: body.target_reference,
            expires_at: body.expires_at,
        });
    StatusCode::ACCEPTED.into_response()
}

async fn get_mock_notifications(
    State(wb): State<SharedWorkbench>,
    headers: HeaderMap,
) -> axum::response::Response {
    let bearer = match authenticated_account(&headers) {
        Ok(bearer) => bearer,
        Err(response) => return response,
    };
    let mut wb = wb.lock_unpoisoned();
    let account = wb.account_scope_for(Some(bearer));
    let notifications = wb
        .mobile_wakes
        .mock_notifications
        .remove(&account)
        .unwrap_or_default();
    (
        StatusCode::OK,
        Json(json!({ "notifications": notifications })),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request};
    use http_body_util::BodyExt;
    use p256::ecdsa::{
        signature::Signer, Signature as P256Signature, SigningKey as P256SigningKey,
    };
    use tower::ServiceExt;

    async fn call(
        app: &Router,
        method: &str,
        path: &str,
        body: Option<serde_json::Value>,
        admission: Option<&str>,
    ) -> (StatusCode, serde_json::Value) {
        let mut request = Request::builder()
            .method(method)
            .uri(path)
            .header("authorization", "Bearer account-test");
        if let Some(admission) = admission {
            request = request.header(crate::home_admission::HOME_ADMISSION_HEADER, admission);
        }
        let body = if let Some(body) = body {
            request = request.header("content-type", "application/json");
            Body::from(body.to_string())
        } else {
            Body::empty()
        };
        let response = app
            .clone()
            .oneshot(request.body(body).unwrap())
            .await
            .unwrap();
        let status = response.status();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let payload = if bytes.is_empty() {
            json!(null)
        } else {
            serde_json::from_slice(&bytes).unwrap()
        };
        (status, payload)
    }

    #[tokio::test]
    async fn proof_bound_registration_and_reference_only_mock_delivery_compose() {
        let root = tempfile::tempdir().unwrap();
        let wb = crate::open_workbench(root.path()).unwrap();
        let key = P256SigningKey::from_slice(&[9u8; 32]).unwrap();
        let device = "device:phone";
        {
            let mut guard = wb.lock_unpoisoned();
            guard
                .upsert_account_device(&crate::account::DeviceRecord {
                    id: device.into(),
                    op: crate::account::RecordOp::Upsert,
                    label: "Phone".into(),
                    subkey_pubkey: hex::encode(key.verifying_key().to_sec1_bytes()),
                    status: crate::account::DeviceStatus::Active,
                    enrolled_at: 1,
                })
                .unwrap();
        }
        let provider_token = "mock-provider-token";
        let token_handle = hex::encode(Sha256::digest(provider_token.as_bytes()));
        let signature: P256Signature = key.sign(&installation_proof_bytes(
            crate::account::ACCOUNT_SCOPE,
            device,
            CarrierPlatform::Fcm,
            &token_handle,
            1,
        ));
        let app = hub_routes().merge(home_routes()).with_state(wb.clone());
        let (status, _) = call(
            &app,
            "POST",
            "/account/mobile/installations",
            Some(json!({
                "device": device,
                "platform": "fcm",
                "providerToken": provider_token,
                "epoch": 1,
                "proof": URL_SAFE_NO_PAD.encode(signature.to_bytes()),
            })),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        let reopened = crate::open_workbench(root.path()).unwrap();
        assert!(
            load_installation(
                reopened.lock_unpoisoned().store_ref(),
                crate::account::ACCOUNT_SCOPE,
                device,
            )
            .active,
            "installation registration must survive a Hub restart"
        );
        drop(reopened);

        let admission = {
            let mut guard = wb.lock_unpoisoned();
            let home = guard.home_id().clone();
            guard
                .home_admissions
                .open(home, AuthorityId::new(crate::LOCAL_AUTHORITY))
                .encode()
        };
        let (status, _) = call(
            &app,
            "POST",
            "/mobile/wakes",
            Some(json!({
                "notificationId": "wake:test",
                "device": device,
                "installationEpoch": 1,
                "targetReference": "gaugewright://open?project=opaque-project",
                "expiresAt": now_secs() + 60,
            })),
            Some(&admission),
        )
        .await;
        assert_eq!(status, StatusCode::ACCEPTED);
        let (status, payload) = call(&app, "GET", "/account/mobile/wakes", None, None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            payload["notifications"][0]["targetReference"],
            "gaugewright://open?project=opaque-project"
        );
        assert!(
            !payload.to_string().contains(provider_token),
            "carrier payload leaked provider material"
        );
    }
}
