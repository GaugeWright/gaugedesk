//! An account's recovery code, shown and used from a desktop window
//! ([DR-0361](../../../specs/decisions/0361-account-and-project-key-custody.md) §3).
//!
//! The code is the account's root in transcribable form, and the account key
//! follows from the root, so a computer that holds neither restores both from
//! it. Losing every computer then loses nothing, as long as the code survives.
//!
//! Both routes answer only this computer's own window, for the account signed
//! in there. A code is taken only when its root is the one the Hub names for
//! that account, so a mistyped or another account's code is refused rather
//! than installed as a new identity.

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};
use serde::Deserialize;
use serde_json::json;

use crate::account_signin::DesktopOperatorPlane;
use crate::{net_http, LockUnpoisoned, SharedWorkbench};

fn refusal(status: StatusCode, message: &'static str) -> Response {
    (status, Json(json!({ "error": message }))).into_response()
}

/// The account signed in to this computer's own window.
fn window_account(
    wb: &SharedWorkbench,
    headers: &HeaderMap,
    window: bool,
) -> Result<String, (StatusCode, &'static str)> {
    let wb = wb.lock_unpoisoned();
    if !wb.desktop_account_mode() {
        return Err((
            StatusCode::NOT_FOUND,
            "recovery codes are kept on a desktop",
        ));
    }
    if !window {
        return Err((
            StatusCode::FORBIDDEN,
            "only this computer's own window handles a recovery code",
        ));
    }
    net_http::bearer(headers)
        .and_then(|token| wb.resolve_account_session(token))
        .map(|(account, _)| account)
        .filter(|account| account != wb.authority().as_str())
        .ok_or((StatusCode::UNAUTHORIZED, "sign in to the account first"))
}

fn now_secs() -> u64 {
    crate::account::device_enrolled_at_now()
}

/// `GET /account/recovery-code`: the signed-in account's code, while this
/// computer holds its keys.
pub async fn get_recovery_code(
    State(wb): State<SharedWorkbench>,
    headers: HeaderMap,
    window: Option<Extension<DesktopOperatorPlane>>,
) -> Response {
    let account = match window_account(&wb, &headers, window.is_some()) {
        Ok(account) => account,
        Err((status, message)) => return refusal(status, message),
    };
    let code = wb
        .lock_unpoisoned()
        .account_key_store()
        .recovery_code(&account, now_secs());
    match code {
        Ok(Some(code)) => Json(json!({ "account": account, "code": code })).into_response(),
        Ok(None) => refusal(
            StatusCode::NOT_FOUND,
            "this computer does not hold this account's keys",
        ),
        Err(_) => refusal(
            StatusCode::INTERNAL_SERVER_ERROR,
            "this account's keys could not be read",
        ),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestoreFromCode {
    pub code: String,
}

/// What restoring decided, before any key is written.
#[derive(Debug, PartialEq, Eq)]
pub enum RestoreRefusal {
    Malformed,
    Checksum,
    /// The Hub names no root for the account, so there is nothing to restore.
    NothingToRestore,
    /// The code's root is not the one the Hub names for the account.
    NotThisAccount,
    AlreadyHeld,
}

impl RestoreRefusal {
    fn response(&self) -> Response {
        match self {
            RestoreRefusal::Malformed => refusal(
                StatusCode::UNPROCESSABLE_ENTITY,
                "that is not a recovery code",
            ),
            RestoreRefusal::Checksum => refusal(
                StatusCode::UNPROCESSABLE_ENTITY,
                "that recovery code has a typo in it",
            ),
            RestoreRefusal::NothingToRestore => refusal(
                StatusCode::CONFLICT,
                "this account has no keys to restore yet",
            ),
            RestoreRefusal::NotThisAccount => refusal(
                StatusCode::CONFLICT,
                "that recovery code belongs to a different account",
            ),
            RestoreRefusal::AlreadyHeld => refusal(
                StatusCode::CONFLICT,
                "this computer already holds this account's keys",
            ),
        }
    }
}

/// Decide whether `code` restores the account whose Hub-projected root is
/// `projected`, without I/O.
pub fn check_code(
    code: &str,
    projected: Option<&str>,
) -> Result<gaugedesk_core::signature::SigningKey, RestoreRefusal> {
    use gaugedesk_core::recovery::{import_recovery, RecoveryError};
    let root = import_recovery(code).map_err(|error| match error {
        RecoveryError::Checksum => RestoreRefusal::Checksum,
        RecoveryError::Malformed | RecoveryError::BadSeed => RestoreRefusal::Malformed,
    })?;
    match projected {
        None => Err(RestoreRefusal::NothingToRestore),
        Some(projected) if projected != root.public_key().as_str() => {
            Err(RestoreRefusal::NotThisAccount)
        }
        Some(_) => Ok(root),
    }
}

/// `POST /account/recovery-code/restore`: restore the signed-in account's
/// keys on this computer from its recovery code, then publish its entry.
pub async fn post_restore_from_code(
    State(wb): State<SharedWorkbench>,
    headers: HeaderMap,
    window: Option<Extension<DesktopOperatorPlane>>,
    Json(body): Json<RestoreFromCode>,
) -> Response {
    let account = match window_account(&wb, &headers, window.is_some()) {
        Ok(account) => account,
        Err((status, message)) => return refusal(status, message),
    };
    let (Some(hub), Some(bearer)) = (
        crate::account_signin::hub_base(),
        crate::account_signin::hub_session_token_for(&wb, &account),
    ) else {
        return refusal(
            StatusCode::UNAUTHORIZED,
            "sign in to the account again first",
        );
    };
    let projected = tokio::task::spawn_blocking(move || {
        let http = crate::net_http::HttpClient::new();
        let headers = [("authorization".to_owned(), format!("Bearer {bearer}"))];
        match http.get_string_headers(&format!("{hub}/account/directory"), &headers) {
            Ok((200, body)) => Ok(crate::account_publish::Projection::from_json(
                &serde_json::from_str(&body).unwrap_or_default(),
            )
            .root),
            Ok((404, _)) => Ok(None),
            Ok((status, _)) => Err(status),
            Err(_) => Err(502),
        }
    })
    .await;
    let projected = match projected {
        Ok(Ok(projected)) => projected,
        _ => {
            return refusal(
                StatusCode::BAD_GATEWAY,
                "the Hub could not say which keys this account has",
            )
        }
    };
    let root = match check_code(&body.code, projected.as_deref()) {
        Ok(root) => root,
        Err(refused) => return refused.response(),
    };
    let restored = {
        let guard = wb.lock_unpoisoned();
        let store = guard.account_key_store();
        if matches!(store.held(&account, now_secs()), Ok(Some(_))) {
            return RestoreRefusal::AlreadyHeld.response();
        }
        store.restore(&account, root, now_secs())
    };
    match restored {
        Ok(_) => {
            crate::account_publish::spawn_publish(&wb, &account);
            Json(json!({ "account": account, "restored": true })).into_response()
        }
        Err(_) => refusal(
            StatusCode::INTERNAL_SERVER_ERROR,
            "this account's keys could not be kept on this computer",
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    async fn get(app: &axum::Router, bearer: Option<&str>) -> (StatusCode, serde_json::Value) {
        let mut request = Request::builder()
            .method("GET")
            .uri("/account/recovery-code");
        if let Some(bearer) = bearer {
            request = request.header("authorization", format!("Bearer {bearer}"));
        }
        let response = app
            .clone()
            .oneshot(request.body(Body::empty()).unwrap())
            .await
            .unwrap();
        let status = response.status();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
        )
    }

    #[tokio::test]
    async fn only_the_window_with_a_signed_in_account_sees_its_recovery_code() {
        let root = tempfile::tempdir().unwrap();
        let wb = crate::open_workbench(root.path()).unwrap();
        let token = wb
            .lock_unpoisoned()
            .mint_account_session("acct-dana", crate::desktop_session::METHOD, 3600)
            .unwrap();
        let window = crate::open_runtime::desktop_operator_plane(wb.clone());
        let relay = crate::open_control_plane(wb.clone());

        // The relay leg reaches the routes as a signed-in account, but it is
        // not the window.
        let (status, body) = get(&relay, Some(&token)).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
        for bearer in [None, Some("not-a-session")] {
            assert_eq!(get(&window, bearer).await.0, StatusCode::UNAUTHORIZED);
        }
        assert_eq!(
            get(&window, Some(&token)).await.0,
            StatusCode::NOT_FOUND,
            "no keys held here yet"
        );

        let keys = wb
            .lock_unpoisoned()
            .account_key_store()
            .mint("acct-dana", now_secs())
            .unwrap();
        let (status, body) = get(&window, Some(&token)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            body["code"],
            gaugedesk_core::recovery::export_recovery(&keys.root)
        );
    }

    #[test]
    fn a_code_restores_only_the_account_the_hub_names() {
        let root = gaugedesk_core::signature::SigningKey::from_seed(&[4; 32]).unwrap();
        let code = gaugedesk_core::recovery::export_recovery(&root);
        let named = root.public_key();
        assert_eq!(
            check_code(&code, Some(named.as_str())).map(|key| key.public_key()),
            Ok(named.clone())
        );
        assert_eq!(
            check_code(&code, Some("another-root")).map(|_| ()),
            Err(RestoreRefusal::NotThisAccount)
        );
        assert_eq!(
            check_code(&code, None).map(|_| ()),
            Err(RestoreRefusal::NothingToRestore)
        );
        assert_eq!(
            check_code("not a code", Some(named.as_str())).map(|_| ()),
            Err(RestoreRefusal::Malformed)
        );
        let typo = code.replacen(&code[0..1], if &code[0..1] == "A" { "B" } else { "A" }, 1);
        assert_eq!(
            check_code(&typo, Some(named.as_str())).map(|_| ()),
            Err(RestoreRefusal::Checksum)
        );
    }
}
