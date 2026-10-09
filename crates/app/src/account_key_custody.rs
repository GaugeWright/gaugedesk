//! Recoverable custody of a computer-held account directory root (DR-0478).
//!
//! The private Hub stores only a ciphertext under the account's secret boundary.
//! A computer that already holds the projected root may seed custody over its
//! device-bound account session. The blind directory never receives a seed.

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use gaugedesk_core::signature::SigningKey;
use serde::{Deserialize, Serialize};

use crate::{account::Account, net_http, LockUnpoisoned, SharedWorkbench, Workbench};

const RECORD_KIND: &str = "account_directory_root_custody";

#[derive(Serialize, Deserialize)]
struct CustodiedRoot {
    id: String,
    root_pubkey: String,
    sealed_seed: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DepositRoot {
    seed: String,
}

fn stored(wb: &Workbench, account_id: &str) -> Option<CustodiedRoot> {
    let scope = crate::account::account_scope(account_id);
    let rows = wb.store_ref().records(&scope, RECORD_KIND).ok()?;
    rows.last().and_then(|row| serde_json::from_str(row).ok())
}

/// Open a deposited root only while it matches the Hub's settled directory
/// projection. A pending hand-over cannot make a new root downloadable.
pub fn open_projected(wb: &Workbench, account_id: &str) -> Option<SigningKey> {
    let scope = crate::account::account_scope(account_id);
    let projected = Account::rebuild_in(wb.store_ref(), &scope)
        .ok()?
        .directory?
        .root_pubkey;
    let record = stored(wb, account_id)?;
    if record.root_pubkey != projected {
        return None;
    }
    let seed = wb.unseal_custodied_account_root(account_id, &record.sealed_seed)?;
    let seed: [u8; 32] = hex::decode(seed).ok()?.try_into().ok()?;
    let root = SigningKey::from_seed(&seed).ok()?;
    (root.public_key().as_str() == projected).then_some(root)
}

/// Deposit the root held by this computer after its directory publication has
/// settled. A session alone cannot invent a root: the seed must yield exactly
/// the public key already projected for this account.
pub async fn post_deposit_root(
    State(wb): State<SharedWorkbench>,
    headers: HeaderMap,
    Json(request): Json<DepositRoot>,
) -> impl IntoResponse {
    let bearer = net_http::bearer(&headers);
    let mut wb = wb.lock_unpoisoned();
    let account_id = wb.actor(bearer);
    if account_id == "anonymous" {
        return StatusCode::UNAUTHORIZED;
    }
    let scope = crate::account::account_scope(&account_id);
    if !crate::account_routes::session_device(&wb, bearer, &scope)
        .is_some_and(|device| device.status == crate::account::DeviceStatus::Active)
    {
        return StatusCode::FORBIDDEN;
    }
    let Some(projected) = Account::rebuild_in(wb.store_ref(), &scope)
        .ok()
        .and_then(|account| account.directory.map(|directory| directory.root_pubkey))
    else {
        return StatusCode::CONFLICT;
    };
    let Ok(seed) = hex::decode(&request.seed).and_then(|bytes| {
        bytes
            .try_into()
            .map_err(|_| hex::FromHexError::InvalidStringLength)
    }) else {
        return StatusCode::BAD_REQUEST;
    };
    let Ok(root) = SigningKey::from_seed(&seed) else {
        return StatusCode::BAD_REQUEST;
    };
    if root.public_key().as_str() != projected {
        return StatusCode::CONFLICT;
    }
    if stored(&wb, &account_id)
        .as_ref()
        .is_some_and(|record| record.root_pubkey == projected)
    {
        return StatusCode::NO_CONTENT;
    }
    let Some(sealed_seed) = wb.seal_custodied_account_root(&account_id, &request.seed) else {
        return StatusCode::SERVICE_UNAVAILABLE;
    };
    let record = CustodiedRoot {
        id: "directory-root".to_owned(),
        root_pubkey: projected,
        sealed_seed,
    };
    match wb.write_account_record_in(&scope, RECORD_KIND, &record.id, &record) {
        Ok(()) => StatusCode::NO_CONTENT,
        Err(_) => StatusCode::SERVICE_UNAVAILABLE,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    use crate::account::{
        AccountDirectoryRecord, DeviceKind, DeviceRecord, DeviceStatus, RecordOp,
        DIRECTORY_RECORD_ID,
    };

    #[tokio::test]
    async fn only_the_projected_root_is_custodied_and_it_opens_under_that_account() {
        let dir = tempfile::tempdir().unwrap();
        let vault = Arc::new(crate::content_vault::ContentVault::new(
            dir.path(),
            Box::new(crate::at_rest::LoopbackKeyWrap::new([11; 32])),
        ));
        let mut wb = Workbench::new(gaugedesk_store::Store::open_in_memory().unwrap())
            .with_content_vault(vault);
        let account_id = "account-a";
        let root = SigningKey::from_seed(&[5; 32]).unwrap();
        let other = SigningKey::from_seed(&[6; 32]).unwrap();
        let scope = crate::account::account_scope(account_id);
        wb.write_account_record_in(
            &scope,
            crate::account::DIRECTORY_RECORD_KIND,
            DIRECTORY_RECORD_ID,
            &AccountDirectoryRecord {
                id: DIRECTORY_RECORD_ID.to_owned(),
                op: RecordOp::Upsert,
                root_pubkey: root.public_key().as_str().to_owned(),
                origin: String::new(),
                transitions: vec![],
                proven: true,
            },
        )
        .unwrap();
        let bearer = wb
            .mint_account_session(account_id, "passkey", 3600)
            .unwrap();
        wb.upsert_account_device_in(
            &scope,
            &DeviceRecord {
                id: "native-device".to_owned(),
                op: RecordOp::Upsert,
                label: "Test computer".to_owned(),
                kind: DeviceKind::Computer,
                subkey_pubkey: String::new(),
                status: DeviceStatus::Active,
                enrolled_at: 1,
            },
        )
        .unwrap();
        let session_id = crate::account_session::session_id(&bearer);
        assert!(wb.bind_account_session_device(&session_id, account_id, "native-device"));
        let shared: SharedWorkbench = Arc::new(Mutex::new(wb));
        let mut headers = HeaderMap::new();
        headers.insert("authorization", format!("Bearer {bearer}").parse().unwrap());

        let refused = post_deposit_root(
            State(shared.clone()),
            headers.clone(),
            Json(DepositRoot {
                seed: hex::encode(other.to_seed_bytes()),
            }),
        )
        .await
        .into_response();
        assert_eq!(refused.status(), StatusCode::CONFLICT);
        assert!(open_projected(&shared.lock_unpoisoned(), account_id).is_none());

        let accepted = post_deposit_root(
            State(shared.clone()),
            headers.clone(),
            Json(DepositRoot {
                seed: hex::encode(root.to_seed_bytes()),
            }),
        )
        .await
        .into_response();
        assert_eq!(accepted.status(), StatusCode::NO_CONTENT);
        let guard = shared.lock_unpoisoned();
        let record = stored(&guard, account_id).unwrap();
        assert!(!record
            .sealed_seed
            .contains(&hex::encode(root.to_seed_bytes())));
        assert_eq!(
            open_projected(&guard, account_id).unwrap().public_key(),
            root.public_key()
        );
        assert!(open_projected(&guard, "account-b").is_none());
        drop(guard);
        shared
            .lock_unpoisoned()
            .revoke_account_device_in(&scope, "native-device")
            .unwrap();
        let revoked = post_deposit_root(
            State(shared),
            headers,
            Json(DepositRoot {
                seed: hex::encode(root.to_seed_bytes()),
            }),
        )
        .await
        .into_response();
        assert_eq!(revoked.status(), StatusCode::UNAUTHORIZED);
    }
}
