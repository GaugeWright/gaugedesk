//! Server custody for several browser account sessions. The browser carries
//! one active HttpOnly account cookie and an independent opaque wallet handle;
//! every other retained session stays sealed in the Hub's event store.

use std::collections::BTreeMap;

use axum::http::{header, HeaderMap, HeaderValue};
use axum::response::Response;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::Workbench;

const WALLET_COOKIE: &str = "gw_account_wallet";
const WALLET_KIND: &str = "retained_session";
const WALLET_STATE_KIND: &str = "state";

#[derive(Clone, Serialize, Deserialize)]
struct StoredAccount {
    id: String,
    sealed_session: String,
    label: String,
}

#[derive(Serialize, Deserialize)]
struct WalletState {
    id: String,
    retired: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct BrowserAccount {
    pub person: String,
    pub label: String,
    pub expired: bool,
}

#[derive(Debug, PartialEq, Eq, Serialize)]
pub struct BrowserAccountRoster {
    pub selected: Option<String>,
    pub accounts: Vec<BrowserAccount>,
}

fn wallet_id_valid(value: &str) -> bool {
    value.len() == 43
        && URL_SAFE_NO_PAD
            .decode(value)
            .is_ok_and(|bytes| bytes.len() == 32)
}

pub fn wallet_cookie(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .filter_map(|part| part.trim().split_once('='))
        .find_map(|(name, value)| {
            (name == WALLET_COOKIE && wallet_id_valid(value)).then_some(value)
        })
}

fn wallet_scope(id: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(b"gaugedesk:browser-wallet:v1");
    digest.update(id.as_bytes());
    format!("browser-wallet::{}", hex::encode(digest.finalize()))
}

fn wallet_cookie_value(id: &str) -> String {
    let mut cookie = format!("{WALLET_COOKIE}={id}; Path=/; HttpOnly; SameSite=Lax");
    if gaugedesk_env::var("SESSION_COOKIE_INSECURE").is_none_or(|value| value != "1") {
        cookie.push_str("; Secure");
    }
    if let Some(domain) =
        gaugedesk_env::var("SESSION_COOKIE_DOMAIN").filter(|value| !value.trim().is_empty())
    {
        cookie.push_str("; Domain=");
        cookie.push_str(domain.trim());
    }
    cookie
}

pub fn append_wallet_cookie(response: &mut Response, id: Option<&str>) {
    let mut value = wallet_cookie_value(id.unwrap_or(""));
    if id.is_none() {
        value.push_str("; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT");
    }
    if let Ok(value) = HeaderValue::from_str(&value) {
        response.headers_mut().append(header::SET_COOKIE, value);
    }
}

fn read_wallet(wb: &Workbench, id: &str) -> Result<BTreeMap<String, StoredAccount>, String> {
    let scope = wallet_scope(id);
    let state = wb
        .store_ref()
        .records(&scope, WALLET_STATE_KIND)
        .map_err(|error| format!("{error:?}"))?;
    if state
        .last()
        .and_then(|value| serde_json::from_str::<WalletState>(value).ok())
        .is_some_and(|state| state.retired)
    {
        return Ok(BTreeMap::new());
    }
    let mut accounts = BTreeMap::new();
    for value in wb
        .store_ref()
        .records(&scope, WALLET_KIND)
        .map_err(|error| format!("{error:?}"))?
    {
        let account: StoredAccount = serde_json::from_str(&value)
            .map_err(|_| "browser wallet record is malformed".to_string())?;
        accounts.insert(account.id.clone(), account);
    }
    Ok(accounts)
}

fn live_session(wb: &Workbench, account: &StoredAccount) -> Option<String> {
    let token = wb.unseal_account_secret(&account.sealed_session)?;
    (wb.resolve_account_session(&token)?.0 == account.id).then_some(token)
}

fn live_accounts(
    wb: &Workbench,
    accounts: BTreeMap<String, StoredAccount>,
) -> BTreeMap<String, StoredAccount> {
    accounts
        .into_iter()
        .filter(|(_, account)| live_session(wb, account).is_some())
        .collect()
}

fn add_token(
    wb: &Workbench,
    accounts: &mut BTreeMap<String, StoredAccount>,
    person: &str,
    label: &str,
    token: &str,
) -> Result<(), String> {
    if wb
        .resolve_account_session(token)
        .as_ref()
        .map(|(id, _)| id.as_str())
        != Some(person)
    {
        return Err("browser wallet session does not name that account".to_string());
    }
    let sealed_session = wb
        .seal_account_secret(token)
        .ok_or_else(|| "could not seal a browser account session".to_string())?;
    accounts.insert(
        person.to_string(),
        StoredAccount {
            id: person.to_string(),
            sealed_session,
            label: label.to_string(),
        },
    );
    Ok(())
}

/// Prefer a verified contact when a passkey or recovery ceremony provides
/// only the opaque account id. This is a display label, never an identity key.
pub fn account_label(wb: &Workbench, person: &str) -> String {
    crate::account_auth::AccountAuth::rebuild(wb.store_ref())
        .ok()
        .and_then(|auth| {
            auth.emails
                .values()
                .find(|email| {
                    email.account_id == person
                        && email.status == crate::account_auth::AuthMethodStatus::Active
                })
                .map(|email| email.email.clone())
        })
        .unwrap_or_else(|| person.to_string())
}

fn mint_wallet_id() -> Result<String, String> {
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes).map_err(|_| "could not mint a browser wallet".to_string())?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

/// Rotate the browser's unguessable wallet handle whenever its contents or
/// selected account changes. The old handle is retired in the same transaction
/// that stores the new sealed roster, so a fixed or replayed cookie cannot
/// acquire the newly signed-in account.
fn rotate(
    wb: &mut Workbench,
    old_id: Option<&str>,
    accounts: BTreeMap<String, StoredAccount>,
) -> Result<Option<String>, String> {
    let new_id = if accounts.is_empty() {
        None
    } else {
        Some(mint_wallet_id()?)
    };
    let new_scope = new_id.as_deref().map(wallet_scope);
    let old_scope = old_id.map(wallet_scope);
    let mut writes: Vec<(&str, &str, String)> = Vec::new();
    if let Some(scope) = new_scope.as_deref() {
        for account in accounts.into_values() {
            writes.push((
                scope,
                WALLET_KIND,
                serde_json::to_string(&account).map_err(|error| error.to_string())?,
            ));
        }
    }
    if let Some(scope) = old_scope.as_deref() {
        writes.push((
            scope,
            WALLET_STATE_KIND,
            serde_json::to_string(&WalletState {
                id: "wallet".to_string(),
                retired: true,
            })
            .map_err(|error| error.to_string())?,
        ));
    }
    let borrowed: Vec<(&str, &str, &str)> = writes
        .iter()
        .map(|(scope, kind, value)| (*scope, *kind, value.as_str()))
        .collect();
    wb.store_mut()
        .append_records_atomically(&borrowed)
        .map_err(|error| format!("{error:?}"))?;
    Ok(new_id)
}

/// A successful browser login always mints a new wallet handle. It retains
/// prior live sessions and the formerly active cookie, then selects the new
/// account through the existing `gw_session` cookie in the caller's response.
pub fn retain_login(
    wb: &mut Workbench,
    headers: &HeaderMap,
    person: &str,
    label: &str,
    token: &str,
) -> Result<String, String> {
    let old_id = wallet_cookie(headers);
    let mut accounts = match old_id {
        Some(id) => live_accounts(wb, read_wallet(wb, id)?),
        None => BTreeMap::new(),
    };
    if let Some(active) = crate::net_http::session_cookie(headers) {
        if let Some((active_person, _)) = wb.resolve_account_session(active) {
            let active_label = accounts
                .get(&active_person)
                .map(|account| account.label.clone())
                .unwrap_or_else(|| account_label(wb, &active_person));
            add_token(wb, &mut accounts, &active_person, &active_label, active)?;
        }
    }
    add_token(wb, &mut accounts, person, label, token)?;
    rotate(wb, old_id, accounts)?.ok_or_else(|| "new browser wallet was empty".to_string())
}

pub fn roster(wb: &Workbench, headers: &HeaderMap) -> Result<BrowserAccountRoster, String> {
    let selected = crate::net_http::session_cookie(headers)
        .and_then(|token| wb.resolve_account_session(token))
        .map(|(person, _)| person);
    let mut accounts = match wallet_cookie(headers) {
        Some(id) => read_wallet(wb, id)?,
        None => BTreeMap::new(),
    };
    if let Some(person) = selected.as_ref() {
        accounts
            .entry(person.clone())
            .or_insert_with(|| StoredAccount {
                id: person.clone(),
                sealed_session: String::new(),
                label: person.clone(),
            });
    }
    Ok(BrowserAccountRoster {
        selected,
        accounts: accounts
            .into_values()
            .map(|account| {
                let expired =
                    !account.sealed_session.is_empty() && live_session(wb, &account).is_none();
                BrowserAccount {
                    person: account.id,
                    label: account.label,
                    expired,
                }
            })
            .collect(),
    })
}

pub fn select(
    wb: &mut Workbench,
    headers: &HeaderMap,
    person: &str,
) -> Result<(String, String), String> {
    let old_id =
        wallet_cookie(headers).ok_or_else(|| "no browser wallet is retained".to_string())?;
    let accounts = live_accounts(wb, read_wallet(wb, old_id)?);
    let account = accounts
        .get(person)
        .ok_or_else(|| "that account is not retained in this browser".to_string())?;
    let token =
        live_session(wb, account).ok_or_else(|| "sign in to that account again".to_string())?;
    let new_id = rotate(wb, Some(old_id), accounts)?
        .ok_or_else(|| "selected browser wallet was empty".to_string())?;
    Ok((token, new_id))
}

pub fn forget(
    wb: &mut Workbench,
    headers: &HeaderMap,
    person: &str,
) -> Result<(Option<String>, Option<String>), String> {
    let old_id =
        wallet_cookie(headers).ok_or_else(|| "no browser wallet is retained".to_string())?;
    let mut accounts = live_accounts(wb, read_wallet(wb, old_id)?);
    let removed = accounts
        .remove(person)
        .and_then(|account| live_session(wb, &account));
    let new_id = rotate(wb, Some(old_id), accounts)?;
    Ok((new_id, removed))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cookie(wallet: Option<&str>, session: Option<&str>) -> HeaderMap {
        let mut headers = HeaderMap::new();
        let mut parts = Vec::new();
        if let Some(wallet) = wallet {
            parts.push(format!("{WALLET_COOKIE}={wallet}"));
        }
        if let Some(session) = session {
            parts.push(format!("gw_session={session}"));
        }
        headers.insert(header::COOKIE, parts.join("; ").parse().unwrap());
        headers
    }

    #[test]
    fn retaining_and_switching_accounts_rotates_handles_and_never_projects_tokens() {
        let mut wb = Workbench::new(gaugedesk_store::Store::open_in_memory().unwrap());
        let alice = wb
            .mint_account_session("account:alice", "passkey", 3600)
            .unwrap();
        let bob = wb
            .mint_account_session("account:bob", "passkey", 3600)
            .unwrap();
        let first = retain_login(
            &mut wb,
            &cookie(None, None),
            "account:alice",
            "Alice",
            &alice,
        )
        .unwrap();
        let second = retain_login(
            &mut wb,
            &cookie(Some(&first), Some(&alice)),
            "account:bob",
            "Bob",
            &bob,
        )
        .unwrap();
        assert_ne!(first, second);
        assert!(
            read_wallet(&wb, &first).unwrap().is_empty(),
            "old handle must be retired"
        );
        let projected = roster(&wb, &cookie(Some(&second), Some(&bob))).unwrap();
        assert_eq!(projected.selected.as_deref(), Some("account:bob"));
        assert_eq!(projected.accounts.len(), 2);
        let json = serde_json::to_string(&projected).unwrap();
        assert!(!json.contains(&alice));
        assert!(!json.contains(&bob));
        let records = wb
            .store_ref()
            .records(&wallet_scope(&second), WALLET_KIND)
            .unwrap();
        assert!(records
            .iter()
            .all(|record| !record.contains(&alice) && !record.contains(&bob)));
        let (chosen, third) =
            select(&mut wb, &cookie(Some(&second), Some(&bob)), "account:alice").unwrap();
        assert_eq!(chosen, alice);
        assert_ne!(second, third);
        assert!(read_wallet(&wb, &second).unwrap().is_empty());
        let (fourth, _) = forget(
            &mut wb,
            &cookie(Some(&third), Some(&alice)),
            "account:alice",
        )
        .unwrap();
        let fourth = fourth.unwrap();
        let remaining = roster(&wb, &cookie(Some(&fourth), None)).unwrap();
        assert_eq!(remaining.accounts.len(), 1);
        assert_eq!(remaining.accounts[0].person, "account:bob");
    }

    #[test]
    fn retained_sessions_survive_reopening_the_store() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("accounts.sqlite");
        let (wallet, token) = {
            let store = gaugedesk_store::Store::open(path.to_str().unwrap()).unwrap();
            let mut wb = Workbench::new(store);
            let token = wb
                .mint_account_session("account:alice", "passkey", 3600)
                .unwrap();
            let wallet = retain_login(
                &mut wb,
                &cookie(None, None),
                "account:alice",
                "Alice",
                &token,
            )
            .unwrap();
            (wallet, token)
        };
        let store = gaugedesk_store::Store::open(path.to_str().unwrap()).unwrap();
        let mut reopened = Workbench::new(store);
        reopened.restore_account_sessions();
        let stored = read_wallet(&reopened, &wallet).unwrap();
        assert!(
            reopened.resolve_account_session(&token).is_some(),
            "account session must reopen"
        );
        assert!(
            reopened
                .unseal_account_secret(&stored["account:alice"].sealed_session)
                .is_some(),
            "wallet seal must reopen"
        );
        let projected = roster(&reopened, &cookie(Some(&wallet), None)).unwrap();
        assert_eq!(projected.accounts.len(), 1);
        assert!(!projected.accounts[0].expired);
        assert_eq!(
            select(&mut reopened, &cookie(Some(&wallet), None), "account:alice")
                .unwrap()
                .0,
            token
        );
    }
}
