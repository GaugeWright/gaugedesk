//! Which account a bearer belongs to, answered by the Hub (DR-0206).
//!
//! A desktop Home cannot judge the credentials remote callers present: desk
//! and the mobile app send a provider id-token or an opaque Hub session, and
//! the desktop has neither the provider's configuration nor the account links
//! that turn one into an account. The Hub has both — it is where the bearer was
//! minted or is honoured — so a Home asks it here, and admits the caller only
//! when the answer is the Home's own owner.
//!
//! The answer is the same judgement every `/account/*` route makes about its
//! caller: [`Workbench::authenticate_bearer`], which resolves an opaque session
//! the Hub minted, or a verified id-token through its account link.

use axum::{extract::State, http::HeaderMap, http::StatusCode, response::IntoResponse, Json};
use serde_json::json;

use crate::{net_http, LockUnpoisoned, SharedWorkbench, Workbench};

/// What `GET /account/identity` answers.
#[derive(Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct AccountIdentity {
    /// The account id — the account's root public key.
    pub account: String,
}

/// `GET /account/identity` — the [`AccountIdentity`] of the presented bearer.
pub async fn get_account_identity(
    State(wb): State<SharedWorkbench>,
    headers: HeaderMap,
) -> axum::response::Response {
    let wb = wb.lock_unpoisoned();
    match bearer_account(
        &wb,
        net_http::bearer(&headers),
        crate::workbench_auth::web_account_mode(),
    ) {
        Ok(account) => (StatusCode::OK, Json(AccountIdentity { account })).into_response(),
        Err((status, message)) => (status, Json(json!({ "error": message }))).into_response(),
    }
}

/// The account `bearer` authenticates as, on a Hub.
///
/// Anywhere else this route does not exist: a desktop answers every caller as
/// its local operator, so its answer would name someone who never presented
/// anything, and a Home that asked it would admit them.
pub(crate) fn bearer_account(
    wb: &Workbench,
    bearer: Option<&str>,
    on_hub: bool,
) -> Result<String, (StatusCode, &'static str)> {
    if !on_hub {
        return Err((StatusCode::NOT_FOUND, "not served here"));
    }
    let token = bearer.ok_or((StatusCode::UNAUTHORIZED, "present a bearer to identify"))?;
    wb.authenticate_bearer(token)
        .map(|authority| authority.as_str().to_owned())
        .ok_or((StatusCode::UNAUTHORIZED, "this bearer is not recognised"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::LoopbackIdentityProvider;
    use gaugedesk_core::abac::AuthorityAttributes;
    use gaugedesk_core::ids::AuthorityId;
    use std::sync::Arc;

    fn hub() -> Workbench {
        let mut wb = Workbench::new(gaugedesk_store::Store::open_in_memory().unwrap());
        wb.set_identity_provider(Some(Arc::new(LoopbackIdentityProvider::new().enroll(
            "alice-login",
            AuthorityId::new("alice"),
            AuthorityAttributes::default(),
        ))));
        wb
    }

    #[test]
    fn names_the_account_a_recognised_bearer_belongs_to() {
        assert_eq!(
            bearer_account(&hub(), Some("alice-login"), true),
            Ok("alice".to_owned())
        );
    }

    #[test]
    fn an_opaque_session_the_hub_minted_names_its_account() {
        let mut wb = hub();
        let token = wb
            .mint_account_session("account-root", "test", 60)
            .expect("session");
        assert_eq!(
            bearer_account(&wb, Some(&token), true),
            Ok("account-root".to_owned())
        );
    }

    #[test]
    fn refuses_an_absent_or_unknown_bearer() {
        let wb = hub();
        assert_eq!(
            bearer_account(&wb, None, true).unwrap_err().0,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            bearer_account(&wb, Some("forged"), true).unwrap_err().0,
            StatusCode::UNAUTHORIZED
        );
    }

    /// A desktop would answer "the local operator" for anyone, which is the
    /// very thing DR-0206 exists to stop being mistaken for an identity.
    #[test]
    fn is_not_served_off_the_hub() {
        let wb = Workbench::new(gaugedesk_store::Store::open_in_memory().unwrap());
        assert_eq!(
            bearer_account(&wb, Some("anything"), false).unwrap_err().0,
            StatusCode::NOT_FOUND
        );
    }
}
