//! Replaceable Home-session admission credentials (`HOME-1`, ADR 0084).
//!
//! A web-account bearer proves identity to the blind hub. It does not itself
//! authorize work. After the target Home admits that identity, it mints a second
//! opaque credential bound to `(HomeId, AuthorityId)`. Home work routes require
//! both credentials; either one alone fails closed.

use std::collections::BTreeMap;

use gaugewright_core::ids::{AuthorityId, HomeId};

/// Header carrying the target Home's admission credential.
pub const HOME_ADMISSION_HEADER: &str = "x-gaugewright-home-admission";

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HomeAdmissionToken([u8; 32]);

impl std::fmt::Debug for HomeAdmissionToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("HomeAdmissionToken(<redacted>)")
    }
}

impl HomeAdmissionToken {
    pub fn mint() -> Self {
        Self(crate::session::random_bytes::<32>())
    }

    pub fn encode(&self) -> String {
        hex::encode(self.0)
    }

    pub fn parse(value: &str) -> Option<Self> {
        let bytes = hex::decode(value).ok()?;
        Some(Self(bytes.try_into().ok()?))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HomeAdmissionRejection {
    UnknownOrRevoked,
    WrongBinding,
}

#[derive(Clone, Debug, Default)]
pub struct HomeAdmissionStore {
    by_principal: BTreeMap<(HomeId, AuthorityId), HomeAdmissionToken>,
    by_token: BTreeMap<HomeAdmissionToken, (HomeId, AuthorityId)>,
}

impl HomeAdmissionStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Admit and rotate one Home session for this identity.
    pub fn open(&mut self, home: HomeId, actor: AuthorityId) -> HomeAdmissionToken {
        let key = (home, actor);
        if let Some(old) = self.by_principal.remove(&key) {
            self.by_token.remove(&old);
        }
        let token = HomeAdmissionToken::mint();
        self.by_principal.insert(key.clone(), token.clone());
        self.by_token.insert(token.clone(), key);
        token
    }

    pub fn authorize(
        &self,
        home: &HomeId,
        actor: &AuthorityId,
        token: &HomeAdmissionToken,
    ) -> Result<(), HomeAdmissionRejection> {
        let Some(bound) = self.by_token.get(token) else {
            return Err(HomeAdmissionRejection::UnknownOrRevoked);
        };
        if &bound.0 != home || &bound.1 != actor {
            return Err(HomeAdmissionRejection::WrongBinding);
        }
        Ok(())
    }

    pub fn revoke(&mut self, home: &HomeId, actor: &AuthorityId) -> bool {
        let Some(token) = self.by_principal.remove(&(home.clone(), actor.clone())) else {
            return false;
        };
        self.by_token.remove(&token);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_is_exact_home_and_actor_bound_and_rotation_retires_old() {
        let mut store = HomeAdmissionStore::new();
        let home = HomeId::new("home:acme");
        let alice = AuthorityId::new("alice");
        let first = store.open(home.clone(), alice.clone());
        assert_eq!(store.authorize(&home, &alice, &first), Ok(()));
        assert_eq!(
            store.authorize(&HomeId::new("home:other"), &alice, &first),
            Err(HomeAdmissionRejection::WrongBinding)
        );
        assert_eq!(
            store.authorize(&home, &AuthorityId::new("mallory"), &first),
            Err(HomeAdmissionRejection::WrongBinding)
        );

        let second = store.open(home.clone(), alice.clone());
        assert_ne!(first, second);
        assert_eq!(
            store.authorize(&home, &alice, &first),
            Err(HomeAdmissionRejection::UnknownOrRevoked)
        );
        assert_eq!(store.authorize(&home, &alice, &second), Ok(()));
    }

    #[test]
    fn wire_encoding_round_trips_and_debug_is_redacted() {
        let token = HomeAdmissionToken::mint();
        assert_eq!(
            HomeAdmissionToken::parse(&token.encode()),
            Some(token.clone())
        );
        assert_eq!(format!("{token:?}"), "HomeAdmissionToken(<redacted>)");
        assert!(HomeAdmissionToken::parse("not-hex").is_none());
    }
}
