//! Replaceable Home-session admission credentials (`HOME-1`, ADR 0084).
//!
//! A web-account bearer proves identity to the blind hub. It does not itself
//! authorize work. After the target Home admits that identity, it mints a second
//! opaque credential bound to `(HomeId, AuthorityId)`. Home work routes require
//! both credentials; either one alone fails closed.

use std::collections::{BTreeMap, VecDeque};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex, Weak,
};

use gaugedesk_core::ids::{AuthorityId, HomeId};

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

/// Process-local standing of one exact admitted Home credential. Capturing it
/// conveys no project permission; revocation, rotation and issuer drop close it.
#[derive(Clone, Debug)]
pub struct HomeAdmissionStanding {
    home: HomeId,
    actor: AuthorityId,
    active: Arc<AtomicBool>,
    source_lease: Option<String>,
    reference: String,
}

impl HomeAdmissionStanding {
    pub(crate) fn reference(&self) -> &str {
        &self.reference
    }

    pub fn source_lease(&self) -> Option<&str> {
        self.source_lease.as_deref()
    }
    pub fn is_bound_to(&self, home: &HomeId, actor: &AuthorityId) -> bool {
        &self.home == home && &self.actor == actor
    }
    pub fn is_active(&self) -> bool {
        self.active.load(Ordering::Acquire)
    }
    fn close(&self) {
        self.active.store(false, Ordering::Release);
    }
}

#[derive(Clone, Debug)]
struct Admission {
    home: HomeId,
    actor: AuthorityId,
    standing: HomeAdmissionStanding,
}

#[derive(Debug, Default)]
struct IssuerLifetime {
    standings: Mutex<Vec<Weak<AtomicBool>>>,
}
impl Drop for IssuerLifetime {
    fn drop(&mut self) {
        for standing in self
            .standings
            .get_mut()
            .unwrap_or_else(|error| error.into_inner())
        {
            if let Some(active) = standing.upgrade() {
                active.store(false, Ordering::Release);
            }
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct HomeAdmissionStore {
    by_principal: BTreeMap<(HomeId, AuthorityId), VecDeque<HomeAdmissionToken>>,
    by_token: BTreeMap<HomeAdmissionToken, Admission>,
    // Copies retain the same issuer lifetime and cancellation standing. A stale
    // snapshot cannot preserve authorization after another copy revokes it.
    issuer: Arc<IssuerLifetime>,
}

impl HomeAdmissionStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Admit an independent session; bound retained credentials per identity.
    pub fn open(&mut self, home: HomeId, actor: AuthorityId) -> HomeAdmissionToken {
        self.open_bound(home, actor, None)
    }

    /// The caller has separately admitted current office/source/software
    /// standing. An office credential additionally names its exact parent lease.
    pub fn open_office(
        &mut self,
        home: &HomeId,
        lease: &crate::office_home_admission::lease::OfficeStaffLease,
    ) -> Result<HomeAdmissionToken, HomeAdmissionRejection> {
        if home != lease.home() {
            return Err(HomeAdmissionRejection::WrongBinding);
        }
        Ok(self.open_bound(
            home.clone(),
            AuthorityId::new(lease.account()),
            Some(lease.reference().into()),
        ))
    }

    fn open_bound(
        &mut self,
        home: HomeId,
        actor: AuthorityId,
        source_lease: Option<String>,
    ) -> HomeAdmissionToken {
        let key = (home, actor);
        if source_lease.is_some() {
            let retired = self
                .by_principal
                .get(&key)
                .into_iter()
                .flatten()
                .filter(|token| {
                    self.by_token
                        .get(*token)
                        .is_some_and(|admission| admission.standing.source_lease == source_lease)
                })
                .cloned()
                .collect::<Vec<_>>();
            for token in retired {
                self.revoke_session(&key.0, &key.1, &token);
            }
        }
        if let Some(sessions) = self.by_principal.get_mut(&key) {
            if sessions.len() == 64 {
                if let Some(oldest) = sessions.pop_front() {
                    if let Some(admission) = self.by_token.remove(&oldest) {
                        admission.standing.close();
                    }
                }
            }
        }
        let token = HomeAdmissionToken::mint();
        let active = Arc::new(AtomicBool::new(true));
        {
            let mut standings = self
                .issuer
                .standings
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            standings.retain(|entry| {
                entry
                    .upgrade()
                    .is_some_and(|flag| flag.load(Ordering::Acquire))
            });
            standings.push(Arc::downgrade(&active));
        }
        self.by_principal
            .entry(key.clone())
            .or_default()
            .push_back(token.clone());
        self.by_token.insert(
            token.clone(),
            Admission {
                home: key.0.clone(),
                actor: key.1.clone(),
                standing: HomeAdmissionStanding {
                    home: key.0,
                    actor: key.1,
                    active,
                    source_lease,
                    // Independent address for signed queued-work parents. This
                    // is never the Home credential or permission to present it.
                    reference: hex::encode(crate::session::random_bytes::<32>()),
                },
            },
        );
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
        if &bound.home != home || &bound.actor != actor {
            return Err(HomeAdmissionRejection::WrongBinding);
        }
        if !bound.standing.is_active() {
            return Err(HomeAdmissionRejection::UnknownOrRevoked);
        }
        Ok(())
    }

    pub fn standing(
        &self,
        home: &HomeId,
        actor: &AuthorityId,
        token: &HomeAdmissionToken,
    ) -> Result<HomeAdmissionStanding, HomeAdmissionRejection> {
        self.authorize(home, actor, token)?;
        Ok(self
            .by_token
            .get(token)
            .expect("authorized token exists")
            .standing
            .clone())
    }

    pub fn office_standing(
        &self,
        lease: &crate::office_home_admission::lease::OfficeStaffLease,
        token: &HomeAdmissionToken,
    ) -> Result<HomeAdmissionStanding, HomeAdmissionRejection> {
        let standing = self.standing(lease.home(), &AuthorityId::new(lease.account()), token)?;
        if standing.source_lease() != Some(lease.reference()) {
            return Err(HomeAdmissionRejection::WrongBinding);
        }
        Ok(standing)
    }

    /// Resolve the current standing named by a verified retained command grant.
    /// The address is inert: callers must separately verify that grant and its
    /// live process/source identity before it can authorize a bounded operation.
    pub(crate) fn office_standing_by_reference(
        &self,
        lease: &crate::office_home_admission::lease::OfficeStaffLease,
        reference: &str,
    ) -> Option<HomeAdmissionStanding> {
        let tokens = self
            .by_principal
            .get(&(lease.home().clone(), AuthorityId::new(lease.account())))?;
        tokens.iter().find_map(|token| {
            self.office_standing(lease, token)
                .ok()
                .filter(|standing| standing.reference() == reference)
        })
    }

    /// Explicitly revoke every session for an exact Home/account binding.
    /// Preserve the existing public API for callers asking for identity-wide
    /// revocation; closing one window uses `revoke_session` instead.
    pub fn revoke(&mut self, home: &HomeId, actor: &AuthorityId) -> bool {
        let Some(tokens) = self.by_principal.remove(&(home.clone(), actor.clone())) else {
            return false;
        };
        for token in tokens {
            if let Some(admission) = self.by_token.remove(&token) {
                admission.standing.close();
            }
        }
        true
    }

    /// Revoke only the presented session, after checking its exact binding.
    pub fn revoke_session(
        &mut self,
        home: &HomeId,
        actor: &AuthorityId,
        token: &HomeAdmissionToken,
    ) -> bool {
        if self.authorize(home, actor, token).is_err() {
            return false;
        }
        if let Some(admission) = self.by_token.remove(token) {
            admission.standing.close();
        }
        let key = (home.clone(), actor.clone());
        if let Some(sessions) = self.by_principal.get_mut(&key) {
            sessions.retain(|entry| entry != token);
            if sessions.is_empty() {
                self.by_principal.remove(&key);
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn independent_sessions_are_bound_and_revoke_only_the_presented_token() {
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
        assert_eq!(store.authorize(&home, &alice, &first), Ok(()));
        assert_eq!(store.authorize(&home, &alice, &second), Ok(()));
        assert!(!store.revoke_session(&home, &AuthorityId::new("mallory"), &first));
        assert!(store.revoke_session(&home, &alice, &first));
        assert_eq!(
            store.authorize(&home, &alice, &first),
            Err(HomeAdmissionRejection::UnknownOrRevoked)
        );
        assert_eq!(store.authorize(&home, &alice, &second), Ok(()));
        assert!(store.revoke(&home, &alice));
        assert_eq!(
            store.authorize(&home, &alice, &second),
            Err(HomeAdmissionRejection::UnknownOrRevoked)
        );
    }

    #[test]
    fn admission_capacity_retires_only_the_oldest_session() {
        let mut store = HomeAdmissionStore::new();
        let home = HomeId::new("home:test");
        let actor = AuthorityId::new("alice");
        let first = store.open(home.clone(), actor.clone());
        let second = store.open(home.clone(), actor.clone());
        for _ in 2..64 {
            store.open(home.clone(), actor.clone());
        }
        assert_eq!(store.authorize(&home, &actor, &first), Ok(()));
        let last = store.open(home.clone(), actor.clone());
        assert_eq!(
            store.authorize(&home, &actor, &first),
            Err(HomeAdmissionRejection::UnknownOrRevoked)
        );
        assert_eq!(store.authorize(&home, &actor, &second), Ok(()));
        assert_eq!(store.authorize(&home, &actor, &last), Ok(()));
        assert_eq!(store.by_token.len(), 64);
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

#[cfg(test)]
mod standing_tests {
    use super::*;

    #[test]
    fn captured_standing_has_exact_binding_and_session_revocation_ends_prepared_use() {
        let mut store = HomeAdmissionStore::new();
        let home = HomeId::new("office");
        let alice = AuthorityId::new("alice");
        let token = store.open(home.clone(), alice.clone());
        let standing = store.standing(&home, &alice, &token).unwrap();
        assert!(standing.is_active());
        assert!(store
            .standing(&HomeId::new("other"), &alice, &token)
            .is_err());
        assert!(store
            .standing(&home, &AuthorityId::new("bob"), &token)
            .is_err());
        let another = store.open(home.clone(), alice.clone());
        assert!(standing.is_active());
        assert!(store.revoke_session(&home, &alice, &token));
        assert!(!standing.is_active());
        assert!(store.authorize(&home, &alice, &another).is_ok());
    }

    #[test]
    fn revocation_and_issuer_drop_close_captured_standing_without_harming_another_person() {
        let mut store = HomeAdmissionStore::new();
        let home = HomeId::new("office");
        let alice = AuthorityId::new("alice");
        let bob = AuthorityId::new("bob");
        let first = store.open(home.clone(), alice.clone());
        let second = store.open(home.clone(), bob.clone());
        let alice_standing = store.standing(&home, &alice, &first).unwrap();
        let bob_standing = store.standing(&home, &bob, &second).unwrap();
        assert!(store.revoke(&home, &alice));
        assert!(!alice_standing.is_active());
        assert!(bob_standing.is_active());
        drop(store.clone());
        assert!(
            bob_standing.is_active(),
            "independent issuer clone closed the original"
        );
        drop(store);
        assert!(!bob_standing.is_active());
    }
}

#[cfg(test)]
mod snapshot_tests {
    use super::*;

    #[test]
    fn a_copied_issuer_cannot_keep_revoked_home_standing_alive() {
        let mut issuer = HomeAdmissionStore::new();
        let home = HomeId::new("office");
        let actor = AuthorityId::new("alice");
        let token = issuer.open(home.clone(), actor.clone());
        let copied = issuer.clone();
        let captured = copied.standing(&home, &actor, &token).unwrap();
        assert!(issuer.revoke(&home, &actor));
        assert!(!captured.is_active());
        assert!(copied.authorize(&home, &actor, &token).is_err());
    }
}
