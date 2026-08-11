//! The serving Home authors the routes for the projects it holds (DESK-5a,
//! [ADR 0131](../../../specs/decisions/0131-a-home-authors-and-signs-its-own-reachability.md)).
//!
//! A route asserts *where work lives and how to reach it*, and only the Home
//! serving the project can say that truthfully — so authorship happens here,
//! never in a client and never in a page. What this module writes is picked up
//! unchanged by the existing publication path: `library_sync_signed_put` folds
//! `acct.home_routes` into the root-signed directory record, and a pulling
//! device merges them back. Nothing about distribution changes; the gap this
//! closes is that the set was always *empty* on the machine that serves work.
//!
//! Two constraints shape everything below. The record is **work-blind** — a
//! project id, a Home id, an endpoint, a locator, and nothing else; no name, no
//! grant, no member, no runtime fact. And departure **tombstones** rather than
//! going quiet, so a relocated project never leaves a live pointer at its former
//! Home.

use crate::account::{Account, HomeRouteRecord, RecordOp, ACCOUNT_SCOPE};
use crate::home::OpaqueRelayLocator;
use crate::{LockUnpoisoned, SharedWorkbench, Workbench};

use gaugedesk_relay_transport::RelayRoute;

/// The reachability this Home currently offers. Either half may be absent: a
/// Home with a public address needs no locator, and a Home behind NAT has no
/// address to give.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HomeReachability {
    pub endpoint: String,
    pub relay: Option<OpaqueRelayLocator>,
}

impl HomeReachability {
    /// A route has to say *something* about how to reach the Home, or it is not
    /// a route. Publishing an unreachable one would be a live pointer at
    /// nothing.
    pub fn is_reachable(&self) -> bool {
        !self.endpoint.is_empty() || self.relay.is_some()
    }
}

/// Render a parked relay leg as the blind locator a client resolves. The
/// fingerprint is lowercase hex because that is what the wire contract and the
/// client's validation both expect.
pub fn locator_of(route: &RelayRoute) -> OpaqueRelayLocator {
    OpaqueRelayLocator {
        endpoint: route.endpoint.clone(),
        handle: route.handle.clone(),
        proof: route.proof.to_base64url(),
        route_epoch: route.epoch,
        home_fingerprint: hex::encode(route.home_fingerprint),
    }
}

impl Workbench {
    /// Author the route set for every project this Home serves, and tombstone
    /// any route this Home previously claimed and no longer serves.
    ///
    /// Idempotent by construction: it writes only where the authored record
    /// differs from what the account scope already holds, so a reconcile at
    /// startup or sign-in is cheap and does not churn the event log.
    pub fn author_home_routes(&mut self, reach: &HomeReachability) -> usize {
        let home = self.home_id().clone();
        let served: Vec<String> = self
            .library
            .projects
            .values()
            .filter(|project| project.home_id == home)
            .map(|project| project.id.clone())
            .collect();
        let existing = Account::rebuild(self.store_ref())
            .map(|account| account.home_routes)
            .unwrap_or_default();

        let mut written = 0;
        if reach.is_reachable() {
            for project in &served {
                let authored = HomeRouteRecord {
                    id: project.clone(),
                    op: RecordOp::Upsert,
                    home_id: home.clone(),
                    endpoint: reach.endpoint.clone(),
                    relay: reach.relay.clone(),
                };
                let unchanged = existing.get(project).is_some_and(|current| {
                    current.op == RecordOp::Upsert
                        && current.home_id == authored.home_id
                        && current.endpoint == authored.endpoint
                        && current.relay == authored.relay
                });
                if unchanged {
                    continue;
                }
                if self
                    .write_account_record_in(ACCOUNT_SCOPE, "home_route", project, &authored)
                    .is_ok()
                {
                    written += 1;
                }
            }
        }

        // Departure: a route this Home claims but no longer serves — the project
        // was relocated, deleted, or handed off — is tombstoned, not abandoned.
        // Routes pointing at *other* Homes are untouched; they are not ours to
        // retract.
        let departed: Vec<HomeRouteRecord> = existing
            .values()
            .filter(|record| record.home_id == home && record.op != RecordOp::Tombstone)
            .filter(|record| !reach.is_reachable() || !served.contains(&record.id))
            .cloned()
            .collect();
        for record in departed {
            let tombstone = HomeRouteRecord {
                op: RecordOp::Tombstone,
                ..record
            };
            if self
                .write_account_record_in(ACCOUNT_SCOPE, "home_route", &tombstone.id, &tombstone)
                .is_ok()
            {
                written += 1;
            }
        }
        written
    }
}

/// Re-author the route set after a reachability change (a rotated proof, a new
/// endpoint, a regenerated identity). Rotation invalidates outstanding locators
/// the moment it lands at the relay, so this runs as part of rotating rather
/// than on a later schedule.
pub fn republish(workbench: &SharedWorkbench, route: &RelayRoute) {
    let reach = HomeReachability {
        endpoint: String::new(),
        relay: Some(locator_of(route)),
    };
    let mut guard = workbench.lock_unpoisoned();
    let written = guard.author_home_routes(&reach);
    if written > 0 {
        eprintln!(
            "[home-relay] re-authored {written} project route(s) at epoch {}",
            route.epoch
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn locator() -> OpaqueRelayLocator {
        OpaqueRelayLocator {
            endpoint: "wss://relay.example".to_owned(),
            handle: "a".repeat(43),
            proof: "b".repeat(43),
            route_epoch: 4,
            home_fingerprint: "c".repeat(64),
        }
    }

    fn reach() -> HomeReachability {
        HomeReachability {
            endpoint: String::new(),
            relay: Some(locator()),
        }
    }

    fn authored(workbench: &crate::SharedWorkbench) -> Vec<(String, RecordOp, String)> {
        let guard = workbench.lock_unpoisoned();
        let mut routes: Vec<_> = Account::rebuild(guard.store_ref())
            .unwrap()
            .home_routes
            .into_iter()
            .map(|(id, record)| (id, record.op, record.home_id.as_str().to_owned()))
            .collect();
        routes.sort_by(|a, b| a.0.cmp(&b.0));
        routes
    }

    /// The whole of the gap DESK-5a closes: the machine that serves the work
    /// never wrote a route for it, so the set that gets published was empty.
    #[test]
    fn the_serving_home_authors_a_route_for_each_project_it_holds() {
        let root = tempfile::tempdir().unwrap();
        let shared = crate::open_workbench(root.path()).unwrap();
        let home = shared.lock_unpoisoned().home_id().as_str().to_owned();

        assert!(authored(&shared).is_empty(), "nothing is authored up front");

        let written = shared.lock_unpoisoned().author_home_routes(&reach());
        assert!(written > 0, "the default project must be authored");
        let routes = authored(&shared);
        assert!(!routes.is_empty());
        for (_, op, home_id) in &routes {
            assert_eq!(*op, RecordOp::Upsert);
            assert_eq!(home_id, &home, "a Home only ever claims itself");
        }
    }

    /// A reconcile runs at startup and at sign-in, so re-authoring an unchanged
    /// set must not churn the event log.
    #[test]
    fn re_authoring_an_unchanged_set_writes_nothing() {
        let root = tempfile::tempdir().unwrap();
        let shared = crate::open_workbench(root.path()).unwrap();
        assert!(shared.lock_unpoisoned().author_home_routes(&reach()) > 0);
        assert_eq!(
            shared.lock_unpoisoned().author_home_routes(&reach()),
            0,
            "an unchanged reconcile is a no-op"
        );
    }

    /// A rotated proof is a different route, so it must be re-authored — this is
    /// what keeps a published locator from pointing at a dead epoch.
    #[test]
    fn a_rotated_locator_is_re_authored() {
        let root = tempfile::tempdir().unwrap();
        let shared = crate::open_workbench(root.path()).unwrap();
        assert!(shared.lock_unpoisoned().author_home_routes(&reach()) > 0);
        let mut rotated = reach();
        rotated.relay.as_mut().unwrap().route_epoch = 5;
        rotated.relay.as_mut().unwrap().proof = "d".repeat(43);
        assert!(shared.lock_unpoisoned().author_home_routes(&rotated) > 0);
    }

    /// Departure tombstones rather than going quiet: an unreachable Home must
    /// not leave a live pointer at itself.
    #[test]
    fn losing_reachability_tombstones_this_homes_routes() {
        let root = tempfile::tempdir().unwrap();
        let shared = crate::open_workbench(root.path()).unwrap();
        assert!(shared.lock_unpoisoned().author_home_routes(&reach()) > 0);

        let written = shared
            .lock_unpoisoned()
            .author_home_routes(&HomeReachability::default());
        assert!(written > 0, "departure is written, not implied");
        for (id, op, _) in authored(&shared) {
            assert_eq!(op, RecordOp::Tombstone, "{id} must be retracted");
        }
    }

    #[test]
    fn reachability_needs_an_endpoint_or_a_locator() {
        assert!(!HomeReachability::default().is_reachable());
        assert!(HomeReachability {
            endpoint: "https://home.example".to_owned(),
            relay: None,
        }
        .is_reachable());
        assert!(HomeReachability {
            endpoint: String::new(),
            relay: Some(locator()),
        }
        .is_reachable());
    }

    #[test]
    fn a_parked_leg_renders_a_lowercase_hex_fingerprint() {
        let route = RelayRoute {
            endpoint: "wss://relay.example".to_owned(),
            handle: "handle".to_owned(),
            epoch: 7,
            proof: gaugedesk_relay_transport::RouteProof::new([2u8; 32]),
            previous_proof: None,
            home_fingerprint: [0xABu8; 32],
        };
        let rendered = locator_of(&route);
        assert_eq!(rendered.route_epoch, 7);
        assert_eq!(rendered.home_fingerprint, "ab".repeat(32));
        assert_eq!(rendered.home_fingerprint.len(), 64);
        assert!(rendered
            .home_fingerprint
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()));
        assert_eq!(rendered.proof, route.proof.to_base64url());
    }
}
