//! A process-wide cache of OIDC provider metadata: discovery documents and
//! signing key sets (WS-855).
//!
//! Every hosted session refresh fetched its provider's discovery document
//! before redeeming the refresh grant, on a fresh connection: a DNS lookup, a
//! TLS handshake and a round trip that the document's own `Cache-Control` says
//! to skip for an hour (Google) or a day (Microsoft). desk refreshes on every
//! load and every 45 minutes per tab, so that leg sat on the critical path of
//! first paint and bought nothing.
//!
//! A document is kept for as long as its publisher allows: its `max-age`,
//! bounded by [`MAX_LIFETIME`]; not at all for `no-store`, `no-cache` or
//! `max-age=0`; and [`DEFAULT_LIFETIME`] when the response says nothing. An
//! expired document is fetched again on its next use. If that fetch fails the
//! expired copy is answered instead (`stale-if-error`, RFC 5861): a provider's
//! endpoints and keys outlive a network blip, and refusing a sign-in for one
//! would be the cache making things worse than no cache.
//! [`OidcMetadataCache::refetch`] ignores freshness for a caller that knows the
//! cached copy is wrong — a verifier shown a token signed by a key the cached
//! set does not hold.
//!
//! The cache's own lock is never held across a fetch, and the cache never
//! fetches by itself: every network call happens on the calling thread. So the
//! rule for callers is the rule for any blocking HTTP — never on the async
//! runtime, and never while holding the workbench lock.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use crate::identity_oidc::HttpGet;

/// How long a document is kept when its response carries no `Cache-Control`.
pub const DEFAULT_LIFETIME: Duration = Duration::from_secs(60 * 60);

/// The longest a document is kept whatever its `max-age` says, so a provider
/// that publishes a year-long lifetime still has its endpoints re-read daily.
pub const MAX_LIFETIME: Duration = Duration::from_secs(24 * 60 * 60);

/// Past this many documents, inserting one first drops every expired one. A
/// deployment names a handful of providers; this only bounds a pathological one.
const PRUNE_AT: usize = 64;

/// How long a response may be kept, from its `Cache-Control` header (RFC 9111
/// §5.2.2). `None` means do not keep it at all.
pub fn lifetime(cache_control: Option<&str>) -> Option<Duration> {
    let Some(header) = cache_control else {
        return Some(DEFAULT_LIFETIME);
    };
    let mut max_age = None;
    for directive in header.split(',') {
        let directive = directive.trim();
        let (name, value) = match directive.split_once('=') {
            Some((name, value)) => (name.trim(), Some(value.trim().trim_matches('"'))),
            None => (directive, None),
        };
        if name.eq_ignore_ascii_case("no-store") || name.eq_ignore_ascii_case("no-cache") {
            return None;
        }
        if name.eq_ignore_ascii_case("max-age") {
            // An unparsable max-age is treated as stale, which RFC 9111 §4.2.1
            // prescribes for an invalid freshness lifetime.
            max_age = Some(value.and_then(|v| v.parse::<u64>().ok()).unwrap_or(0));
        }
    }
    match max_age {
        Some(0) => None,
        Some(seconds) => Some(Duration::from_secs(seconds).min(MAX_LIFETIME)),
        None => Some(DEFAULT_LIFETIME),
    }
}

#[derive(Clone)]
struct Document {
    body: String,
    /// When this copy stops being fresh. A copy kept only for `stale-if-error`
    /// (its response forbade caching) is stale from the moment it was stored.
    fresh_until: Instant,
}

/// Provider metadata documents by URL. See the module documentation.
#[derive(Default)]
pub struct OidcMetadataCache {
    documents: Mutex<HashMap<String, Document>>,
}

impl OidcMetadataCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// The one cache every composition in this process shares, so the
    /// verifier and the refresh leg read the same provider's metadata once.
    pub fn shared() -> Arc<OidcMetadataCache> {
        static SHARED: OnceLock<Arc<OidcMetadataCache>> = OnceLock::new();
        Arc::clone(SHARED.get_or_init(|| Arc::new(OidcMetadataCache::new())))
    }

    /// The document at `url`: the cached copy while it is fresh, else fetched
    /// with `http` and kept per its `Cache-Control`. Blocks on a miss.
    pub fn get(&self, url: &str, http: &(impl HttpGet + ?Sized)) -> Result<String, String> {
        self.get_at(url, http, Instant::now())
    }

    /// [`get`](Self::get) at an explicit instant, so freshness is testable
    /// without waiting for it.
    pub fn get_at(
        &self,
        url: &str,
        http: &(impl HttpGet + ?Sized),
        now: Instant,
    ) -> Result<String, String> {
        let cached = self.lock().get(url).cloned();
        if let Some(document) = &cached {
            if now < document.fresh_until {
                return Ok(document.body.clone());
            }
        }
        match http.get_cacheable(url) {
            Ok((body, cache_control)) => {
                self.store(url, &body, cache_control.as_deref(), now);
                Ok(body)
            }
            // stale-if-error: an expired copy beats no answer.
            Err(error) => cached.map(|document| document.body).ok_or(error),
        }
    }

    /// Fetch `url` again whatever the cached copy's freshness, and keep the
    /// answer. For a caller that knows the cached copy is wrong; a failed fetch
    /// leaves the cached copy in place and reports the failure.
    pub fn refetch(&self, url: &str, http: &(impl HttpGet + ?Sized)) -> Result<String, String> {
        self.refetch_at(url, http, Instant::now())
    }

    /// [`refetch`](Self::refetch) at an explicit instant.
    pub fn refetch_at(
        &self,
        url: &str,
        http: &(impl HttpGet + ?Sized),
        now: Instant,
    ) -> Result<String, String> {
        let (body, cache_control) = http.get_cacheable(url)?;
        self.store(url, &body, cache_control.as_deref(), now);
        Ok(body)
    }

    /// When the cached copy of `url` stops being fresh, or `None` when nothing
    /// is cached. Never touches the network.
    pub fn fresh_until(&self, url: &str) -> Option<Instant> {
        self.lock().get(url).map(|document| document.fresh_until)
    }

    /// Drop the cached copy of `url`, so its next use fetches it.
    pub fn forget(&self, url: &str) {
        self.lock().remove(url);
    }

    fn store(&self, url: &str, body: &str, cache_control: Option<&str>, now: Instant) {
        // A response that forbids caching is still kept, already stale: it is
        // never answered while fresh, only in place of a failed fetch.
        let fresh_until = lifetime(cache_control).map_or(now, |lifetime| now + lifetime);
        let mut documents = self.lock();
        if documents.len() >= PRUNE_AT && !documents.contains_key(url) {
            documents.retain(|_, document| now < document.fresh_until);
        }
        documents.insert(
            url.to_owned(),
            Document {
                body: body.to_owned(),
                fresh_until,
            },
        );
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Document>> {
        self.documents
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// An [`HttpGet`] that answers from an [`OidcMetadataCache`], fetching with
/// `http` on a miss. Hand it to [`crate::identity_oidc::discover_endpoints`]
/// and the discovery document is read once per its lifetime, not per call.
pub struct Cached<'a, H: ?Sized> {
    cache: &'a OidcMetadataCache,
    http: &'a H,
}

impl<'a, H: HttpGet + ?Sized> Cached<'a, H> {
    pub fn new(cache: &'a OidcMetadataCache, http: &'a H) -> Self {
        Self { cache, http }
    }
}

impl<H: HttpGet + ?Sized> HttpGet for Cached<'_, H> {
    fn get(&self, url: &str) -> Result<String, String> {
        self.cache.get(url, self.http)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Serves one body with one `Cache-Control`, counting fetches, and can be
    /// told to fail.
    struct Publisher {
        body: Mutex<String>,
        cache_control: Option<&'static str>,
        fetches: AtomicUsize,
        down: std::sync::atomic::AtomicBool,
    }

    impl Publisher {
        fn new(body: &str, cache_control: Option<&'static str>) -> Self {
            Self {
                body: Mutex::new(body.to_owned()),
                cache_control,
                fetches: AtomicUsize::new(0),
                down: std::sync::atomic::AtomicBool::new(false),
            }
        }
        fn fetches(&self) -> usize {
            self.fetches.load(Ordering::SeqCst)
        }
    }

    impl HttpGet for Publisher {
        fn get(&self, url: &str) -> Result<String, String> {
            self.get_cacheable(url).map(|(body, _)| body)
        }
        fn get_cacheable(&self, _url: &str) -> Result<(String, Option<String>), String> {
            self.fetches.fetch_add(1, Ordering::SeqCst);
            if self.down.load(Ordering::SeqCst) {
                return Err("transport: connection refused".into());
            }
            Ok((
                self.body.lock().unwrap().clone(),
                self.cache_control.map(str::to_owned),
            ))
        }
    }

    const URL: &str = "https://idp.example.test/.well-known/openid-configuration";

    #[test]
    fn lifetime_follows_cache_control() {
        assert_eq!(lifetime(None), Some(DEFAULT_LIFETIME));
        assert_eq!(
            lifetime(Some("public, max-age=3600")),
            Some(Duration::from_secs(3600))
        );
        // Google's JWKS and Microsoft's discovery, as served on 2026-10-07.
        assert_eq!(
            lifetime(Some("public, max-age=23433, must-revalidate, no-transform")),
            Some(Duration::from_secs(23433))
        );
        assert_eq!(
            lifetime(Some("max-age=86400, private")),
            Some(Duration::from_secs(86400))
        );
        assert_eq!(
            lifetime(Some("Max-Age=\"60\"")),
            Some(Duration::from_secs(60))
        );
        assert_eq!(lifetime(Some("max-age=31536000")), Some(MAX_LIFETIME));
        assert_eq!(lifetime(Some("public")), Some(DEFAULT_LIFETIME));
        assert_eq!(lifetime(Some("no-store")), None);
        assert_eq!(lifetime(Some("private, no-cache")), None);
        assert_eq!(lifetime(Some("max-age=0")), None);
        assert_eq!(lifetime(Some("max-age=soon")), None);
    }

    #[test]
    fn a_fresh_document_is_answered_without_the_network() {
        let cache = OidcMetadataCache::new();
        let publisher = Publisher::new("doc-1", Some("max-age=3600"));
        let t0 = Instant::now();
        assert_eq!(cache.get_at(URL, &publisher, t0).unwrap(), "doc-1");
        assert_eq!(publisher.fetches(), 1);
        for minute in 1..60 {
            let at = t0 + Duration::from_secs(minute * 60 - 1);
            assert_eq!(cache.get_at(URL, &publisher, at).unwrap(), "doc-1");
        }
        assert_eq!(publisher.fetches(), 1, "a cache hit must not fetch");
    }

    #[test]
    fn an_expired_document_is_fetched_again() {
        let cache = OidcMetadataCache::new();
        let publisher = Publisher::new("doc-1", Some("max-age=60"));
        let t0 = Instant::now();
        cache.get_at(URL, &publisher, t0).unwrap();
        *publisher.body.lock().unwrap() = "doc-2".into();
        assert_eq!(
            cache
                .get_at(URL, &publisher, t0 + Duration::from_secs(59))
                .unwrap(),
            "doc-1"
        );
        assert_eq!(
            cache
                .get_at(URL, &publisher, t0 + Duration::from_secs(60))
                .unwrap(),
            "doc-2"
        );
        assert_eq!(publisher.fetches(), 2);
    }

    #[test]
    fn a_document_that_forbids_caching_is_fetched_every_time() {
        let cache = OidcMetadataCache::new();
        let publisher = Publisher::new("doc", Some("no-store"));
        let t0 = Instant::now();
        cache.get_at(URL, &publisher, t0).unwrap();
        cache.get_at(URL, &publisher, t0).unwrap();
        assert_eq!(publisher.fetches(), 2);
    }

    #[test]
    fn an_expired_document_answers_when_the_publisher_is_down() {
        let cache = OidcMetadataCache::new();
        let publisher = Publisher::new("doc-1", Some("max-age=60"));
        let t0 = Instant::now();
        cache.get_at(URL, &publisher, t0).unwrap();
        publisher.down.store(true, Ordering::SeqCst);
        assert_eq!(
            cache
                .get_at(URL, &publisher, t0 + Duration::from_secs(600))
                .unwrap(),
            "doc-1"
        );
        // Nothing cached and nothing reachable is still a failure.
        assert!(OidcMetadataCache::new()
            .get_at(URL, &publisher, t0)
            .is_err());
    }

    #[test]
    fn refetch_replaces_a_fresh_copy_and_keeps_it_on_failure() {
        let cache = OidcMetadataCache::new();
        let publisher = Publisher::new("keys-1", Some("max-age=3600"));
        let t0 = Instant::now();
        cache.get_at(URL, &publisher, t0).unwrap();
        *publisher.body.lock().unwrap() = "keys-2".into();
        assert_eq!(cache.refetch_at(URL, &publisher, t0).unwrap(), "keys-2");
        assert_eq!(cache.get_at(URL, &publisher, t0).unwrap(), "keys-2");
        publisher.down.store(true, Ordering::SeqCst);
        assert!(cache.refetch_at(URL, &publisher, t0).is_err());
        assert_eq!(cache.get_at(URL, &publisher, t0).unwrap(), "keys-2");
        assert_eq!(publisher.fetches(), 3);
    }

    #[test]
    fn the_cached_getter_reads_discovery_once() {
        let cache = OidcMetadataCache::new();
        let publisher = Publisher::new(
            r#"{"issuer":"https://idp.example.test",
                "authorization_endpoint":"https://idp.example.test/authorize",
                "token_endpoint":"https://idp.example.test/token",
                "jwks_uri":"https://idp.example.test/keys"}"#,
            Some("public, max-age=3600"),
        );
        for _ in 0..5 {
            let endpoints = crate::identity_oidc::discover_endpoints(
                "https://idp.example.test",
                &Cached::new(&cache, &publisher),
            )
            .unwrap();
            assert_eq!(endpoints.token_endpoint, "https://idp.example.test/token");
        }
        assert_eq!(publisher.fetches(), 1);
    }
}
