//! Retaining a TokenWright box's audit anchors, on the Home.
//!
//! A box chains its command trail and signs the head, which detects an edit, a
//! reorder or a deletion — but not the box rewriting its own history, because
//! the box holds the signing key and can re-sign a consistent head. What
//! survives that is **retention**: every signed head the box reports is
//! appended here, in a store the box cannot reach, and a later walk of the
//! trail it serves must still reproduce every head already written down. A
//! rewrite contradicts something outside its reach. That is TokenWright's own
//! design (`API.md`, "The command trail"; `DESIGN.md`, "The command trail"),
//! and this module is the Home's half of it.
//!
//! Three properties are load-bearing:
//!
//! - **Append, never replace.** An anchor that overwrote its predecessor would
//!   let a compromised box publish one fresh consistent head and erase the
//!   contradiction. Anchors are records of their own kind in the person's
//!   account scope, each with its own id, and nothing in this module writes a
//!   tombstone for one.
//! - **Bound to the box.** A head is admitted only for a box this account has
//!   paired, under the certificate fingerprint the *transport* presented —
//!   never one a body names — and only when it verifies under the box's audit
//!   key. The first key a box presents is pinned with its first anchor; a later
//!   head under a different key is refused as an alarm, the same discipline the
//!   Home already applies to the certificate itself.
//! - **Acknowledged only once durable.** [`AnchorAck`] is constructed after the
//!   store has committed the record, and not before, so a box that records an
//!   anchor as covered on the strength of an ack is never covered by something
//!   a crash could lose.
//!
//! The detection is [`check_trail`]: walk the fetched trail from genesis,
//! recomputing every hash, and test each retained anchor against the verified
//! prefix. An anchor whose count the walk cannot reach, or whose head the walk
//! does not reproduce, is a contradiction, and there is no innocent cause —
//! the trail is append-only, so a head that was true once stays true.

use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::account::RecordOp;
use crate::tokenwright::{pin_bytes, request, route_bytes, BoxError};
use crate::workbench_state::SharedWorkbench;
use crate::{LockUnpoisoned, Workbench};
use gaugedesk_store::AdmitError;

/// Record kind for a retained anchor, in the person's own account scope — so an
/// account erasure covers it without naming it, as it does a box record.
pub const ANCHOR_RECORD_KIND: &str = "tokenwright_anchor";

/// The `kind` a box's report carries.
pub const HEAD_KIND: &str = "tokenwright.audit.head";

/// The `kind` of the acknowledgement this Home returns.
pub const ACK_KIND: &str = "tokenwright.audit.ack";

/// A report is five short fields. Anything larger is not one, and reading it
/// would only spend memory on a peer's say-so.
pub const MAX_HEAD_BYTES: usize = 1024;

/// The most entries one audit walk will hold. A trail longer than this is
/// refused rather than read into memory without bound; it is far beyond what a
/// box records in years of administration.
pub const MAX_TRAIL_ENTRIES: usize = 1_000_000;

/// The page size the box allows at most (`server.read_audit`).
const AUDIT_PAGE_LIMIT: u64 = 500;

/// Exactly the fields a trail entry carries (`tokenwright.audit.ENTRY_FIELDS`).
const ENTRY_FIELDS: [&str; 9] = [
    "seq",
    "at",
    "actor",
    "command_id",
    "base_revision",
    "receipt_id",
    "outcome",
    "prev",
    "hash",
];

/// The chain is anchored to the application rather than to zeros, so an empty
/// trail from elsewhere cannot be grafted on as a prefix
/// (`tokenwright.audit.GENESIS`).
pub fn genesis() -> String {
    hex::encode(Sha256::digest(b"tokenwright/audit/genesis/v1"))
}

#[derive(Debug)]
pub enum AnchorError {
    /// Not a signed head this Home can read. The message names the field.
    Malformed(String),
    /// No box with this fingerprint is paired in the account.
    Unpaired,
    /// The box signed under a key other than the one pinned with its first
    /// anchor. Never an update: it is the alarm.
    KeyChanged,
    /// The signature does not verify under the box's audit key.
    BadSignature,
    /// The store did not commit the anchor, so nothing is acknowledged.
    Store(AdmitError),
}

impl std::fmt::Display for AnchorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AnchorError::Malformed(why) => write!(f, "not a signed audit head: {why}"),
            AnchorError::Unpaired => f.write_str("no paired box presents that certificate"),
            AnchorError::KeyChanged => f.write_str(
                "the box signed its audit head under a different key than the one pinned \
                 with its first anchor",
            ),
            AnchorError::BadSignature => {
                f.write_str("the audit head's signature does not verify under the box's key")
            }
            AnchorError::Store(error) => write!(f, "the anchor was not recorded: {error:?}"),
        }
    }
}

impl std::error::Error for AnchorError {}

fn malformed<T>(why: impl Into<String>) -> Result<T, AnchorError> {
    Err(AnchorError::Malformed(why.into()))
}

/// What a box reports: `count`, `head` and `at`, signed under its audit key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedHead {
    pub count: u64,
    /// `None` exactly when `count` is zero: an empty trail has no head.
    pub head: Option<String>,
    /// `YYYY-MM-DDTHH:MM:SSZ`, the one spelling the box writes.
    pub at: String,
    /// Ed25519, lowercase hex.
    pub signature: String,
}

fn is_lower_hex(text: &str, len: usize) -> bool {
    text.len() == len && text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// The box's `to_rfc3339` never varies its format, which is also what makes
/// the signed bytes reproducible here without a general JSON canonicaliser.
fn is_box_timestamp(text: &str) -> bool {
    let b = text.as_bytes();
    b.len() == 20
        && b.iter().enumerate().all(|(i, c)| match i {
            4 | 7 => *c == b'-',
            10 => *c == b'T',
            13 | 16 => *c == b':',
            19 => *c == b'Z',
            _ => c.is_ascii_digit(),
        })
}

/// Read a `tokenwright.audit.head` report, or say which part is wrong.
pub fn parse_head(raw: &[u8]) -> Result<SignedHead, AnchorError> {
    if raw.len() > MAX_HEAD_BYTES {
        return malformed(format!("larger than {MAX_HEAD_BYTES} bytes"));
    }
    let Ok(Value::Object(fields)) = serde_json::from_slice::<Value>(raw) else {
        return malformed("not a JSON object");
    };
    if let Some(extra) = fields
        .keys()
        .find(|k| !matches!(k.as_str(), "kind" | "count" | "head" | "at" | "signature"))
    {
        return malformed(format!("unexpected field {extra:?}"));
    }
    if fields.get("kind").and_then(Value::as_str) != Some(HEAD_KIND) {
        return malformed(format!("kind is not {HEAD_KIND:?}"));
    }
    let Some(count) = fields.get("count").and_then(Value::as_u64) else {
        return malformed("count is not a non-negative integer");
    };
    let head = match fields.get("head") {
        Some(Value::Null) => None,
        Some(Value::String(head)) if is_lower_hex(head, 64) => Some(head.clone()),
        _ => return malformed("head is neither null nor a SHA-256 in lowercase hex"),
    };
    if (count == 0) != head.is_none() {
        return malformed("count and head disagree about whether the trail is empty");
    }
    let at = match fields.get("at") {
        Some(Value::String(at)) if is_box_timestamp(at) => at.clone(),
        _ => return malformed("at is not a YYYY-MM-DDTHH:MM:SSZ timestamp"),
    };
    let signature = match fields.get("signature") {
        Some(Value::String(signature)) if is_lower_hex(signature, 128) => signature.clone(),
        _ => return malformed("signature is not an Ed25519 signature in lowercase hex"),
    };
    Ok(SignedHead {
        count,
        head,
        at,
        signature,
    })
}

impl SignedHead {
    /// The bytes the box signed: `canonical_bytes({"count", "head", "at"})` —
    /// sorted keys, no whitespace. Every value was validated to a charset JSON
    /// never escapes, so this spelling is the only one.
    pub fn signed_bytes(&self) -> Vec<u8> {
        let head = match &self.head {
            Some(head) => format!("\"{head}\""),
            None => "null".to_owned(),
        };
        format!(
            "{{\"at\":\"{}\",\"count\":{},\"head\":{}}}",
            self.at, self.count, head
        )
        .into_bytes()
    }

    /// Whether this head verifies under `audit_key`, the box's Ed25519 public key.
    pub fn verifies_under(&self, audit_key: &[u8; 32]) -> bool {
        let Ok(signature) = hex::decode(&self.signature) else {
            return false;
        };
        ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, audit_key)
            .verify(&self.signed_bytes(), &signature)
            .is_ok()
    }
}

/// One retained anchor, as stored.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct AnchorRecord {
    /// Derived from the box and the signed head, so the same report recorded
    /// twice is one anchor rather than two.
    pub id: String,
    /// Always `upsert`. Present so the record reads like every other account
    /// record; an anchor is never tombstoned.
    #[serde(default)]
    pub op: RecordOp,
    /// The box's certificate fingerprint, hex, without `sha256:` — the same id
    /// its [`BoxRecord`](crate::account::BoxRecord) carries.
    pub box_id: String,
    /// The Ed25519 public key the head verified under, hex.
    pub audit_key: String,
    pub count: u64,
    pub head: Option<String>,
    pub at: String,
    pub signature: String,
    /// When this Home committed it, milliseconds since the epoch.
    pub received_at_ms: u64,
}

impl AnchorRecord {
    pub fn signed_head(&self) -> SignedHead {
        SignedHead {
            count: self.count,
            head: self.head.clone(),
            at: self.at.clone(),
            signature: self.signature.clone(),
        }
    }
}

fn anchor_id(box_id: &str, head: &SignedHead) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"gaugedesk/tokenwright-anchor/v1\0");
    hasher.update(box_id.as_bytes());
    hasher.update(b"\0");
    hasher.update(head.signed_bytes());
    hasher.update(b"\0");
    hasher.update(head.signature.as_bytes());
    hex::encode(hasher.finalize())
}

/// What the Home answers once an anchor is durable. The box may count the head
/// as covered only on receiving this.
#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
pub struct AnchorAck {
    pub kind: &'static str,
    /// `sha256:<hex>`, the box's own spelling of its fingerprint.
    #[serde(rename = "box")]
    pub box_fingerprint: String,
    pub count: u64,
    pub head: Option<String>,
    pub at: String,
    /// How many anchors this Home now holds for the box.
    pub retained: usize,
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Every anchor `scope` holds for each box, in the order they were recorded.
fn anchors_by_box(
    workbench: &Workbench,
    scope: &str,
) -> Result<BTreeMap<String, Vec<AnchorRecord>>, AdmitError> {
    let mut by_box: BTreeMap<String, Vec<AnchorRecord>> = BTreeMap::new();
    for row in workbench.store_ref().records(scope, ANCHOR_RECORD_KIND)? {
        let record: AnchorRecord = serde_json::from_str(&row)?;
        by_box
            .entry(record.box_id.clone())
            .or_default()
            .push(record);
    }
    Ok(by_box)
}

impl Workbench {
    /// Retain a box's signed audit head.
    ///
    /// `presented_fingerprint` is the certificate the transport the head
    /// arrived on was pinned to — the caller's claim that this report came
    /// from that box, which is why it must never be taken from the report or
    /// from a request body. `audit_key` is the box's Ed25519 public key, as the
    /// box declared it over that same channel.
    ///
    /// Returns the acknowledgement only after the store has committed the
    /// anchor. A report already retained is acknowledged again without being
    /// appended twice.
    pub fn receive_tokenwright_head_in(
        &mut self,
        scope: &str,
        presented_fingerprint: &str,
        audit_key: &[u8; 32],
        raw: &[u8],
    ) -> Result<AnchorAck, AnchorError> {
        let box_id = pin_bytes(presented_fingerprint)
            .map(hex::encode)
            .map_err(|_| AnchorError::Unpaired)?;
        let paired = self
            .account_boxes_in(scope)
            .map_err(AnchorError::Store)?
            .into_iter()
            .any(|record| record.id == box_id);
        if !paired {
            return Err(AnchorError::Unpaired);
        }

        let head = parse_head(raw)?;
        let retained = anchors_by_box(self, scope)
            .map_err(AnchorError::Store)?
            .remove(&box_id)
            .unwrap_or_default();
        let key_hex = hex::encode(audit_key);
        if let Some(first) = retained.first() {
            if first.audit_key != key_hex {
                return Err(AnchorError::KeyChanged);
            }
        }
        if !head.verifies_under(audit_key) {
            return Err(AnchorError::BadSignature);
        }

        let id = anchor_id(&box_id, &head);
        let ack = |retained: usize| AnchorAck {
            kind: ACK_KIND,
            box_fingerprint: format!("sha256:{box_id}"),
            count: head.count,
            head: head.head.clone(),
            at: head.at.clone(),
            retained,
        };
        if retained.iter().any(|anchor| anchor.id == id) {
            return Ok(ack(retained.len()));
        }

        let record = AnchorRecord {
            id: id.clone(),
            op: RecordOp::Upsert,
            box_id: box_id.clone(),
            audit_key: key_hex,
            count: head.count,
            head: head.head.clone(),
            at: head.at.clone(),
            signature: head.signature.clone(),
            received_at_ms: now_ms(),
        };
        self.write_account_record_in(scope, ANCHOR_RECORD_KIND, &id, &record)
            .map_err(AnchorError::Store)?;
        Ok(ack(retained.len() + 1))
    }

    /// Every anchor `scope` retains for one box, oldest first.
    pub fn tokenwright_anchors_in(
        &self,
        scope: &str,
        fingerprint: &str,
    ) -> Result<Vec<AnchorRecord>, AdmitError> {
        let Ok(box_id) = pin_bytes(fingerprint).map(hex::encode) else {
            return Ok(Vec::new());
        };
        Ok(anchors_by_box(self, scope)?
            .remove(&box_id)
            .unwrap_or_default())
    }
}

// --- the detection ----------------------------------------------------------

/// `canonical_bytes` as the box writes it: sorted keys, no whitespace, UTF-8
/// left unescaped, and JSON's mandatory escapes spelled the way Python's
/// `json.dumps` spells them. Floats are refused, because no trail field is one
/// and two languages disagree about how to print them.
fn canonical_json(value: &Value, out: &mut String) -> Result<(), String> {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                out.push_str(&i.to_string());
            } else if let Some(u) = n.as_u64() {
                out.push_str(&u.to_string());
            } else {
                return Err("a trail entry carries a non-integer number".to_owned());
            }
        }
        Value::String(s) => canonical_string(s, out),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                canonical_json(item, out)?;
            }
            out.push(']');
        }
        Value::Object(fields) => {
            let mut keys: Vec<&String> = fields.keys().collect();
            keys.sort();
            out.push('{');
            for (i, key) in keys.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                canonical_string(key, out);
                out.push(':');
                canonical_json(&fields[key], out)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

fn canonical_string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

/// `tokenwright.audit.entry_hash`: SHA-256 over the canonical entry without its
/// own `hash`, `prev` included — which is what makes the chain a chain.
pub fn entry_hash(entry: &Map<String, Value>) -> Result<String, String> {
    let mut without = entry.clone();
    without.remove("hash");
    let mut text = String::new();
    canonical_json(&Value::Object(without), &mut text)?;
    Ok(hex::encode(Sha256::digest(text.as_bytes())))
}

/// What a walk of a fetched trail found, against the anchors this Home holds.
#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
pub struct TrailCheck {
    /// Entries the box served.
    pub entries: u64,
    /// Whether every link held, from genesis to the last entry served.
    pub chain_verified: bool,
    /// The first sequence number whose link did not hold, if any.
    pub broken_at: Option<u64>,
    /// The longest prefix covered by an anchor the trail still reproduces.
    pub anchored_count: u64,
    /// Anchors the trail no longer accounts for. Non-empty is the detection:
    /// the box's history no longer matches something written down here.
    pub contradicted: Vec<AnchorRecord>,
}

impl TrailCheck {
    /// The trail is consistent with everything this Home retained.
    pub fn holds(&self) -> bool {
        self.chain_verified && self.contradicted.is_empty()
    }
}

/// Walk `entries` from genesis and test every retained anchor against the
/// prefix whose links hold.
///
/// Only the verified prefix counts. An entry past a broken link carries a
/// `hash` field the walk could not reproduce, and a box that kept the old
/// hashes beside rewritten content would otherwise satisfy every anchor.
pub fn check_trail(entries: &[Value], anchors: &[AnchorRecord]) -> TrailCheck {
    let mut verified: Vec<String> = Vec::new();
    let mut broken_at = None;
    let mut expected_prev = genesis();
    for (index, entry) in entries.iter().enumerate() {
        let seq = index as u64 + 1;
        let link_holds = entry.as_object().is_some_and(|fields| {
            fields.len() == ENTRY_FIELDS.len()
                && ENTRY_FIELDS.iter().all(|name| fields.contains_key(*name))
                && fields.get("seq").and_then(Value::as_u64) == Some(seq)
                && fields.get("prev").and_then(Value::as_str) == Some(expected_prev.as_str())
                && match (
                    fields.get("hash").and_then(Value::as_str),
                    entry_hash(fields),
                ) {
                    (Some(claimed), Ok(computed)) => claimed == computed,
                    _ => false,
                }
        });
        if !link_holds {
            broken_at = Some(seq);
            break;
        }
        expected_prev = entry["hash"].as_str().unwrap_or_default().to_owned();
        verified.push(expected_prev.clone());
    }

    let covers = |anchor: &AnchorRecord| match anchor.count {
        0 => anchor.head.is_none(),
        count => usize::try_from(count - 1)
            .ok()
            .and_then(|index| verified.get(index))
            .is_some_and(|hash| anchor.head.as_deref() == Some(hash.as_str())),
    };
    let mut anchored_count = 0;
    let mut contradicted = Vec::new();
    for anchor in anchors {
        if covers(anchor) {
            anchored_count = anchored_count.max(anchor.count);
        } else {
            contradicted.push(anchor.clone());
        }
    }
    TrailCheck {
        entries: entries.len() as u64,
        chain_verified: broken_at.is_none(),
        broken_at,
        anchored_count,
        contradicted,
    }
}

// --- fetching the trail -----------------------------------------------------

/// One page of `GET /environments/tokenwright/audit`: its entries, and where
/// the next page starts. A `next_from` that does not move past this page is
/// refused, because following it would loop for as long as the box liked.
pub fn parse_audit_page(raw: &[u8], from: u64) -> Result<(Vec<Value>, Option<u64>), BoxError> {
    #[derive(Deserialize)]
    struct Page {
        entries: Vec<Value>,
        next_from: Option<u64>,
    }
    let page: Page = serde_json::from_slice(raw)
        .map_err(|_| BoxError("the box's audit page could not be read".to_owned()))?;
    if let Some(next) = page.next_from {
        if page.entries.is_empty() || next <= from {
            return Err(BoxError(
                "the box's audit page pointed back at itself".to_owned(),
            ));
        }
    }
    Ok((page.entries, page.next_from))
}

/// Read a box's whole trail, oldest first, over legs pinned to `fingerprint`.
pub async fn fetch_audit_trail(
    endpoint: &str,
    route: [u8; 32],
    fingerprint: &str,
    key: &str,
) -> Result<Vec<Value>, BoxError> {
    let pin = pin_bytes(fingerprint)?;
    let mut headers = BTreeMap::new();
    headers.insert("Authorization".to_owned(), format!("Bearer {key}"));

    let (status, raw) = request(
        endpoint,
        route,
        pin,
        "POST",
        "/environments/tokenwright/sessions",
        &headers,
        Some(b"{}"),
    )
    .await?;
    if status != 200 {
        return Err(BoxError(format!("the box refused a session ({status})")));
    }
    let session: Value = serde_json::from_slice(&raw)
        .map_err(|_| BoxError("the box's session could not be read".to_owned()))?;
    let Some(session) = session["session"]["id"].as_str().map(str::to_owned) else {
        return Err(BoxError("the box opened no session".to_owned()));
    };
    if !session
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        return Err(BoxError(
            "the box named a session this Home will not send".to_owned(),
        ));
    }

    let mut trail = Vec::new();
    let mut from = 1;
    loop {
        let path = format!(
            "/environments/tokenwright/audit?session={session}&from={from}&limit={AUDIT_PAGE_LIMIT}"
        );
        let (status, raw) = request(endpoint, route, pin, "GET", &path, &headers, None).await?;
        if status != 200 {
            return Err(BoxError(format!(
                "the box refused its audit trail ({status})"
            )));
        }
        let (entries, next) = parse_audit_page(&raw, from)?;
        trail.extend(entries);
        if trail.len() > MAX_TRAIL_ENTRIES {
            return Err(BoxError(format!(
                "the box's trail is longer than the {MAX_TRAIL_ENTRIES} entries one walk reads"
            )));
        }
        match next {
            Some(next) => from = next,
            None => return Ok(trail),
        }
    }
}

/// Fetch one paired box's trail and test it against every anchor retained for
/// it. The workbench is released before any network work, as the carried
/// requests do.
pub async fn audit_box_in(
    shared: &SharedWorkbench,
    scope: &str,
    fingerprint: &str,
) -> Result<TrailCheck, BoxError> {
    let box_id = hex::encode(pin_bytes(fingerprint)?);
    let (endpoint, material, anchors) = {
        let wb = shared.lock_unpoisoned();
        let record = wb
            .account_boxes_in(scope)
            .map_err(|error| BoxError(format!("reading boxes: {error:?}")))?
            .into_iter()
            .find(|record| record.id == box_id)
            .ok_or_else(|| BoxError("no such box".to_owned()))?;
        let material = wb
            .resolve_account_box_in(scope, &box_id)
            .ok_or_else(|| BoxError("this box's stored credential cannot be opened".to_owned()))?;
        let anchors = wb
            .tokenwright_anchors_in(scope, &box_id)
            .map_err(|error| BoxError(format!("reading anchors: {error:?}")))?;
        (record.relay_endpoint, material, anchors)
    };
    let route = route_bytes(&material.route)?;
    let trail = fetch_audit_trail(&endpoint, route, &box_id, &material.key).await?;
    Ok(check_trail(&trail, &anchors))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn genesis_is_the_boxes_own() {
        // `tokenwright.audit.GENESIS`, printed by the box.
        assert_eq!(
            genesis(),
            "9d66d80271626791b4add0fc15e5c99ac6762909c13bcf4dfba8622fe95de5c9"
        );
    }

    #[test]
    fn a_head_reads_back_and_signs_the_boxes_bytes() {
        let raw = br#"{"kind":"tokenwright.audit.head","count":2,"head":"fc52fe4debc7f4965894e996aebe2452da6273afca5cc9354746b622f5f8d9cc","at":"2026-08-30T12:02:00Z","signature":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"}"#;
        let head = parse_head(raw).expect("parse");
        assert_eq!(head.count, 2);
        assert_eq!(
            String::from_utf8(head.signed_bytes()).unwrap(),
            r#"{"at":"2026-08-30T12:02:00Z","count":2,"head":"fc52fe4debc7f4965894e996aebe2452da6273afca5cc9354746b622f5f8d9cc"}"#
        );
    }

    #[test]
    fn an_empty_trail_signs_a_null_head() {
        let raw = format!(
            r#"{{"kind":"tokenwright.audit.head","count":0,"head":null,"at":"2026-08-30T12:00:00Z","signature":"{}"}}"#,
            "0".repeat(128)
        );
        let head = parse_head(raw.as_bytes()).expect("parse");
        assert_eq!(
            String::from_utf8(head.signed_bytes()).unwrap(),
            r#"{"at":"2026-08-30T12:00:00Z","count":0,"head":null}"#
        );
    }

    #[test]
    fn every_refusal_names_the_field() {
        let sig = "0".repeat(128);
        let head = "a".repeat(64);
        let cases = [
            (
                format!(
                    r#"{{"kind":"x","count":1,"head":"{head}","at":"2026-08-30T12:00:00Z","signature":"{sig}"}}"#
                ),
                "kind",
            ),
            (
                format!(
                    r#"{{"kind":"tokenwright.audit.head","count":-1,"head":"{head}","at":"2026-08-30T12:00:00Z","signature":"{sig}"}}"#
                ),
                "count",
            ),
            (
                format!(
                    r#"{{"kind":"tokenwright.audit.head","count":1,"head":"{}","at":"2026-08-30T12:00:00Z","signature":"{sig}"}}"#,
                    "A".repeat(64)
                ),
                "head",
            ),
            (
                format!(
                    r#"{{"kind":"tokenwright.audit.head","count":0,"head":"{head}","at":"2026-08-30T12:00:00Z","signature":"{sig}"}}"#
                ),
                "disagree",
            ),
            (
                format!(
                    r#"{{"kind":"tokenwright.audit.head","count":1,"head":"{head}","at":"2026-08-30 12:00:00","signature":"{sig}"}}"#
                ),
                "at",
            ),
            (
                format!(
                    r#"{{"kind":"tokenwright.audit.head","count":1,"head":"{head}","at":"2026-08-30T12:00:00Z","signature":"zz"}}"#
                ),
                "signature",
            ),
            (
                format!(
                    r#"{{"kind":"tokenwright.audit.head","count":1,"head":"{head}","at":"2026-08-30T12:00:00Z","signature":"{sig}","note":"x"}}"#
                ),
                "note",
            ),
            ("[]".to_owned(), "object"),
            (" ".repeat(MAX_HEAD_BYTES + 1), "larger"),
        ];
        for (raw, expected) in cases {
            let error = parse_head(raw.as_bytes()).expect_err(&raw).to_string();
            assert!(
                error.contains(expected),
                "{raw:?} said {error:?}, wanted {expected:?}"
            );
        }
    }

    #[test]
    fn canonical_strings_match_pythons_spelling() {
        let mut out = String::new();
        canonical_string("é\"\\\n\u{01}\u{7f}/", &mut out);
        assert_eq!(out, "\"é\\\"\\\\\\n\\u0001\u{7f}/\"");
    }

    #[test]
    fn a_page_that_points_back_at_itself_is_refused() {
        let page = br#"{"entries":[{"seq":1}],"next_from":1}"#;
        assert!(parse_audit_page(page, 1).is_err());
        let empty_but_more = br#"{"entries":[],"next_from":5}"#;
        assert!(parse_audit_page(empty_but_more, 1).is_err());
        let last = br#"{"entries":[{"seq":1}],"next_from":null}"#;
        assert_eq!(parse_audit_page(last, 1).expect("page").1, None);
    }
}
