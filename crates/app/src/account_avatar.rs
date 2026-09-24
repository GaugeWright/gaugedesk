//! The account avatar (DR-0195): image bytes the account owns, which a verified
//! provider identity may supply once and the person may replace or remove.
//!
//! Three things live here and nowhere else:
//!
//! - [`normalize`] — every image, whether a provider's or an upload, is decoded
//!   under limits and re-encoded square at [`AVATAR_SIZE`]. Nothing a third
//!   party or a browser sent is stored verbatim, which is also how EXIF and any
//!   trailing payload go away.
//! - [`fetch_provider_picture`] — the one outbound fetch of a URL somebody else
//!   chose. `https` only on every hop; every connection, redirects included,
//!   resolves through [`PublicOnlyResolver`], so no hop can reach a private,
//!   loopback or link-local address; the byte ceiling is enforced while
//!   reading, not after.
//! - [`adopt_provider_avatar`] and [`replace_avatar`] — the two write rules.
//!   A sign-in may *fill* an account that has never had an avatar; only the
//!   person's explicit act may *replace* one or undo a removal (DR-0195 §3–4).
//!
//! Failure is silent by design. The avatar is a convenience, and no sign-in may
//! fail because a photograph did not arrive.

use std::io::{Cursor, Read as _};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
use std::time::Duration;

use base64::Engine as _;
use gaugedesk_store::AdmitError;
use image::{imageops::FilterType, DynamicImage, GenericImageView, ImageFormat, ImageReader};

use crate::account::{
    account_scope, Account, AccountAvatarRecord, AvatarSource, RecordOp, ACCOUNT_AVATAR_ID,
    ACCOUNT_AVATAR_KIND,
};
use crate::Workbench;

/// The stored edge, in pixels. Twice the largest place an avatar is drawn, so
/// it stays sharp on a 2x display without storing a photograph.
pub const AVATAR_SIZE: u32 = 128;

/// The most source bytes read from a provider or accepted from an upload.
/// Enforced during the read; a larger body is refused rather than truncated.
pub const MAX_SOURCE_BYTES: usize = 5 * 1024 * 1024;

/// Decoder limits. A small file can declare an enormous canvas, so the
/// dimensions and allocation are bounded independently of the byte ceiling.
const MAX_SOURCE_DIMENSION: u32 = 4096;
const MAX_DECODE_ALLOC: u64 = 96 * 1024 * 1024;

const FETCH_TIMEOUT: Duration = Duration::from_secs(8);
const FETCH_REDIRECTS: u32 = 3;
const JPEG_QUALITY: u8 = 85;

/// A normalized avatar, ready to store.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredAvatar {
    pub media_type: &'static str,
    pub bytes: Vec<u8>,
}

impl StoredAvatar {
    fn record(&self, source: AvatarSource, now_ms: u64) -> AccountAvatarRecord {
        AccountAvatarRecord {
            id: ACCOUNT_AVATAR_ID.to_owned(),
            op: RecordOp::Upsert,
            source,
            media_type: self.media_type.to_owned(),
            data: base64::engine::general_purpose::STANDARD.encode(&self.bytes),
            set_at_ms: now_ms,
        }
    }
}

/// Why an image was not admitted. Deliberately coarse: the reason is shown to
/// the person uploading, and nothing about the bytes is echoed back.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AvatarRejection {
    TooLarge,
    NotAnImage,
}

impl AvatarRejection {
    pub fn message(self) -> &'static str {
        match self {
            Self::TooLarge => "the image is larger than 5 MB",
            Self::NotAnImage => "the file is not a PNG, JPEG, WebP or GIF image",
        }
    }
}

/// Decode `source` under limits and re-encode it square at [`AVATAR_SIZE`].
///
/// The format is taken from the bytes, never from a `Content-Type` or a file
/// name. An image with real transparency is kept as PNG so a round mask does
/// not show a flattened corner; everything else becomes JPEG, which is a fifth
/// of the size for a photograph.
pub fn normalize(source: &[u8]) -> Result<StoredAvatar, AvatarRejection> {
    if source.len() > MAX_SOURCE_BYTES {
        return Err(AvatarRejection::TooLarge);
    }
    let mut reader = ImageReader::new(Cursor::new(source))
        .with_guessed_format()
        .map_err(|_| AvatarRejection::NotAnImage)?;
    match reader.format() {
        Some(ImageFormat::Png | ImageFormat::Jpeg | ImageFormat::WebP | ImageFormat::Gif) => {}
        _ => return Err(AvatarRejection::NotAnImage),
    }
    let mut limits = image::Limits::default();
    limits.max_image_width = Some(MAX_SOURCE_DIMENSION);
    limits.max_image_height = Some(MAX_SOURCE_DIMENSION);
    limits.max_alloc = Some(MAX_DECODE_ALLOC);
    reader.limits(limits);
    let decoded = reader.decode().map_err(|_| AvatarRejection::NotAnImage)?;
    let (width, height) = decoded.dimensions();
    if width == 0 || height == 0 {
        return Err(AvatarRejection::NotAnImage);
    }
    let side = width.min(height);
    let square = decoded
        .crop_imm((width - side) / 2, (height - side) / 2, side, side)
        .resize_exact(AVATAR_SIZE, AVATAR_SIZE, FilterType::Lanczos3);
    encode(square)
}

fn encode(image: DynamicImage) -> Result<StoredAvatar, AvatarRejection> {
    let mut out = Vec::new();
    let translucent =
        image.color().has_alpha() && image.to_rgba8().pixels().any(|pixel| pixel.0[3] < u8::MAX);
    if translucent {
        DynamicImage::ImageRgba8(image.to_rgba8())
            .write_to(&mut Cursor::new(&mut out), ImageFormat::Png)
            .map_err(|_| AvatarRejection::NotAnImage)?;
        return Ok(StoredAvatar {
            media_type: "image/png",
            bytes: out,
        });
    }
    image::codecs::jpeg::JpegEncoder::new_with_quality(&mut out, JPEG_QUALITY)
        .encode_image(&DynamicImage::ImageRgb8(image.to_rgb8()))
        .map_err(|_| AvatarRejection::NotAnImage)?;
    Ok(StoredAvatar {
        media_type: "image/jpeg",
        bytes: out,
    })
}

/// Decode an uploaded `data:` URI or bare base64 body into source bytes.
/// The declared media type is ignored; [`normalize`] reads the bytes.
pub fn decode_upload(payload: &str) -> Result<Vec<u8>, AvatarRejection> {
    let body = payload.trim();
    let body = match body.strip_prefix("data:") {
        Some(rest) => rest
            .split_once(";base64,")
            .map(|(_, data)| data)
            .ok_or(AvatarRejection::NotAnImage)?,
        None => body,
    };
    // Four base64 characters carry three bytes; refuse before allocating.
    if body.len() / 4 * 3 > MAX_SOURCE_BYTES + 3 {
        return Err(AvatarRejection::TooLarge);
    }
    base64::engine::general_purpose::STANDARD
        .decode(body)
        .map_err(|_| AvatarRejection::NotAnImage)
}

/// The `picture` claim of an already-verified id-token, if it is an `https`
/// URL. Read only after signature, issuer, audience and nonce verification.
pub fn picture_claim(claims: &serde_json::Value) -> Option<String> {
    let raw = claims.get("picture")?.as_str()?.trim();
    let parsed = url::Url::parse(raw).ok()?;
    (parsed.scheme() == "https" && parsed.username().is_empty() && parsed.password().is_none())
        .then(|| raw.to_owned())
}

/// Fetch the picture a verified assertion named. `None` on any failure: a
/// non-`https` URL or hop, an address outside the public internet, a non-200,
/// a body over [`MAX_SOURCE_BYTES`], or a timeout.
pub fn fetch_provider_picture(url: &str) -> Option<Vec<u8>> {
    let parsed = url::Url::parse(url).ok()?;
    if parsed.scheme() != "https" {
        return None;
    }
    let agent = ureq::AgentBuilder::new()
        .https_only(true)
        .redirects(FETCH_REDIRECTS)
        .timeout(FETCH_TIMEOUT)
        .resolver(PublicOnlyResolver)
        .build();
    let response = agent.get(parsed.as_str()).call().ok()?;
    if response.status() != 200 {
        return None;
    }
    let mut body = Vec::new();
    response
        .into_reader()
        .take(MAX_SOURCE_BYTES as u64 + 1)
        .read_to_end(&mut body)
        .ok()?;
    (body.len() <= MAX_SOURCE_BYTES).then_some(body)
}

/// Resolves a host and keeps only public addresses, refusing when none remain.
///
/// It is the resolver rather than a check on the URL because ureq resolves
/// every connection through it — an IP-literal host, a redirect hop, and a
/// name that resolves differently the second time all arrive here, and the
/// connection is made to the address this returns, not to one looked up again.
pub struct PublicOnlyResolver;

impl ureq::Resolver for PublicOnlyResolver {
    fn resolve(&self, netloc: &str) -> std::io::Result<Vec<SocketAddr>> {
        let public: Vec<SocketAddr> = netloc
            .to_socket_addrs()?
            .filter(|address| is_public(address.ip()))
            .collect();
        if public.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "the avatar host resolves only to non-public addresses",
            ));
        }
        Ok(public)
    }
}

/// Whether an address is on the public internet. Written out rather than
/// using `IpAddr::is_global`, which is unstable.
pub fn is_public(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(v4) => is_public_v4(v4),
        IpAddr::V6(v6) => {
            if let Some(mapped) = v6.to_ipv4_mapped() {
                return is_public_v4(mapped);
            }
            is_public_v6(v6)
        }
    }
}

fn is_public_v4(address: Ipv4Addr) -> bool {
    let [a, b, c, _] = address.octets();
    !(address.is_unspecified()
        || address.is_loopback()
        || address.is_private()
        || address.is_link_local()
        || address.is_broadcast()
        || address.is_documentation()
        || address.is_multicast()
        || a == 0
        // 100.64.0.0/10, carrier-grade NAT.
        || (a == 100 && (64..=127).contains(&b))
        // 192.0.0.0/24, IETF protocol assignments.
        || (a == 192 && b == 0 && c == 0)
        // 198.18.0.0/15, benchmarking.
        || (a == 198 && (18..=19).contains(&b))
        // 240.0.0.0/4, reserved.
        || a >= 240)
}

fn is_public_v6(address: Ipv6Addr) -> bool {
    let first = address.segments()[0];
    !(address.is_unspecified()
        || address.is_loopback()
        || address.is_multicast()
        // fc00::/7, unique local.
        || (first & 0xfe00) == 0xfc00
        // fe80::/10, link local.
        || (first & 0xffc0) == 0xfe80
        // 2001:db8::/32, documentation.
        || (first == 0x2001 && address.segments()[1] == 0x0db8)
        // 64:ff9b::/96 translates to IPv4 the resolver cannot see; refuse it.
        || (first == 0x0064 && address.segments()[1] == 0xff9b))
}

/// Fill an account that has never had an avatar from a provider's picture.
///
/// Returns whether it wrote. An account with any avatar record — including a
/// removed one — is left alone: a sign-in supplies the first avatar and never
/// the next one (DR-0195 §2–4).
pub fn adopt_provider_avatar(
    wb: &mut Workbench,
    account_id: &str,
    avatar: &StoredAvatar,
    now_ms: u64,
) -> Result<bool, AdmitError> {
    let scope = account_scope(account_id);
    if Account::rebuild_in(wb.store_ref(), &scope)?
        .avatar
        .is_some()
    {
        return Ok(false);
    }
    let record = avatar.record(AvatarSource::Provider, now_ms);
    wb.write_account_record_in(&scope, ACCOUNT_AVATAR_KIND, ACCOUNT_AVATAR_ID, &record)?;
    Ok(true)
}

/// The record for the person's explicit act: an upload, a re-fetch from a
/// linked provider, or a removal. Replaces whatever is there.
pub fn replacement_record(
    avatar: Option<&StoredAvatar>,
    source: AvatarSource,
    now_ms: u64,
) -> AccountAvatarRecord {
    match avatar {
        Some(avatar) if source != AvatarSource::Removed => avatar.record(source, now_ms),
        _ => AccountAvatarRecord {
            id: ACCOUNT_AVATAR_ID.to_owned(),
            op: RecordOp::Upsert,
            source: AvatarSource::Removed,
            media_type: String::new(),
            data: String::new(),
            set_at_ms: now_ms,
        },
    }
}

/// Write [`replacement_record`] into the account's scope.
pub fn replace_avatar(
    wb: &mut Workbench,
    account_id: &str,
    avatar: Option<&StoredAvatar>,
    source: AvatarSource,
    now_ms: u64,
) -> Result<(), AdmitError> {
    let record = replacement_record(avatar, source, now_ms);
    wb.write_account_record_in(
        &account_scope(account_id),
        ACCOUNT_AVATAR_KIND,
        ACCOUNT_AVATAR_ID,
        &record,
    )
}

/// Fetch, normalize and adopt a provider's picture without holding up the
/// sign-in that named it. Detached: the caller has already answered the
/// browser, and a failure anywhere leaves the account exactly as it was.
pub fn spawn_provider_adoption(wb: crate::SharedWorkbench, account_id: String, picture: String) {
    use crate::LockUnpoisoned as _;
    let Ok(runtime) = tokio::runtime::Handle::try_current() else {
        return;
    };
    // Checked before the fetch so an account that already has an avatar costs
    // no outbound request; checked again under the lock before writing.
    let absent = {
        let guard = wb.lock_unpoisoned();
        Account::rebuild_in(guard.store_ref(), &account_scope(&account_id))
            .map(|account| account.avatar.is_none())
            .unwrap_or(false)
    };
    if !absent {
        return;
    }
    runtime.spawn_blocking(move || {
        let Some(avatar) =
            fetch_provider_picture(&picture).and_then(|bytes| normalize(&bytes).ok())
        else {
            return;
        };
        let mut guard = wb.lock_unpoisoned();
        let _ = adopt_provider_avatar(
            &mut guard,
            &account_id,
            &avatar,
            crate::account::session_now_ms(),
        );
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use image::{Rgb, RgbImage, Rgba, RgbaImage};

    fn png(image: DynamicImage) -> Vec<u8> {
        let mut out = Vec::new();
        image
            .write_to(&mut Cursor::new(&mut out), ImageFormat::Png)
            .unwrap();
        out
    }

    #[test]
    fn a_photograph_is_cropped_square_and_becomes_a_small_jpeg() {
        let wide = RgbImage::from_fn(600, 300, |x, _| {
            if !(150..450).contains(&x) {
                Rgb([255, 0, 0])
            } else {
                Rgb([0, 0, 255])
            }
        });
        let stored = normalize(&png(DynamicImage::ImageRgb8(wide))).unwrap();
        assert_eq!(stored.media_type, "image/jpeg");
        let back = image::load_from_memory(&stored.bytes).unwrap();
        assert_eq!(back.dimensions(), (AVATAR_SIZE, AVATAR_SIZE));
        // The centre crop kept the blue middle and dropped the red sides.
        let Rgb([r, _, b]) = back.to_rgb8().get_pixel(4, 64).to_owned();
        assert!(
            b > 200 && r < 60,
            "expected the centre of the source, got r={r} b={b}"
        );
    }

    #[test]
    fn real_transparency_survives_as_png_and_opaque_alpha_does_not_count() {
        let clear =
            RgbaImage::from_fn(64, 64, |x, _| Rgba([0, 0, 0, if x < 32 { 0 } else { 255 }]));
        assert_eq!(
            normalize(&png(DynamicImage::ImageRgba8(clear)))
                .unwrap()
                .media_type,
            "image/png"
        );
        let opaque = RgbaImage::from_pixel(64, 64, Rgba([10, 20, 30, 255]));
        assert_eq!(
            normalize(&png(DynamicImage::ImageRgba8(opaque)))
                .unwrap()
                .media_type,
            "image/jpeg"
        );
    }

    #[test]
    fn what_is_not_an_admitted_image_is_refused_without_decoding() {
        assert_eq!(normalize(b"<svg/>"), Err(AvatarRejection::NotAnImage));
        assert_eq!(normalize(b""), Err(AvatarRejection::NotAnImage));
        // A BMP signature is recognized and still refused: the admitted formats
        // are a list, not whatever the decoder happens to understand.
        assert_eq!(
            normalize(b"BM\x3a\0\0\0\0\0\0\0"),
            Err(AvatarRejection::NotAnImage)
        );
        assert_eq!(
            normalize(&vec![0_u8; MAX_SOURCE_BYTES + 1]),
            Err(AvatarRejection::TooLarge)
        );
    }

    #[test]
    fn a_declared_canvas_past_the_limit_is_refused() {
        // A tiny PNG declaring 5000x1 is refused by the decoder limits rather
        // than allocated.
        let tall = png(DynamicImage::ImageRgb8(RgbImage::new(
            MAX_SOURCE_DIMENSION + 1,
            1,
        )));
        assert_eq!(normalize(&tall), Err(AvatarRejection::NotAnImage));
    }

    #[test]
    fn uploads_decode_from_a_data_uri_or_bare_base64() {
        let bytes = png(DynamicImage::ImageRgb8(RgbImage::new(4, 4)));
        let encoded = base64::engine::general_purpose::STANDARD.encode(&bytes);
        assert_eq!(decode_upload(&encoded).unwrap(), bytes);
        assert_eq!(
            decode_upload(&format!("data:image/png;base64,{encoded}")).unwrap(),
            bytes
        );
        assert_eq!(
            decode_upload("data:image/png,raw"),
            Err(AvatarRejection::NotAnImage)
        );
        assert_eq!(
            decode_upload("not base64 !"),
            Err(AvatarRejection::NotAnImage)
        );
    }

    #[test]
    fn only_an_https_picture_claim_is_read() {
        let claim = |value: &str| picture_claim(&serde_json::json!({ "picture": value }));
        assert_eq!(
            claim("https://lh3.googleusercontent.com/a/abc=s96-c").as_deref(),
            Some("https://lh3.googleusercontent.com/a/abc=s96-c")
        );
        assert_eq!(claim("http://example.com/a.png"), None);
        assert_eq!(claim("https://user:pw@example.com/a.png"), None);
        assert_eq!(claim("file:///etc/passwd"), None);
        assert_eq!(picture_claim(&serde_json::json!({})), None);
    }

    #[test]
    fn non_public_addresses_are_refused_and_public_ones_admitted() {
        for refused in [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.169.254",
            "100.64.0.1",
            "0.0.0.0",
            "198.18.0.1",
            "224.0.0.1",
            "255.255.255.255",
            "::1",
            "fe80::1",
            "fd00::1",
            "::ffff:127.0.0.1",
            "::ffff:169.254.169.254",
            "2001:db8::1",
            "64:ff9b::a9fe:a9fe",
        ] {
            assert!(
                !is_public(refused.parse().unwrap()),
                "{refused} must be refused"
            );
        }
        for admitted in ["142.250.72.1", "8.8.8.8", "2607:f8b0:4005:80a::2001"] {
            assert!(
                is_public(admitted.parse().unwrap()),
                "{admitted} must be admitted"
            );
        }
    }

    #[test]
    fn the_resolver_refuses_a_loopback_literal_and_the_fetch_refuses_http() {
        use ureq::Resolver as _;
        assert!(PublicOnlyResolver.resolve("127.0.0.1:443").is_err());
        assert!(PublicOnlyResolver.resolve("[::1]:443").is_err());
        assert_eq!(fetch_provider_picture("http://example.com/a.png"), None);
        // An https URL whose host is a private literal never connects.
        assert_eq!(fetch_provider_picture("https://127.0.0.1/a.png"), None);
    }

    fn sealed_workbench() -> (tempfile::TempDir, std::path::PathBuf, Workbench) {
        use std::sync::Arc;
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("hub.sqlite");
        let vault = Arc::new(crate::content_vault::ContentVault::new(
            dir.path().join("keys"),
            Box::new(crate::at_rest::LoopbackKeyWrap::new([5_u8; 32])),
        ));
        let store = gaugedesk_store::Store::open(db.to_str().unwrap())
            .unwrap()
            .with_codec(vault.clone());
        (dir, db, Workbench::new(store).with_content_vault(vault))
    }

    fn avatar(bytes: &[u8]) -> StoredAvatar {
        StoredAvatar {
            media_type: "image/jpeg",
            bytes: bytes.to_vec(),
        }
    }

    fn current(wb: &Workbench, account: &str) -> Option<AccountAvatarRecord> {
        Account::rebuild_in(wb.store_ref(), &account_scope(account))
            .unwrap()
            .avatar
    }

    #[test]
    fn a_sign_in_fills_an_empty_account_once_and_never_replaces() {
        let (_dir, _db, mut wb) = sealed_workbench();
        assert!(adopt_provider_avatar(&mut wb, "alice", &avatar(b"first"), 1).unwrap());
        assert!(!adopt_provider_avatar(&mut wb, "alice", &avatar(b"second"), 2).unwrap());
        let held = current(&wb, "alice").unwrap();
        assert_eq!(held.source, AvatarSource::Provider);
        assert_eq!(
            held.data,
            base64::engine::general_purpose::STANDARD.encode(b"first")
        );
        // Another person's account is untouched by alice's adoption.
        assert_eq!(current(&wb, "bob"), None);
    }

    #[test]
    fn a_removal_is_not_undone_by_the_next_sign_in_but_an_upload_replaces_it() {
        let (_dir, _db, mut wb) = sealed_workbench();
        replace_avatar(&mut wb, "alice", None, AvatarSource::Removed, 1).unwrap();
        assert!(!adopt_provider_avatar(&mut wb, "alice", &avatar(b"provider"), 2).unwrap());
        assert_eq!(current(&wb, "alice").unwrap().source, AvatarSource::Removed);
        replace_avatar(
            &mut wb,
            "alice",
            Some(&avatar(b"mine")),
            AvatarSource::Upload,
            3,
        )
        .unwrap();
        let held = current(&wb, "alice").unwrap();
        assert_eq!(held.source, AvatarSource::Upload);
        assert!(held
            .data_uri()
            .unwrap()
            .starts_with("data:image/jpeg;base64,"));
    }

    /// DR-0195's erasure claim holds only because `avatar` is a sealed kind:
    /// crypto-erasing a scope destroys its key, which protects nothing written
    /// in cleartext. This is the test that would have caught the draft's
    /// assumption that the scope alone was enough.
    #[test]
    fn the_avatar_is_ciphertext_at_rest_and_gone_after_the_scope_is_erased() {
        let (_dir, db, mut wb) = sealed_workbench();
        let photo = b"a photograph of alice";
        adopt_provider_avatar(&mut wb, "alice", &avatar(photo), 1).unwrap();
        let encoded = base64::engine::general_purpose::STANDARD.encode(photo);

        let raw = gaugedesk_store::Store::open(db.to_str().unwrap()).unwrap();
        let stored = raw
            .records(&account_scope("alice"), ACCOUNT_AVATAR_KIND)
            .unwrap();
        assert_eq!(stored.len(), 1);
        assert!(
            stored[0].starts_with("gwenc:1:"),
            "the avatar row is not sealed"
        );
        assert!(!stored[0].contains(&encoded));

        assert!(wb.crypto_erase_content(&account_scope("alice")));
        assert_eq!(current(&wb, "alice"), None);
    }

    #[test]
    fn removal_writes_a_removed_record_and_carries_no_bytes() {
        let stored = StoredAvatar {
            media_type: "image/jpeg",
            bytes: vec![1, 2, 3],
        };
        let removed = replacement_record(Some(&stored), AvatarSource::Removed, 7);
        assert_eq!(removed.source, AvatarSource::Removed);
        assert!(removed.data.is_empty() && removed.media_type.is_empty());
        assert_eq!(removed.data_uri(), None);
        let uploaded = replacement_record(Some(&stored), AvatarSource::Upload, 7);
        assert_eq!(
            uploaded.data_uri().as_deref(),
            Some("data:image/jpeg;base64,AQID")
        );
    }
}
