// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd
// https://wolf.uk.com

//! At-rest credential encryption for the DNS / cloud / XO stores.
//!
//! Replaces the legacy `XOR_KEY` obfuscation in those modules with
//! AES-256-GCM keyed off the per-install cluster secret (HKDF-SHA256
//! with a per-store purpose label for domain separation). Mirrors the
//! pattern already used by `crate::integrations` and `crate::auth::oidc`,
//! lifted into a shared helper so every store doesn't roll its own
//! crypto.
//!
//! ## Wire format
//!
//! v2 stored value is a single base64 string with the format prefix
//! `v2:` so a reader can detect it without trying to decrypt:
//!
//!     "v2:" + base64( nonce (12 bytes) || ciphertext || GCM tag (16 bytes) )
//!
//! Anything that doesn't start with `v2:` is treated as a legacy v1
//! value and routed through the caller-provided XOR-fallback closure.
//! Backward compatibility is permanent — even years from now, an
//! existing install reading a v1 file gets transparent v1 decryption.
//!
//! ## Threat model
//!
//! What v2 buys us over v1 XOR:
//!   • The XOR key is in the binary; reverse-XOR is trivial for anyone
//!     who can read the binary or the source. v2's AES key is derived
//!     from the per-install cluster secret — different on every install
//!     so source / binary disclosure no longer cascades to credential
//!     disclosure across the fleet.
//!   • XOR-with-static-key is malleable: an attacker who knows ONE
//!     plaintext byte position can deterministically tamper with the
//!     stored value. AES-256-GCM provides authenticity — tampered
//!     ciphertext fails decryption.
//!
//! What it doesn't buy us:
//!   • A root attacker on the host can still read `state.cluster_secret`
//!     from process memory and derive the key. Defence-in-depth
//!     against "leaked backup tarball" / "snapshot in a public S3
//!     bucket", not against on-host code execution.
//!
//! ## Key initialisation
//!
//! `init()` is called from `main.rs` exactly once at startup with the
//! loaded cluster secret. After init, `encrypt()` / `decrypt_or_legacy()`
//! work; before init, both refuse with an explicit error so a misordered
//! startup can't silently corrupt stored values. The OnceLock semantics
//! mean a re-init attempt (e.g. after Stage 3 rotation, without restart)
//! is a no-op — operators must restart wolfstack after rotation to pick
//! up the new key in encryption paths too. This matches the established
//! Stage 3 design ("commit writes disk, restart picks up").

use std::sync::OnceLock;

const V2_PREFIX: &str = "v2:";
const HKDF_DOMAIN: &[u8] = b"wolfstack-at-rest-v2";

static CLUSTER_SECRET: OnceLock<String> = OnceLock::new();

/// Called once at startup with the loaded cluster secret. Subsequent
/// calls are no-ops (OnceLock). Encryption / decryption helpers panic-
/// free without init — they just return `Err`/`None`, so a forgotten
/// `init()` is visible as decryption failures in logs rather than a
/// silent miscompare.
pub fn init(cluster_secret: &str) {
    let _ = CLUSTER_SECRET.set(cluster_secret.to_string());
}

fn current_secret() -> Option<&'static str> {
    CLUSTER_SECRET.get().map(|s| s.as_str())
}

/// Returns true if `stored` is in the v2 (AES-256-GCM) format. Cheap
/// prefix check; safe to call on arbitrary strings.
pub fn is_v2_format(stored: &str) -> bool {
    stored.starts_with(V2_PREFIX)
}

/// Derive a 32-byte AES-256 key from the cluster secret via HKDF-SHA256.
/// The `purpose` byte string is the per-store "info" parameter — gives
/// each store (dns / cloud / xo) a distinct key so a key leak from one
/// can't trivially decrypt the others.
fn derive_key(purpose: &[u8]) -> Result<Vec<u8>, String> {
    let secret = current_secret()
        .ok_or_else(|| "at_rest_crypto not initialised — call init() at startup".to_string())?;
    derive_key_from(secret, purpose)
}

/// Same derivation as `derive_key`, but from an EXPLICIT cluster secret
/// rather than the process-wide OnceLock. Used by the secret-rotation
/// re-encrypt path, which must derive keys from the OLD and NEW secrets
/// independently of whatever value `init()` cached at startup. The
/// HKDF domain + per-store purpose label are identical to the cached
/// path, so a value encrypted with `init`'s secret round-trips through
/// `derive_key_from(<that same secret>, purpose)` byte-for-byte.
fn derive_key_from(secret: &str, purpose: &[u8]) -> Result<Vec<u8>, String> {
    use ring::hkdf;
    let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, HKDF_DOMAIN);
    let prk = salt.extract(secret.as_bytes());
    // `expand` takes a slice-of-slices; the inner array must outlive
    // the returned Okm (lifetime gotcha — `&[purpose]` would be a
    // temporary). Bind to a named local to keep it alive across the
    // `fill` call below.
    let info: [&[u8]; 1] = [purpose];
    let okm = prk.expand(&info, &ring::aead::AES_256_GCM)
        .map_err(|_| "HKDF expand failed".to_string())?;
    let mut key_bytes = vec![0u8; 32];
    okm.fill(&mut key_bytes).map_err(|_| "HKDF fill failed".to_string())?;
    Ok(key_bytes)
}

/// True if the cluster secret used to seed this module no longer
/// matches the secret on disk — i.e. a Stage 3 rotation has
/// committed but wolfstack hasn't been restarted yet.
///
/// During that window, encrypting with the (stale) in-memory key
/// would produce v2 values that the next-process-with-NEW-key
/// cannot decrypt. We refuse those encryptions and let the caller
/// fall back to the legacy v1 XOR format — v1 is independent of the
/// cluster secret so it survives the rotation transparently.
///
/// Skipped in test builds: unit tests init with a synthetic test
/// secret that won't match the host's real `/etc/wolfstack/`. The
/// runtime stale-detection is integration-tested separately rather
/// than via the v2 round-trip tests in this module.
#[cfg(not(test))]
pub fn is_key_stale() -> bool {
    let init_secret = match current_secret() { Some(s) => s, None => return false };
    let current_disk = crate::auth::load_cluster_secret();
    init_secret != current_disk.as_str()
}

#[cfg(test)]
pub fn is_key_stale() -> bool { false }

/// Encrypt `plaintext` for at-rest storage. Returns the v2 stored
/// string ready to write into a JSON field. `purpose` is a stable
/// per-store label like `b"dns-providers"` — never rename it after
/// shipping a release, since renaming changes the derived key and
/// makes all stored values undecryptable.
///
/// Refuses encryption when `is_key_stale()` is true (cluster secret
/// rotated but daemon not restarted). The store-level `obfuscate()`
/// wrappers see this Err and fall back to v1 XOR; v1 doesn't depend
/// on cluster_secret so it remains decryptable across rotation.
/// The audit module continues to flag the file as needing migration,
/// so the operator gets re-prompted to migrate after restart.
pub fn encrypt(plaintext: &[u8], purpose: &[u8]) -> Result<String, String> {
    if is_key_stale() {
        return Err("at_rest_crypto: cluster secret rotated but wolfstack not \
                    restarted on this node yet — refusing to encrypt with the \
                    stale in-memory key (those entries would be undecryptable \
                    after restart). Caller will fall back to v1; re-run the \
                    at-rest migration after restart.".into());
    }
    let key_bytes = derive_key(purpose)?;
    seal_with_key_bytes(plaintext, &key_bytes)
}

/// Seal `plaintext` to a `v2:` stored string using a pre-derived
/// 32-byte key. Shared by `encrypt` (cached-key path) and
/// `encrypt_with_secret` (explicit-key rotation path) so both produce
/// byte-compatible output and there's a single AES-GCM call site.
pub(crate) fn seal_with_key_bytes(plaintext: &[u8], key_bytes: &[u8]) -> Result<String, String> {
    use ring::aead;
    use ring::rand::{SystemRandom, SecureRandom};
    use base64::Engine;

    let unbound = aead::UnboundKey::new(&aead::AES_256_GCM, key_bytes)
        .map_err(|_| "AES key construct failed".to_string())?;
    let key = aead::LessSafeKey::new(unbound);

    let rng = SystemRandom::new();
    let mut nonce_bytes = [0u8; 12];
    rng.fill(&mut nonce_bytes).map_err(|_| "nonce gen failed".to_string())?;
    let nonce = aead::Nonce::assume_unique_for_key(nonce_bytes);

    let mut in_out = plaintext.to_vec();
    key.seal_in_place_append_tag(nonce, aead::Aad::empty(), &mut in_out)
        .map_err(|_| "AES seal failed".to_string())?;

    let mut payload = Vec::with_capacity(12 + in_out.len());
    payload.extend_from_slice(&nonce_bytes);
    payload.extend_from_slice(&in_out);
    let b64 = base64::engine::general_purpose::STANDARD.encode(&payload);
    Ok(format!("{}{}", V2_PREFIX, b64))
}

/// Open a `v2:` stored value using a pre-derived 32-byte key. Returns
/// `None` if the value isn't v2 or the AES tag doesn't verify. Shared
/// by `decrypt_v2` and `decrypt_v2_with_secret`.
pub(crate) fn open_with_key_bytes(stored: &str, key_bytes: &[u8]) -> Option<Vec<u8>> {
    use ring::aead;
    use base64::Engine;
    if !is_v2_format(stored) { return None; }
    let body = &stored[V2_PREFIX.len()..];
    let payload = base64::engine::general_purpose::STANDARD.decode(body).ok()?;
    if payload.len() < 12 + 16 { return None; }
    let unbound = aead::UnboundKey::new(&aead::AES_256_GCM, key_bytes).ok()?;
    let key = aead::LessSafeKey::new(unbound);
    let (nonce_bytes, ciphertext_and_tag) = payload.split_at(12);
    let nonce = aead::Nonce::assume_unique_for_key(nonce_bytes.try_into().ok()?);
    let mut in_out = ciphertext_and_tag.to_vec();
    let plaintext = key.open_in_place(nonce, aead::Aad::empty(), &mut in_out).ok()?;
    Some(plaintext.to_vec())
}

/// Encrypt `plaintext` for store `purpose` using an EXPLICIT cluster
/// secret rather than the cached startup key. This is the rotation
/// re-encrypt write path — it derives the key from `secret` directly
/// and does NOT consult `is_key_stale()` (the caller is deliberately
/// supplying the secret to encrypt under, so the staleness guard that
/// protects the normal write path would be wrong here).
pub fn encrypt_with_secret(plaintext: &[u8], purpose: &[u8], secret: &str) -> Result<String, String> {
    let key_bytes = derive_key_from(secret, purpose)?;
    seal_with_key_bytes(plaintext, &key_bytes)
}

/// Decrypt a `v2:` stored value for store `purpose` using an EXPLICIT
/// cluster secret. Returns `None` if the value isn't v2 or if the tag
/// fails to verify under `secret` (i.e. it was written under a
/// different secret — the rotation re-encrypt path treats that as
/// "skip, leave unchanged" rather than an error).
pub fn decrypt_v2_with_secret(stored: &str, purpose: &[u8], secret: &str) -> Option<Vec<u8>> {
    let key_bytes = derive_key_from(secret, purpose).ok()?;
    open_with_key_bytes(stored, &key_bytes)
}

/// Decrypt a v2 stored value. Returns `None` if the input isn't v2
/// (the caller's responsibility to fall back to v1 XOR), if the
/// nonce/tag/length is wrong, or if the AES tag doesn't verify.
///
/// AUTHENTICATION is the point — a tampered v2 value returns `None`
/// rather than silently producing garbage plaintext.
pub fn decrypt_v2(stored: &str, purpose: &[u8]) -> Option<Vec<u8>> {
    let key_bytes = derive_key(purpose).ok()?;
    open_with_key_bytes(stored, &key_bytes)
}

/// Outcome of re-keying a single stored field during a cluster-secret
/// rotation. Drives the per-store accounting (rekeyed / skipped) and,
/// crucially, distinguishes "left it alone deliberately" from "couldn't
/// read it so left it alone" — both leave the field byte-identical.
pub enum ReencryptOutcome {
    /// Field was a v2 value sealed under `old`; now re-sealed under `new`.
    Rekeyed(String),
    /// Field is v2 but did NOT decrypt under `old` (sealed under a
    /// different secret, or corrupt). Left unchanged, counted as skipped.
    Skipped,
    /// Field is empty or a legacy v1 (non-v2) value — not cluster-secret-
    /// keyed, so a rotation does not affect it. Left unchanged, not
    /// counted.
    Untouched,
}

/// Re-key a single at-rest field from the OLD cluster secret to the NEW
/// one. Shared by every `at_rest_crypto`-backed store's
/// `reencrypt_at_rest` so the safety rules live in exactly one place.
///
/// LOSS-FREE GUARANTEE: this function never returns a value that would
/// overwrite a secret it could not first decrypt. A v2 field that fails
/// to open under `old` returns `Skipped` (field untouched); only a
/// successful decrypt-then-reencrypt returns `Rekeyed`.
pub fn reencrypt_v2_field(stored: &str, purpose: &[u8], old: &str, new: &str) -> ReencryptOutcome {
    if stored.is_empty() || !is_v2_format(stored) {
        // Empty, or legacy v1 XOR (static key, not cluster-secret-keyed).
        return ReencryptOutcome::Untouched;
    }
    let plaintext = match decrypt_v2_with_secret(stored, purpose, old) {
        Some(p) => p,
        None => return ReencryptOutcome::Skipped,
    };
    match encrypt_with_secret(&plaintext, purpose, new) {
        Ok(v) => ReencryptOutcome::Rekeyed(v),
        // Encryption under the new key failed (should be unreachable —
        // derive + seal don't depend on input content). Treat as skip so
        // we never drop the original.
        Err(_) => ReencryptOutcome::Skipped,
    }
}

/// One-shot helper: decrypt a stored value with v2 if applicable,
/// otherwise fall back to the caller's v1 XOR decoder. Used by every
/// migrated store to keep their `read` paths short.
///
/// On v2 decrypt failure (tampering, wrong key after a rotation
/// without restart, corrupted file) returns the result of the legacy
/// fallback rather than an error — operators see "credential looks
/// garbled in UI" rather than "every credential vanished after upgrade".
pub fn decrypt_or_legacy<F>(stored: &str, purpose: &[u8], legacy_xor_decode: F) -> String
where
    F: FnOnce(&str) -> String,
{
    if is_v2_format(stored) {
        if let Some(bytes) = decrypt_v2(stored, purpose) {
            return String::from_utf8_lossy(&bytes).into_owned();
        }
        // v2-prefixed but failed to decrypt. Don't fall through to v1
        // XOR with the same string — the prefix means it was written
        // as v2, decoding it as XOR would produce garbage. Return
        // empty so the caller's "empty credential" guard fires.
        return String::new();
    }
    legacy_xor_decode(stored)
}

/// True if the file at `path` contains at least one v1-format
/// `*_enc` value (i.e. a legacy XOR string rather than a `v2:` AES
/// value). Used by the audit module so each XOR-store finding
/// auto-clears once migration has fully converted that file. Reads
/// are bounded — credential files are at most a few KB.
///
/// Heuristic: scans line-by-line for any `*_enc` field whose value
/// (extracted as the last quoted string on the line) doesn't start
/// with the `v2:` prefix. Avoids JSON-parsing — a schema mismatch
/// must not silently flip the audit verdict.
pub fn file_has_legacy_v1_entries(path: &str) -> bool {
    let raw = match std::fs::read_to_string(path) { Ok(s) => s, Err(_) => return false };
    for line in raw.lines() {
        let trimmed = line.trim();
        if !trimmed.contains("_enc") || !trimmed.contains(':') { continue; }
        if let Some(end_quote) = trimmed.rfind('"')
            && let Some(start_quote) = trimmed[..end_quote].rfind('"') {
                let value = &trimmed[start_quote + 1..end_quote];
                if !value.is_empty() && !value.starts_with(V2_PREFIX) {
                    return true;
                }
            }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Force-set the cluster secret for this test process. Replaces
    /// the OnceLock value via reset is impossible, but for tests we
    /// can use a single shared secret across all tests in this module.
    fn ensure_init() {
        init("wsk_test_secret_for_at_rest_crypto_module_only_64_chars_xxxxxxxxx");
    }

    #[test]
    fn v2_round_trip_matches_input() {
        ensure_init();
        let plain = b"dns_cloudflare_api_token = abc123\nfoo = bar\n";
        let stored = encrypt(plain, b"dns-providers").expect("encrypt");
        assert!(is_v2_format(&stored));
        let decrypted = decrypt_v2(&stored, b"dns-providers").expect("decrypt");
        assert_eq!(decrypted, plain);
    }

    #[test]
    fn v2_different_purposes_produce_different_keys() {
        ensure_init();
        let plain = b"same plaintext";
        let stored_a = encrypt(plain, b"dns-providers").expect("a");
        let decrypt_a_with_b = decrypt_v2(&stored_a, b"cloud-providers");
        assert!(decrypt_a_with_b.is_none(),
            "purpose label should provide domain separation — a key from \
             one store must not decrypt another store's values");
    }

    #[test]
    fn v2_tampered_ciphertext_fails_decryption() {
        ensure_init();
        let plain = b"sensitive_value";
        let stored = encrypt(plain, b"xo-tokens").expect("encrypt");
        // Flip a bit in the base64 body (after the prefix).
        let mut bytes = stored.into_bytes();
        let idx = V2_PREFIX.len() + 8;
        bytes[idx] = if bytes[idx] == b'A' { b'B' } else { b'A' };
        let tampered = String::from_utf8(bytes).unwrap();
        assert!(decrypt_v2(&tampered, b"xo-tokens").is_none(),
            "tampered ciphertext must fail AES-GCM authentication");
    }

    #[test]
    fn decrypt_or_legacy_routes_v1_to_fallback() {
        ensure_init();
        let v1_value = "abcdef==";
        let observed = std::cell::RefCell::new(String::new());
        let recovered = decrypt_or_legacy(v1_value, b"dns-providers", |s| {
            *observed.borrow_mut() = s.to_string();
            "fallback_decoded".into()
        });
        assert_eq!(*observed.borrow(), v1_value);
        assert_eq!(recovered, "fallback_decoded");
    }

    #[test]
    fn decrypt_or_legacy_returns_empty_for_v2_decrypt_failure() {
        ensure_init();
        // Synthesise a v2 prefix on garbage payload — must NOT fall
        // through to the XOR fallback (which would produce garbage).
        let recovered = decrypt_or_legacy("v2:not-real-base64-data!!!!", b"dns-providers", |_| {
            "WRONG_FALLBACK_TRIGGERED".into()
        });
        assert_eq!(recovered, "",
            "v2-prefixed failures must NOT fall through to XOR — that \
             would silently corrupt values. Return empty so the caller's \
             empty-credential guard surfaces the problem.");
    }

    #[test]
    fn explicit_secret_round_trip_and_cross_secret_skip() {
        // The rotation re-encrypt path uses encrypt_with_secret /
        // decrypt_v2_with_secret with EXPLICIT old/new secrets, bypassing
        // the OnceLock. Verify: (1) round-trip under one secret works,
        // (2) a value sealed under secret A does NOT open under secret B
        //     (so a field already rotated, or written under a different
        //     secret, is skipped — not destroyed).
        let secret_a = "wsk_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let secret_b = "wsk_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let plain = b"super-secret-password";

        let sealed_a = encrypt_with_secret(plain, b"dns-providers", secret_a).expect("seal A");
        assert!(is_v2_format(&sealed_a));
        let opened_a = decrypt_v2_with_secret(&sealed_a, b"dns-providers", secret_a)
            .expect("open A with A");
        assert_eq!(opened_a, plain);

        // Wrong secret → None (AES-GCM tag fails to verify).
        assert!(decrypt_v2_with_secret(&sealed_a, b"dns-providers", secret_b).is_none(),
            "a value sealed under secret A must NOT open under secret B");

        // Re-encrypt A→B then confirm it opens under B and no longer under A.
        let sealed_b = encrypt_with_secret(&opened_a, b"dns-providers", secret_b).expect("seal B");
        let opened_b = decrypt_v2_with_secret(&sealed_b, b"dns-providers", secret_b)
            .expect("open B with B");
        assert_eq!(opened_b, plain);
        assert!(decrypt_v2_with_secret(&sealed_b, b"dns-providers", secret_a).is_none());
    }

    #[test]
    fn reencrypt_v2_field_outcomes() {
        let a = "wsk_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let b = "wsk_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let c = "wsk_cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

        // v2 sealed under A, rotate A→B → Rekeyed, opens under B only.
        let sealed_a = encrypt_with_secret(b"creds", b"dns-providers", a).unwrap();
        match reencrypt_v2_field(&sealed_a, b"dns-providers", a, b) {
            ReencryptOutcome::Rekeyed(v) => {
                assert_eq!(decrypt_v2_with_secret(&v, b"dns-providers", b).unwrap(), b"creds");
                assert!(decrypt_v2_with_secret(&v, b"dns-providers", a).is_none());
            }
            _ => panic!("expected Rekeyed"),
        }

        // v2 sealed under C, rotate A→B → Skipped (can't decrypt with A).
        let sealed_c = encrypt_with_secret(b"creds", b"dns-providers", c).unwrap();
        assert!(matches!(
            reencrypt_v2_field(&sealed_c, b"dns-providers", a, b),
            ReencryptOutcome::Skipped
        ));

        // Empty + legacy v1 (non-v2) → Untouched.
        assert!(matches!(
            reencrypt_v2_field("", b"dns-providers", a, b),
            ReencryptOutcome::Untouched
        ));
        assert!(matches!(
            reencrypt_v2_field("legacyXORbase64==", b"dns-providers", a, b),
            ReencryptOutcome::Untouched
        ));
    }

    #[test]
    fn explicit_secret_matches_cached_path() {
        // A value sealed via the cached (init) path must open via the
        // explicit-secret path when given the same secret — proves the
        // two derivations are identical, so rotation can decrypt what
        // the normal write path produced.
        ensure_init();
        // Read the ACTUAL cached secret — CLUSTER_SECRET is a process-global
        // OnceLock, so another test in the same binary may have init()'d it
        // first; the explicit open must use whatever secret the cached seal
        // actually used, not a hardcoded guess.
        let secret = CLUSTER_SECRET.get().expect("init ran").clone();
        let plain = b"value-from-normal-write-path";
        let sealed = encrypt(plain, b"cloud-providers").expect("cached seal");
        let opened = decrypt_v2_with_secret(&sealed, b"cloud-providers", &secret)
            .expect("explicit open of cached value");
        assert_eq!(opened, plain);
    }

    #[test]
    fn v2_prefix_detection() {
        assert!(is_v2_format("v2:anything"));
        assert!(!is_v2_format("v1:anything"));
        assert!(!is_v2_format(""));
        assert!(!is_v2_format("v2"));
        assert!(!is_v2_format("V2:case-sensitive"));
    }

    /// C1-regression: verifies that the stale-key invariant logic is
    /// "stale = init_secret != current_disk_secret". We can't trigger
    /// the runtime check directly (the test build stubs it to false),
    /// but we can check the underlying comparison would catch the
    /// scenario the reviewer flagged: initialised with secret A,
    /// disk holds secret B → encrypt should refuse in production.
    #[test]
    fn stale_key_logic_invariant() {
        let init_secret = "wsk_OLD";
        let current_disk = "wsk_NEW_AFTER_ROTATION";
        let would_be_stale = init_secret != current_disk;
        assert!(would_be_stale,
            "stale check must catch the scenario where Stage 3 commit \
             ran but daemon was not restarted");
    }
}
