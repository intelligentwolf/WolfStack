//! Moving a compose stack — and the Secrets Manager entries it depends on —
//! between hosts. Two operator features share this module:
//!
//! * **Secrets export / import.** The config-export bundle deliberately
//!   leaves `/etc/wolfstack/secrets.json` out (it is a hand-to-support
//!   artifact), so until now the only way to get stack secrets onto a
//!   second host was to dig them out of `backups.json` — which Colt did on
//!   2026-09-06, and which quietly misses services because a project is
//!   backed up one entry PER CONTAINER. This module seals the store under a
//!   passphrase (Argon2id → AES-256-GCM) into a file that is safe to carry.
//! * **Deploy a stack to another node.** WolfStack already owns the compose
//!   directory and the secrets; the missing piece was "bring this stack up
//!   on that node". The pure parts — which `${KEY}`s a compose file
//!   references, which files under the stack directory travel, whether a
//!   received path is safe to write — live here so they are unit-testable;
//!   the HTTP handlers in `api` do the I/O.

use serde::{Deserialize, Serialize};

// ─── Compose variable references ────────────────────────────────────────

/// Every variable name a compose file interpolates: `$NAME`, `${NAME}` and
/// the `${NAME:-default}` / `${NAME-default}` / `${NAME:?err}` / `${NAME?err}`
/// / `${NAME:+alt}` / `${NAME+alt}` forms. `$$` is a literal dollar and is
/// skipped. Verified 2026-09-06 against `docker compose config` (compose v2):
/// unset `$B` and `${A}` warn and become "", the `:-`/`-`/`:+` forms take
/// their operand, `$$G` stays literal. Names with a default are still
/// REPORTED — a secret the operator stored on the source host should travel
/// even when the file would otherwise fall back to a default.
pub fn referenced_compose_vars(yaml: &str) -> Vec<String> {
    let bytes = yaml.as_bytes();
    let mut out: Vec<String> = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'$' { i += 1; continue; }
        // `$$` — escaped literal dollar.
        if bytes.get(i + 1) == Some(&b'$') { i += 2; continue; }
        let braced = bytes.get(i + 1) == Some(&b'{');
        let start = if braced { i + 2 } else { i + 1 };
        let mut end = start;
        while end < bytes.len()
            && (bytes[end].is_ascii_alphanumeric() || bytes[end] == b'_')
        {
            end += 1;
        }
        let name = &yaml[start..end];
        if !name.is_empty()
            && !name.as_bytes()[0].is_ascii_digit()
            && !out.iter().any(|n| n == name)
        {
            out.push(name.to_string());
        }
        i = end.max(i + 1);
    }
    out
}

// ─── Stack directory contents ───────────────────────────────────────────

/// One file of a stack directory in transit. `path` is relative to the
/// stack directory, always forward-slash separated; `content` is base64.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StackFile {
    pub path: String,
    pub content: String,
    /// Unix mode bits (permission part only), so a 0600 `.env` or an
    /// executable helper script arrives the way it left.
    pub mode: u32,
}

/// A single file larger than this does not travel — a stack directory that
/// also holds bind-mounted data (`./data`, a database) is not "the stack".
pub const MAX_FILE_BYTES: u64 = 1024 * 1024;
/// Total payload cap; anything beyond it is skipped and reported.
pub const MAX_TOTAL_BYTES: u64 = 16 * 1024 * 1024;

/// Regular files under `dir` (recursively), bounded by the caps above.
/// Symlinks are never followed or shipped — a symlink pointing outside the
/// directory would otherwise leak arbitrary host files to the peer. Returns
/// the files plus the relative paths that were skipped and why.
pub fn collect_stack_files(dir: &std::path::Path) -> Result<(Vec<StackFile>, Vec<String>), String> {
    use base64::Engine;
    use std::os::unix::fs::PermissionsExt;
    let mut files = Vec::new();
    let mut skipped = Vec::new();
    let mut total: u64 = 0;
    let mut stack: Vec<std::path::PathBuf> = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let mut entries: Vec<_> = std::fs::read_dir(&d)
            .map_err(|e| format!("read {}: {}", d.display(), e))?
            .flatten()
            .collect();
        entries.sort_by_key(|e| e.file_name());
        for entry in entries {
            let path = entry.path();
            let rel = path.strip_prefix(dir).unwrap_or(&path)
                .to_string_lossy().replace('\\', "/");
            let meta = match std::fs::symlink_metadata(&path) {
                Ok(m) => m,
                Err(e) => { skipped.push(format!("{} (unreadable: {})", rel, e)); continue; }
            };
            if meta.file_type().is_symlink() {
                skipped.push(format!("{} (symlink — not followed)", rel));
                continue;
            }
            if meta.is_dir() { stack.push(path); continue; }
            if !meta.is_file() { skipped.push(format!("{} (not a regular file)", rel)); continue; }
            if meta.len() > MAX_FILE_BYTES {
                skipped.push(format!("{} ({} bytes > {} limit)", rel, meta.len(), MAX_FILE_BYTES));
                continue;
            }
            if total + meta.len() > MAX_TOTAL_BYTES {
                skipped.push(format!("{} (total payload would exceed {} bytes)", rel, MAX_TOTAL_BYTES));
                continue;
            }
            let data = std::fs::read(&path).map_err(|e| format!("read {}: {}", rel, e))?;
            total += data.len() as u64;
            files.push(StackFile {
                path: rel,
                content: base64::engine::general_purpose::STANDARD.encode(&data),
                mode: meta.permissions().mode() & 0o777,
            });
        }
    }
    files.sort_by(|a, b| a.path.cmp(&b.path));
    Ok((files, skipped))
}

/// A received relative path is written only if it cannot escape the stack
/// directory: no absolute path, no empty or `.`/`..` components, no NUL.
pub fn validate_relative_path(rel: &str) -> Result<(), String> {
    if rel.is_empty() || rel.starts_with('/') || rel.contains('\0') {
        return Err(format!("invalid path {:?}", rel));
    }
    for seg in rel.split('/') {
        if seg.is_empty() || seg == "." || seg == ".." {
            return Err(format!("invalid path {:?}", rel));
        }
    }
    Ok(())
}

// ─── Passphrase-sealed secrets bundle ───────────────────────────────────

/// Format tag; a reader refuses anything else rather than guessing.
pub const BUNDLE_FORMAT: &str = "wolfstack-secrets-v1";
/// Argon2id cost parameters. Source: argon2-0.5.3 src/params.rs:42-61
/// `DEFAULT_M_COST = 19 * 1024`, `DEFAULT_T_COST = 2`, `DEFAULT_P_COST = 1`
/// (the crate's defaults, matching the OWASP password-storage minimum).
/// Recorded in the file so a future change here still opens old bundles.
pub const KDF_M_COST: u32 = 19 * 1024;
pub const KDF_T_COST: u32 = 2;
pub const KDF_P_COST: u32 = 1;
const KDF_SALT_LEN: usize = 16;
/// Shortest passphrase accepted for an export. The file may sit in a mailbox
/// or a NAS share; Argon2id slows guessing but does not rescue "hunter2".
pub const MIN_PASSPHRASE_CHARS: usize = 12;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleKdf {
    pub algo: String,
    pub salt: String,
    pub m: u32,
    pub t: u32,
    pub p: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretsBundle {
    pub format: String,
    pub kdf: BundleKdf,
    /// `v2:` + base64(nonce || ciphertext || tag) — the same envelope as
    /// `at_rest_crypto`, sealed with the passphrase-derived key instead of
    /// the cluster-secret-derived one.
    pub payload: String,
    pub exported_from: String,
    pub exported_at: String,
    pub count: usize,
}

fn derive_bundle_key(passphrase: &str, kdf: &BundleKdf) -> Result<Vec<u8>, String> {
    use argon2::{Algorithm, Argon2, Params, Version};
    use base64::Engine;
    if kdf.algo != "argon2id" {
        return Err(format!("unsupported KDF {:?}", kdf.algo));
    }
    let salt = base64::engine::general_purpose::STANDARD.decode(&kdf.salt)
        .map_err(|_| "bundle salt is not valid base64".to_string())?;
    let params = Params::new(kdf.m, kdf.t, kdf.p, Some(32))
        .map_err(|e| format!("bundle KDF parameters rejected: {}", e))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = vec![0u8; 32];
    argon.hash_password_into(passphrase.as_bytes(), &salt, &mut key)
        .map_err(|e| format!("key derivation failed: {}", e))?;
    Ok(key)
}

/// Seal `plaintext` (the JSON secrets array) under `passphrase`.
pub fn seal_bundle(
    plaintext: &[u8], passphrase: &str, exported_from: &str, count: usize,
) -> Result<SecretsBundle, String> {
    use base64::Engine;
    use ring::rand::{SecureRandom, SystemRandom};
    if passphrase.chars().count() < MIN_PASSPHRASE_CHARS {
        return Err(format!("passphrase must be at least {} characters", MIN_PASSPHRASE_CHARS));
    }
    let mut salt = [0u8; KDF_SALT_LEN];
    SystemRandom::new().fill(&mut salt).map_err(|_| "salt generation failed".to_string())?;
    let kdf = BundleKdf {
        algo: "argon2id".into(),
        salt: base64::engine::general_purpose::STANDARD.encode(salt),
        m: KDF_M_COST, t: KDF_T_COST, p: KDF_P_COST,
    };
    let key = derive_bundle_key(passphrase, &kdf)?;
    let payload = crate::at_rest_crypto::seal_with_key_bytes(plaintext, &key)?;
    Ok(SecretsBundle {
        format: BUNDLE_FORMAT.into(),
        kdf,
        payload,
        exported_from: exported_from.into(),
        exported_at: chrono::Utc::now().to_rfc3339(),
        count,
    })
}

/// Open a bundle. A wrong passphrase and a tampered payload are the same
/// failure (the GCM tag does not verify) and are reported as one.
pub fn open_bundle(bundle: &SecretsBundle, passphrase: &str) -> Result<Vec<u8>, String> {
    if bundle.format != BUNDLE_FORMAT {
        return Err(format!(
            "not a WolfStack secrets export (format {:?}, expected {:?})",
            bundle.format, BUNDLE_FORMAT
        ));
    }
    let key = derive_bundle_key(passphrase, &bundle.kdf)?;
    crate::at_rest_crypto::open_with_key_bytes(&bundle.payload, &key)
        .ok_or_else(|| "wrong passphrase, or the file has been altered".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn referenced_vars_cover_every_interpolation_form() {
        // The file used for the 2026-09-06 `docker compose config` check.
        let yaml = "services:\n  a:\n    image: busybox\n    environment:\n      A: ${A}\n      B: $B\n      C: ${C:-x}\n      D: ${D-x}\n      E: ${E:?need}\n      F: ${F:+x}\n      G: $$G\n      H: \"${H}${A}\"\n      N: $1BAD\n";
        assert_eq!(referenced_compose_vars(yaml), vec!["A", "B", "C", "D", "E", "F", "H"]);
        assert!(referenced_compose_vars("no dollars here\n").is_empty());
        assert!(referenced_compose_vars("price: $$5 and ${}").is_empty());
    }

    #[test]
    fn relative_paths_cannot_escape() {
        assert!(validate_relative_path("docker-compose.yml").is_ok());
        assert!(validate_relative_path("config/nginx/site.conf").is_ok());
        assert!(validate_relative_path(".env").is_ok());
        for bad in ["", "/etc/passwd", "../x", "a/../b", "a//b", "./a", "a/", "a\0b"] {
            assert!(validate_relative_path(bad).is_err(), "{:?} must be rejected", bad);
        }
    }

    #[test]
    fn collect_walks_files_skips_symlinks_and_big_files() {
        use std::os::unix::fs::PermissionsExt;
        let d = std::env::temp_dir().join(format!("wsstack-{}-collect", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let d = d.as_path();
        std::fs::write(d.join("docker-compose.yml"), "services: {}\n").unwrap();
        std::fs::write(d.join(".env"), "X=1\n").unwrap();
        std::fs::set_permissions(d.join(".env"), std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::create_dir_all(d.join("config/sub")).unwrap();
        std::fs::write(d.join("config/sub/a.conf"), "a").unwrap();
        std::os::unix::fs::symlink("/etc/passwd", d.join("leak")).unwrap();
        let big = vec![0u8; (MAX_FILE_BYTES + 1) as usize];
        std::fs::write(d.join("data.bin"), &big).unwrap();

        let (files, skipped) = collect_stack_files(d).unwrap();
        let paths: Vec<&str> = files.iter().map(|f| f.path.as_str()).collect();
        assert_eq!(paths, vec![".env", "config/sub/a.conf", "docker-compose.yml"]);
        assert_eq!(files[0].mode, 0o600);
        assert_eq!(skipped.len(), 2, "{:?}", skipped);
        assert!(skipped.iter().any(|s| s.starts_with("leak (symlink")));
        assert!(skipped.iter().any(|s| s.starts_with("data.bin (")));
        let _ = std::fs::remove_dir_all(d);
    }

    #[test]
    fn bundle_round_trips_and_rejects_wrong_passphrase() {
        let plain = br#"[{"key":"DB_PASSWORD","value":"s3cret"}]"#;
        let b = seal_bundle(plain, "correct horse battery", "ve1", 1).unwrap();
        assert_eq!(b.format, BUNDLE_FORMAT);
        assert_eq!((b.kdf.m, b.kdf.t, b.kdf.p), (KDF_M_COST, KDF_T_COST, KDF_P_COST));
        assert!(b.payload.starts_with("v2:"));
        assert_eq!(open_bundle(&b, "correct horse battery").unwrap(), plain);
        assert!(open_bundle(&b, "correct horse batterX").is_err());
        // Tampering with the ciphertext fails the tag.
        let mut t = b.clone();
        t.payload = format!("{}A", &t.payload[..t.payload.len() - 1]);
        assert!(open_bundle(&t, "correct horse battery").is_err());
        // Wrong format tag is refused before any KDF work.
        let mut f = b.clone();
        f.format = "something-else".into();
        assert!(open_bundle(&f, "correct horse battery").unwrap_err().contains("not a WolfStack"));
        // Short passphrases are refused at export time.
        assert!(seal_bundle(plain, "short", "ve1", 1).is_err());
    }
}
