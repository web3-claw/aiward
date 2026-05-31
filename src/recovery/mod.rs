use std::path::PathBuf;

use anyhow::{Context, Result};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{fs_util, logs, vault};

const RECOVERY_MEMORY_COST: u32 = 262_144; // 256 MiB — ~2s per attempt
const RECOVERY_TIME_COST: u32 = 8;

#[derive(Serialize, Deserialize)]
struct RecoveryBlob {
    version: u32,
    project: String,
    passphrase: String,
}

/// Creates the real recovery file and 39-59 same-size decoys in ~/.ward/recovery/.
/// Returns the path to the real recovery file.
pub fn create_recovery_files(project: &str, passphrase: &str, pin: &str) -> Result<PathBuf> {
    let dir = logs::recovery_dir();
    fs_util::ensure_private_dir(&dir)?;

    let blob = RecoveryBlob {
        version: 1,
        project: project.to_string(),
        passphrase: passphrase.to_string(),
    };
    let plaintext = serde_json::to_string(&blob)?;
    let envelope = vault::encrypt_env_with_params(&plaintext, pin, RECOVERY_MEMORY_COST, RECOVERY_TIME_COST)?;
    let real_bytes = serde_json::to_vec_pretty(&envelope)?;

    let real_filename = derive_recovery_filename(passphrase, project);
    let real_path = dir.join(&real_filename);
    fs_util::write_private_file(&real_path, &real_bytes)?;

    // Generate 39-59 decoys of identical serialized size
    let decoy_count = (OsRng.next_u32() % 21 + 39) as usize;
    for _ in 0..decoy_count {
        let mut key = [0u8; 32];
        let mut random_plain = vec![0u8; real_bytes.len()];
        OsRng.fill_bytes(&mut key);
        OsRng.fill_bytes(&mut random_plain);
        let decoy_envelope = vault::encrypt_raw_bytes(&random_plain, &key)?;
        let mut decoy_bytes = serde_json::to_vec_pretty(&decoy_envelope)?;
        // Pad or trim to exactly real_bytes.len() so all files are identical size
        decoy_bytes.resize(real_bytes.len(), b' ');
        fs_util::write_private_file(&dir.join(generate_decoy_filename()), &decoy_bytes)?;
    }

    Ok(real_path)
}

/// Restores the vault passphrase from a recovery file using the PIN.
/// If passphrase is known it derives the filename directly; otherwise tries all .key files.
pub fn restore_from_recovery(
    project: &str,
    known_passphrase: Option<&str>,
    pin: &str,
) -> Result<String> {
    let dir = logs::recovery_dir();

    if let Some(passphrase) = known_passphrase {
        let filename = derive_recovery_filename(passphrase, project);
        let path = dir.join(filename);
        return decrypt_recovery_file(&path, pin);
    }

    // Try all .key files — only the real one will decrypt successfully with the correct PIN
    let entries = std::fs::read_dir(&dir)
        .context(format!("failed to read recovery directory {}", dir.display()))?;

    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) == Some("key") {
            if let Ok(passphrase) = decrypt_recovery_file(&path, pin) {
                // Verify the recovered blob belongs to this project
                let blob: RecoveryBlob = serde_json::from_str(&passphrase)
                    .map_err(|_| anyhow::anyhow!("invalid recovery blob"))?;
                if blob.project == project {
                    return Ok(blob.passphrase);
                }
            }
        }
    }

    anyhow::bail!(
        "no valid recovery file found in {} for project '{}'",
        dir.display(),
        project
    )
}

/// Imports a recovery file backup from an external path into ~/.ward/recovery/.
pub fn import_recovery_file(source: &std::path::Path) -> Result<PathBuf> {
    let dir = logs::recovery_dir();
    fs_util::ensure_private_dir(&dir)?;

    let filename = source
        .file_name()
        .context("source path has no filename")?
        .to_string_lossy()
        .into_owned();

    let dest = dir.join(&filename);
    let contents = std::fs::read(source)
        .context(format!("failed to read {}", source.display()))?;
    fs_util::write_private_file(&dest, &contents)?;
    Ok(dest)
}

/// Exports the real recovery file to a destination path.
pub fn export_recovery_file(
    project: &str,
    passphrase: &str,
    dest: &std::path::Path,
) -> Result<PathBuf> {
    let dir = logs::recovery_dir();
    let filename = derive_recovery_filename(passphrase, project);
    let source = dir.join(&filename);

    anyhow::ensure!(
        source.exists(),
        "recovery file not found at {} — run ward setup to create one",
        source.display()
    );

    let contents = std::fs::read(&source)
        .context(format!("failed to read {}", source.display()))?;

    let out_path = if dest.is_dir() {
        dest.join(&filename)
    } else {
        dest.to_path_buf()
    };

    std::fs::write(&out_path, contents)
        .context(format!("failed to write {}", out_path.display()))?;
    Ok(out_path)
}

/// Returns true if the real recovery file exists for this project.
pub fn recovery_file_exists(project: &str, passphrase: &str) -> bool {
    let dir = logs::recovery_dir();
    dir.join(derive_recovery_filename(passphrase, project)).exists()
}

fn decrypt_recovery_file(path: &std::path::Path, pin: &str) -> Result<String> {
    let contents = std::fs::read_to_string(path)
        .context(format!("failed to read {}", path.display()))?;
    let envelope: vault::VaultEnvelope = serde_json::from_str(&contents)
        .context(format!("failed to parse {}", path.display()))?;
    vault::decrypt_env(&envelope, pin)
}

fn derive_recovery_filename(passphrase: &str, project: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"ward-recovery\x00");
    hasher.update(passphrase.as_bytes());
    hasher.update(b"\x00");
    hasher.update(project.as_bytes());
    let hash = hasher.finalize();
    format!("{}.key", hex::encode(&hash[..6]))
}

fn generate_decoy_filename() -> String {
    let mut bytes = [0u8; 6];
    OsRng.fill_bytes(&mut bytes);
    format!("{}.key", hex::encode(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, OnceLock};

    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(())).lock().unwrap()
    }

    #[test]
    #[serial_test::serial]
    fn derive_recovery_filename_is_deterministic_and_distinct() {
        let f1 = derive_recovery_filename("passphrase", "project");
        let f2 = derive_recovery_filename("passphrase", "project");
        let f3 = derive_recovery_filename("other", "project");

        assert_eq!(f1, f2);
        assert_ne!(f1, f3);
        assert!(f1.ends_with(".key"));
    }

    #[test]
    #[serial_test::serial]
    fn create_and_restore_recovery_files() {
        let _guard = env_lock();
        let tmpdir = tempfile::tempdir().unwrap();
        std::env::set_var("WARD_HOME", tmpdir.path());

        create_recovery_files("myproject", "vault-passphrase", "1234").unwrap();

        let dir = logs::recovery_dir();
        let key_files: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .filter(|e| e.path().extension().and_then(|x| x.to_str()) == Some("key"))
            .collect();

        // At least 40 files (real + minimum 39 decoys)
        assert!(key_files.len() >= 40, "expected >= 40 .key files, got {}", key_files.len());

        // All .key files have identical size
        let sizes: std::collections::HashSet<u64> = key_files
            .iter()
            .map(|e| e.metadata().unwrap().len())
            .collect();
        assert_eq!(sizes.len(), 1, "all .key files should be same size");

        let recovered = restore_from_recovery("myproject", None, "1234").unwrap();
        assert_eq!(recovered, "vault-passphrase");

        std::env::remove_var("WARD_HOME");
    }

    #[test]
    #[serial_test::serial]
    fn restore_with_wrong_pin_fails() {
        let _guard = env_lock();
        let tmpdir = tempfile::tempdir().unwrap();
        std::env::set_var("WARD_HOME", tmpdir.path());

        create_recovery_files("myproject", "vault-passphrase", "1234").unwrap();
        assert!(restore_from_recovery("myproject", None, "wrong").is_err());

        std::env::remove_var("WARD_HOME");
    }
}
