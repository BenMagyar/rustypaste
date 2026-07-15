//! Filesystem reconciliation helpers for paste ownership metadata.

use crate::paste::PasteType;
use crate::store::NewPaste;
use crate::util;
use path_clean::PathClean;
use std::fs::{self, DirEntry, File};
use std::io::{Error as IoError, Result as IoResult};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

/// Paste metadata collected during a filesystem scan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PasteScan {
    /// Successfully read paste entries.
    pub pastes: Vec<NewPaste>,
    /// Entries omitted because their metadata or content could not be read.
    pub skipped_entries: usize,
}

/// Scans all paste storage directories for ownership reconciliation.
pub fn scan_pastes(upload_path: &Path) -> IoResult<PasteScan> {
    let mut pastes = Vec::new();
    let mut skipped_entries = 0;
    for paste_type in [
        PasteType::File,
        PasteType::Oneshot,
        PasteType::Url,
        PasteType::OneshotUrl,
        PasteType::ProtectedFile,
    ] {
        let directory = paste_type.get_path(upload_path)?;
        if !directory.exists() {
            continue;
        }
        for entry in fs::read_dir(&directory)? {
            let entry = match entry {
                Ok(entry) => entry,
                Err(error) => {
                    warn!(
                        "Skipping an unreadable entry in {} during ownership reconciliation: \
                         {error}",
                        directory.display()
                    );
                    skipped_entries += 1;
                    continue;
                }
            };
            let path = entry.path();
            match scan_entry(entry, paste_type) {
                Ok(Some(paste)) => pastes.push(paste),
                Ok(None) => {}
                Err(error) => {
                    warn!(
                        "Skipping {} during ownership reconciliation: {error}",
                        path.display()
                    );
                    skipped_entries += 1;
                }
            }
        }
    }
    Ok(PasteScan {
        pastes,
        skipped_entries,
    })
}

fn scan_entry(entry: DirEntry, paste_type: PasteType) -> IoResult<Option<NewPaste>> {
    let path = entry.path().clean();
    let metadata = entry.metadata()?;
    if !metadata.is_file() || is_password_sidecar(&path, paste_type) {
        return Ok(None);
    }
    let stored_filename = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| IoError::other("paste filename is not valid UTF-8"))?;
    let (public_filename, expires_at) = split_expiry(stored_filename)?;
    let created_at = metadata
        .created()
        .or_else(|_| metadata.modified())
        .unwrap_or_else(|_| SystemTime::now())
        .duration_since(UNIX_EPOCH)
        .map_err(IoError::other)?
        .as_secs()
        .try_into()
        .map_err(|_| IoError::other("paste creation time is too large"))?;
    let content_hash = util::sha256_digest(File::open(&path)?)
        .map_err(|error| IoError::other(error.to_string()))?;
    Ok(Some(NewPaste {
        owner_principal_id: None,
        public_filename,
        storage_path: path,
        paste_type,
        created_at,
        size_bytes: metadata.len(),
        expires_at,
        content_hash,
    }))
}

fn is_password_sidecar(path: &Path, paste_type: PasteType) -> bool {
    paste_type == PasteType::ProtectedFile
        && path.extension().and_then(|value| value.to_str()) == Some("password")
        && path.with_extension("").is_file()
        && crate::password::is_password_hash_file(path)
}

fn split_expiry(filename: &str) -> IoResult<(String, Option<i64>)> {
    let Some((public_filename, suffix)) = filename.rsplit_once('.') else {
        return Ok((filename.to_string(), None));
    };
    if suffix.len() < 10 || !suffix.bytes().all(|value| value.is_ascii_digit()) {
        return Ok((filename.to_string(), None));
    }
    let expires_millis = suffix
        .parse::<u128>()
        .map_err(|error| IoError::other(error.to_string()))?;
    let expires_seconds = expires_millis
        .checked_add(999)
        .ok_or_else(|| IoError::other("paste expiry is too large"))?
        / 1000;
    let expires_at =
        i64::try_from(expires_seconds).map_err(|_| IoError::other("paste expiry is too large"))?;
    Ok((public_filename.to_string(), Some(expires_at)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_millisecond_expiry_suffix() {
        assert_eq!(
            (String::from("hello.txt"), Some(1_750_000_001)),
            split_expiry("hello.txt.1750000000001").expect("valid expiry")
        );
        assert_eq!(
            (String::from("hello.txt"), None),
            split_expiry("hello.txt").expect("filename without expiry")
        );
    }

    #[test]
    fn scan_ignores_password_sidecars() {
        let root = std::env::temp_dir().join(format!(
            "rustypaste-ownership-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system time")
                .as_nanos()
        ));
        fs::create_dir_all(root.join("protected")).expect("create protected directory");
        let paste_path = root.join("protected/secret.txt");
        fs::write(&paste_path, b"secret").expect("write paste");
        crate::password::store_password_hash(&paste_path, "secret-password")
            .expect("write sidecar");

        let scan = scan_pastes(&root).expect("scan pastes");
        let pastes = scan.pastes;
        assert_eq!(1, pastes.len());
        assert_eq!(PasteType::ProtectedFile, pastes[0].paste_type);
        assert_eq!("secret.txt", pastes[0].public_filename);

        fs::remove_dir_all(root).expect("remove fixture");
    }

    #[test]
    fn scan_keeps_legitimate_password_named_uploads() {
        let root = fixture_root("password-uploads");
        fs::create_dir_all(root.join("protected")).expect("create protected directory");
        fs::write(root.join("notes.password"), b"root paste").expect("write root paste");
        fs::write(root.join("protected/orphan.password"), b"protected paste")
            .expect("write protected paste");

        let scan = scan_pastes(&root).expect("scan pastes");
        let pastes = scan.pastes;
        assert_eq!(2, pastes.len());
        assert!(pastes.iter().any(|paste| {
            paste.paste_type == PasteType::File && paste.public_filename == "notes.password"
        }));
        assert!(pastes.iter().any(|paste| {
            paste.paste_type == PasteType::ProtectedFile
                && paste.public_filename == "orphan.password"
        }));

        fs::remove_dir_all(root).expect("remove fixture");
    }

    #[cfg(unix)]
    #[test]
    fn scan_skips_unreadable_entries_without_losing_valid_pastes() {
        use std::os::unix::fs::PermissionsExt;

        let root = fixture_root("invalid-entries");
        fs::create_dir_all(&root).expect("create fixture directory");
        fs::write(root.join("valid.txt"), b"valid").expect("write valid paste");
        let unreadable = root.join("unreadable.txt");
        fs::write(&unreadable, b"unreadable").expect("write unreadable paste");
        fs::set_permissions(&unreadable, fs::Permissions::from_mode(0o000))
            .expect("remove paste read permissions");

        let scan = scan_pastes(&root).expect("scan pastes");
        assert_eq!(1, scan.skipped_entries);
        assert_eq!(1, scan.pastes.len());
        assert_eq!("valid.txt", scan.pastes[0].public_filename);

        fs::set_permissions(&unreadable, fs::Permissions::from_mode(0o600))
            .expect("restore paste read permissions");
        fs::remove_dir_all(root).expect("remove fixture");
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    #[test]
    fn scan_skips_non_utf8_filenames_without_losing_valid_pastes() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;

        let root = fixture_root("non-utf8-entry");
        fs::create_dir_all(&root).expect("create fixture directory");
        fs::write(root.join("valid.txt"), b"valid").expect("write valid paste");
        fs::write(
            root.join(OsString::from_vec(vec![b'i', b'n', 0xff])),
            b"invalid utf-8",
        )
        .expect("write invalid UTF-8 paste");

        let scan = scan_pastes(&root).expect("scan pastes");
        assert_eq!(1, scan.skipped_entries);
        assert_eq!(1, scan.pastes.len());
        assert_eq!("valid.txt", scan.pastes[0].public_filename);

        fs::remove_dir_all(root).expect("remove fixture");
    }

    fn fixture_root(label: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "rustypaste-ownership-{label}-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system time")
                .as_nanos()
        ))
    }
}
