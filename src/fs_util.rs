use std::{
    fs::{self, File, OpenOptions},
    path::Path,
};

use anyhow::{Context, Result};

pub(crate) fn ensure_parent_dir(path: &Path) -> Result<()> {
    match path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        Some(parent) => {
            fs::create_dir_all(parent).context(format!("failed to create {}", parent.display()))
        }
        None => Ok(()),
    }
}

pub(crate) fn ensure_private_parent_dir(path: &Path) -> Result<()> {
    match path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        Some(parent) => ensure_private_dir(parent),
        None => Ok(()),
    }
}

pub(crate) fn ensure_private_dir(path: &Path) -> Result<()> {
    fs::create_dir_all(path).context(format!("failed to create {}", path.display()))?;
    set_private_dir_permissions(path)
}

pub(crate) fn write_private_file(path: &Path, contents: &[u8]) -> Result<()> {
    ensure_private_parent_dir(path)?;
    fs::write(path, contents).context(format!("failed to write {}", path.display()))?;
    set_private_file_permissions(path)
}

pub(crate) fn open_private_append(path: &Path) -> Result<File> {
    ensure_private_parent_dir(path)?;
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .context(format!("failed to open {}", path.display()))?;
    set_private_file_permissions(path)?;
    Ok(file)
}

#[cfg(unix)]
pub(crate) fn set_private_dir_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .context(format!("failed to chmod {}", path.display()))
}

#[cfg(not(unix))]
pub(crate) fn set_private_dir_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
pub(crate) fn set_private_file_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .context(format!("failed to chmod {}", path.display()))
}

#[cfg(not(unix))]
pub(crate) fn set_private_file_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn ensure_parent_dir_creates_parent_and_allows_plain_file_name() {
        let tempdir = tempfile::tempdir().unwrap();
        let nested = tempdir.path().join("nested").join("file.txt");

        ensure_parent_dir(&nested).unwrap();
        ensure_parent_dir(Path::new("file.txt")).unwrap();
        ensure_private_parent_dir(Path::new("file.txt")).unwrap();

        assert!(tempdir.path().join("nested").is_dir());
    }

    #[test]
    fn private_file_helpers_write_and_append() {
        let tempdir = tempfile::tempdir().unwrap();
        let path = tempdir.path().join("state").join("file.jsonl");

        write_private_file(&path, b"one\n").unwrap();
        {
            use std::io::Write;
            let mut file = open_private_append(&path).unwrap();
            writeln!(file, "two").unwrap();
        }

        assert_eq!(std::fs::read_to_string(&path).unwrap(), "one\ntwo\n");

        #[cfg(unix)]
        {
            let dir_mode = std::fs::metadata(path.parent().unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            let file_mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(dir_mode, 0o700);
            assert_eq!(file_mode, 0o600);
        }
    }

    #[test]
    fn private_helpers_report_blocked_paths() {
        let tempdir = tempfile::tempdir().unwrap();
        let blocked = tempdir.path().join("blocked");
        std::fs::write(&blocked, "").unwrap();

        assert!(ensure_private_dir(&blocked).is_err());
        assert!(write_private_file(&blocked, b"contents").is_ok());
        assert!(open_private_append(&blocked).is_ok());
    }
}
