use std::{path::Path, process::Command};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct GitContext {
    pub user_name: Option<String>,
    pub user_email: Option<String>,
    pub remote: Option<String>,
    pub branch: Option<String>,
    pub commit: Option<String>,
    pub worktree_path: Option<String>,
    pub common_dir: Option<String>,
}

pub fn collect_git_context(cwd: &Path) -> GitContext {
    GitContext {
        user_name: run_git(cwd, &["config", "user.name"]),
        user_email: run_git(cwd, &["config", "user.email"]),
        remote: run_git(cwd, &["remote", "get-url", "origin"]),
        branch: run_git(cwd, &["rev-parse", "--abbrev-ref", "HEAD"]),
        commit: run_git(cwd, &["rev-parse", "HEAD"]),
        worktree_path: run_git(cwd, &["rev-parse", "--show-toplevel"]),
        common_dir: run_git(cwd, &["rev-parse", "--git-common-dir"]),
    }
}

fn run_git(cwd: &Path, args: &[&str]) -> Option<String> {
    let output = Command::new("git")
        .args(args)
        .current_dir(cwd)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }

    let value = String::from_utf8(output.stdout).ok()?.trim().to_string();
    if value.is_empty() {
        None
    } else {
        Some(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    #[test]
    fn git_context_is_empty_outside_repository() {
        let tempdir = tempfile::tempdir().unwrap();
        let context = collect_git_context(tempdir.path());

        assert!(context.remote.is_none());
        assert!(context.branch.is_none());
        assert!(context.commit.is_none());
    }

    #[test]
    fn git_context_collects_available_safe_metadata() {
        let tempdir = tempfile::tempdir().unwrap();
        Command::new("git")
            .args(["init"])
            .current_dir(tempdir.path())
            .output()
            .unwrap();
        Command::new("git")
            .args(["config", "user.name", "Ward Tester"])
            .current_dir(tempdir.path())
            .output()
            .unwrap();
        Command::new("git")
            .args(["config", "user.email", "tester@example.test"])
            .current_dir(tempdir.path())
            .output()
            .unwrap();
        Command::new("git")
            .args(["remote", "add", "origin", "https://example.test/repo.git"])
            .current_dir(tempdir.path())
            .output()
            .unwrap();

        let context = collect_git_context(tempdir.path());

        assert_eq!(context.user_name.as_deref(), Some("Ward Tester"));
        assert_eq!(context.user_email.as_deref(), Some("tester@example.test"));
        assert_eq!(
            context.remote.as_deref(),
            Some("https://example.test/repo.git")
        );
        assert!(context.worktree_path.is_some());
        assert!(context.common_dir.is_some());
    }

    #[test]
    fn run_git_treats_empty_stdout_as_missing_value() {
        let tempdir = tempfile::tempdir().unwrap();
        Command::new("git")
            .args(["init"])
            .current_dir(tempdir.path())
            .output()
            .unwrap();
        Command::new("git")
            .args(["config", "user.name", ""])
            .current_dir(tempdir.path())
            .output()
            .unwrap();

        assert!(run_git(tempdir.path(), &["config", "user.name"]).is_none());
    }
}
