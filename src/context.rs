use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{git_context, registry};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ClaimedContext {
    pub agent: Option<String>,
    pub agent_key_id: Option<String>,
    pub worktree: Option<PathBuf>,
    pub branch: Option<String>,
    pub git_remote: Option<String>,
    pub commit: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct VerifiedContext {
    pub project: String,
    pub agent: String,
    pub agent_key_id: String,
    pub worktree: PathBuf,
    pub branch: String,
    pub git_remote: String,
    pub commit: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub git_common_dir: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ContextProblem {
    ContextRequired {
        missing: Vec<&'static str>,
    },
    ContextMismatch {
        field: &'static str,
        claimed: String,
        actual: String,
    },
}

pub fn verify_no_prompt_context(
    claimed: &ClaimedContext,
    cwd: &Path,
    resolved: &registry::ResolvedProject,
    agent_key_id: String,
) -> std::result::Result<VerifiedContext, ContextProblem> {
    let mut missing = Vec::new();
    if claimed.agent.as_deref().unwrap_or_default().is_empty() {
        missing.push("agent");
    }
    if claimed.worktree.is_none() {
        missing.push("worktree");
    }
    if claimed.branch.as_deref().unwrap_or_default().is_empty() {
        missing.push("branch");
    }
    if claimed.git_remote.is_none() {
        missing.push("gitRemote");
    }
    if claimed.commit.as_deref().unwrap_or_default().is_empty() {
        missing.push("commit");
    }
    if !missing.is_empty() {
        return Err(ContextProblem::ContextRequired { missing });
    }

    let agent = claimed.agent.clone().unwrap_or_default();
    let claimed_worktree = claimed.worktree.as_ref().expect("checked above");
    let worktree = canonicalize_or_problem("worktree", claimed_worktree)?;
    let cwd = canonicalize_or_problem("cwd", cwd)?;
    if !cwd.starts_with(&worktree) {
        return Err(ContextProblem::ContextMismatch {
            field: "worktree",
            claimed: worktree.display().to_string(),
            actual: cwd.display().to_string(),
        });
    }

    let git = git_context::collect_git_context(&worktree);
    let actual_worktree = git
        .worktree_path
        .as_deref()
        .map(PathBuf::from)
        .and_then(|path| path.canonicalize().ok())
        .unwrap_or_else(|| worktree.clone());
    if actual_worktree != worktree {
        return Err(ContextProblem::ContextMismatch {
            field: "worktree",
            claimed: worktree.display().to_string(),
            actual: actual_worktree.display().to_string(),
        });
    }

    require_match("branch", claimed.branch.as_deref(), git.branch.as_deref())?;
    require_remote_match(claimed.git_remote.as_deref(), git.remote.as_deref())?;
    require_match("commit", claimed.commit.as_deref(), git.commit.as_deref())?;

    Ok(VerifiedContext {
        project: resolved.name.clone(),
        agent,
        agent_key_id,
        worktree,
        branch: claimed.branch.clone().unwrap_or_default(),
        git_remote: normalize_remote(claimed.git_remote.as_deref().unwrap_or_default()),
        commit: claimed.commit.clone().unwrap_or_default(),
        git_common_dir: git.common_dir,
    })
}

pub fn normalize_remote(remote: &str) -> String {
    let mut value = remote.trim().trim_end_matches('/').to_string();
    if let Some(stripped) = value.strip_suffix(".git") {
        value = stripped.to_string();
    }
    value
}

fn canonicalize_or_problem(
    field: &'static str,
    path: &Path,
) -> std::result::Result<PathBuf, ContextProblem> {
    path.canonicalize()
        .map_err(|error| ContextProblem::ContextMismatch {
            field,
            claimed: path.display().to_string(),
            actual: error.to_string(),
        })
}

fn require_match(
    field: &'static str,
    claimed: Option<&str>,
    actual: Option<&str>,
) -> std::result::Result<(), ContextProblem> {
    let claimed = claimed.unwrap_or_default();
    let actual = actual.unwrap_or_default();
    if claimed == actual {
        Ok(())
    } else {
        Err(ContextProblem::ContextMismatch {
            field,
            claimed: claimed.to_string(),
            actual: actual.to_string(),
        })
    }
}

fn require_remote_match(
    claimed: Option<&str>,
    actual: Option<&str>,
) -> std::result::Result<(), ContextProblem> {
    let claimed = normalize_remote(claimed.unwrap_or_default());
    let actual = normalize_remote(actual.unwrap_or_default());
    if claimed == actual {
        Ok(())
    } else {
        Err(ContextProblem::ContextMismatch {
            field: "gitRemote",
            claimed,
            actual,
        })
    }
}

pub fn context_problem_json(problem: &ContextProblem) -> Result<String> {
    match problem {
        ContextProblem::ContextRequired { .. } => {
            serde_json::to_string_pretty(problem).context("failed to serialize context problem")
        }
        ContextProblem::ContextMismatch {
            field,
            claimed,
            actual,
        } => {
            #[derive(Serialize)]
            #[serde(rename_all = "camelCase")]
            struct RedactedMismatch<'a> {
                status: &'static str,
                field: &'a str,
                claimed: &'a str,
                actual_present: bool,
                actual_hash: String,
            }

            let actual_hash = hex::encode(Sha256::digest(actual.as_bytes()));
            let response = RedactedMismatch {
                status: "context_mismatch",
                field,
                claimed,
                actual_present: !actual.is_empty(),
                actual_hash,
            };
            serde_json::to_string_pretty(&response).context("failed to serialize context problem")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    fn git_repo() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        Command::new("git")
            .args(["init"])
            .current_dir(dir.path())
            .output()
            .unwrap();
        Command::new("git")
            .args(["config", "user.email", "tester@example.test"])
            .current_dir(dir.path())
            .output()
            .unwrap();
        Command::new("git")
            .args(["config", "user.name", "Tester"])
            .current_dir(dir.path())
            .output()
            .unwrap();
        std::fs::write(dir.path().join("README.md"), "demo").unwrap();
        Command::new("git")
            .args(["add", "."])
            .current_dir(dir.path())
            .output()
            .unwrap();
        Command::new("git")
            .args(["commit", "-m", "init"])
            .env("GIT_AUTHOR_NAME", "Tester")
            .env("GIT_AUTHOR_EMAIL", "tester@example.test")
            .env("GIT_COMMITTER_NAME", "Tester")
            .env("GIT_COMMITTER_EMAIL", "tester@example.test")
            .current_dir(dir.path())
            .output()
            .unwrap();
        Command::new("git")
            .args(["remote", "add", "origin", "https://example.test/repo.git"])
            .current_dir(dir.path())
            .output()
            .unwrap();
        dir
    }

    #[test]
    fn normalize_remote_ignores_git_suffix_and_trailing_slash() {
        assert_eq!(
            normalize_remote("https://example.test/repo.git/"),
            "https://example.test/repo"
        );
    }

    #[test]
    fn verifies_matching_context_and_rejects_mismatches() {
        let repo = git_repo();
        let git = git_context::collect_git_context(repo.path());
        let resolved = registry::ResolvedProject {
            name: "demo".to_string(),
            path: repo.path().to_path_buf(),
            vault: repo.path().join(".env.vault"),
        };
        let claimed = ClaimedContext {
            agent: Some("codex".to_string()),
            agent_key_id: None,
            worktree: Some(repo.path().to_path_buf()),
            branch: git.branch.clone(),
            git_remote: git.remote.clone(),
            commit: git.commit.clone(),
        };
        let verified =
            verify_no_prompt_context(&claimed, repo.path(), &resolved, "key".to_string()).unwrap();
        assert_eq!(verified.project, "demo");

        let mut bad = claimed.clone();
        bad.branch = Some("main".to_string());
        assert!(matches!(
            verify_no_prompt_context(&bad, repo.path(), &resolved, "key".to_string()),
            Err(ContextProblem::ContextMismatch {
                field: "branch",
                ..
            })
        ));

        let outside = tempfile::tempdir().unwrap();
        assert!(matches!(
            verify_no_prompt_context(&claimed, outside.path(), &resolved, "key".to_string()),
            Err(ContextProblem::ContextMismatch {
                field: "worktree",
                ..
            })
        ));

        let subdir = repo.path().join("subdir");
        std::fs::create_dir(&subdir).unwrap();
        let mut subdir_claim = claimed.clone();
        subdir_claim.worktree = Some(subdir.clone());
        assert!(matches!(
            verify_no_prompt_context(&subdir_claim, &subdir, &resolved, "key".to_string()),
            Err(ContextProblem::ContextMismatch {
                field: "worktree",
                ..
            })
        ));

        let mut missing_path = claimed.clone();
        missing_path.worktree = Some(repo.path().join("missing"));
        assert!(matches!(
            verify_no_prompt_context(&missing_path, repo.path(), &resolved, "key".to_string()),
            Err(ContextProblem::ContextMismatch {
                field: "worktree",
                ..
            })
        ));

        let mut bad_remote = claimed.clone();
        bad_remote.git_remote = Some("https://example.test/other.git".to_string());
        assert!(matches!(
            verify_no_prompt_context(&bad_remote, repo.path(), &resolved, "key".to_string()),
            Err(ContextProblem::ContextMismatch {
                field: "gitRemote",
                ..
            })
        ));

        let missing = ClaimedContext {
            agent: None,
            agent_key_id: None,
            worktree: None,
            branch: None,
            git_remote: None,
            commit: None,
        };
        assert!(matches!(
            verify_no_prompt_context(&missing, repo.path(), &resolved, "key".to_string()),
            Err(ContextProblem::ContextRequired { .. })
        ));
    }

    #[test]
    fn verifies_explicit_empty_remote_and_redacts_mismatch_json() {
        let repo = git_repo();
        Command::new("git")
            .args(["remote", "remove", "origin"])
            .current_dir(repo.path())
            .output()
            .unwrap();
        let git = git_context::collect_git_context(repo.path());
        let resolved = registry::ResolvedProject {
            name: "demo".to_string(),
            path: repo.path().to_path_buf(),
            vault: repo.path().join(".env.vault"),
        };
        let claimed = ClaimedContext {
            agent: Some("codex".to_string()),
            agent_key_id: None,
            worktree: Some(repo.path().to_path_buf()),
            branch: git.branch.clone(),
            git_remote: Some(String::new()),
            commit: git.commit.clone(),
        };
        let verified =
            verify_no_prompt_context(&claimed, repo.path(), &resolved, "key".to_string()).unwrap();
        assert_eq!(verified.git_remote, "");

        let missing_remote = ClaimedContext {
            git_remote: None,
            ..claimed.clone()
        };
        assert!(matches!(
            verify_no_prompt_context(&missing_remote, repo.path(), &resolved, "key".to_string()),
            Err(ContextProblem::ContextRequired { missing }) if missing == vec!["gitRemote"]
        ));

        let mut wrong_remote = claimed;
        wrong_remote.git_remote = Some("https://example.test/wrong.git".to_string());
        let problem =
            verify_no_prompt_context(&wrong_remote, repo.path(), &resolved, "key".to_string())
                .unwrap_err();
        let json = context_problem_json(&problem).unwrap();
        assert!(json.contains("\"actualPresent\": false"));
        assert!(json.contains("\"actualHash\""));
        assert!(!json.contains("\"actual\":"));
    }

    #[test]
    fn context_verification_reports_canonicalization_and_git_fallback_edges() {
        let cwd = tempfile::tempdir().unwrap();
        let resolved = registry::ResolvedProject {
            name: "demo".to_string(),
            path: cwd.path().to_path_buf(),
            vault: cwd.path().join(".env.vault"),
        };
        let missing_worktree = cwd.path().join("missing");
        let missing_claim = ClaimedContext {
            agent: Some("codex".to_string()),
            agent_key_id: None,
            worktree: Some(missing_worktree),
            branch: Some("main".to_string()),
            git_remote: Some("https://example.test/repo.git".to_string()),
            commit: Some("abc".to_string()),
        };
        assert!(matches!(
            verify_no_prompt_context(&missing_claim, cwd.path(), &resolved, "key".to_string()),
            Err(ContextProblem::ContextMismatch {
                field: "worktree",
                ..
            })
        ));

        let no_git_claim = ClaimedContext {
            agent: Some("codex".to_string()),
            agent_key_id: None,
            worktree: Some(cwd.path().to_path_buf()),
            branch: Some("main".to_string()),
            git_remote: Some("https://example.test/repo.git".to_string()),
            commit: Some("abc".to_string()),
        };
        assert!(matches!(
            verify_no_prompt_context(&no_git_claim, cwd.path(), &resolved, "key".to_string()),
            Err(ContextProblem::ContextMismatch {
                field: "branch",
                ..
            })
        ));
    }
}
