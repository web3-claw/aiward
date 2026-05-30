use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::{approvals::ApprovalScope, policy::ApprovalMode};

pub const PROJECT_CONFIG_FILE: &str = ".ward.json";
pub const DEFAULT_VAULT_FILE: &str = ".env.vault";
pub const AGENT_INSTRUCTIONS_FILE: &str = "AGENTS.md";
pub const CLAUDE_INSTRUCTIONS_FILE: &str = "CLAUDE.md";

const ENV_EXAMPLE_HEADER: &str = "# Ward managed environment.\n# Plaintext .env files should not be committed or shared with AI agents.\n# Agents should request scoped access with ward request, then run approved commands with ward run.\n\n";
const AGENT_INSTRUCTIONS_MARKER: &str = "<!-- ward-agent-instructions -->";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectConfig {
    pub version: u32,
    pub project: String,
    pub vault: PathBuf,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub presets: Vec<PresetConfig>,
    #[serde(default)]
    pub profiles: BTreeMap<String, ProfileConfig>,
    #[serde(default = "default_anomaly_detection")]
    pub anomaly_detection: AnomalyDetectionConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PresetConfig {
    pub name: String,
    #[serde(rename = "match")]
    pub match_commands: Vec<String>,
    pub allowed_env: Vec<String>,
    pub approval: ApprovalMode,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ProfileConfig {
    pub command: String,
    pub env: Vec<String>,
    pub default_scope: ApprovalScope,
    pub action: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AnomalyDetectionConfig {
    pub enabled: bool,
    pub working_hours_start: u8,
    pub working_hours_end: u8,
    pub max_runs_per_hour_per_grant: usize,
    pub max_branches_per_grant: usize,
}

impl ProjectConfig {
    pub fn default_for_dir(cwd: &Path, project: Option<String>) -> Result<Self> {
        let project = match project {
            Some(project) => project,
            None => cwd
                .file_name()
                .and_then(|name| name.to_str())
                .map(str::to_owned)
                .context("could not infer project name from current directory")?,
        };

        let profiles = default_profiles(&default_env_keys(), cwd);

        Ok(Self {
            version: 1,
            project,
            vault: PathBuf::from(DEFAULT_VAULT_FILE),
            presets: Vec::new(),
            profiles,
            anomaly_detection: default_anomaly_detection(),
        })
    }
}

pub fn config_path(cwd: &Path) -> PathBuf {
    cwd.join(PROJECT_CONFIG_FILE)
}

pub fn read_project_config(cwd: &Path) -> Result<ProjectConfig> {
    let path = config_path(cwd);
    let contents =
        fs::read_to_string(&path).context(format!("failed to read {}", path.display()))?;
    serde_json::from_str(&contents).context(format!("failed to parse {}", path.display()))
}

pub fn write_project_config(cwd: &Path, config: &ProjectConfig, force: bool) -> Result<PathBuf> {
    let path = config_path(cwd);
    if path.exists() && !force {
        anyhow::bail!(
            "{} already exists; pass --force to overwrite",
            path.display()
        );
    }

    let contents = serde_json::to_string_pretty(config)?;
    fs::write(&path, format!("{contents}\n"))
        .context(format!("failed to write {}", path.display()))?;
    Ok(path)
}

pub fn env_keys_from_dotenv_file(path: &Path) -> Result<Vec<String>> {
    let iter =
        dotenvy::from_path_iter(path).context(format!("failed to parse {}", path.display()))?;
    env_keys_from_dotenv_iter(iter, &path.display().to_string())
}

pub fn env_keys_from_dotenv_str(contents: &str) -> Result<Vec<String>> {
    let iter = dotenvy::from_read_iter(std::io::Cursor::new(contents.as_bytes()));
    env_keys_from_dotenv_iter(iter, "dotenv contents")
}

fn env_keys_from_dotenv_iter<I, E>(iter: I, label: &str) -> Result<Vec<String>>
where
    I: IntoIterator<Item = Result<(String, String), E>>,
    E: std::error::Error + Send + Sync + 'static,
{
    let mut keys = BTreeSet::new();
    for item in iter {
        let (key, _) = item.context(format!("failed to parse {label}"))?;
        keys.insert(key);
    }
    Ok(keys.into_iter().collect())
}

pub fn default_profiles(env_keys: &[String], cwd: &Path) -> BTreeMap<String, ProfileConfig> {
    let commands = detected_commands(cwd);
    let env = env_keys.iter().cloned().collect::<BTreeSet<_>>();
    let known = |name: &str| env.contains(name);

    let mut dev_env = Vec::new();
    for name in ["DATABASE_URL", "DATABASE_URI", "PAYLOAD_SECRET"] {
        if known(name) {
            dev_env.push(name.to_string());
        }
    }
    dev_env.extend(
        env.iter()
            .filter(|name| name.starts_with("NEXT_PUBLIC_"))
            .cloned(),
    );
    let mut migrate_env = Vec::new();
    for name in ["DATABASE_URL", "DATABASE_URI", "PAYLOAD_SECRET"] {
        if known(name) {
            migrate_env.push(name.to_string());
        }
    }

    BTreeMap::from([
        (
            "dev".to_string(),
            ProfileConfig {
                command: commands.dev,
                env: dev_env,
                default_scope: ApprovalScope::Always,
                action: "Run development server".to_string(),
            },
        ),
        (
            "migrate".to_string(),
            ProfileConfig {
                command: commands.migrate,
                env: migrate_env,
                default_scope: ApprovalScope::Branch,
                action: "Run Payload migration".to_string(),
            },
        ),
    ])
}

pub fn merge_default_profiles(config: &mut ProjectConfig, env_keys: &[String], cwd: &Path) {
    for (name, profile) in default_profiles(env_keys, cwd) {
        config.profiles.entry(name).or_insert(profile);
    }
}

pub fn replace_default_profiles(config: &mut ProjectConfig, env_keys: &[String], cwd: &Path) {
    for (name, profile) in default_profiles(env_keys, cwd) {
        config.profiles.insert(name, profile);
    }
}

pub fn ensure_gitignore(cwd: &Path, commit_vault: bool) -> Result<PathBuf> {
    let path = cwd.join(".gitignore");
    let existing = if path.exists() {
        fs::read_to_string(&path).context(format!("failed to read {}", path.display()))?
    } else {
        String::new()
    };

    let vault_exception = format!("!{DEFAULT_VAULT_FILE}");
    let mut lines = existing
        .lines()
        .filter(|line| commit_vault || line.trim() != vault_exception)
        .map(str::to_string)
        .collect::<Vec<_>>();

    append_gitignore_line(&mut lines, ".env");
    append_gitignore_line(&mut lines, ".env.*");
    if commit_vault {
        append_gitignore_line(&mut lines, &format!("!{DEFAULT_VAULT_FILE}"));
    }

    let mut contents = lines.join("\n");
    if !contents.is_empty() {
        contents.push('\n');
    }
    fs::write(&path, contents).context(format!("failed to write {}", path.display()))?;
    Ok(path)
}

pub fn ensure_env_example(cwd: &Path) -> Result<Option<PathBuf>> {
    let path = cwd.join(".env.example");
    if path.exists() {
        let contents =
            fs::read_to_string(&path).context(format!("failed to read {}", path.display()))?;
        if contents.contains("Ward managed environment") {
            return Ok(None);
        }

        fs::write(&path, format!("{ENV_EXAMPLE_HEADER}{contents}"))
            .context(format!("failed to write {}", path.display()))?;
        return Ok(Some(path));
    }

    fs::write(
        &path,
        format!("{ENV_EXAMPLE_HEADER}# Add non-secret env names here.\n"),
    )
    .context(format!("failed to write {}", path.display()))?;
    Ok(Some(path))
}

pub fn ensure_agent_instructions(cwd: &Path, project: &str) -> Result<Option<PathBuf>> {
    let claude_path = cwd.join(CLAUDE_INSTRUCTIONS_FILE);
    let path = if claude_path.exists() {
        claude_path
    } else {
        cwd.join(AGENT_INSTRUCTIONS_FILE)
    };
    let section = agent_instructions_section(project);

    if path.exists() {
        let contents =
            fs::read_to_string(&path).context(format!("failed to read {}", path.display()))?;
        if contents.contains(AGENT_INSTRUCTIONS_MARKER) {
            return Ok(None);
        }

        let separator = if contents.ends_with('\n') {
            "\n"
        } else {
            "\n\n"
        };
        fs::write(&path, format!("{contents}{separator}{section}"))
            .context(format!("failed to write {}", path.display()))?;
        return Ok(Some(path));
    }

    fs::write(&path, section).context(format!("failed to write {}", path.display()))?;
    Ok(Some(path))
}

fn agent_instructions_section(project: &str) -> String {
    format!(
        r#"{AGENT_INSTRUCTIONS_MARKER}
# Ward Secret Access

This repository uses Ward for local secret access. Do not read, print, copy,
or modify plaintext `.env` files. Request only the env vars needed for the
declared command.

Project: {project}

Use profiles where available:

```bash
ward request --profile dev --agent <agent-name> --worktree <absolute-path> --git-remote <remote-url-or-empty> --commit <sha> --branch <branch> --json --no-prompt
ward run --profile dev --agent <agent-name> --worktree <absolute-path> --git-remote <remote-url-or-empty> --commit <sha> --branch <branch> --json --no-prompt
ward dev --agent <agent-name> --worktree <absolute-path> --git-remote <remote-url-or-empty> --commit <sha> --branch <branch> --json --no-prompt
ward migrate --agent <agent-name> --worktree <absolute-path> --git-remote <remote-url-or-empty> --commit <sha> --branch <branch> --json --no-prompt
```

Profiles are the user-facing command layer. They map a short name such as
`dev` or `migrate` to one command and exact env names. Presets may be added to
`.ward.json` as lower-level policy rules for raw command matching and
approval behavior; prefer profiles unless a profile does not exist.

No-prompt agent calls must always send full context up front: `--agent`,
`--worktree`, `--branch`, `--git-remote`, `--commit`, `--action`, and either
`--profile` or an exact `--command` plus exact `--env` names. Do not wait for
Ward to ask follow-up questions. Ward verifies the claimed branch, remote,
commit, and worktree path locally before creating or reusing approvals.
For repositories with no `origin` remote, pass `--git-remote ""` explicitly.

Manual request template:

```bash
ward request \
  --agent <agent-name> \
  --worktree <absolute-path> \
  --branch <branch-name> \
  --git-remote <remote-url-or-empty> \
  --commit <sha> \
  --action "<why this command needs secrets>" \
  --command "<exact command to run>" \
  --env <ENV_NAME> \
  --json \
  --no-prompt
```

If a no-prompt command returns `"approvalRequired": true`, show
`approvalOptions`, `approveCommands`, `denyCommand`, and all `findings` to the
user as explicit choices. Use native structured choice UI when your agent
interface supports it; do not present approval choices as loose prose when
buttons, selectors, or typed choice prompts are available. If your structured
choice UI has a 4-option limit, present the approval scopes in the picker and
show `denyCommand` as a separate explicit denial action.

Surface `action.*` findings before asking for approval. They mean the declared
action text may include prompt-injection, approval-coercion, or secret-exposure
language.

After the user approves in the agent UI, record that approval with the matching
approve command:

```bash
ward unlock --ttl 8h
ward approve <request-id> --scope <session|branch|always> --agent-mediated --json
```

Approvals are signed. If `ward approve` or `ward allow` reports
`"status": "unlock_required"` or `signing_key_unavailable`, ask the user to run
`ward unlock --ttl 8h` and then retry the approval. Never ask the user for
the PIN/passphrase directly.

If a no-prompt command returns `"unlockRequired": true`, ask the user to run:

```bash
ward unlock --ttl 8h
```

This usually means the init/setup-created unlock expired, setup was run with
`--no-unlock`, or the user explicitly ran `ward lock`.

If a no-prompt command returns `"status": "vault_key_missing"`, do not ask the
user to unlock again. The broker is already reachable, but the approved profile
or command requested an env var that is not present in `.env.vault`. Surface
`missingEnv` and ask the user to update `.ward.json` or run `ward env
unlock`, add the missing key, then run `ward env lock`.

If the JSON response contains `"confirmationRequired": true`, show the
`confirmation.title`, `confirmation.body`, and recommended action to the user.
Do not rewrite, summarize away, or hide the critical confirmation text. Do not
auto-approve it and do not create a durable grant. Critical requests can only be
denied or approved once:

```bash
ward deny <request-id> --agent-mediated --json
ward approve <request-id> --scope once --confirm-critical --agent-mediated --json
```

Run template:

```bash
ward run \
  --agent <agent-name> \
  --worktree <absolute-path> \
  --branch <branch-name> \
  --git-remote <remote-url-or-empty> \
  --commit <sha> \
  --action "<why this command needs secrets>" \
  --env <ENV_NAME> \
  --json \
  --no-prompt \
  -- <command> <args>
```

All Ward flags must appear before `--`. Everything after `--` is the child
command and its arguments, so do not put `--json`, `--no-prompt`, `--agent`, or
other Ward flags after `--`.

Ward is passive: commands that need secrets must be run through
`ward run`. Automatic worktree delivery means Ward injects scoped
environment variables into the approved child process. It does not write
plaintext `.env` files for agents.

Never ask for, echo, store, or pipe the Ward vault PIN/passphrase.
`ward init` and `ward setup` create the initial run unlock by default; the
user may run `ward unlock --ttl 8h` locally later to refresh it. Viewing
decrypted logs always requires the user's PIN/passphrase. Agent-mediated
approvals are logged trust events, not cryptographic proof of human approval.
"#
    )
}

pub fn resolve_vault_path(cwd: &Path, config: &ProjectConfig) -> PathBuf {
    if config.vault.is_absolute() {
        config.vault.clone()
    } else {
        cwd.join(&config.vault)
    }
}

fn default_anomaly_detection() -> AnomalyDetectionConfig {
    AnomalyDetectionConfig {
        enabled: true,
        working_hours_start: 8,
        working_hours_end: 20,
        max_runs_per_hour_per_grant: 20,
        max_branches_per_grant: 3,
    }
}

fn default_env_keys() -> Vec<String> {
    vec![
        "DATABASE_URL".to_string(),
        "DATABASE_URI".to_string(),
        "PAYLOAD_SECRET".to_string(),
    ]
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DetectedCommands {
    dev: String,
    migrate: String,
}

fn detected_commands(cwd: &Path) -> DetectedCommands {
    match detected_package_manager(cwd).as_deref() {
        Some("npm") => DetectedCommands {
            dev: "npm run dev".to_string(),
            migrate: "npm run payload -- migrate".to_string(),
        },
        Some("yarn") => DetectedCommands {
            dev: "yarn dev".to_string(),
            migrate: "yarn payload migrate".to_string(),
        },
        Some("bun") => DetectedCommands {
            dev: "bun run dev".to_string(),
            migrate: "bun run payload migrate".to_string(),
        },
        _ => DetectedCommands {
            dev: "pnpm dev".to_string(),
            migrate: "pnpm payload migrate".to_string(),
        },
    }
}

fn detected_package_manager(cwd: &Path) -> Option<String> {
    if let Some(manager) = package_manager_from_package_json(cwd) {
        return Some(manager);
    }
    for (file, manager) in [
        ("pnpm-lock.yaml", "pnpm"),
        ("yarn.lock", "yarn"),
        ("package-lock.json", "npm"),
        ("bun.lockb", "bun"),
        ("bun.lock", "bun"),
    ] {
        if cwd.join(file).exists() {
            return Some(manager.to_string());
        }
    }
    None
}

fn package_manager_from_package_json(cwd: &Path) -> Option<String> {
    let path = cwd.join("package.json");
    let contents = fs::read_to_string(path).ok()?;
    let value = serde_json::from_str::<serde_json::Value>(&contents).ok()?;
    let manager = value.get("packageManager")?.as_str()?;
    ["pnpm", "npm", "yarn", "bun"]
        .iter()
        .find(|candidate| manager.starts_with(&format!("{candidate}@")))
        .map(|candidate| (*candidate).to_string())
}

fn append_gitignore_line(lines: &mut Vec<String>, expected: &str) {
    if !lines.iter().any(|line| {
        let trimmed = line.trim();
        !trimmed.starts_with('#') && trimmed == expected
    }) {
        lines.push(expected.to_string());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_infers_project_and_profiles() {
        let tempdir = tempfile::tempdir().unwrap();
        let config = ProjectConfig::default_for_dir(tempdir.path(), None).unwrap();

        assert_eq!(
            config.project,
            tempdir.path().file_name().unwrap().to_string_lossy()
        );
        assert_eq!(config.vault, PathBuf::from(DEFAULT_VAULT_FILE));
        assert!(config.presets.is_empty());
        let serialized = serde_json::to_string(&config).unwrap();
        assert!(!serialized.contains("\"presets\""));
        assert!(config.profiles.contains_key("dev"));
        assert!(config.anomaly_detection.enabled);
    }

    #[test]
    fn legacy_config_with_presets_still_parses() {
        let json = r#"{
          "version": 1,
          "project": "demo",
          "vault": ".env.vault",
          "presets": [
            {
              "name": "Raw dev",
              "match": ["pnpm dev"],
              "allowedEnv": ["DATABASE_URI"],
              "approval": "prompt"
            }
          ],
          "profiles": {}
        }"#;
        let config = serde_json::from_str::<ProjectConfig>(json).unwrap();
        assert_eq!(config.presets.len(), 1);
        assert_eq!(config.presets[0].allowed_env, vec!["DATABASE_URI"]);
    }

    #[test]
    fn write_project_config_refuses_overwrite_without_force() {
        let tempdir = tempfile::tempdir().unwrap();
        let config =
            ProjectConfig::default_for_dir(tempdir.path(), Some("demo".to_string())).unwrap();

        write_project_config(tempdir.path(), &config, false).unwrap();
        assert!(write_project_config(tempdir.path(), &config, false).is_err());
        assert!(write_project_config(tempdir.path(), &config, true).is_ok());
        assert_eq!(read_project_config(tempdir.path()).unwrap().project, "demo");
    }

    #[test]
    fn ensure_env_example_is_idempotent() {
        let tempdir = tempfile::tempdir().unwrap();

        let path = ensure_env_example(tempdir.path()).unwrap().unwrap();
        assert!(std::fs::read_to_string(&path)
            .unwrap()
            .contains("Ward managed environment"));
        assert!(ensure_env_example(tempdir.path()).unwrap().is_none());
    }

    #[test]
    fn ensure_env_example_prepends_existing_file() {
        let tempdir = tempfile::tempdir().unwrap();
        let path = tempdir.path().join(".env.example");
        std::fs::write(&path, "DATABASE_URL=\n").unwrap();

        assert_eq!(
            ensure_env_example(tempdir.path()).unwrap(),
            Some(path.clone())
        );
        let contents = std::fs::read_to_string(&path).unwrap();
        assert!(contents.starts_with("# Ward managed environment."));
        assert!(contents.contains("DATABASE_URL="));
    }

    #[test]
    fn ensure_agent_instructions_creates_appends_and_is_idempotent() {
        let tempdir = tempfile::tempdir().unwrap();
        let agents_path = tempdir.path().join(AGENT_INSTRUCTIONS_FILE);

        assert_eq!(
            ensure_agent_instructions(tempdir.path(), "demo").unwrap(),
            Some(agents_path.clone())
        );
        assert!(std::fs::read_to_string(&agents_path)
            .unwrap()
            .contains("Project: demo"));
        assert!(ensure_agent_instructions(tempdir.path(), "demo")
            .unwrap()
            .is_none());

        let tempdir = tempfile::tempdir().unwrap();
        let claude_path = tempdir.path().join(CLAUDE_INSTRUCTIONS_FILE);
        std::fs::write(&claude_path, "# Existing instructions\n").unwrap();

        assert_eq!(
            ensure_agent_instructions(tempdir.path(), "claude-demo").unwrap(),
            Some(claude_path.clone())
        );
        let contents = std::fs::read_to_string(&claude_path).unwrap();
        assert!(contents.contains("# Existing instructions"));
        assert!(contents.contains("Project: claude-demo"));
        assert!(contents.contains("Profiles are the user-facing command layer"));
        assert!(contents.contains("Presets may be added"));
        assert!(contents.contains("All Ward flags must appear before `--`"));

        let tempdir = tempfile::tempdir().unwrap();
        let claude_path = tempdir.path().join(CLAUDE_INSTRUCTIONS_FILE);
        std::fs::write(&claude_path, "# Existing instructions").unwrap();

        assert_eq!(
            ensure_agent_instructions(tempdir.path(), "no-newline-demo").unwrap(),
            Some(claude_path.clone())
        );
        let contents = std::fs::read_to_string(&claude_path).unwrap();
        assert!(contents.contains("# Existing instructions\n\n<!-- ward-agent-instructions -->"));
    }

    #[test]
    fn resolves_absolute_and_relative_vault_paths() {
        let tempdir = tempfile::tempdir().unwrap();
        let mut config =
            ProjectConfig::default_for_dir(tempdir.path(), Some("demo".to_string())).unwrap();

        assert_eq!(
            resolve_vault_path(tempdir.path(), &config),
            tempdir.path().join(DEFAULT_VAULT_FILE)
        );

        config.vault = tempdir.path().join("custom.vault");
        assert_eq!(resolve_vault_path(tempdir.path(), &config), config.vault);
    }

    #[test]
    fn dotenv_keys_and_default_profiles_use_exact_env_names() {
        let tempdir = tempfile::tempdir().unwrap();
        let env_path = tempdir.path().join(".env");
        std::fs::write(
            &env_path,
            "DATABASE_URL=postgres://local\nPAYLOAD_SECRET=payload\nNEXT_PUBLIC_API_URL=http://localhost\nOPENAI_API_KEY=test\n",
        )
        .unwrap();

        let keys = env_keys_from_dotenv_file(&env_path).unwrap();
        let profiles = default_profiles(&keys, tempdir.path());

        assert_eq!(
            profiles["dev"].env,
            vec![
                "DATABASE_URL".to_string(),
                "PAYLOAD_SECRET".to_string(),
                "NEXT_PUBLIC_API_URL".to_string(),
            ]
        );
        assert_eq!(
            profiles["migrate"].env,
            vec!["DATABASE_URL".to_string(), "PAYLOAD_SECRET".to_string()]
        );
        assert!(!profiles["dev"].env.iter().any(|name| name.contains('*')));

        let keys = env_keys_from_dotenv_str("DATABASE_URI=mongodb://local\n").unwrap();
        let profiles = default_profiles(&keys, tempdir.path());
        assert_eq!(profiles["dev"].env, vec!["DATABASE_URI".to_string()]);
        assert_eq!(profiles["migrate"].env, vec!["DATABASE_URI".to_string()]);
        assert!(!profiles["dev"].env.contains(&"DATABASE_URL".to_string()));
    }

    #[test]
    fn profile_generation_and_detection_use_package_metadata_and_lockfiles() {
        let tempdir = tempfile::tempdir().unwrap();
        std::fs::write(
            tempdir.path().join("package.json"),
            r#"{"packageManager":"npm@10.0.0"}"#,
        )
        .unwrap();
        assert_eq!(
            package_manager_from_package_json(tempdir.path()),
            Some("npm".to_string())
        );
        assert_eq!(detected_commands(tempdir.path()).dev, "npm run dev");

        std::fs::write(tempdir.path().join("package.json"), "{bad-json}").unwrap();
        std::fs::write(tempdir.path().join("yarn.lock"), "").unwrap();
        assert_eq!(
            detected_package_manager(tempdir.path()),
            Some("yarn".to_string())
        );
        assert_eq!(
            detected_commands(tempdir.path()).migrate,
            "yarn payload migrate"
        );

        let bun = tempfile::tempdir().unwrap();
        std::fs::write(bun.path().join("bun.lock"), "").unwrap();
        assert_eq!(detected_commands(bun.path()).dev, "bun run dev");

        let fallback = tempfile::tempdir().unwrap();
        assert_eq!(detected_commands(fallback.path()).dev, "pnpm dev");
    }

    #[test]
    fn merge_profiles_and_gitignore_updates_are_idempotent() {
        let tempdir = tempfile::tempdir().unwrap();
        let mut config =
            ProjectConfig::default_for_dir(tempdir.path(), Some("demo".to_string())).unwrap();
        config.profiles.clear();

        merge_default_profiles(
            &mut config,
            &["DATABASE_URL".to_string(), "PAYLOAD_SECRET".to_string()],
            tempdir.path(),
        );
        assert!(config.profiles.contains_key("dev"));
        let original = config.profiles["dev"].clone();
        config.profiles.get_mut("dev").unwrap().command = "custom dev".to_string();
        merge_default_profiles(&mut config, &[], tempdir.path());
        assert_eq!(config.profiles["dev"].command, "custom dev");
        assert_ne!(config.profiles["dev"], original);

        let empty = tempfile::tempdir().unwrap();
        ensure_gitignore(empty.path(), true).unwrap();
        let contents = std::fs::read_to_string(empty.path().join(".gitignore")).unwrap();
        assert!(contents.contains(".env\n"));
        assert!(contents.contains(".env.*\n"));
        assert!(contents.contains("!.env.vault\n"));

        std::fs::write(tempdir.path().join(".gitignore"), "# existing\n.env\n").unwrap();
        ensure_gitignore(tempdir.path(), true).unwrap();
        let contents = std::fs::read_to_string(tempdir.path().join(".gitignore")).unwrap();
        assert!(contents.contains(".env\n"));
        assert!(contents.contains(".env.*\n"));
        assert!(contents.contains("!.env.vault\n"));

        ensure_gitignore(tempdir.path(), false).unwrap();
        let contents = std::fs::read_to_string(tempdir.path().join(".gitignore")).unwrap();
        assert!(!contents.contains("!.env.vault"));
    }

    #[test]
    fn env_key_parsing_reports_invalid_dotenv() {
        let tempdir = tempfile::tempdir().unwrap();
        let env_path = tempdir.path().join(".env");
        std::fs::write(&env_path, "DATABASE_URL='unterminated\n").unwrap();

        assert!(env_keys_from_dotenv_file(&env_path).is_err());
    }
}
