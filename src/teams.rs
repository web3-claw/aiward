use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::PathBuf,
};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::{fs_util, logs};

const TEAM_RECORD_VERSION: u32 = 1;
const TEAM_STORE_DIR: &str = "store/teams";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct TeamRecord {
    pub version: u32,
    pub project: String,
    pub created_at: String,
    pub updated_at: String,
    #[serde(default)]
    pub members: BTreeMap<String, TeamMember>,
    #[serde(default)]
    pub policies: BTreeMap<String, TeamPolicy>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct TeamMember {
    pub id: String,
    pub name: String,
    pub role: TeamRole,
    #[serde(default)]
    pub agents: Vec<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum TeamRole {
    Owner,
    Admin,
    Developer,
    Viewer,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct TeamPolicy {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub member_id: Option<String>,
    #[serde(default)]
    pub agents: Vec<String>,
    #[serde(default)]
    pub profiles: Vec<String>,
    #[serde(default)]
    pub env: Vec<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct TeamSummary {
    pub project: String,
    pub path: PathBuf,
    pub member_count: usize,
    pub policy_count: usize,
    pub agent_count: usize,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct TeamSnapshot {
    pub project: String,
    pub member_count: usize,
    pub policy_count: usize,
    pub agents: Vec<String>,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TeamMemberInput {
    pub id: String,
    pub name: Option<String>,
    pub role: Option<TeamRole>,
    #[serde(default)]
    pub agents: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TeamPolicyInput {
    pub name: String,
    pub member_id: Option<String>,
    #[serde(default)]
    pub agents: Vec<String>,
    #[serde(default)]
    pub profiles: Vec<String>,
    #[serde(default)]
    pub env: Vec<String>,
}

pub fn teams_dir() -> PathBuf {
    logs::ward_home().join(TEAM_STORE_DIR)
}

pub fn record_path(project: &str) -> PathBuf {
    teams_dir().join(format!("{}.json", slugify(project)))
}

pub fn current_member_id() -> String {
    std::env::var("WARD_LOCAL_MEMBER")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| std::env::var("USER").ok())
        .or_else(|| std::env::var("USERNAME").ok())
        .unwrap_or_else(|| "local".to_string())
}

pub fn load_or_default(project: &str) -> Result<TeamRecord> {
    let path = record_path(project);
    if path.exists() {
        read_record(project)
    } else {
        Ok(default_record(project))
    }
}

pub fn read_record(project: &str) -> Result<TeamRecord> {
    let path = record_path(project);
    let contents =
        fs::read_to_string(&path).with_context(|| format!("failed to read {}", path.display()))?;
    serde_json::from_str(&contents).with_context(|| format!("failed to parse {}", path.display()))
}

pub fn write_record(record: &TeamRecord) -> Result<PathBuf> {
    fs_util::ensure_private_dir(&teams_dir())?;
    let path = record_path(&record.project);
    let contents = serde_json::to_string_pretty(record)?;
    fs_util::write_private_file(&path, format!("{contents}\n").as_bytes())?;
    Ok(path)
}

pub fn summary(project: &str) -> Result<TeamSummary> {
    let record = load_or_default(project)?;
    Ok(summary_for_record(&record))
}

pub fn snapshot(project: &str) -> Result<Option<TeamSnapshot>> {
    let path = record_path(project);
    if !path.exists() {
        return Ok(None);
    }
    let record = read_record(project)?;
    Ok(Some(snapshot_for_record(&record)))
}

pub fn upsert_member(
    record: &mut TeamRecord,
    input: TeamMemberInput,
    existing_id: Option<&str>,
) -> Result<()> {
    let id = normalize_identity(&input.id, "member id")?;
    if let Some(existing_id) = existing_id {
        let existing_id = normalize_identity(existing_id, "member id")?;
        if existing_id != id {
            record.members.remove(&existing_id);
        }
    }
    let now = chrono::Utc::now().to_rfc3339();
    let existing = record.members.get(&id);
    let role = input
        .role
        .or_else(|| existing.map(|member| member.role))
        .unwrap_or(TeamRole::Developer);
    let name = input
        .name
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .or_else(|| existing.map(|member| member.name.clone()))
        .unwrap_or_else(|| id.clone());
    let agents = normalize_identities(input.agents, "agent")?;
    let created_at = existing
        .map(|member| member.created_at.clone())
        .unwrap_or_else(|| now.clone());
    record.members.insert(
        id.clone(),
        TeamMember {
            id,
            name,
            role,
            agents,
            created_at,
            updated_at: now,
        },
    );
    touch(record);
    Ok(())
}

pub fn upsert_policy(
    record: &mut TeamRecord,
    input: TeamPolicyInput,
    existing_name: Option<&str>,
) -> Result<()> {
    let name = normalize_policy_name(&input.name)?;
    if let Some(existing_name) = existing_name {
        let existing_name = normalize_policy_name(existing_name)?;
        if existing_name != name {
            record.policies.remove(&existing_name);
        }
    }
    let now = chrono::Utc::now().to_rfc3339();
    let existing = record.policies.get(&name);
    let member_id = match input.member_id {
        Some(value) => Some(normalize_identity(&value, "member id")?),
        None => existing.and_then(|policy| policy.member_id.clone()),
    };
    let agents = normalize_identities(input.agents, "agent")?;
    if agents.is_empty() {
        anyhow::bail!("team policy requires at least one agent");
    }
    let profiles = normalize_identities(input.profiles, "profile")?;
    let env = normalize_env_names(input.env)?;
    let created_at = existing
        .map(|policy| policy.created_at.clone())
        .unwrap_or_else(|| now.clone());
    record.policies.insert(
        name.clone(),
        TeamPolicy {
            name,
            member_id,
            agents,
            profiles,
            env,
            created_at,
            updated_at: now,
        },
    );
    touch(record);
    Ok(())
}

pub fn remove_member(record: &mut TeamRecord, member_id: &str) -> Result<()> {
    let member_id = normalize_identity(member_id, "member id")?;
    if record.members.remove(&member_id).is_none() {
        anyhow::bail!("team member {member_id} not found");
    }
    touch(record);
    Ok(())
}

pub fn remove_policy(record: &mut TeamRecord, policy: &str) -> Result<()> {
    let policy = normalize_policy_name(policy)?;
    if record.policies.remove(&policy).is_none() {
        anyhow::bail!("team policy {policy} not found");
    }
    touch(record);
    Ok(())
}

pub fn can_manage(record: &TeamRecord, member_id: &str) -> bool {
    record
        .members
        .get(member_id)
        .map(|member| matches!(member.role, TeamRole::Owner | TeamRole::Admin))
        .unwrap_or(false)
}

pub fn policy_agents(record: &TeamRecord) -> BTreeSet<String> {
    record
        .policies
        .values()
        .flat_map(|policy| policy.agents.iter().cloned())
        .collect()
}

pub fn default_record(project: &str) -> TeamRecord {
    let now = chrono::Utc::now().to_rfc3339();
    let local_id = current_member_id();
    let mut members = BTreeMap::new();
    members.insert(
        local_id.clone(),
        TeamMember {
            id: local_id.clone(),
            name: local_id,
            role: TeamRole::Owner,
            agents: Vec::new(),
            created_at: now.clone(),
            updated_at: now.clone(),
        },
    );
    TeamRecord {
        version: TEAM_RECORD_VERSION,
        project: project.to_string(),
        created_at: now.clone(),
        updated_at: now,
        members,
        policies: BTreeMap::new(),
    }
}

fn summary_for_record(record: &TeamRecord) -> TeamSummary {
    TeamSummary {
        project: record.project.clone(),
        path: record_path(&record.project),
        member_count: record.members.len(),
        policy_count: record.policies.len(),
        agent_count: policy_agents(record).len(),
        updated_at: record.updated_at.clone(),
    }
}

fn snapshot_for_record(record: &TeamRecord) -> TeamSnapshot {
    TeamSnapshot {
        project: record.project.clone(),
        member_count: record.members.len(),
        policy_count: record.policies.len(),
        agents: policy_agents(record).into_iter().collect(),
        updated_at: record.updated_at.clone(),
    }
}

fn touch(record: &mut TeamRecord) {
    record.updated_at = chrono::Utc::now().to_rfc3339();
}

fn normalize_env_names(names: Vec<String>) -> Result<Vec<String>> {
    let mut normalized = BTreeSet::new();
    for name in names {
        let name = name.trim();
        if !is_valid_env_name(name) {
            anyhow::bail!("invalid env name: {name}");
        }
        normalized.insert(name.to_string());
    }
    Ok(normalized.into_iter().collect())
}

fn normalize_identities(values: Vec<String>, label: &str) -> Result<Vec<String>> {
    let mut normalized = BTreeSet::new();
    for value in values {
        normalized.insert(normalize_identity(&value, label)?);
    }
    Ok(normalized.into_iter().collect())
}

fn normalize_identity(value: &str, label: &str) -> Result<String> {
    let value = value.trim();
    if value.is_empty()
        || value.len() > 128
        || !value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.' | '@' | ':'))
    {
        anyhow::bail!("invalid {label}: {value}");
    }
    Ok(value.to_string())
}

fn normalize_policy_name(value: &str) -> Result<String> {
    let value = value.trim();
    if value.is_empty()
        || value.len() > 80
        || !value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | ':' | '.'))
    {
        anyhow::bail!("invalid team policy name: {value}");
    }
    Ok(value.to_string())
}

fn is_valid_env_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name
            .chars()
            .all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
        && name
            .chars()
            .next()
            .is_some_and(|ch| ch == '_' || ch.is_ascii_alphabetic())
}

fn slugify(project: &str) -> String {
    project
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
                ch
            } else {
                '-'
            }
        })
        .collect::<String>()
        .trim_matches('-')
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    struct WardHomeGuard {
        previous: Option<std::ffi::OsString>,
    }

    impl WardHomeGuard {
        fn set(path: &std::path::Path) -> Self {
            let previous = std::env::var_os("WARD_HOME");
            std::env::set_var("WARD_HOME", path);
            Self { previous }
        }
    }

    impl Drop for WardHomeGuard {
        fn drop(&mut self) {
            match &self.previous {
                Some(value) => std::env::set_var("WARD_HOME", value),
                None => std::env::remove_var("WARD_HOME"),
            }
        }
    }

    #[test]
    #[serial]
    fn missing_team_record_returns_local_owner_default() {
        let home = tempfile::tempdir().unwrap();
        let _guard = WardHomeGuard::set(home.path());
        let record = load_or_default("demo").unwrap();
        assert_eq!(record.project, "demo");
        assert_eq!(record.members.len(), 1);
        assert!(can_manage(&record, &current_member_id()));
    }

    #[test]
    #[serial]
    fn team_records_store_policy_metadata_without_secret_values() {
        let home = tempfile::tempdir().unwrap();
        let _guard = WardHomeGuard::set(home.path());
        let mut record = default_record("demo");
        upsert_member(
            &mut record,
            TeamMemberInput {
                id: "dev@example.com".to_string(),
                name: Some("Developer".to_string()),
                role: Some(TeamRole::Developer),
                agents: vec!["codex".to_string()],
            },
            None,
        )
        .unwrap();
        upsert_policy(
            &mut record,
            TeamPolicyInput {
                name: "codex-dev".to_string(),
                member_id: Some("dev@example.com".to_string()),
                agents: vec!["codex".to_string()],
                profiles: vec!["dev".to_string()],
                env: vec!["API_KEY".to_string()],
            },
            None,
        )
        .unwrap();
        write_record(&record).unwrap();
        let serialized = fs::read_to_string(record_path("demo")).unwrap();
        assert!(serialized.contains("API_KEY"));
        assert!(serialized.contains("codex"));
        assert!(!serialized.contains("super-secret-value"));
    }

    #[test]
    #[serial]
    fn invalid_team_names_are_rejected() {
        let mut record = default_record("demo");
        assert!(upsert_member(
            &mut record,
            TeamMemberInput {
                id: "bad id".to_string(),
                name: None,
                role: None,
                agents: Vec::new(),
            },
            None,
        )
        .is_err());
        assert!(upsert_policy(
            &mut record,
            TeamPolicyInput {
                name: "bad name".to_string(),
                member_id: None,
                agents: vec!["codex".to_string()],
                profiles: vec!["dev".to_string()],
                env: vec!["API_KEY".to_string()],
            },
            None,
        )
        .is_err());
    }
}
