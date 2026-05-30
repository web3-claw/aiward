use std::{
    env, fs,
    io::IsTerminal,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use serde::Serialize;
use serde_json::Value;

use crate::{
    agents, anomaly,
    approvals::{self, ApprovalDecision, ApprovalScope},
    broker, config, context, detection, env_file, git_context, grants,
    logs::{self as audit_logs, LogKind},
    modes, pending_requests,
    policy::{self, AccessRequest, ApprovalMode},
    registry,
    runner::{self, RunCommandRequest},
    unlock, vault, worktrees,
};

#[derive(Debug)]
pub struct ChildExit {
    code: i32,
}

impl ChildExit {
    pub fn new(code: i32) -> Self {
        Self { code }
    }

    pub fn exit_code(&self) -> u8 {
        u8::try_from(self.code).unwrap_or(1)
    }
}

impl std::fmt::Display for ChildExit {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "child process exited with {}", self.code)
    }
}

impl std::error::Error for ChildExit {}

#[derive(Debug, Parser)]
#[command(
    name = "ward",
    version,
    about = "AI secret firewall for local development"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Initialize, import, register, and create short profiles.
    Setup {
        #[arg(long)]
        yes: bool,
        #[arg(long)]
        project: Option<String>,
        #[arg(long, default_value = ".env")]
        source: PathBuf,
        #[arg(long, default_value = config::DEFAULT_VAULT_FILE)]
        vault: PathBuf,
        #[arg(long)]
        commit_vault: bool,
        #[arg(long)]
        ignore_vault: bool,
        #[arg(long)]
        remove_plaintext: bool,
        #[arg(long)]
        keep_plaintext: bool,
        #[arg(long, default_value = "8h")]
        unlock_ttl: String,
        #[arg(long)]
        no_unlock: bool,
    },
    /// Create .ward.json and baseline local files.
    Init {
        #[arg(long)]
        project: Option<String>,
        #[arg(long)]
        force: bool,
        #[arg(long)]
        bare: bool,
    },
    /// Encrypt an existing dotenv file into .env.vault.
    Import {
        source: PathBuf,
        #[arg(long)]
        vault: Option<PathBuf>,
    },
    /// Register the current project in ~/.ward/registry.json.
    Register {
        project: String,
        #[arg(long)]
        path: Option<PathBuf>,
        #[arg(long)]
        vault: Option<PathBuf>,
    },
    /// Select an already registered project as the active project.
    Use { project: String },
    /// Manage globally registered Ward projects.
    Projects {
        #[command(subcommand)]
        command: ProjectsCommand,
    },
    /// Manage the current project's dotenv vault and locked .env file.
    Env {
        #[command(subcommand)]
        command: EnvCommand,
    },
    /// Request scoped secret access without running a command.
    Request {
        #[arg(long)]
        profile: Option<String>,
        #[arg(long)]
        agent: Option<String>,
        #[arg(long)]
        agent_key_id: Option<String>,
        #[arg(long)]
        worktree: Option<PathBuf>,
        #[arg(long)]
        git_remote: Option<String>,
        #[arg(long)]
        commit: Option<String>,
        #[arg(long)]
        branch: Option<String>,
        #[arg(long)]
        action: Option<String>,
        #[arg(long)]
        command: Option<String>,
        #[arg(long = "env")]
        env_names: Vec<String>,
        #[arg(long)]
        json: bool,
        #[arg(long)]
        no_prompt: bool,
    },
    /// Create an approval grant directly for a known safe command.
    Allow {
        #[arg(long)]
        profile: Option<String>,
        #[arg(long, value_enum)]
        scope: Option<ApprovalScope>,
        #[arg(long)]
        agent: Option<String>,
        #[arg(long)]
        branch: Option<String>,
        #[arg(long)]
        command: Option<String>,
        #[arg(long = "env")]
        env_names: Vec<String>,
    },
    /// Manage stored approval grants.
    Grants {
        #[command(subcommand)]
        command: GrantsCommand,
    },
    /// Approve a pending non-interactive request.
    Approve {
        request_id: uuid::Uuid,
        #[arg(long, value_enum)]
        scope: ApprovalScope,
        #[arg(long)]
        confirm_critical: bool,
        #[arg(long)]
        agent_mediated: bool,
        #[arg(long)]
        json: bool,
    },
    /// Deny a pending non-interactive request.
    Deny {
        request_id: uuid::Uuid,
        #[arg(long)]
        agent_mediated: bool,
        #[arg(long)]
        json: bool,
    },
    /// Run a command with only approved env vars injected.
    Run {
        #[arg(long)]
        profile: Option<String>,
        #[arg(long)]
        project: Option<String>,
        #[arg(long)]
        agent: Option<String>,
        #[arg(long)]
        agent_key_id: Option<String>,
        #[arg(long)]
        worktree: Option<PathBuf>,
        #[arg(long)]
        git_remote: Option<String>,
        #[arg(long)]
        commit: Option<String>,
        #[arg(long)]
        branch: Option<String>,
        #[arg(long)]
        action: Option<String>,
        #[arg(long = "env")]
        env_names: Vec<String>,
        #[arg(long)]
        json: bool,
        #[arg(long)]
        no_prompt: bool,
        #[arg(
            last = true,
            help = "Child command and args after --. Put all Ward flags before --."
        )]
        command: Vec<String>,
    },
    /// Run the dev profile.
    Dev {
        #[arg(long)]
        agent: Option<String>,
        #[arg(long)]
        agent_key_id: Option<String>,
        #[arg(long)]
        worktree: Option<PathBuf>,
        #[arg(long)]
        git_remote: Option<String>,
        #[arg(long)]
        commit: Option<String>,
        #[arg(long)]
        branch: Option<String>,
        #[arg(long)]
        json: bool,
        #[arg(long)]
        no_prompt: bool,
    },
    /// Run the migrate profile.
    Migrate {
        #[arg(long)]
        agent: Option<String>,
        #[arg(long)]
        agent_key_id: Option<String>,
        #[arg(long)]
        worktree: Option<PathBuf>,
        #[arg(long)]
        git_remote: Option<String>,
        #[arg(long)]
        commit: Option<String>,
        #[arg(long)]
        branch: Option<String>,
        #[arg(long)]
        json: bool,
        #[arg(long)]
        no_prompt: bool,
    },
    /// Validate the current Ward setup.
    Doctor,
    /// Inspect and control the local Ward broker.
    Broker {
        #[command(subcommand)]
        command: BrokerCommand,
    },
    /// Manage trusted project worktrees.
    Worktrees {
        #[command(subcommand)]
        command: WorktreesCommand,
    },
    /// Print encrypted audit log paths.
    Logs {
        #[command(subcommand)]
        command: Option<LogsCommand>,
        #[arg(value_enum)]
        kind: Option<LogKind>,
    },
    /// Safely edit the encrypted env vault.
    Edit,
    /// Create a short-lived run unlock session.
    Unlock {
        #[arg(long, default_value = "8h")]
        ttl: String,
        /// Activate a named session mode after unlocking (must be pushed first via `ward modes push`).
        #[arg(long)]
        mode: Option<String>,
    },
    /// Manage session mode permission envelopes.
    Modes {
        #[command(subcommand)]
        command: ModesCommand,
    },
    /// Clear unlock sessions and revoke session-scoped approval grants.
    Lock,
    /// Export plaintext env and remove Ward files from a project.
    Teardown {
        #[arg(long)]
        project: Option<String>,
        #[arg(long = "export", default_value = ".env.export")]
        export_path: PathBuf,
        #[arg(long)]
        yes: bool,
        #[arg(long)]
        restore_env: bool,
    },
    #[cfg(all(coverage, not(test)))]
    #[command(hide = true, name = "__coverage")]
    Coverage,
    #[command(hide = true, name = "__broker")]
    BrokerServe,
    /// Activate human mode for this terminal window.
    Human {
        /// Unlock duration (e.g. 8h, 30m).
        #[arg(long, default_value = "8h")]
        ttl: String,
    },
    #[command(hide = true, name = "__human-guardian")]
    HumanGuardian {
        #[arg(long)]
        shell_pid: u32,
        #[arg(long)]
        session_token: String,
        #[arg(long)]
        ttl_seconds: i64,
    },
}

#[derive(Debug, Subcommand)]
pub enum ProjectsCommand {
    /// List globally registered projects.
    List,
    /// Show one registered project, or the resolved current project.
    Show { project: Option<String> },
    /// Register a project in the global registry.
    Register {
        project: String,
        #[arg(long)]
        path: Option<PathBuf>,
        #[arg(long)]
        vault: Option<PathBuf>,
    },
    /// Select an already registered project as active.
    Use { project: String },
    /// Remove a project from the global registry.
    Remove { project: String },
}

#[derive(Debug, Subcommand)]
pub enum BrokerCommand {
    /// Print broker status.
    Status,
    /// Stop the broker if it is running.
    Stop,
    /// Print the broker Unix socket path.
    SocketPath,
}

#[derive(Debug, Subcommand)]
pub enum WorktreesCommand {
    /// List trusted and pending worktrees for a project.
    List {
        #[arg(long)]
        project: String,
    },
    /// Allow worktrees under a root folder for a project.
    AllowRoot {
        #[arg(long)]
        project: String,
        path: PathBuf,
    },
    /// Remove an allowed worktree root for a project.
    RemoveRoot {
        #[arg(long)]
        project: String,
        path: PathBuf,
    },
    /// Approve a pending worktree binding.
    Approve {
        request_id: uuid::Uuid,
        #[arg(long)]
        json: bool,
    },
    /// Deny a pending worktree binding.
    Deny {
        request_id: uuid::Uuid,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Subcommand)]
pub enum EnvCommand {
    /// List env names in the encrypted vault.
    List {
        #[arg(long)]
        project: Option<String>,
    },
    /// Set one encrypted env value with KEY=value syntax.
    Set {
        #[arg(long)]
        project: Option<String>,
        assignment: String,
    },
    /// Remove one encrypted env value.
    Unset {
        #[arg(long)]
        project: Option<String>,
        key: String,
    },
    /// Write plaintext .env for manual local development.
    Unlock {
        #[arg(long)]
        project: Option<String>,
        #[arg(long, default_value = ".env")]
        output: PathBuf,
        #[arg(long)]
        force: bool,
    },
    /// Re-encrypt a plaintext .env and restore the locked marker file.
    Lock {
        #[arg(long)]
        project: Option<String>,
        #[arg(long, default_value = ".env")]
        source: PathBuf,
    },
    /// Export plaintext dotenv contents.
    Export {
        #[arg(long)]
        project: Option<String>,
        #[arg(long)]
        output: Option<PathBuf>,
        #[arg(long)]
        force: bool,
        #[arg(long)]
        unsafe_stdout: bool,
    },
}

#[derive(Debug, Subcommand)]
pub enum GrantsCommand {
    /// List stored approval grants.
    List,
    /// Revoke one approval grant by id.
    Revoke { grant_id: uuid::Uuid },
    /// Remove expired grants.
    Prune,
}

#[derive(Debug, Subcommand)]
pub enum LogsCommand {
    /// Decrypt and print one encrypted log kind.
    View {
        #[arg(value_enum)]
        kind: LogKind,
    },
    /// Verify encrypted log hash chains.
    Verify {
        #[arg(value_enum)]
        kind: Option<LogKind>,
        #[arg(long)]
        full: bool,
    },
    /// Decrypt and write one encrypted log kind to a file.
    Export {
        #[arg(value_enum)]
        kind: LogKind,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        force: bool,
    },
    /// Temporarily unlock encrypted log viewing.
    Unlock {
        #[arg(long, default_value = "15m")]
        ttl: String,
    },
}

#[derive(Debug, Subcommand)]
pub enum ModesCommand {
    /// List modes defined in .ward.modes.json.
    List,
    /// Push local .ward.modes.json to broker vault (PIN required).
    Push {
        /// Apply globally across all projects.
        #[arg(long)]
        global: bool,
        /// Apply to a specific project by name.
        #[arg(long)]
        project: Option<String>,
    },
    /// Show the active session mode (if any).
    Status,
}

pub fn dispatch(cli: Cli) -> Result<()> {
    match cli.command {
        Commands::Setup {
            yes,
            project,
            source,
            vault,
            commit_vault,
            ignore_vault,
            remove_plaintext,
            keep_plaintext,
            unlock_ttl,
            no_unlock,
        } => setup(SetupOptions {
            yes,
            project,
            source,
            vault,
            commit_vault,
            ignore_vault,
            remove_plaintext,
            keep_plaintext,
            unlock_ttl,
            no_unlock,
        }),
        Commands::Init {
            project,
            force,
            bare,
        } => init(project, force, bare),
        Commands::Import { source, vault } => import(source, vault),
        Commands::Register {
            project,
            path,
            vault,
        } => register(project, path, vault),
        Commands::Use { project } => use_project(&project),
        Commands::Projects { command } => projects_command(command),
        Commands::Env { command } => env_command(command),
        Commands::Request {
            profile,
            agent,
            agent_key_id,
            worktree,
            git_remote,
            commit,
            branch,
            action,
            command,
            env_names,
            json,
            no_prompt,
        } => request(
            profile,
            AgentContextOptions {
                agent,
                agent_key_id,
                worktree,
                git_remote,
                commit,
                branch,
            },
            action,
            command,
            env_names,
            json,
            no_prompt,
        ),
        Commands::Allow {
            profile,
            scope,
            agent,
            branch,
            command,
            env_names,
        } => allow(profile, scope, agent, branch, command, env_names),
        Commands::Grants { command } => grants_command(command),
        Commands::Approve {
            request_id,
            scope,
            confirm_critical,
            agent_mediated,
            json,
        } => approve(request_id, scope, confirm_critical, agent_mediated, json),
        Commands::Deny {
            request_id,
            agent_mediated,
            json,
        } => deny(request_id, agent_mediated, json),
        Commands::Run {
            profile,
            project,
            agent,
            agent_key_id,
            worktree,
            git_remote,
            commit,
            branch,
            action,
            env_names,
            json,
            no_prompt,
            command,
        } => run_with_context(
            RunOptions {
                profile,
                project,
                agent: agent.clone(),
                branch: branch.clone(),
                action,
                env_names,
                command,
                json,
                no_prompt,
            },
            AgentContextOptions {
                agent,
                agent_key_id,
                worktree,
                git_remote,
                commit,
                branch,
            },
        ),
        Commands::Dev {
            agent,
            agent_key_id,
            worktree,
            git_remote,
            commit,
            branch,
            json,
            no_prompt,
        } => run_with_context(
            RunOptions {
                profile: Some("dev".to_string()),
                project: None,
                agent: agent.clone(),
                branch: branch.clone(),
                action: None,
                env_names: Vec::new(),
                command: Vec::new(),
                json,
                no_prompt,
            },
            AgentContextOptions {
                agent,
                agent_key_id,
                worktree,
                git_remote,
                commit,
                branch,
            },
        ),
        Commands::Migrate {
            agent,
            agent_key_id,
            worktree,
            git_remote,
            commit,
            branch,
            json,
            no_prompt,
        } => run_with_context(
            RunOptions {
                profile: Some("migrate".to_string()),
                project: None,
                agent: agent.clone(),
                branch: branch.clone(),
                action: None,
                env_names: Vec::new(),
                command: Vec::new(),
                json,
                no_prompt,
            },
            AgentContextOptions {
                agent,
                agent_key_id,
                worktree,
                git_remote,
                commit,
                branch,
            },
        ),
        Commands::Doctor => doctor(),
        Commands::Broker { command } => broker_command(command),
        Commands::Worktrees { command } => worktrees_command(command),
        Commands::Logs { command, kind } => logs(command, kind),
        Commands::Edit => edit(),
        Commands::Unlock { ttl, mode } => unlock_vault(&ttl, mode.as_deref()),
        Commands::Modes { command } => modes_command(command),
        Commands::Lock => lock(),
        Commands::Teardown {
            project,
            export_path,
            yes,
            restore_env,
        } => teardown(project, export_path, yes, restore_env),
        #[cfg(all(coverage, not(test)))]
        Commands::Coverage => coverage_exercise_cli_edges(),
        Commands::BrokerServe => broker::serve(),
        Commands::Human { ttl } => crate::human::activate_human_mode(&ttl),
        Commands::HumanGuardian {
            shell_pid,
            session_token,
            ttl_seconds,
        } => crate::human::serve_guardian(shell_pid, &session_token, ttl_seconds),
    }
}

#[derive(Serialize)]
struct VaultImportEvent<'a> {
    #[serde(rename = "type")]
    event_type: &'static str,
    project: &'a str,
    source: &'a Path,
    vault: &'a Path,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EnvFileEvent<'a> {
    #[serde(rename = "type")]
    event_type: &'static str,
    project: &'a str,
    vault: &'a Path,
    #[serde(skip_serializing_if = "Option::is_none")]
    env_file: Option<&'a Path>,
    #[serde(skip_serializing_if = "Option::is_none")]
    key: Option<&'a str>,
}

#[derive(Serialize)]
struct RequestEvent<'a> {
    access: &'a AccessRequest,
    policy: &'a policy::PolicyEvaluation,
    git: &'a git_context::GitContext,
    #[serde(skip_serializing_if = "Option::is_none")]
    verified_context: Option<&'a context::VerifiedContext>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ApprovalEvent<'a> {
    decision: &'a ApprovalDecision,
    persisted_grant: Option<uuid::Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    approval_receipt_hash: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    signer_key_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    signature_algorithm: Option<&'a str>,
    critical_confirmation: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    human_proof: Option<&'static str>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ExecutionStartedEvent<'a> {
    #[serde(rename = "type")]
    event_type: &'static str,
    project: &'a str,
    agent: &'a Option<String>,
    branch: &'a Option<String>,
    declared_action: &'a Option<String>,
    requested_command: &'a str,
    cwd: &'a Path,
    git: &'a git_context::GitContext,
    requested_env: &'a [String],
    injected_env: &'a [String],
    policy_findings: &'a [detection::Finding],
    approval_scope: ApprovalScope,
    approval_source: approvals::ApprovalSource,
    grant_id: Option<uuid::Uuid>,
    approval_receipt_hash: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    agent_key_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    verified_context: Option<&'a context::VerifiedContext>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ExecutionEvent<'a> {
    #[serde(rename = "type")]
    event_type: &'static str,
    project: &'a str,
    agent: &'a Option<String>,
    branch: &'a Option<String>,
    declared_action: &'a Option<String>,
    requested_command: &'a str,
    cwd: &'a Path,
    git: &'a git_context::GitContext,
    requested_env: &'a [String],
    injected_env: &'a [String],
    policy_findings: &'a [detection::Finding],
    approval_scope: ApprovalScope,
    approval_source: approvals::ApprovalSource,
    grant_id: Option<uuid::Uuid>,
    approval_receipt_hash: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    agent_key_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    verified_context: Option<&'a context::VerifiedContext>,
    outcome: &'a runner::RunCommandOutcome,
}

#[derive(Serialize)]
struct OutputRedactionEvent<'a> {
    #[serde(rename = "type")]
    event_type: &'static str,
    command: &'a str,
    count: usize,
    alerts: &'a [runner::OutputAlert],
}

#[derive(Serialize)]
struct VaultEditEvent<'a> {
    #[serde(rename = "type")]
    event_type: &'static str,
    project: &'a str,
    vault: &'a Path,
}

#[derive(Serialize)]
struct VaultUnlockEvent<'a> {
    #[serde(rename = "type")]
    event_type: &'static str,
    status: &'a str,
    project: &'a str,
    vault: &'a Path,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    expires_at: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct VaultLockEvent {
    #[serde(rename = "type")]
    event_type: &'static str,
    revoked_session_grants: usize,
    cleared_unlock_sessions: usize,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct LogsUnlockEvent<'a> {
    #[serde(rename = "type")]
    event_type: &'static str,
    project: &'a str,
    vault: &'a Path,
    expires_at: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TeardownEvent<'a> {
    #[serde(rename = "type")]
    event_type: &'static str,
    project: &'a str,
    export_path: &'a Path,
    removed_files: Vec<String>,
    removed_grants: usize,
    removed_pending_requests: usize,
    cleared_unlock_sessions: usize,
}

struct SetupOptions {
    yes: bool,
    project: Option<String>,
    source: PathBuf,
    vault: PathBuf,
    commit_vault: bool,
    ignore_vault: bool,
    remove_plaintext: bool,
    keep_plaintext: bool,
    unlock_ttl: String,
    no_unlock: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SetupEvent<'a> {
    #[serde(rename = "type")]
    event_type: &'static str,
    project: &'a str,
    source: &'a Path,
    vault: &'a Path,
    imported: bool,
    removed_plaintext: bool,
    locked_env: bool,
    committed_vault: bool,
    unlock_created: bool,
    unlock_expires_at: Option<String>,
}

struct RunOptions {
    profile: Option<String>,
    project: Option<String>,
    agent: Option<String>,
    branch: Option<String>,
    action: Option<String>,
    env_names: Vec<String>,
    command: Vec<String>,
    json: bool,
    no_prompt: bool,
}

#[derive(Debug, Clone, Default)]
struct AgentContextOptions {
    agent: Option<String>,
    agent_key_id: Option<String>,
    worktree: Option<PathBuf>,
    git_remote: Option<String>,
    commit: Option<String>,
    branch: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RunApprovalRequiredResponse<'a> {
    status: &'static str,
    unlock_required: bool,
    #[serde(flatten)]
    request: pending_requests::PendingRequestResponse<'a>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RunUnlockRequiredResponse<'a> {
    status: &'static str,
    approval_required: bool,
    unlock_required: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    unlock_reason: Option<&'a str>,
    project: &'a str,
    command: &'a str,
    env: &'a [String],
    findings: &'a [detection::Finding],
    risk: String,
    unlock_command: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RunDeniedResponse<'a> {
    status: &'static str,
    approval_required: bool,
    unlock_required: bool,
    project: &'a str,
    command: &'a str,
    env: &'a [String],
    findings: &'a [detection::Finding],
    risk: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RunVaultKeyMissingResponse<'a> {
    status: &'static str,
    approval_required: bool,
    unlock_required: bool,
    project: &'a str,
    command: &'a str,
    env: &'a [String],
    missing_env: Vec<String>,
    findings: &'a [detection::Finding],
    risk: String,
    message: &'static str,
    remediation: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct InvalidInvocationResponse {
    status: &'static str,
    reason: &'static str,
    message: &'static str,
    correct_example: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct WorktreeRequiredResponse<'a> {
    status: &'static str,
    project: &'a str,
    worktree: &'a Path,
    git_remote: &'a str,
    branch: &'a str,
    commit: &'a str,
    reason: &'a str,
    approve_command: String,
    deny_command: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct WorktreeBoundResponse<'a> {
    status: &'static str,
    project: &'a str,
    worktree: &'a Path,
    match_kind: &'a str,
    continued: bool,
}

#[derive(Debug, Clone)]
struct ResolvedProfile {
    command: String,
    command_args: Vec<String>,
    env_names: Vec<String>,
    action: Option<String>,
    default_scope: ApprovalScope,
}

fn setup(options: SetupOptions) -> Result<()> {
    if options.commit_vault && options.ignore_vault {
        anyhow::bail!("choose either --commit-vault or --ignore-vault");
    }
    if options.remove_plaintext && options.keep_plaintext {
        anyhow::bail!("choose either --remove-plaintext or --keep-plaintext");
    }
    if !options.no_unlock {
        unlock::parse_ttl(&options.unlock_ttl)?;
    }

    let cwd = env::current_dir()?;
    let commit_vault = !options.ignore_vault;
    let remove_plaintext = options.remove_plaintext && !options.keep_plaintext;
    let source_exists = options.source.exists();
    let vault_path = if options.vault.is_absolute() {
        options.vault.clone()
    } else {
        cwd.join(&options.vault)
    };
    let source_is_locked = if source_exists {
        env_file::is_locked_env_file(&options.source)?
    } else {
        false
    };

    if !source_exists && !vault_path.exists() {
        anyhow::bail!(
            "{} does not exist and {} is missing",
            options.source.display(),
            vault_path.display()
        );
    }

    let env_keys = if source_exists && !source_is_locked {
        config::env_keys_from_dotenv_file(&options.source)?
    } else if let Ok(existing) = config::read_project_config(&cwd) {
        let mut keys = std::collections::BTreeSet::new();
        for profile in existing.profiles.values() {
            keys.extend(profile.env.iter().cloned());
        }
        keys.into_iter().collect::<Vec<_>>()
    } else {
        Vec::new()
    };

    let mut project_config = match config::read_project_config(&cwd) {
        Ok(mut existing) => {
            existing.project = options.project.unwrap_or(existing.project);
            existing.vault = options.vault.clone();
            config::merge_default_profiles(&mut existing, &env_keys, &cwd);
            existing
        }
        Err(_) => {
            let mut created = config::ProjectConfig::default_for_dir(&cwd, options.project)?;
            created.vault = options.vault.clone();
            created.profiles = config::default_profiles(&env_keys, &cwd);
            created
        }
    };
    config::merge_default_profiles(&mut project_config, &env_keys, &cwd);

    let mut config_path = config::write_project_config(&cwd, &project_config, true)?;
    let env_example = config::ensure_env_example(&cwd)?;
    let agent_instructions = config::ensure_agent_instructions(&cwd, &project_config.project)?;
    let gitignore = config::ensure_gitignore(&cwd, commit_vault)?;

    let mut imported = false;
    let mut locked_env = false;
    let mut setup_passphrase = None;
    let mut verified_env_keys = None;
    if source_exists {
        if source_is_locked {
            if !vault_path.exists() {
                anyhow::bail!(
                    "{} is an Ward locked marker but {} is missing; restore a plaintext dotenv file or the vault before setup",
                    options.source.display(),
                    vault_path.display()
                );
            }
            env_file::lock_env_file(&options.source, &vault_path)?;
            locked_env = true;
        } else {
            let passphrase = vault::read_new_passphrase()?;
            vault::import_env_file(&options.source, &vault_path, &passphrase)?;
            let plaintext = vault::decrypt_vault_file(&vault_path, &passphrase)?;
            verified_env_keys = Some(config::env_keys_from_dotenv_str(&plaintext)?);
            setup_passphrase = Some(passphrase);
            imported = true;
            if !options.keep_plaintext && !remove_plaintext {
                env_file::lock_env_file(&options.source, &vault_path)?;
                locked_env = true;
            }
        }
    }

    if let Some(env_keys) = verified_env_keys.as_deref() {
        config::replace_default_profiles(&mut project_config, env_keys, &cwd);
        config_path = config::write_project_config(&cwd, &project_config, true)?;
    }

    registry::register_project(
        project_config.project.clone(),
        cwd.clone(),
        vault_path.clone(),
    )?;

    let mut removed_plaintext = false;
    if source_exists && !source_is_locked && remove_plaintext {
        fs::remove_file(&options.source)
            .context(format!("failed to remove {}", options.source.display()))?;
        removed_plaintext = true;
    }

    let unlock_session = if options.no_unlock {
        None
    } else {
        let passphrase = match setup_passphrase {
            Some(passphrase) => passphrase,
            None => vault::read_existing_passphrase()?,
        };
        match create_run_unlock_session(
            &project_config.project,
            &vault_path,
            &passphrase,
            &options.unlock_ttl,
            None,
        ) {
            Ok(session) => Some(session),
            Err(error) => {
                if error.to_string().contains("failed to decrypt vault") {
                    return Err(error);
                }
                println!(
                    "Warning: setup completed, but broker unlock failed: {error}. Run ward unlock --ttl {} before running protected commands.",
                    options.unlock_ttl
                );
                None
            }
        }
    };

    let event = SetupEvent {
        event_type: "setup.completed",
        project: &project_config.project,
        source: &options.source,
        vault: &vault_path,
        imported,
        removed_plaintext,
        locked_env,
        committed_vault: commit_vault,
        unlock_created: unlock_session.is_some(),
        unlock_expires_at: unlock_session
            .as_ref()
            .map(|session| session.expires_at.to_rfc3339()),
    };
    audit_logs::append_event(LogKind::Sessions, event)?;

    println!("Ward setup complete.");
    println!("Config: {}", config_path.display());
    println!("Vault: {}", vault_path.display());
    println!("Gitignore: {}", gitignore.display());
    if let Some(path) = env_example {
        println!("Env example: {}", path.display());
    }
    if let Some(path) = agent_instructions {
        println!("Agent instructions: {}", path.display());
    }
    if let Some(session) = &unlock_session {
        println!("Vault unlocked until {}.", session.expires_at.to_rfc3339());
        println!("Next: ward dev");
    } else {
        println!("Next: ward unlock --ttl {}", options.unlock_ttl);
        println!("Then: ward dev");
    }
    if locked_env {
        println!("Locked env: {}", options.source.display());
    }
    if options.keep_plaintext {
        println!("Warning: plaintext env was kept by --keep-plaintext.");
    }
    if options.yes {
        println!("Used setup defaults.");
    }
    Ok(())
}

fn init(project: Option<String>, force: bool, bare: bool) -> Result<()> {
    let cwd = env::current_dir()?;
    let source = cwd.join(".env");
    let vault_path = cwd.join(config::DEFAULT_VAULT_FILE);
    if !bare && (source.exists() || vault_path.exists()) {
        return setup(SetupOptions {
            yes: true,
            project,
            source: PathBuf::from(".env"),
            vault: PathBuf::from(config::DEFAULT_VAULT_FILE),
            commit_vault: false,
            ignore_vault: false,
            remove_plaintext: false,
            keep_plaintext: false,
            unlock_ttl: "8h".to_string(),
            no_unlock: false,
        });
    }

    init_bare(project, force)
}

fn init_bare(project: Option<String>, force: bool) -> Result<()> {
    let cwd = env::current_dir()?;
    let config = config::ProjectConfig::default_for_dir(&cwd, project)?;
    let config_path = config::write_project_config(&cwd, &config, force)?;
    let env_example = config::ensure_env_example(&cwd)?;
    let agent_instructions = config::ensure_agent_instructions(&cwd, &config.project)?;

    println!("Created {}", config_path.display());
    if let Some(path) = env_example {
        println!("Created or updated {}", path.display());
    }
    if let Some(path) = agent_instructions {
        println!("Created or updated {}", path.display());
    }
    if cwd.join(".env").exists() {
        println!("Warning: plaintext .env exists. Run ward import .env, then remove .env.");
    }

    Ok(())
}

fn import(source: PathBuf, explicit_vault: Option<PathBuf>) -> Result<()> {
    let cwd = env::current_dir()?;
    let mut config = config::read_project_config(&cwd)
        .context("missing .ward.json; run ward init first")?;
    let vault_path = match explicit_vault {
        Some(vault) => {
            config.vault = vault.clone();
            config::write_project_config(&cwd, &config, true)?;
            if vault.is_absolute() {
                vault
            } else {
                cwd.join(vault)
            }
        }
        None => config::resolve_vault_path(&cwd, &config),
    };
    if env_file::is_locked_env_file(&source)? {
        anyhow::bail!(
            "{} is already an Ward locked marker; use ward env unlock to restore plaintext before importing",
            source.display()
        );
    }
    let passphrase = vault::read_new_passphrase()?;

    let written = vault::import_env_file(&source, &vault_path, &passphrase)?;
    vault::decrypt_vault_file(&written, &passphrase)?;
    env_file::lock_env_file(&source, &written)?;
    let event = VaultImportEvent {
        event_type: "vault.import",
        project: &config.project,
        source: &source,
        vault: &written,
    };
    audit_logs::append_event(LogKind::Sessions, event)?;

    println!("Created encrypted vault {}", written.display());
    println!("Locked {}", source.display());
    Ok(())
}

fn register(project: String, path: Option<PathBuf>, explicit_vault: Option<PathBuf>) -> Result<()> {
    let cwd = env::current_dir()?;
    let project_path = path.unwrap_or(cwd.clone());
    let vault_path = match explicit_vault {
        Some(vault) if vault.is_absolute() => vault,
        Some(vault) => project_path.join(vault),
        None => {
            let project_config = config::read_project_config(&project_path)
                .context("missing .ward.json; run ward init first")?;
            config::resolve_vault_path(&project_path, &project_config)
        }
    };

    let registered = registry::register_project(project.clone(), project_path, vault_path)?;
    println!("Registered {project}");
    println!("Path: {}", registered.path.display());
    println!("Vault: {}", registered.vault.display());
    Ok(())
}

fn use_project(project: &str) -> Result<()> {
    registry::set_active_project(project)?;
    println!("Active Ward project: {project}");
    Ok(())
}

fn projects_command(command: ProjectsCommand) -> Result<()> {
    match command {
        ProjectsCommand::List => {
            let registry = registry::list_projects()?;
            for (name, project) in registry.projects {
                let active = if registry.active_project.as_deref() == Some(name.as_str()) {
                    "*"
                } else {
                    " "
                };
                println!(
                    "{active} {name} path={} vault={}",
                    project.path.display(),
                    project.vault.display()
                );
            }
        }
        ProjectsCommand::Show { project } => {
            let cwd = env::current_dir()?;
            let resolved = registry::resolve_project(project.as_deref(), &cwd)?;
            println!("Project: {}", resolved.name);
            println!("Path: {}", resolved.path.display());
            println!("Vault: {}", resolved.vault.display());
        }
        ProjectsCommand::Register {
            project,
            path,
            vault,
        } => register(project, path, vault)?,
        ProjectsCommand::Use { project } => use_project(&project)?,
        ProjectsCommand::Remove { project } => {
            if registry::remove_project(&project)? {
                println!("Removed project {project}");
            } else {
                println!("Project not found: {project}");
            }
        }
    }
    Ok(())
}

fn broker_command(command: BrokerCommand) -> Result<()> {
    match command {
        BrokerCommand::Status => {
            let status = broker::status()?;
            println!("{}", serde_json::to_string_pretty(&status)?);
        }
        BrokerCommand::Stop => {
            broker::stop()?;
            println!("Ward broker stopped.");
        }
        BrokerCommand::SocketPath => println!("{}", broker::socket_path().display()),
    }
    Ok(())
}

fn worktrees_command(command: WorktreesCommand) -> Result<()> {
    match command {
        WorktreesCommand::List { project } => {
            let state = worktrees::list_project(&project)?;
            println!("{}", serde_json::to_string_pretty(&state)?);
        }
        WorktreesCommand::AllowRoot { project, path } => {
            let root = worktrees::allow_root(&project, &path)?;
            println!("Allowed worktree root for {project}: {}", root.display());
        }
        WorktreesCommand::RemoveRoot { project, path } => {
            if worktrees::remove_root(&project, &path)? {
                println!("Removed worktree root for {project}: {}", path.display());
            } else {
                println!("Worktree root not found for {project}: {}", path.display());
            }
        }
        WorktreesCommand::Approve { request_id, json } => {
            if let Some(worktree) = worktrees::approve_pending(request_id)? {
                if json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&serde_json::json!({
                            "status": "approved",
                            "requestId": request_id,
                            "worktree": worktree.path,
                        }))?
                    );
                    return Ok(());
                }
                println!("Approved worktree {}", worktree.path.display());
            } else {
                if json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&serde_json::json!({
                            "status": "not_found",
                            "requestId": request_id,
                        }))?
                    );
                    return Ok(());
                }
                println!("Worktree request not found: {request_id}");
            }
        }
        WorktreesCommand::Deny { request_id, json } => {
            if worktrees::deny_pending(request_id)? {
                if json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&serde_json::json!({
                            "status": "denied",
                            "requestId": request_id,
                        }))?
                    );
                    return Ok(());
                }
                println!("Denied worktree request {request_id}");
            } else {
                if json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&serde_json::json!({
                            "status": "not_found",
                            "requestId": request_id,
                        }))?
                    );
                    return Ok(());
                }
                println!("Worktree request not found: {request_id}");
            }
        }
    }
    Ok(())
}

fn env_command(command: EnvCommand) -> Result<()> {
    match command {
        EnvCommand::List { project } => {
            let resolved = resolve_env_project(project.as_deref())?;
            let passphrase = vault::read_existing_passphrase()?;
            for name in env_file::list_env_names(&resolved.vault, &passphrase)? {
                println!("{name}");
            }
        }
        EnvCommand::Set {
            project,
            assignment,
        } => {
            let resolved = resolve_env_project(project.as_deref())?;
            let passphrase = vault::read_existing_passphrase()?;
            let key = env_file::set_env_value(&resolved.vault, &passphrase, &assignment)?;
            env_file::refresh_locked_env(&resolved.path, &resolved.vault)?;
            log_env_file_event("env.set", &resolved, None, Some(&key))?;
            println!("Set encrypted env {key}");
        }
        EnvCommand::Unset { project, key } => {
            let resolved = resolve_env_project(project.as_deref())?;
            let passphrase = vault::read_existing_passphrase()?;
            let removed = env_file::unset_env_value(&resolved.vault, &passphrase, &key)?;
            env_file::refresh_locked_env(&resolved.path, &resolved.vault)?;
            log_env_file_event("env.unset", &resolved, None, Some(&key))?;
            if removed {
                println!("Removed encrypted env {key}");
            } else {
                println!("Encrypted env not found: {key}");
            }
        }
        EnvCommand::Unlock {
            project,
            output,
            force,
        } => {
            let resolved = resolve_env_project(project.as_deref())?;
            let output = project_relative_path(&resolved.path, output);
            let passphrase = vault::read_existing_passphrase()?;
            env_file::unlock_env_file(&output, &resolved.vault, &passphrase, force)?;
            log_env_file_event("env.unlock", &resolved, Some(&output), None)?;
            println!("Wrote plaintext env {}", output.display());
            println!("Run ward env lock when you are done.");
        }
        EnvCommand::Lock { project, source } => {
            let resolved = resolve_env_project(project.as_deref())?;
            let source = project_relative_path(&resolved.path, source);
            let active_broker_expires_at =
                broker::active_session_expiry(&resolved.name, &resolved.vault)?;
            let passphrase = vault::read_existing_passphrase()?;
            env_file::lock_plaintext_source(&source, &resolved.vault, &passphrase)?;
            log_env_file_event("env.lock", &resolved, Some(&source), None)?;
            println!("Re-encrypted vault and locked {}", source.display());
            refresh_broker_after_env_lock(&resolved, &passphrase, active_broker_expires_at)?;
        }
        EnvCommand::Export {
            project,
            output,
            force,
            unsafe_stdout,
        } => {
            let resolved = resolve_env_project(project.as_deref())?;
            let passphrase = vault::read_existing_passphrase()?;
            if unsafe_stdout {
                let plaintext = vault::decrypt_vault_file(&resolved.vault, &passphrase)?;
                vault::validate_dotenv(&plaintext)?;
                print!("{plaintext}");
                log_env_file_event("env.export.stdout", &resolved, None, None)?;
            } else {
                let output_path = match output {
                    Some(path) => path,
                    None => ".env.export".into(),
                };
                let output = project_relative_path(&resolved.path, output_path);
                env_file::export_env_file(&output, &resolved.vault, &passphrase, force)?;
                log_env_file_event("env.export", &resolved, Some(&output), None)?;
                println!("Exported plaintext env {}", output.display());
            }
        }
    }
    Ok(())
}

fn resolve_env_project(project: Option<&str>) -> Result<registry::ResolvedProject> {
    let cwd = env::current_dir()?;
    registry::resolve_project(project, &cwd)
}

fn project_relative_path(project_path: &Path, path: PathBuf) -> PathBuf {
    if path.is_absolute() {
        path
    } else {
        project_path.join(path)
    }
}

fn log_env_file_event(
    event_type: &'static str,
    resolved: &registry::ResolvedProject,
    env_file: Option<&Path>,
    key: Option<&str>,
) -> Result<()> {
    let event = EnvFileEvent {
        event_type,
        project: &resolved.name,
        vault: &resolved.vault,
        env_file,
        key,
    };
    audit_logs::append_event(LogKind::Sessions, event)
}

fn refresh_broker_after_env_lock(
    resolved: &registry::ResolvedProject,
    passphrase: &str,
    active_broker_expires_at: Option<chrono::DateTime<chrono::Utc>>,
) -> Result<()> {
    let Some(expires_at) = active_broker_expires_at else {
        println!(
            "No active agent unlock session. Run ward unlock --ttl 8h if agents need access."
        );
        return Ok(());
    };
    let Some(ttl) = remaining_session_ttl(expires_at, chrono::Utc::now()) else {
        println!(
            "No active agent unlock session. Run ward unlock --ttl 8h if agents need access."
        );
        return Ok(());
    };

    if let Err(error) = broker::unlock_project(&resolved.name, &resolved.vault, passphrase, ttl) {
        eprintln!(
            "Warning: .env was locked, but Ward could not refresh the active agent unlock session: {error}"
        );
        anyhow::bail!("active agent unlock session refresh failed; run ward unlock --ttl 8h");
    }

    println!(
        "Refreshed active agent unlock session until {}.",
        expires_at.to_rfc3339()
    );
    Ok(())
}

fn remaining_session_ttl(
    expires_at: chrono::DateTime<chrono::Utc>,
    now: chrono::DateTime<chrono::Utc>,
) -> Option<chrono::Duration> {
    let ttl = expires_at.signed_duration_since(now);
    (ttl.num_seconds() > 0).then_some(ttl)
}

fn verified_no_prompt_context(
    cwd: &Path,
    resolved: &registry::ResolvedProject,
    context_options: &AgentContextOptions,
) -> Result<Option<context::VerifiedContext>> {
    let Some(agent_name) = context_options.agent.as_deref() else {
        let problem = context::ContextProblem::ContextRequired {
            missing: vec!["agent"],
        };
        println!("{}", context::context_problem_json(&problem)?);
        return Ok(None);
    };
    let agent = agents::ensure_agent(&resolved.name, agent_name)?;
    if let Some(claimed_key) = context_options.agent_key_id.as_deref() {
        if claimed_key != agent.agent_key_id {
            let problem = context::ContextProblem::ContextMismatch {
                field: "agentKeyId",
                claimed: claimed_key.to_string(),
                actual: agent.agent_key_id,
            };
            println!("{}", context::context_problem_json(&problem)?);
            return Ok(None);
        }
    }
    let claimed = context::ClaimedContext {
        agent: context_options.agent.clone(),
        agent_key_id: Some(agent.agent_key_id.clone()),
        worktree: context_options.worktree.clone(),
        branch: context_options.branch.clone(),
        git_remote: context_options.git_remote.clone(),
        commit: context_options.commit.clone(),
    };
    match context::verify_no_prompt_context(&claimed, cwd, resolved, agent.agent_key_id) {
        Ok(verified) => Ok(Some(verified)),
        Err(problem) => {
            println!("{}", context::context_problem_json(&problem)?);
            Ok(None)
        }
    }
}

fn enforce_worktree_for_no_prompt(
    resolved: &registry::ResolvedProject,
    verified: &context::VerifiedContext,
) -> Result<bool> {
    let registry = registry::load_registry()?;
    let Some(registered) = registry.projects.get(&resolved.name) else {
        return Ok(true);
    };
    match worktrees::evaluate_worktree(registered, &resolved.name, verified)? {
        worktrees::WorktreeDecision::Trusted { .. } => Ok(true),
        worktrees::WorktreeDecision::AutoBound { match_kind } => {
            let response = WorktreeBoundResponse {
                status: "worktree_bound",
                project: &resolved.name,
                worktree: &verified.worktree,
                match_kind: &match_kind,
                continued: true,
            };
            println!("{}", serde_json::to_string_pretty(&response)?);
            Ok(true)
        }
        worktrees::WorktreeDecision::ApprovalRequired { request } => {
            let response = WorktreeRequiredResponse {
                status: "worktree_approval_required",
                project: &resolved.name,
                worktree: &request.path,
                git_remote: &request.git_remote,
                branch: &request.branch,
                commit: &request.commit,
                reason: &request.reason,
                approve_command: format!("ward worktrees approve {}", request.id),
                deny_command: format!("ward worktrees deny {}", request.id),
            };
            println!("{}", serde_json::to_string_pretty(&response)?);
            Ok(false)
        }
        worktrees::WorktreeDecision::Denied { reason } => {
            let response = serde_json::json!({
                "status": "worktree_denied",
                "project": resolved.name,
                "worktree": verified.worktree,
                "reason": reason,
            });
            println!("{}", serde_json::to_string_pretty(&response)?);
            Ok(false)
        }
    }
}

fn request(
    profile: Option<String>,
    context_options: AgentContextOptions,
    action: Option<String>,
    command: Option<String>,
    env_names: Vec<String>,
    json: bool,
    no_prompt: bool,
) -> Result<()> {
    let cwd = env::current_dir()?;
    let resolved = registry::resolve_project(None, &cwd)?;
    let config = config::read_project_config(&resolved.path)?;
    let git = git_context::collect_git_context(&cwd);
    let branch = context_options.branch.clone().or(git.branch.clone());
    let resolved_profile =
        resolve_profile(&config, profile.as_deref(), action, command, env_names)?;
    let access = AccessRequest {
        project: resolved.name.clone(),
        agent: context_options.agent.clone(),
        branch,
        action: resolved_profile.action,
        command: resolved_profile.command,
        env: resolved_profile.env_names,
    };
    let evaluation = evaluate_access(&config, &access);

    if no_prompt {
        if !json {
            anyhow::bail!("--no-prompt requires --json");
        }
        let Some(verified_context) = verified_no_prompt_context(&cwd, &resolved, &context_options)?
        else {
            return Ok(());
        };
        if !enforce_worktree_for_no_prompt(&resolved, &verified_context)? {
            return Ok(());
        }
        let pending =
            create_run_pending_request(&access, &evaluation, &git, Some(verified_context))?;
        let request_event = RequestEvent {
            access: &pending.access,
            policy: &pending.policy,
            git: &pending.git,
            verified_context: pending.verified_context.as_ref(),
        };
        audit_logs::append_event(LogKind::Requests, request_event)?;
        let response = serde_json::to_string_pretty(&pending_requests::response_for(&pending))?;
        println!("{response}");
        return Ok(());
    }

    let decision = decide_access(&access, &evaluation, true)?;
    let critical_confirmation = critical_confirmation_for_decision(&decision, &evaluation);
    let receipt_context = Some(grants::GrantReceiptContext::synthetic(
        critical_confirmation,
    ));
    let persisted_grant =
        grants::persist_grant(&access, &decision, &resolved.vault, receipt_context)?;
    let receipt = persisted_grant
        .as_ref()
        .and_then(|grant| grant.receipt.as_ref());

    let request_event = RequestEvent {
        access: &access,
        policy: &evaluation,
        git: &git,
        verified_context: None,
    };
    let approval_event = ApprovalEvent {
        decision: &decision,
        persisted_grant: persisted_grant.as_ref().map(|grant| grant.id),
        approval_receipt_hash: receipt.map(|receipt| receipt.payload_hash.as_str()),
        signer_key_id: receipt.map(|receipt| receipt.signer_key_id.as_str()),
        signature_algorithm: receipt.map(|receipt| receipt.signature_algorithm.as_str()),
        critical_confirmation,
        human_proof: approval_human_proof(decision.source),
    };
    audit_logs::append_event(LogKind::Requests, request_event)?;
    audit_logs::append_event(LogKind::Approvals, &approval_event)?;

    if json {
        println!("{}", serde_json::to_string_pretty(&approval_event)?);
    } else if decision.approved {
        println!("Approved: {}", decision.approved_env.join(", "));
    } else {
        println!("Denied");
    }

    Ok(())
}

fn allow(
    profile: Option<String>,
    scope: Option<ApprovalScope>,
    agent: Option<String>,
    branch: Option<String>,
    command: Option<String>,
    env_names: Vec<String>,
) -> Result<()> {
    let cwd = env::current_dir()?;
    let resolved = registry::resolve_project(None, &cwd)?;
    let config = config::read_project_config(&resolved.path)?;
    let resolved_profile = resolve_profile(
        &config,
        profile.as_deref(),
        Some("Manual allow grant".to_string()),
        command,
        env_names,
    )?;
    let scope = match scope {
        Some(scope) => scope,
        None if profile.is_some() => resolved_profile.default_scope,
        None => anyhow::bail!("--scope is required unless --profile is used"),
    };
    if matches!(scope, ApprovalScope::Once | ApprovalScope::Deny) {
        anyhow::bail!("ward allow supports session, branch, and always scopes");
    }

    let git = git_context::collect_git_context(&cwd);
    let branch = branch.or(git.branch.clone());
    let access = AccessRequest {
        project: resolved.name,
        agent,
        branch,
        action: resolved_profile.action,
        command: resolved_profile.command,
        env: resolved_profile.env_names,
    };
    let evaluation = evaluate_access(&config, &access);
    if detection::has_critical_findings(&evaluation.findings) {
        anyhow::bail!(
            "critical exploit findings cannot be stored as durable allow grants; use ward request and approve once with --confirm-critical"
        );
    }
    approvals::validate_scope_for_findings(scope, &evaluation.findings)?;
    let receipt_context = Some(grants::GrantReceiptContext::synthetic(false));
    let source = approvals::ApprovalSource::ManualAllow;
    let grant =
        grants::persist_manual_grant(&access, scope, source, &resolved.vault, receipt_context)?;
    let receipt = grant.receipt.as_ref();
    let mut decision = grants::approval_from_grant(&access, &grant);
    decision.source = approvals::ApprovalSource::ManualAllow;
    let approval_event = ApprovalEvent {
        decision: &decision,
        persisted_grant: Some(grant.id),
        approval_receipt_hash: receipt.map(|receipt| receipt.payload_hash.as_str()),
        signer_key_id: receipt.map(|receipt| receipt.signer_key_id.as_str()),
        signature_algorithm: receipt.map(|receipt| receipt.signature_algorithm.as_str()),
        critical_confirmation: false,
        human_proof: approval_human_proof(decision.source),
    };
    audit_logs::append_event(LogKind::Approvals, approval_event)?;
    println!("Created {} grant {}", scope, grant.id);
    Ok(())
}

fn grants_command(command: GrantsCommand) -> Result<()> {
    match command {
        GrantsCommand::List => {
            for grant in grants::load_grants()? {
                let expires = match grant.expires_at {
                    Some(value) => value.to_rfc3339(),
                    None => "-".to_string(),
                };
                let status =
                    grant_status_label(grants::grant_integrity_status(&grant, chrono::Utc::now()));
                let receipt_hash = grant
                    .receipt
                    .as_ref()
                    .map(|receipt| receipt.payload_hash.as_str())
                    .unwrap_or("-");
                println!(
                    "{} scope={:?} status={} project={} command=\"{}\" env={} agent={} branch={} expires={} receipt={}",
                    grant.id,
                    grant.scope,
                    status,
                    grant.project,
                    grant.command,
                    grant.approved_env.join(","),
                    grant.agent.as_deref().unwrap_or("-"),
                    grant.branch.as_deref().unwrap_or("-"),
                    expires,
                    receipt_hash,
                );
            }
        }
        GrantsCommand::Revoke { grant_id } => {
            if grants::revoke_grant(grant_id)? {
                println!("Revoked grant {grant_id}");
            } else {
                println!("Grant not found: {grant_id}");
            }
        }
        GrantsCommand::Prune => {
            let pruned = grants::prune_expired_grants()?;
            println!("Pruned {pruned} expired grant(s).");
        }
    }
    Ok(())
}

fn approve(
    request_id: uuid::Uuid,
    scope: ApprovalScope,
    confirm_critical: bool,
    agent_mediated: bool,
    json: bool,
) -> Result<()> {
    match approve_inner(request_id, scope, confirm_critical, agent_mediated) {
        Ok(response) => {
            if json {
                println!("{}", serde_json::to_string_pretty(&response)?);
            } else {
                println!("Approved request {request_id}: grant {}", response.grant_id);
            }
            Ok(())
        }
        Err(error) if json && is_unlock_or_signing_error(&error) => {
            print_unlock_required_json(error.to_string())?;
            Ok(())
        }
        Err(error) if json => {
            if print_pending_request_error_json(request_id, &error)? {
                Ok(())
            } else {
                Err(error)
            }
        }
        Err(error) => Err(error),
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ApproveJsonResponse {
    status: &'static str,
    request_id: uuid::Uuid,
    project: String,
    grant_id: uuid::Uuid,
    approval_receipt_hash: Option<String>,
    signer_key_id: Option<String>,
    signature_algorithm: Option<String>,
    approval_source: approvals::ApprovalSource,
}

fn approve_inner(
    request_id: uuid::Uuid,
    scope: ApprovalScope,
    confirm_critical: bool,
    agent_mediated: bool,
) -> Result<ApproveJsonResponse> {
    if scope == ApprovalScope::Deny {
        anyhow::bail!("use ward deny for denied requests");
    }
    let pending = pending_requests::load_pending_request(request_id)?;
    let cwd = env::current_dir()?;
    let resolved = registry::resolve_project(Some(&pending.access.project), &cwd)?;
    let critical = detection::has_critical_findings(&pending.policy.findings);
    validate_pending_approval(&pending, scope, confirm_critical)?;
    let source = if agent_mediated {
        approvals::ApprovalSource::AgentMediated
    } else {
        approvals::ApprovalSource::LocalTty
    };
    let receipt_context = Some(grants::GrantReceiptContext {
        request_id,
        critical_confirmation: critical && confirm_critical,
        verified_context: pending.verified_context.clone(),
    });
    let access = &pending.access;
    let vault = &resolved.vault;
    let grant = grants::persist_manual_grant(access, scope, source, vault, receipt_context)?;
    pending_requests::consume_pending_request(request_id)?;
    let receipt = grant.receipt.as_ref();
    let mut decision = grants::approval_from_grant(&pending.access, &grant);
    decision.source = source;
    let approval_event = ApprovalEvent {
        decision: &decision,
        persisted_grant: Some(grant.id),
        approval_receipt_hash: receipt.map(|receipt| receipt.payload_hash.as_str()),
        signer_key_id: receipt.map(|receipt| receipt.signer_key_id.as_str()),
        signature_algorithm: receipt.map(|receipt| receipt.signature_algorithm.as_str()),
        critical_confirmation: critical && confirm_critical,
        human_proof: approval_human_proof(source),
    };
    audit_logs::append_event(LogKind::Approvals, approval_event)?;
    Ok(ApproveJsonResponse {
        status: "approved",
        request_id,
        project: pending.access.project,
        grant_id: grant.id,
        approval_receipt_hash: receipt.map(|receipt| receipt.payload_hash.clone()),
        signer_key_id: receipt.map(|receipt| receipt.signer_key_id.clone()),
        signature_algorithm: receipt.map(|receipt| receipt.signature_algorithm.clone()),
        approval_source: source,
    })
}

fn validate_pending_approval(
    pending: &pending_requests::PendingRequest,
    scope: ApprovalScope,
    confirm_critical: bool,
) -> Result<()> {
    let critical = detection::has_critical_findings(&pending.policy.findings);
    if critical && !confirm_critical {
        anyhow::bail!("critical request requires --confirm-critical");
    }
    approvals::validate_scope_for_findings(scope, &pending.policy.findings)
}

fn deny(request_id: uuid::Uuid, agent_mediated: bool, json: bool) -> Result<()> {
    let pending = match pending_requests::consume_pending_request(request_id) {
        Ok(pending) => pending,
        Err(error) if json => {
            if print_pending_request_error_json(request_id, &error)? {
                return Ok(());
            }
            return Err(error);
        }
        Err(error) => return Err(error),
    };
    let source = if agent_mediated {
        approvals::ApprovalSource::AgentMediated
    } else {
        approvals::ApprovalSource::LocalTty
    };
    let decision = ApprovalDecision {
        approved: false,
        scope: ApprovalScope::Deny,
        approved_env: Vec::new(),
        denied_env: pending.access.env.clone(),
        source,
        grant_id: None,
    };
    let approval_event = ApprovalEvent {
        decision: &decision,
        persisted_grant: None,
        approval_receipt_hash: None,
        signer_key_id: None,
        signature_algorithm: None,
        critical_confirmation: false,
        human_proof: approval_human_proof(source),
    };
    audit_logs::append_event(LogKind::Approvals, approval_event)?;
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "status": "denied",
                "requestId": request_id,
                "project": pending.access.project,
                "approvalSource": source,
            }))?
        );
    } else {
        println!("Denied request {request_id}");
    }
    Ok(())
}

fn is_unlock_or_signing_error(error: &anyhow::Error) -> bool {
    let message = error.to_string();
    message.contains("signing_key_unavailable")
        || message.contains("unlock_required")
        || message.contains("missing broker unlock session")
        || message.contains("expired broker unlock session")
        || message.contains("Ward broker is unavailable")
}

fn print_unlock_required_json(reason: String) -> Result<()> {
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "status": "unlock_required",
            "reason": reason,
            "unlockCommand": "ward unlock --ttl 8h",
        }))?
    );
    Ok(())
}

fn print_pending_request_error_json(request_id: uuid::Uuid, error: &anyhow::Error) -> Result<bool> {
    let path = pending_requests::pending_request_path(request_id);
    let (status, reason) = if !path.exists() {
        ("not_found", "pending_request_not_found")
    } else {
        let message = error.to_string();
        if message.contains("failed to parse") {
            ("invalid_request", "pending_request_malformed")
        } else if message.contains("pending request") && message.contains("expired") {
            ("invalid_request", "pending_request_expired")
        } else if message.contains("failed to read") {
            ("invalid_request", "pending_request_unreadable")
        } else {
            return Ok(false);
        }
    };
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "status": status,
            "requestId": request_id,
            "reason": reason,
        }))?
    );
    Ok(true)
}

#[cfg(any(test, coverage))]
fn run(options: RunOptions) -> Result<()> {
    run_with_context(options, AgentContextOptions::default())
}

fn run_with_context(options: RunOptions, context_options: AgentContextOptions) -> Result<()> {
    if reject_misplaced_run_flags(&options.command)? {
        return Ok(());
    }
    let cwd = env::current_dir()?;
    let resolved = registry::resolve_project(options.project.as_deref(), &cwd)?;
    let config = config::read_project_config(&resolved.path)?;
    let git = git_context::collect_git_context(&cwd);
    let branch = options.branch.or(git.branch.clone());
    let mut context_options = context_options;
    if context_options.agent.is_none() {
        context_options.agent = options.agent.clone();
    }
    if context_options.branch.is_none() {
        context_options.branch = branch.clone();
    }
    let resolved_profile = resolve_run_profile(
        &config,
        options.profile.as_deref(),
        options.action,
        options.env_names,
        options.command,
    )?;
    let command_text = resolved_profile.command.clone();

    let access = AccessRequest {
        project: resolved.name.clone(),
        agent: options.agent,
        branch,
        action: resolved_profile.action,
        command: command_text.clone(),
        env: resolved_profile.env_names,
    };
    let evaluation = evaluate_access(&config, &access);
    let mut verified_context = None;
    let decision = if options.no_prompt {
        if !options.json {
            anyhow::bail!("--no-prompt requires --json");
        }
        let Some(context) = verified_no_prompt_context(&cwd, &resolved, &context_options)? else {
            return Ok(());
        };
        if !enforce_worktree_for_no_prompt(&resolved, &context)? {
            return Ok(());
        }
        verified_context = Some(context);
        let Some(decision) =
            non_interactive_decision_with_context(&access, &evaluation, verified_context.as_ref())?
        else {
            let pending =
                create_run_pending_request(&access, &evaluation, &git, verified_context.clone())?;
            let request_event = RequestEvent {
                access: &pending.access,
                policy: &pending.policy,
                git: &pending.git,
                verified_context: pending.verified_context.as_ref(),
            };
            audit_logs::append_event(LogKind::Requests, request_event)?;
            print_run_approval_required(&pending)?;
            return Ok(());
        };
        if !decision.approved {
            print_run_denied(&access, &evaluation)?;
            return Ok(());
        }
        decision
    } else {
        decide_access(&access, &evaluation, true)?
    };
    let critical_confirmation = critical_confirmation_for_decision(&decision, &evaluation);
    let receipt_context = Some(grants::GrantReceiptContext {
        request_id: uuid::Uuid::new_v4(),
        critical_confirmation,
        verified_context: verified_context.clone(),
    });
    let persisted_grant =
        grants::persist_grant(&access, &decision, &resolved.vault, receipt_context)?;
    let receipt = persisted_grant
        .as_ref()
        .and_then(|grant| grant.receipt.as_ref());

    let request_event = RequestEvent {
        access: &access,
        policy: &evaluation,
        git: &git,
        verified_context: verified_context.as_ref(),
    };
    let approval_event = ApprovalEvent {
        decision: &decision,
        persisted_grant: persisted_grant.as_ref().map(|grant| grant.id),
        approval_receipt_hash: receipt.map(|receipt| receipt.payload_hash.as_str()),
        signer_key_id: receipt.map(|receipt| receipt.signer_key_id.as_str()),
        signature_algorithm: receipt.map(|receipt| receipt.signature_algorithm.as_str()),
        critical_confirmation,
        human_proof: approval_human_proof(decision.source),
    };
    audit_logs::append_event(LogKind::Requests, request_event)?;
    audit_logs::append_event(LogKind::Approvals, approval_event)?;

    if !decision.approved {
        anyhow::bail!("Ward access denied");
    }

    let grant_id = effective_grant_id(&decision, persisted_grant.as_ref());
    let approval_receipt_hash = grant_receipt_hash(&decision, persisted_grant.as_ref())?;
    let started_event = ExecutionStartedEvent {
        event_type: "execution.started",
        project: &resolved.name,
        agent: &access.agent,
        branch: &access.branch,
        declared_action: &access.action,
        requested_command: &command_text,
        cwd: &cwd,
        git: &git,
        requested_env: &evaluation.requested_env,
        injected_env: &decision.approved_env,
        policy_findings: &evaluation.findings,
        approval_scope: decision.scope,
        approval_source: decision.source,
        grant_id,
        approval_receipt_hash: approval_receipt_hash.as_deref(),
        agent_key_id: verified_agent_key_id(verified_context.as_ref()),
        verified_context: verified_context.as_ref(),
    };
    audit_logs::append_event(LogKind::Executions, started_event)?;

    consume_once_grant_if_reused(&decision)?;

    let outcome = if options.no_prompt {
        let context = verified_context
            .as_ref()
            .expect("verified in no-prompt mode");
        let proof_payload =
            serde_json::to_string(context).expect("verified context should serialize");
        let proof = agents::sign_payload(&resolved.name, &context.agent, &proof_payload)?;
        match broker::execute(
            &resolved.name,
            &resolved.vault,
            &cwd,
            decision.approved_env.clone(),
            resolved_profile.command_args,
            Some(proof),
        ) {
            Ok(outcome) => outcome,
            Err(error) => {
                if let Some(missing_env) = broker_vault_key_missing_envs(&error) {
                    print_run_vault_key_missing(&access, &evaluation, missing_env)?;
                    return Ok(());
                }
                let reason = error.to_string();
                print_run_unlock_required(&access, &evaluation, Some(&reason))?;
                return Ok(());
            }
        }
    } else {
        match broker::execute(
            &resolved.name,
            &resolved.vault,
            &cwd,
            decision.approved_env.clone(),
            resolved_profile.command_args.clone(),
            None,
        ) {
            Ok(outcome) => outcome,
            Err(_) => {
                let passphrase = vault::read_existing_passphrase()?;
                runner::run_command(RunCommandRequest {
                    cwd: cwd.clone(),
                    vault: resolved.vault.clone(),
                    env_names: decision.approved_env.clone(),
                    command: resolved_profile.command_args,
                    passphrase,
                    inherited_env: std::env::vars().collect(),
                })?
            }
        }
    };

    let execution_event = ExecutionEvent {
        event_type: "execution.finished",
        project: &resolved.name,
        agent: &access.agent,
        branch: &access.branch,
        declared_action: &access.action,
        requested_command: &command_text,
        cwd: &cwd,
        git: &git,
        requested_env: &evaluation.requested_env,
        injected_env: &decision.approved_env,
        policy_findings: &evaluation.findings,
        approval_scope: decision.scope,
        approval_source: decision.source,
        grant_id,
        approval_receipt_hash: approval_receipt_hash.as_deref(),
        agent_key_id: verified_agent_key_id(verified_context.as_ref()),
        verified_context: verified_context.as_ref(),
        outcome: &outcome,
    };
    let finish_result = audit_logs::append_event(LogKind::Executions, execution_event);
    let anomaly_result = log_anomaly_alerts(&config, grant_id);

    let alert_result = if outcome.redaction_alerts > 0 {
        let output_redaction_event = OutputRedactionEvent {
            event_type: "output.redaction",
            command: &command_text,
            count: outcome.redaction_alerts,
            alerts: &outcome.output_alerts,
        };
        audit_logs::append_event(LogKind::Alerts, output_redaction_event)
    } else {
        Ok(())
    };

    handle_post_run_logging_result(outcome.exit_code, finish_result.and(alert_result))?;
    warn_anomaly_failure(anomaly_result);

    if outcome.exit_code != 0 {
        return Err(ChildExit::new(outcome.exit_code).into());
    }

    Ok(())
}

fn reject_misplaced_run_flags(command: &[String]) -> Result<bool> {
    if !command.iter().any(|arg| arg == "--no-prompt") {
        return Ok(false);
    }
    let response = InvalidInvocationResponse {
        status: "invalid_invocation",
        reason: "ward_flags_after_separator",
        message: "Move Ward flags before --.",
        correct_example: "ward run --json --no-prompt --env DATABASE_URI -- <command>",
    };
    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(true)
}

fn doctor() -> Result<()> {
    let cwd = env::current_dir()?;
    let config_path = config::config_path(&cwd);
    let plaintext_env = cwd.join(".env");

    println!("Ward doctor");
    println!("{} {}", marker(config_path.exists()), config_path.display());

    match config::read_project_config(&cwd) {
        Ok(project_config) => {
            println!("[ok] Project config parses.");
            let vault_path = config::resolve_vault_path(&cwd, &project_config);
            println!("{} {}", marker(vault_path.exists()), vault_path.display());
        }
        Err(error) if config_path.exists() => {
            println!("! Project config does not parse: {error}");
        }
        Err(_) => {
            println!("! Project config missing. Run ward init.");
        }
    }

    match config::read_project_config(&cwd) {
        Ok(project_config) => {
            let vault_path = config::resolve_vault_path(&cwd, &project_config);
            match env_file::inspect_env_file(&plaintext_env, &vault_path) {
                Ok(env_file::EnvFileState::Locked) => println!("[ok] .env is Ward locked."),
                Ok(env_file::EnvFileState::StaleLocked) => {
                    println!("! .env is Ward locked but stale; run ward env lock.")
                }
                Ok(env_file::EnvFileState::Plaintext) => {
                    println!("! Plaintext .env exists. Run ward env lock.")
                }
                Ok(env_file::EnvFileState::Missing) => println!("! .env missing."),
                Err(error) => println!("! .env state check failed: {error}"),
            }
        }
        Err(_) if plaintext_env.exists() => {
            println!("! Plaintext .env exists. Run ward setup or ward import .env.");
        }
        Err(_) => println!("! .env missing."),
    }

    let likely_secret_env_files = likely_secret_env_files(&cwd)?;
    if likely_secret_env_files.is_empty() {
        println!("[ok] No .env.* secret variants found.");
    } else {
        for path in likely_secret_env_files {
            println!("! Likely plaintext env file: {}", path.display());
        }
    }

    check_gitignore(&cwd)?;

    match registry::resolve_project(None, &cwd) {
        Ok(project) => {
            println!("[ok] Resolved project: {}", project.name);
            println!("  Vault: {}", project.vault.display());
            println!(
                "{} Registered vault exists: {}",
                marker(project.vault.exists()),
                project.vault.display()
            );
            match broker::status() {
                Ok(status) if status.running => {
                    let active = status.sessions.iter().any(|session| {
                        session.project == project.name && session.vault == project.vault
                    });
                    if active {
                        println!("[ok] Active broker unlock session is available.");
                        println!("[ok] Active signing key capability is broker-held.");
                    } else {
                        println!("! Broker is running without an active session for this project. Run ward unlock --ttl 8h.");
                    }
                }
                Ok(_) => {
                    println!("! Broker is not running. Run ward unlock --ttl 8h.")
                }
                Err(error) => {
                    println!("! Broker status check failed: {error}")
                }
            }
        }
        Err(error) => println!("! Registry resolution failed: {error}"),
    }

    match grants::load_grants() {
        Ok(loaded_grants) => {
            let now = chrono::Utc::now();
            let unsigned = loaded_grants
                .iter()
                .filter(|grant| {
                    grants::grant_integrity_status(grant, now)
                        == grants::GrantIntegrityStatus::LegacyUnsigned
                })
                .count();
            let invalid = loaded_grants
                .iter()
                .filter(|grant| {
                    grants::grant_integrity_status(grant, now)
                        == grants::GrantIntegrityStatus::Invalid
                })
                .count();
            for message in grant_integrity_messages(unsigned, invalid) {
                println!("{message}");
            }
        }
        Err(error) => println!("! Approval grant check failed: {error}"),
    }

    match audit_logs::entry_count(LogKind::Alerts) {
        Ok(0) => println!("[ok] No encrypted alerts logged."),
        Ok(count) => println!("! Encrypted alerts: {count}. Run ward logs view alerts."),
        Err(error) => println!("! Alert log check failed: {error}"),
    }

    Ok(())
}

#[cfg(any(test, coverage))]
fn signing_lookup_message(result: Result<unlock::RunSigningLookup>) -> String {
    match result {
        Ok(unlock::RunSigningLookup::Available(_)) => {
            "[ok] Active signing key session is readable.".to_string()
        }
        Ok(unlock::RunSigningLookup::Missing) => {
            "! No active signing key session. Run ward unlock --ttl 8h.".to_string()
        }
        Ok(unlock::RunSigningLookup::MaterialUnavailable { reason }) => {
            format!(
                "! Active signing key session is unavailable ({reason}). Run ward unlock --ttl 8h."
            )
        }
        Err(error) => format!("! Signing key session check failed: {error}"),
    }
}

fn logs(command: Option<LogsCommand>, kind: Option<LogKind>) -> Result<()> {
    match command {
        Some(LogsCommand::View { kind }) => {
            ensure_logs_passphrase()?;
            warn_log_view_access();
            let output = render_log_events(&audit_logs::decrypt_events(kind)?)?;
            if !output.is_empty() {
                println!("{output}");
            }
        }
        Some(LogsCommand::Verify { kind, full }) => {
            let reports = if full {
                ensure_logs_passphrase()?;
                audit_logs::verify_logs_full(kind)?
            } else {
                audit_logs::verify_logs(kind)?
            };
            for report in reports {
                println!(
                    "[ok] {} entries={} path={}",
                    report.kind.as_str(),
                    report.entries,
                    report.path.display()
                );
            }
        }
        Some(LogsCommand::Export {
            kind,
            output,
            force,
        }) => {
            if output.exists() && !force {
                anyhow::bail!(
                    "{} already exists; pass --force to overwrite",
                    output.display()
                );
            }
            ensure_logs_passphrase()?;
            warn_log_view_access();
            let output_contents = render_log_events(&audit_logs::decrypt_events(kind)?)?;
            crate::fs_util::write_private_file(&output, output_contents.as_bytes())?;
            println!("Exported decrypted log {}", output.display());
        }
        Some(LogsCommand::Unlock { ttl }) => unlock_logs(&ttl)?,
        None => match kind {
            Some(kind) => println!("{}", audit_logs::log_path(kind).display()),
            None => println!("{}", audit_logs::logs_dir().display()),
        },
    }
    Ok(())
}

fn render_log_events(events: &[Value]) -> Result<String> {
    let mut lines = Vec::with_capacity(events.len());
    for event in events {
        lines.push(serde_json::to_string(event)?);
    }
    Ok(lines.join("\n"))
}

fn edit() -> Result<()> {
    let cwd = env::current_dir()?;
    let resolved = registry::resolve_project(None, &cwd)?;
    let passphrase = vault::read_existing_passphrase()?;
    vault::edit_vault_file(&resolved.vault, &passphrase)?;
    let event = VaultEditEvent {
        event_type: "vault.edit",
        project: &resolved.name,
        vault: &resolved.vault,
    };
    audit_logs::append_event(LogKind::Sessions, event)?;
    println!("Updated encrypted vault.");
    Ok(())
}

pub(crate) fn create_run_unlock_session(
    project: &str,
    vault_path: &Path,
    passphrase: &str,
    ttl: &str,
    mode: Option<&str>,
) -> Result<unlock::UnlockSession> {
    let ttl = unlock::parse_ttl(ttl)?;
    match vault::decrypt_vault_file(vault_path, passphrase) {
        Ok(_) => {
            let session = if let Some(mode_name) = mode {
                unlock::create_mode_unlock(project, vault_path, passphrase, ttl, mode_name)?
            } else {
                unlock::create_run_unlock(project, vault_path, passphrase, ttl)?
            };
            broker::unlock_project_with_mode(project, vault_path, passphrase, ttl, mode.map(str::to_string))?;
            let event = VaultUnlockEvent {
                event_type: "vault.unlock",
                status: "success",
                project,
                vault: vault_path,
                error: None,
                expires_at: Some(session.expires_at.to_rfc3339()),
            };
            audit_logs::append_event(LogKind::Sessions, event)?;
            Ok(session)
        }
        Err(error) => {
            let error_message = error.to_string();
            let event = VaultUnlockEvent {
                event_type: "vault.unlock",
                status: "failure",
                project,
                vault: vault_path,
                error: Some(&error_message),
                expires_at: None,
            };
            audit_logs::append_event(LogKind::Sessions, event)?;
            Err(error)
        }
    }
}

fn unlock_vault(ttl: &str, mode: Option<&str>) -> Result<()> {
    let cwd = env::current_dir()?;
    let resolved = registry::resolve_project(None, &cwd)?;
    let passphrase = vault::read_existing_passphrase()?;
    let session = create_run_unlock_session(&resolved.name, &resolved.vault, &passphrase, ttl, mode)?;
    if let Some(mode_name) = mode {
        println!("Vault unlocked with mode '{}' until {}.", mode_name, session.expires_at.to_rfc3339());
    } else {
        println!("Vault unlocked until {}.", session.expires_at.to_rfc3339());
    }
    Ok(())
}

fn lock() -> Result<()> {
    if crate::human::is_human_terminal() {
        let _ = crate::human::send_guardian_shutdown();
    }
    let revoked = grants::revoke_session_grants()?;
    let cleared_unlocks = unlock::clear_all_unlocks()?;
    broker::stop()?;
    let event = VaultLockEvent {
        event_type: "vault.lock",
        revoked_session_grants: revoked,
        cleared_unlock_sessions: cleared_unlocks,
    };
    audit_logs::append_event(LogKind::Sessions, event)?;
    println!("Revoked {revoked} session grant(s).");
    println!("Cleared {cleared_unlocks} unlock session(s).");
    if crate::human::is_human_terminal() {
        crate::human::display::print_padlock_closing();
    }
    Ok(())
}

fn modes_command(command: ModesCommand) -> Result<()> {
    match command {
        ModesCommand::List => {
            let cwd = env::current_dir()?;
            let resolved = registry::resolve_project(None, &cwd)?;
            let modes = modes::load_local_modes(&resolved.path)?;
            if modes.is_empty() {
                println!("No modes defined in .ward.modes.json");
            } else {
                for mode in &modes {
                    println!("{} ({})", mode.name, serde_json::to_string(&mode.level).unwrap_or_default().trim_matches('"'));
                }
            }
            Ok(())
        }
        ModesCommand::Push { project, .. } => {
            let cwd = env::current_dir()?;
            let resolved = registry::resolve_project(project.as_deref(), &cwd)?;
            let modes_path = modes::local_modes_path(&resolved.path);
            let local_modes = modes::load_local_modes(&resolved.path)?;
            if local_modes.is_empty() {
                anyhow::bail!("no modes found in {}", modes_path.display());
            }
            let passphrase = vault::read_existing_passphrase()?;
            // Validate passphrase by decrypting the vault
            vault::decrypt_vault_file(&resolved.vault, &passphrase)
                .context("invalid passphrase — cannot push modes")?;
            modes::push_modes(&local_modes, &resolved.name, &passphrase, &modes_path)?;
            println!("Pushed {} mode(s) for project '{}'.", local_modes.len(), resolved.name);
            Ok(())
        }
        ModesCommand::Status => {
            let cwd = env::current_dir()?;
            let resolved = registry::resolve_project(None, &cwd)?;
            match broker::status() {
                Ok(status) => {
                    let session = status.sessions.iter().find(|s| s.project == resolved.name);
                    match session.and_then(|s| s.active_mode.as_deref()) {
                        Some(mode_name) => println!("Active mode: {mode_name}"),
                        None => println!("No active mode for project '{}'.", resolved.name),
                    }
                }
                Err(_) => println!("Broker not running — no active mode."),
            }
            Ok(())
        }
    }
}

fn teardown(
    project: Option<String>,
    export_path: PathBuf,
    yes: bool,
    restore_env: bool,
) -> Result<()> {
    if !yes {
        anyhow::bail!("teardown requires --yes");
    }
    let cwd = env::current_dir()?;
    let resolved = registry::resolve_project(project.as_deref(), &cwd)?;
    let export_path = if restore_env && export_path == PathBuf::from(".env.export") {
        PathBuf::from(".env")
    } else {
        export_path
    };
    let output = project_relative_path(&resolved.path, export_path);
    if output == resolved.path.join(".env") && !restore_env {
        anyhow::bail!("restoring plaintext .env requires --restore-env");
    }
    if env::var_os("WARD_UNSAFE_TEST_PASSPHRASE").is_none() && !std::io::stdin().is_terminal() {
        anyhow::bail!(
            "teardown requires the vault PIN/passphrase; --yes only skips destructive confirmation and does not bypass secret export approval"
        );
    }
    let passphrase = vault::read_existing_passphrase().context(
        "teardown requires the vault PIN/passphrase even with --yes; run from an interactive terminal or set the unsafe test passphrase only in tests",
    )?;
    env_file::export_env_file(&output, &resolved.vault, &passphrase, true)?;
    vault::validate_dotenv(&fs::read_to_string(&output)?)?;

    let mut removed_files = Vec::new();
    for path in [
        resolved.path.join(config::PROJECT_CONFIG_FILE),
        resolved.vault.clone(),
    ] {
        remove_project_file_if_exists(&path, &mut removed_files)?;
    }
    let env_path = resolved.path.join(".env");
    remove_locked_env_if_needed(&env_path, &output, &mut removed_files)?;
    for path in [
        resolved.path.join(config::AGENT_INSTRUCTIONS_FILE),
        resolved.path.join(config::CLAUDE_INSTRUCTIONS_FILE),
    ] {
        if remove_agent_instruction_section(&path)? {
            removed_files.push(format!("updated {}", path.display()));
        }
    }
    registry::remove_project(&resolved.name)?;
    let removed_grants = grants::remove_project_grants(&resolved.name)?;
    let removed_pending_requests = pending_requests::remove_project_requests(&resolved.name)?;
    let cleared_unlock_sessions = unlock::clear_project_unlocks(&resolved.name)?;
    let event = TeardownEvent {
        event_type: "teardown.completed",
        project: &resolved.name,
        export_path: &output,
        removed_files,
        removed_grants,
        removed_pending_requests,
        cleared_unlock_sessions,
    };
    audit_logs::append_event(LogKind::Sessions, event)?;
    println!("Exported plaintext env {}", output.display());
    println!("Removed Ward project {}", resolved.name);
    println!("Encrypted audit logs were preserved.");
    Ok(())
}

fn remove_locked_env_if_needed(
    env_path: &Path,
    output: &Path,
    removed_files: &mut Vec<String>,
) -> Result<()> {
    let should_keep_env = env_path == output || !env_file::is_locked_env_file(env_path)?;
    if should_keep_env {
        return Ok(());
    }
    remove_project_file_if_exists(env_path, removed_files)
}

fn remove_project_file_if_exists(path: &Path, removed_files: &mut Vec<String>) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }
    fs::remove_file(path).context(format!("failed to remove {}", path.display()))?;
    removed_files.push(path.display().to_string());
    Ok(())
}

fn remove_agent_instruction_section(path: &Path) -> Result<bool> {
    if !path.exists() {
        return Ok(false);
    }
    let contents =
        fs::read_to_string(path).context(format!("failed to read {}", path.display()))?;
    let Some(index) = contents.find("<!-- ward-agent-instructions -->") else {
        return Ok(false);
    };
    let retained = contents[..index].trim_end();
    if retained.is_empty() {
        fs::remove_file(path).context(format!("failed to remove {}", path.display()))?;
    } else {
        fs::write(path, format!("{retained}\n"))
            .context(format!("failed to write {}", path.display()))?;
    }
    Ok(true)
}

fn unlock_logs(ttl: &str) -> Result<()> {
    let cwd = env::current_dir()?;
    let resolved = registry::resolve_project(None, &cwd)?;
    let passphrase = vault::read_existing_passphrase()?;
    vault::decrypt_vault_file(&resolved.vault, &passphrase)?;
    let event = LogsUnlockEvent {
        event_type: "logs.unlock",
        project: &resolved.name,
        vault: &resolved.vault,
        expires_at: "deprecated-validate-only".to_string(),
    };
    audit_logs::append_event(LogKind::Sessions, event)?;
    println!(
        "Log passphrase validated. Note: ward logs unlock is deprecated; logs view/export prompts every time."
    );
    println!("Requested TTL {ttl} was ignored.");
    Ok(())
}

fn ensure_logs_passphrase() -> Result<()> {
    let cwd = env::current_dir()?;
    let resolved = registry::resolve_project(None, &cwd)?;
    let passphrase = vault::read_existing_passphrase()?;
    vault::decrypt_vault_file(&resolved.vault, &passphrase)?;
    Ok(())
}

fn warn_log_view_access() {
    eprintln!(
        "Ward warning: decrypted logs are for review only. Edits are tamper-evident through the hash chain; deleted logs should be treated as a high-severity signal."
    );
}

fn resolve_profile(
    config: &config::ProjectConfig,
    profile: Option<&str>,
    action: Option<String>,
    command: Option<String>,
    env_names: Vec<String>,
) -> Result<ResolvedProfile> {
    if let Some(profile_name) = profile {
        if command.is_some() || !env_names.is_empty() {
            anyhow::bail!("--profile cannot be combined with --command or --env");
        }
        let Some(profile) = config.profiles.get(profile_name) else {
            anyhow::bail!("profile {profile_name} is not defined in .ward.json");
        };
        return Ok(ResolvedProfile {
            command: profile.command.clone(),
            command_args: split_profile_command(&profile.command),
            env_names: profile.env.clone(),
            action: action.or_else(|| Some(profile.action.clone())),
            default_scope: profile.default_scope,
        });
    }

    let command = command.context("--command is required unless --profile is used")?;
    if env_names.is_empty() {
        anyhow::bail!("at least one --env is required unless --profile is used");
    }
    Ok(ResolvedProfile {
        command: command.clone(),
        command_args: split_profile_command(&command),
        env_names,
        action,
        default_scope: ApprovalScope::Once,
    })
}

fn resolve_run_profile(
    config: &config::ProjectConfig,
    profile: Option<&str>,
    action: Option<String>,
    env_names: Vec<String>,
    command: Vec<String>,
) -> Result<ResolvedProfile> {
    if let Some(profile_name) = profile {
        if !command.is_empty() || !env_names.is_empty() {
            anyhow::bail!("--profile cannot be combined with explicit command args or --env");
        }
        let Some(profile) = config.profiles.get(profile_name) else {
            anyhow::bail!("profile {profile_name} is not defined in .ward.json");
        };
        return Ok(ResolvedProfile {
            command: profile.command.clone(),
            command_args: split_profile_command(&profile.command),
            env_names: profile.env.clone(),
            action: action.or_else(|| Some(profile.action.clone())),
            default_scope: profile.default_scope,
        });
    }

    if command.is_empty() {
        anyhow::bail!("command args are required unless --profile is used");
    }
    if env_names.is_empty() {
        anyhow::bail!("at least one --env is required unless --profile is used");
    }
    Ok(ResolvedProfile {
        command: command.join(" "),
        command_args: command,
        env_names,
        action,
        default_scope: ApprovalScope::Once,
    })
}

fn split_profile_command(command: &str) -> Vec<String> {
    command
        .split_whitespace()
        .map(str::to_string)
        .collect::<Vec<_>>()
}

fn effective_grant_id(
    decision: &ApprovalDecision,
    persisted_grant: Option<&grants::ApprovalGrant>,
) -> Option<uuid::Uuid> {
    decision
        .grant_id
        .or_else(|| persisted_grant.map(|grant| grant.id))
}

fn grant_receipt_hash(
    decision: &ApprovalDecision,
    persisted_grant: Option<&grants::ApprovalGrant>,
) -> Result<Option<String>> {
    if let Some(grant) = persisted_grant {
        return Ok(grant
            .receipt
            .as_ref()
            .map(|receipt| receipt.payload_hash.clone()));
    }
    let Some(grant_id) = decision.grant_id else {
        return Ok(None);
    };
    Ok(grants::load_grants()?
        .into_iter()
        .find(|grant| grant.id == grant_id)
        .and_then(|grant| grant.receipt.map(|receipt| receipt.payload_hash)))
}

fn log_anomaly_alerts(config: &config::ProjectConfig, grant_id: Option<uuid::Uuid>) -> Result<()> {
    let Some(grant_id) = grant_id else {
        return Ok(());
    };
    let events = audit_logs::decrypt_events(LogKind::Executions)?;
    for alert in anomaly::detect_grant_anomalies(
        &config.anomaly_detection,
        &events,
        grant_id,
        chrono::Utc::now(),
    ) {
        audit_logs::append_event(LogKind::Alerts, alert)?;
    }
    Ok(())
}

fn evaluate_access(
    config: &config::ProjectConfig,
    access: &AccessRequest,
) -> policy::PolicyEvaluation {
    let findings =
        detection::preflight_findings(&access.command, &access.env, access.action.as_deref());
    policy::evaluate_request(config, access, None, findings)
}

fn approval_human_proof(source: approvals::ApprovalSource) -> Option<&'static str> {
    match source {
        approvals::ApprovalSource::AgentMediated => Some("external-agent-ui"),
        approvals::ApprovalSource::LocalTty => Some("local-tty"),
        approvals::ApprovalSource::ManualAllow => Some("local-cli"),
        _ => None,
    }
}

fn critical_confirmation_for_decision(
    decision: &ApprovalDecision,
    evaluation: &policy::PolicyEvaluation,
) -> bool {
    decision.approved
        && decision.scope == ApprovalScope::Once
        && detection::has_critical_findings(&evaluation.findings)
}

fn handle_post_run_logging_result(exit_code: i32, result: Result<()>) -> Result<()> {
    if let Err(error) = result {
        eprintln!("Ward warning: post-run audit logging failed: {error}");
        if exit_code == 0 {
            anyhow::bail!("Ward post-run audit logging failed");
        }
    }
    Ok(())
}

fn warn_anomaly_failure(result: Result<()>) {
    if let Err(error) = result {
        eprintln!("Ward warning: anomaly detection failed: {error}");
    }
}

fn consume_once_grant_if_reused(decision: &ApprovalDecision) -> Result<()> {
    let should_consume = decision.source == approvals::ApprovalSource::Grant
        && decision.scope == ApprovalScope::Once;
    if !should_consume {
        return Ok(());
    }

    let Some(grant_id) = decision.grant_id else {
        return Ok(());
    };

    grants::consume_once_grant(grant_id).map(|_| ())
}

fn decide_access(
    access: &AccessRequest,
    evaluation: &policy::PolicyEvaluation,
    allow_grants: bool,
) -> Result<ApprovalDecision> {
    if evaluation.approval_mode == ApprovalMode::Deny {
        return Ok(ApprovalDecision {
            approved: false,
            scope: ApprovalScope::Deny,
            approved_env: Vec::new(),
            denied_env: access.env.clone(),
            source: approvals::ApprovalSource::PolicyDeny,
            grant_id: None,
        });
    }

    let critical = detection::has_critical_findings(&evaluation.findings);
    let suspicious_action = detection::has_suspicious_action_findings(&evaluation.findings);
    if allow_grants {
        let grant = if critical {
            grants::find_matching_once_grant(access, true)?
        } else if suspicious_action {
            grants::find_matching_non_always_grant(access)?
        } else {
            grants::find_matching_grant(access)?
        };
        if let Some(grant) = grant {
            return Ok(grants::approval_from_grant(access, &grant));
        }
    }

    if evaluation.requires_prompt {
        approvals::prompt_for_approval(access, evaluation)
    } else {
        Ok(approvals::auto_approval(evaluation))
    }
}

fn non_interactive_decision(
    access: &AccessRequest,
    evaluation: &policy::PolicyEvaluation,
) -> Result<Option<ApprovalDecision>> {
    if evaluation.approval_mode == ApprovalMode::Deny {
        return Ok(Some(ApprovalDecision {
            approved: false,
            scope: ApprovalScope::Deny,
            approved_env: Vec::new(),
            denied_env: access.env.clone(),
            source: approvals::ApprovalSource::PolicyDeny,
            grant_id: None,
        }));
    }

    let critical = detection::has_critical_findings(&evaluation.findings);
    let suspicious_action = detection::has_suspicious_action_findings(&evaluation.findings);
    let grant = if critical {
        grants::find_matching_once_grant(access, true)?
    } else if suspicious_action {
        grants::find_matching_non_always_grant(access)?
    } else {
        grants::find_matching_grant(access)?
    };
    if let Some(grant) = grant {
        return Ok(Some(grants::approval_from_grant(access, &grant)));
    }
    if evaluation.requires_prompt {
        return Ok(None);
    }
    Ok(Some(approvals::auto_approval(evaluation)))
}

fn non_interactive_decision_with_context(
    access: &AccessRequest,
    evaluation: &policy::PolicyEvaluation,
    verified_context: Option<&context::VerifiedContext>,
) -> Result<Option<ApprovalDecision>> {
    let Some(verified_context) = verified_context else {
        return non_interactive_decision(access, evaluation);
    };
    if evaluation.approval_mode == ApprovalMode::Deny {
        return Ok(Some(ApprovalDecision {
            approved: false,
            scope: ApprovalScope::Deny,
            approved_env: Vec::new(),
            denied_env: access.env.clone(),
            source: approvals::ApprovalSource::PolicyDeny,
            grant_id: None,
        }));
    }

    let critical = detection::has_critical_findings(&evaluation.findings);
    let suspicious_action = detection::has_suspicious_action_findings(&evaluation.findings);
    let grant = if critical {
        grants::find_matching_once_grant_with_context(access, true, verified_context)?
    } else if suspicious_action {
        grants::find_matching_non_always_grant_with_context(access, verified_context)?
    } else {
        grants::find_matching_grant_with_context(access, verified_context)?
    };
    if let Some(grant) = grant {
        return Ok(Some(grants::approval_from_grant(access, &grant)));
    }
    if evaluation.requires_prompt {
        return Ok(None);
    }
    Ok(Some(approvals::auto_approval(evaluation)))
}

fn create_run_pending_request(
    access: &AccessRequest,
    evaluation: &policy::PolicyEvaluation,
    git: &git_context::GitContext,
    verified_context: Option<context::VerifiedContext>,
) -> Result<pending_requests::PendingRequest> {
    pending_requests::create_pending_request_with_context(
        access.clone(),
        evaluation.clone(),
        git.clone(),
        verified_context,
    )
}

fn print_run_approval_required(pending: &pending_requests::PendingRequest) -> Result<()> {
    let response = RunApprovalRequiredResponse {
        status: "approval_required",
        unlock_required: false,
        request: pending_requests::response_for(pending),
    };
    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}

fn print_run_unlock_required(
    access: &AccessRequest,
    evaluation: &policy::PolicyEvaluation,
    unlock_reason: Option<&str>,
) -> Result<()> {
    let response = RunUnlockRequiredResponse {
        status: "unlock_required",
        approval_required: false,
        unlock_required: true,
        unlock_reason,
        project: &access.project,
        command: &access.command,
        env: &access.env,
        findings: &evaluation.findings,
        risk: run_risk_summary(evaluation),
        unlock_command: "ward unlock --ttl 8h",
    };
    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}

fn print_run_vault_key_missing(
    access: &AccessRequest,
    evaluation: &policy::PolicyEvaluation,
    missing_env: Vec<String>,
) -> Result<()> {
    let response = RunVaultKeyMissingResponse {
        status: "vault_key_missing",
        approval_required: false,
        unlock_required: false,
        project: &access.project,
        command: &access.command,
        env: &access.env,
        missing_env,
        findings: &evaluation.findings,
        risk: run_risk_summary(evaluation),
        message: "One or more approved env vars are not present in the vault.",
        remediation: "Update .ward.json to request only vault-present keys, or run ward env unlock, add the missing key, then ward env lock.",
    };
    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}

fn print_run_denied(access: &AccessRequest, evaluation: &policy::PolicyEvaluation) -> Result<()> {
    let response = RunDeniedResponse {
        status: "denied",
        approval_required: false,
        unlock_required: false,
        project: &access.project,
        command: &access.command,
        env: &access.env,
        findings: &evaluation.findings,
        risk: run_risk_summary(evaluation),
    };
    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}

fn broker_vault_key_missing_envs(error: &anyhow::Error) -> Option<Vec<String>> {
    let broker_error = error.downcast_ref::<broker::BrokerError>()?;
    if broker_error.reason() != "vault_key_missing" {
        return None;
    }
    Some(
        broker_error
            .message()
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string)
            .collect(),
    )
}

fn run_risk_summary(evaluation: &policy::PolicyEvaluation) -> String {
    if detection::has_critical_findings(&evaluation.findings) {
        "critical".to_string()
    } else if !evaluation.findings.is_empty() || !evaluation.denied_env.is_empty() {
        "warning".to_string()
    } else {
        "low".to_string()
    }
}

fn marker(ok: bool) -> &'static str {
    if ok {
        "[ok]"
    } else {
        "!"
    }
}

fn grant_integrity_messages(unsigned: usize, invalid: usize) -> Vec<String> {
    let mut messages = Vec::new();
    if unsigned == 0 && invalid == 0 {
        messages.push("[ok] Approval grants are signed and valid.".to_string());
    }
    if unsigned > 0 {
        messages.push(format!(
            "! Legacy unsigned approval grants: {unsigned}. Re-approve them."
        ));
    }
    if invalid > 0 {
        messages.push(format!(
            "! Invalid signed approval grants: {invalid}. Revoke and re-approve them."
        ));
    }
    messages
}

fn grant_status_label(status: grants::GrantIntegrityStatus) -> &'static str {
    match status {
        grants::GrantIntegrityStatus::Valid => "valid-signed",
        grants::GrantIntegrityStatus::Expired => "expired",
        grants::GrantIntegrityStatus::LegacyUnsigned => "legacy-unsigned",
        grants::GrantIntegrityStatus::Invalid => "invalid-signature",
    }
}

fn verified_agent_key_id(context: Option<&context::VerifiedContext>) -> Option<&str> {
    match context {
        Some(context) => Some(context.agent_key_id.as_str()),
        None => None,
    }
}

#[cfg(all(coverage, not(test)))]
#[doc(hidden)]
pub fn coverage_exercise_cli_edges() -> Result<()> {
    let old_cwd = env::current_dir()?;
    let home = tempfile::tempdir()?;
    env::set_var("WARD_HOME", home.path());
    env::set_var("WARD_UNSAFE_TEST_KEYRING", "1");
    env::set_var("WARD_UNSAFE_TEST_PASSPHRASE", "coverage passphrase");

    let project = tempfile::tempdir()?;
    env::set_current_dir(project.path())?;
    fs::write(project.path().join(".gitignore"), ".env\n.env.*\n")?;
    let project_env = project.path().join(".env");
    fs::write(&project_env, "DATABASE_URL=postgres://coverage\n")?;
    let main_setup = SetupOptions {
        yes: true,
        project: Some("coverage-main".to_string()),
        source: ".env".into(),
        vault: ".env.vault".into(),
        commit_vault: false,
        ignore_vault: false,
        remove_plaintext: false,
        keep_plaintext: false,
        unlock_ttl: "8h".to_string(),
        no_unlock: false,
    };
    setup(main_setup)?;
    dispatch(Cli {
        command: Commands::Broker {
            command: BrokerCommand::SocketPath,
        },
    })
    .expect("coverage broker socket dispatch should succeed");
    dispatch(Cli {
        command: Commands::Worktrees {
            command: WorktreesCommand::List {
                project: "coverage-main".to_string(),
            },
        },
    })
    .expect("coverage worktree list dispatch should succeed");
    broker_command(BrokerCommand::SocketPath)?;
    broker_command(BrokerCommand::Status)?;
    broker_command(BrokerCommand::Stop)?;
    let allowed_root = tempfile::tempdir()?;
    worktrees_command(WorktreesCommand::AllowRoot {
        project: "coverage-main".to_string(),
        path: allowed_root.path().to_path_buf(),
    })
    .expect("coverage allow-root should succeed");
    worktrees_command(WorktreesCommand::List {
        project: "coverage-main".to_string(),
    })
    .expect("coverage list should succeed");
    worktrees_command(WorktreesCommand::RemoveRoot {
        project: "coverage-main".to_string(),
        path: allowed_root.path().to_path_buf(),
    })
    .expect("coverage remove-root should succeed");
    worktrees_command(WorktreesCommand::RemoveRoot {
        project: "coverage-main".to_string(),
        path: allowed_root.path().to_path_buf(),
    })
    .expect("coverage missing remove-root should succeed");
    worktrees_command(WorktreesCommand::Approve {
        request_id: uuid::Uuid::new_v4(),
        json: false,
    })
    .expect("coverage missing worktree approval should succeed");
    worktrees_command(WorktreesCommand::Deny {
        request_id: uuid::Uuid::new_v4(),
        json: false,
    })
    .expect("coverage missing worktree denial should succeed");

    let absolute_export = EnvCommand::Export {
        project: None,
        output: Some(project.path().join(".env.absolute.export")),
        force: false,
        unsafe_stdout: false,
    };
    env_command(absolute_export)?;
    let stdout_export = EnvCommand::Export {
        project: None,
        output: None,
        force: false,
        unsafe_stdout: true,
    };
    env_command(stdout_export)?;

    let access = AccessRequest {
        project: "coverage-main".to_string(),
        agent: Some("codex".to_string()),
        branch: None,
        action: Some("Coverage".to_string()),
        command: "sh -c true".to_string(),
        env: vec!["DATABASE_URL".to_string()],
    };
    let clean = policy::PolicyEvaluation {
        matched_profile: None,
        matched_preset: None,
        approval_mode: ApprovalMode::Auto,
        requested_env: access.env.clone(),
        approved_env: access.env.clone(),
        denied_env: Vec::new(),
        requires_prompt: false,
        findings: Vec::new(),
    };
    let mut critical = clean.clone();
    critical.findings.push(detection::Finding::critical(
        "critical.coverage",
        "critical coverage finding",
    ));
    critical.requires_prompt = true;
    let _ = decide_access(&access, &clean, true)?;
    let _ = non_interactive_decision(&access, &clean)?;
    let mut denied = clean.clone();
    denied.approval_mode = ApprovalMode::Deny;
    let _ = non_interactive_decision(&access, &denied)?;
    let _ = non_interactive_decision(&access, &critical)?;
    let _ = run_risk_summary(&critical);
    let mut suspicious = clean.clone();
    suspicious.findings.push(detection::Finding::warning(
        "action.prompt_injection",
        "coverage suspicious action finding",
    ));
    suspicious.requires_prompt = true;
    let _ = decide_access(&access, &suspicious, true)?;
    let _ = signing_lookup_message(Ok(unlock::RunSigningLookup::Missing));
    let _ = signing_lookup_message(Ok(unlock::RunSigningLookup::MaterialUnavailable {
        reason: "coverage".to_string(),
    }));
    let _ = signing_lookup_message(Err(anyhow::anyhow!("coverage")));
    let _ = grant_integrity_messages(1, 1);
    let _ = grant_status_label(grants::GrantIntegrityStatus::Expired);
    let _ = grant_status_label(grants::GrantIntegrityStatus::LegacyUnsigned);
    let _ = grant_status_label(grants::GrantIntegrityStatus::Invalid);
    let resolved_main = registry::resolve_project(Some("coverage-main"), project.path())?;
    let missing_context = AgentContextOptions {
        agent: None,
        agent_key_id: None,
        worktree: None,
        git_remote: None,
        commit: None,
        branch: None,
    };
    assert!(
        verified_no_prompt_context(project.path(), &resolved_main, &missing_context)?.is_none()
    );
    request(
        None,
        missing_context.clone(),
        Some("Coverage missing context".to_string()),
        Some("sh -c true".to_string()),
        access.env.clone(),
        true,
        true,
    )
    .expect("coverage missing-context request should return structured JSON");
    let wrong_key_context = AgentContextOptions {
        agent: Some("codex".to_string()),
        agent_key_id: Some("agent:wrong".to_string()),
        worktree: None,
        git_remote: None,
        commit: None,
        branch: None,
    };
    assert!(
        verified_no_prompt_context(project.path(), &resolved_main, &wrong_key_context)?.is_none()
    );
    let agent = agents::ensure_agent("coverage-main", "codex")?;
    let proof = agents::sign_payload("coverage-main", "codex", "coverage payload")?;
    let _ = agents::verify_proof("coverage-main", &proof)?;
    let _ = context::normalize_remote("https://example.test/demo.git/");
    let mut agent_state = agents::load_agents()?;
    let agent_record = agent_state
        .projects
        .get_mut("coverage-main")
        .and_then(|agents| agents.iter_mut().find(|agent| agent.agent_name == "codex"))
        .expect("coverage agent should exist");
    agent_record.private_seed = "AQID".to_string();
    agents::save_agents(&agent_state)?;
    assert!(agents::sign_payload("coverage-main", "codex", "coverage payload").is_err());
    let mut agent_state = agents::load_agents()?;
    let agent_record = agent_state
        .projects
        .get_mut("coverage-main")
        .and_then(|agents| agents.iter_mut().find(|agent| agent.agent_name == "codex"))
        .expect("coverage agent should exist");
    agent_record.public_key = "AQID".to_string();
    agents::save_agents(&agent_state)?;
    assert!(agents::verify_proof("coverage-main", &proof).is_err());
    let matching_key_context = AgentContextOptions {
        agent: Some("codex".to_string()),
        agent_key_id: Some(agent.agent_key_id),
        worktree: None,
        git_remote: None,
        commit: None,
        branch: None,
    };
    assert!(
        verified_no_prompt_context(project.path(), &resolved_main, &matching_key_context)?
            .is_none()
    );
    let no_git_claim = context::ClaimedContext {
        agent: Some("codex".to_string()),
        agent_key_id: None,
        worktree: Some(project.path().to_path_buf()),
        branch: Some("main".to_string()),
        git_remote: Some("https://example.test/demo.git".to_string()),
        commit: Some("abc".to_string()),
    };
    assert!(context::verify_no_prompt_context(
        &no_git_claim,
        project.path(),
        &resolved_main,
        "agent:coverage".to_string(),
    )
    .is_err());
    let verified_worktree = |path: PathBuf, remote: &str| context::VerifiedContext {
        project: "coverage-main".to_string(),
        agent: "codex".to_string(),
        agent_key_id: "agent:coverage".to_string(),
        worktree: path,
        branch: "main".to_string(),
        git_remote: remote.to_string(),
        commit: "abc123".to_string(),
        git_common_dir: None,
    };
    let unregistered = registry::ResolvedProject {
        name: "coverage-unregistered".to_string(),
        path: project.path().to_path_buf(),
        vault: project.path().join(".env.vault"),
    };
    let unregistered_context =
        verified_worktree(project.path().to_path_buf(), "https://example.test/demo");
    let unregistered_allowed =
        enforce_worktree_for_no_prompt(&unregistered, &unregistered_context)?;
    assert!(unregistered_allowed);
    let autobind_root = tempfile::tempdir()?;
    let autobind_worktree = autobind_root.path().join("agent-wt");
    fs::create_dir(&autobind_worktree)?;
    worktrees::allow_root("coverage-main", autobind_root.path())?;
    let missing_root = home.path().join("missing-root");
    let missing_worktree = missing_root.join("child");
    let _ = worktrees::allow_root("coverage-main", &missing_root)?;
    let autobind_context = verified_worktree(autobind_worktree, "https://example.test/demo");
    let autobind_allowed = enforce_worktree_for_no_prompt(&resolved_main, &autobind_context)?;
    assert!(autobind_allowed);
    let missing_autobind_context = verified_worktree(missing_worktree, "https://example.test/demo");
    let _ = enforce_worktree_for_no_prompt(&resolved_main, &missing_autobind_context)?;
    let _ = worktrees::remove_root("coverage-main", &missing_root)?;
    let approval_worktree = tempfile::tempdir()?;
    let approval_context = verified_worktree(
        approval_worktree.path().to_path_buf(),
        "https://example.test/demo",
    );
    let approval_allowed = enforce_worktree_for_no_prompt(&resolved_main, &approval_context)?;
    assert!(!approval_allowed);
    let registered_for_worktree = registry::load_registry()?
        .projects
        .get("coverage-main")
        .cloned()
        .context("coverage-main should be registered")?;
    let approve_pending_worktree = tempfile::tempdir()?;
    let approve_context = verified_worktree(
        approve_pending_worktree.path().to_path_buf(),
        "https://example.test/demo",
    );
    let decision =
        worktrees::evaluate_worktree(&registered_for_worktree, "coverage-main", &approve_context)?;
    assert!(matches!(
        decision,
        worktrees::WorktreeDecision::ApprovalRequired { .. }
    ));
    let request = worktrees::list_project("coverage-main")?
        .pending
        .last()
        .cloned()
        .context("coverage approve pending worktree missing")?;
    worktrees_command(WorktreesCommand::Approve {
        request_id: request.id,
        json: false,
    })
    .expect("coverage pending worktree approval should succeed");
    let deny_pending_worktree = tempfile::tempdir()?;
    let deny_context = verified_worktree(
        deny_pending_worktree.path().to_path_buf(),
        "https://example.test/demo",
    );
    let decision =
        worktrees::evaluate_worktree(&registered_for_worktree, "coverage-main", &deny_context)?;
    assert!(matches!(
        decision,
        worktrees::WorktreeDecision::ApprovalRequired { .. }
    ));
    let request = worktrees::list_project("coverage-main")?
        .pending
        .last()
        .cloned()
        .context("coverage deny pending worktree missing")?;
    worktrees_command(WorktreesCommand::Deny {
        request_id: request.id,
        json: false,
    })
    .expect("coverage pending worktree denial should succeed");
    let mut registry = registry::load_registry()?;
    registry
        .projects
        .get_mut("coverage-main")
        .expect("coverage-main should be registered")
        .git_remote = Some("https://example.test/expected.git".to_string());
    registry::save_registry(&registry)?;
    let denied_worktree = tempfile::tempdir()?;
    let denied_context = verified_worktree(
        denied_worktree.path().to_path_buf(),
        "https://example.test/other",
    );
    let denied_allowed = enforce_worktree_for_no_prompt(&resolved_main, &denied_context)?;
    assert!(!denied_allowed);
    registry
        .projects
        .get_mut("coverage-main")
        .expect("coverage-main should be registered")
        .git_remote = None;
    registry::save_registry(&registry)?;

    let missing_grant = ApprovalDecision {
        approved: true,
        scope: ApprovalScope::Once,
        approved_env: access.env.clone(),
        denied_env: Vec::new(),
        source: approvals::ApprovalSource::Grant,
        grant_id: None,
    };
    consume_once_grant_if_reused(&missing_grant)?;
    handle_post_run_logging_result(7, Err(anyhow::anyhow!("coverage log failure")))?;

    let mut removed_files = Vec::new();
    let missing_file = project.path().join("missing");
    remove_project_file_if_exists(&missing_file, &mut removed_files)?;
    remove_locked_env_if_needed(&missing_file, &missing_file, &mut removed_files)?;
    let no_marker = project.path().join("AGENTS.no-marker.md");
    fs::write(&no_marker, "Intro\n")?;
    let _ = remove_agent_instruction_section(&no_marker)?;
    let retained = project.path().join("AGENTS.retained.md");
    let retained_contents = "Intro\n\n<!-- ward-agent-instructions -->\nGenerated\n";
    fs::write(&retained, retained_contents)?;
    let _ = remove_agent_instruction_section(&retained)?;

    let no_json = run(RunOptions {
        profile: None,
        project: None,
        agent: Some("codex".to_string()),
        branch: None,
        action: Some("No prompt without json".to_string()),
        env_names: access.env.clone(),
        command: vec!["sh".to_string(), "-c".to_string(), "true".to_string()],
        json: false,
        no_prompt: true,
    });
    assert!(no_json.is_err());
    let critical_run = RunOptions {
        profile: None,
        project: None,
        agent: Some("codex".to_string()),
        branch: None,
        action: Some("Critical pending".to_string()),
        env_names: access.env.clone(),
        command: vec!["sh".to_string(), "-c".to_string(), "printenv".to_string()],
        json: true,
        no_prompt: true,
    };
    run(critical_run)?;
    let grant_source = approvals::ApprovalSource::ManualAllow;
    unlock_vault("1h", None)?;
    let receipt_context = Some(grants::GrantReceiptContext::synthetic(false));
    let scope = ApprovalScope::Always;
    let vault = &resolved_main.vault;
    let auto_context = context::VerifiedContext {
        project: "coverage-main".to_string(),
        agent: "codex".to_string(),
        agent_key_id: "agent:coverage".to_string(),
        worktree: project.path().to_path_buf(),
        branch: "main".to_string(),
        git_remote: "https://example.test/demo".to_string(),
        commit: "abc123".to_string(),
        git_common_dir: None,
    };
    let session_grant = grants::persist_manual_grant(
        &access,
        ApprovalScope::Session,
        approvals::ApprovalSource::ManualAllow,
        vault,
        None,
    )
    .expect("coverage default manual grant should persist");
    assert!(grants::persist_manual_grant(
        &access,
        ApprovalScope::Always,
        approvals::ApprovalSource::Grant,
        vault,
        Some(grants::GrantReceiptContext::synthetic(false)),
    )
    .is_err());
    assert!(grants::persist_manual_grant(
        &access,
        ApprovalScope::Deny,
        approvals::ApprovalSource::ManualAllow,
        vault,
        Some(grants::GrantReceiptContext::synthetic(false)),
    )
    .is_err());
    assert!(grants::persist_manual_grant(
        &access,
        ApprovalScope::Branch,
        approvals::ApprovalSource::ManualAllow,
        vault,
        Some(grants::GrantReceiptContext::synthetic(false)),
    )
    .is_err());
    let context_receipt = grants::GrantReceiptContext {
        request_id: uuid::Uuid::new_v4(),
        critical_confirmation: false,
        verified_context: Some(auto_context.clone()),
    };
    let _ = grants::persist_manual_grant(
        &access,
        ApprovalScope::Once,
        approvals::ApprovalSource::ManualAllow,
        vault,
        Some(context_receipt),
    )
    .expect("coverage context manual grant should persist");
    grants::persist_manual_grant(&access, scope, grant_source, vault, receipt_context.clone())?;
    let _ = grants::find_matching_grant(&access)?;
    let _ = grants::find_matching_grant_with_context(&access, &auto_context)?;
    let _ = grants::find_matching_non_always_grant(&access)?;
    let _ = grants::find_matching_non_always_grant_with_context(&access, &auto_context)?;
    let _ = grants::find_matching_once_grant(&access, false)?;
    let _ = grants::find_matching_once_grant_with_context(&access, false, &auto_context)?;
    let unlocked_run = RunOptions {
        profile: None,
        project: None,
        agent: Some("codex".to_string()),
        branch: None,
        action: Some("Unlocked run".to_string()),
        env_names: access.env.clone(),
        command: vec!["sh".to_string(), "-c".to_string(), "true".to_string()],
        json: true,
        no_prompt: true,
    };
    run(unlocked_run)?;
    let suspicious_session = ApprovalDecision {
        approved: true,
        scope: ApprovalScope::Session,
        approved_env: access.env.clone(),
        denied_env: Vec::new(),
        source: approvals::ApprovalSource::LocalTty,
        grant_id: None,
    };
    let _ = grants::persist_grant(&access, &suspicious_session, vault, receipt_context.clone())?;
    let _ = grants::persist_grant(&access, &suspicious_session, vault, None)?;
    let grants_edge_path = home.path().join("sessions").join("coverage-grants.jsonl");
    let grants_edge_parent = grants_edge_path
        .parent()
        .context("coverage grants edge path has no parent")?;
    fs::create_dir_all(grants_edge_parent)?;
    fs::write(&grants_edge_path, "\n")?;
    assert!(grants::load_grants_from_path(&grants_edge_path)?.is_empty());
    assert!(!grants::consume_once_grant(uuid::Uuid::new_v4())?);
    assert_eq!(grants::revoke_session_grants_at_path(&grants_edge_path)?, 0);
    let mut expired_grant = session_grant.clone();
    expired_grant.id = uuid::Uuid::new_v4();
    expired_grant.expires_at = Some(chrono::Utc::now() - chrono::Duration::minutes(1));
    let mut future_grant = session_grant.clone();
    future_grant.id = uuid::Uuid::new_v4();
    future_grant.expires_at = Some(chrono::Utc::now() + chrono::Duration::minutes(1));
    let mut durable_grant = session_grant.clone();
    durable_grant.id = uuid::Uuid::new_v4();
    durable_grant.expires_at = None;
    grants::append_grant_to_path(&grants_edge_path, &expired_grant)?;
    grants::append_grant_to_path(&grants_edge_path, &future_grant)?;
    grants::append_grant_to_path(&grants_edge_path, &durable_grant)?;
    assert_eq!(
        grants::prune_expired_grants_at_path(&grants_edge_path, chrono::Utc::now())?,
        1
    );
    assert_eq!(
        grants::grant_integrity_status(&expired_grant, chrono::Utc::now()),
        grants::GrantIntegrityStatus::Expired
    );
    let mut legacy_grant = future_grant.clone();
    legacy_grant.receipt = None;
    assert_eq!(
        grants::grant_integrity_status(&legacy_grant, chrono::Utc::now()),
        grants::GrantIntegrityStatus::LegacyUnsigned
    );
    let mut invalid_grant = future_grant.clone();
    invalid_grant.project = "tampered".to_string();
    assert_eq!(
        grants::grant_integrity_status(&invalid_grant, chrono::Utc::now()),
        grants::GrantIntegrityStatus::Invalid
    );
    let _ = non_interactive_decision(&access, &suspicious)?;
    let _ = non_interactive_decision_with_context(&access, &clean, None)?;
    let _ = non_interactive_decision_with_context(&access, &denied, Some(&auto_context))?;
    let fresh_access = AccessRequest {
        project: "coverage-main".to_string(),
        agent: Some("codex".to_string()),
        branch: None,
        action: Some("Fresh auto".to_string()),
        command: "sh -c echo fresh".to_string(),
        env: vec!["DATABASE_URL".to_string()],
    };
    let _ = non_interactive_decision_with_context(&fresh_access, &clean, Some(&auto_context))?;
    let _ = non_interactive_decision_with_context(&access, &clean, Some(&auto_context))?;
    broker_command(BrokerCommand::Stop)?;
    let _ = unlock::clear_all_unlocks()?;
    assert!(grants::persist_manual_grant(
        &access,
        ApprovalScope::Session,
        approvals::ApprovalSource::ManualAllow,
        vault,
        Some(grants::GrantReceiptContext::synthetic(false)),
    )
    .is_err());
    let unavailable_session = unlock::create_run_unlock(
        "coverage-main",
        vault,
        "coverage passphrase",
        chrono::Duration::hours(1),
    )
    .expect("coverage unavailable signing session should be created");
    crate::key_store::delete_secret(&unavailable_session.key_name)?;
    assert!(grants::persist_manual_grant(
        &access,
        ApprovalScope::Session,
        approvals::ApprovalSource::ManualAllow,
        vault,
        Some(grants::GrantReceiptContext::synthetic(false)),
    )
    .is_err());
    unlock_vault("1h", None)?;
    let verify_logs = Some(LogsCommand::Verify {
        kind: Some(LogKind::Requests),
        full: true,
    });
    logs(verify_logs, None)?;
    let export_logs = Some(LogsCommand::Export {
        kind: LogKind::Requests,
        output: project.path().join("requests.export.jsonl"),
        force: false,
    });
    logs(export_logs, None)?;
    assert!(teardown(None, ".env.unused".into(), false, false).is_err());

    let remove_project = tempfile::tempdir()?;
    env::set_current_dir(remove_project.path())?;
    fs::write(remove_project.path().join(".gitignore"), ".env\n.env.*\n")?;
    let remove_env = remove_project.path().join(".env");
    fs::write(&remove_env, "DATABASE_URL=postgres://remove\n")?;
    let remove_setup = SetupOptions {
        yes: true,
        project: Some("coverage-remove".to_string()),
        source: ".env".into(),
        vault: ".env.vault".into(),
        commit_vault: false,
        ignore_vault: false,
        remove_plaintext: true,
        keep_plaintext: false,
        unlock_ttl: "8h".to_string(),
        no_unlock: false,
    };
    setup(remove_setup)?;

    let import_project = tempfile::tempdir()?;
    env::set_current_dir(import_project.path())?;
    init(Some("coverage-import".to_string()), false, false)?;
    let import_env = import_project.path().join(".env");
    fs::write(&import_env, "DATABASE_URL=postgres://import\n")?;
    import(".env".into(), Some("relative.vault".into()))?;

    let doctor_project = tempfile::tempdir()?;
    env::set_current_dir(doctor_project.path())?;
    fs::write(doctor_project.path().join(".gitignore"), ".env\n.env.*\n")?;
    let doctor_env = doctor_project.path().join(".env");
    let doctor_vault = doctor_project.path().join(".env.vault");
    fs::write(&doctor_env, "DATABASE_URL=postgres://doctor\n")?;
    let doctor_setup = SetupOptions {
        yes: true,
        project: Some("coverage-doctor".to_string()),
        source: ".env".into(),
        vault: ".env.vault".into(),
        commit_vault: false,
        ignore_vault: false,
        remove_plaintext: false,
        keep_plaintext: false,
        unlock_ttl: "8h".to_string(),
        no_unlock: false,
    };
    setup(doctor_setup)?;
    doctor()?;
    fs::write(&doctor_env, "DATABASE_URL=postgres://plaintext\n")?;
    doctor()?;
    env_file::lock_env_file(&doctor_env, &doctor_vault)?;
    fs::write(&doctor_vault, "changed")?;
    doctor()?;
    fs::remove_file(&doctor_env)?;
    doctor()?;
    fs::create_dir(&doctor_env)?;
    doctor()?;
    let grants_path = grants::grants_path();
    let grants_parent = grants_path.parent().context("grants path has no parent")?;
    fs::create_dir_all(grants_parent)?;
    fs::write(grants_path, "{bad-json}\n")?;
    doctor()?;
    crate::broker::coverage_exercise_broker_edges()?;

    env::set_current_dir(old_cwd)?;
    env::remove_var("WARD_HOME");
    env::remove_var("WARD_UNSAFE_TEST_KEYRING");
    env::remove_var("WARD_UNSAFE_TEST_PASSPHRASE");
    Ok(())
}

fn likely_secret_env_files(cwd: &Path) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    for entry in fs::read_dir(cwd)? {
        let entry = entry?;
        let path = entry.path();
        let name = path
            .file_name()
            .map(|value| value.to_string_lossy())
            .unwrap_or_default();
        if name.starts_with(".env.") && name != ".env.example" && name != config::DEFAULT_VAULT_FILE
        {
            files.push(path);
        }
    }
    files.sort();
    Ok(files)
}

fn check_gitignore(cwd: &Path) -> Result<()> {
    let path = cwd.join(".gitignore");
    if !path.exists() {
        println!("! .gitignore missing; add .env and .env.*");
        return Ok(());
    }

    let contents =
        fs::read_to_string(&path).context(format!("failed to read {}", path.display()))?;
    let has_env = gitignore_contains(&contents, ".env");
    let has_env_variants = gitignore_contains(&contents, ".env.*");

    if has_env {
        println!("[ok] .gitignore contains .env");
    } else {
        println!("! .gitignore should contain .env");
    }

    if has_env_variants {
        println!("[ok] .gitignore contains .env.*");
        if gitignore_contains(&contents, "!.env.vault") {
            println!("[ok] .gitignore allows .env.vault");
        } else {
            println!("! If encrypted vaults should be committed, add !.env.vault after .env.*");
        }
    } else {
        println!("! .gitignore should contain .env.*");
    }

    Ok(())
}

fn gitignore_contains(contents: &str, expected: &str) -> bool {
    contents.lines().any(|line| {
        let trimmed = line.trim();
        !trimmed.starts_with('#') && trimmed == expected
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::ProjectConfig,
        policy::{AccessRequest, ApprovalMode, PolicyEvaluation},
    };
    use clap::CommandFactory;
    use std::{
        path::{Path, PathBuf},
        process::Command as StdCommand,
        sync::{Mutex, OnceLock},
    };

    fn cwd_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    #[test]
    fn remaining_session_ttl_only_returns_positive_duration() {
        let now = chrono::Utc::now();
        assert_eq!(
            remaining_session_ttl(now + chrono::Duration::seconds(30), now)
                .unwrap()
                .num_seconds(),
            30
        );
        assert!(remaining_session_ttl(now, now).is_none());
        assert!(remaining_session_ttl(now - chrono::Duration::seconds(1), now).is_none());
    }

    fn prepare_git_context(path: &Path, agent: &str, branch: Option<&str>) -> AgentContextOptions {
        StdCommand::new("git")
            .args(["init"])
            .current_dir(path)
            .output()
            .unwrap();
        StdCommand::new("git")
            .args(["config", "user.email", "tester@example.test"])
            .current_dir(path)
            .output()
            .unwrap();
        StdCommand::new("git")
            .args(["config", "user.name", "Tester"])
            .current_dir(path)
            .output()
            .unwrap();
        StdCommand::new("git")
            .args(["remote", "add", "origin", "https://example.test/demo.git"])
            .current_dir(path)
            .output()
            .unwrap();
        if let Some(branch_name) = branch {
            StdCommand::new("git")
                .args(["checkout", "-B", branch_name])
                .current_dir(path)
                .output()
                .unwrap();
        }
        StdCommand::new("git")
            .args(["add", "."])
            .current_dir(path)
            .output()
            .unwrap();
        StdCommand::new("git")
            .args(["commit", "--allow-empty", "-m", "init"])
            .env("GIT_AUTHOR_NAME", "Tester")
            .env("GIT_AUTHOR_EMAIL", "tester@example.test")
            .env("GIT_COMMITTER_NAME", "Tester")
            .env("GIT_COMMITTER_EMAIL", "tester@example.test")
            .current_dir(path)
            .output()
            .unwrap();
        let branch_name = branch.map(str::to_string).unwrap_or_else(|| {
            String::from_utf8(
                StdCommand::new("git")
                    .args(["branch", "--show-current"])
                    .current_dir(path)
                    .output()
                    .unwrap()
                    .stdout,
            )
            .unwrap()
            .trim()
            .to_string()
        });
        let commit = String::from_utf8(
            StdCommand::new("git")
                .args(["rev-parse", "HEAD"])
                .current_dir(path)
                .output()
                .unwrap()
                .stdout,
        )
        .unwrap()
        .trim()
        .to_string();
        AgentContextOptions {
            agent: Some(agent.to_string()),
            agent_key_id: None,
            worktree: Some(path.to_path_buf()),
            git_remote: Some("https://example.test/demo.git".to_string()),
            commit: Some(commit),
            branch: Some(branch_name),
        }
    }

    #[test]
    #[serial_test::serial]
    fn broker_and_worktree_command_helpers_execute_all_branches() {
        let _guard = cwd_lock();
        let home = tempfile::tempdir().unwrap();
        std::env::set_var("WARD_HOME", home.path());

        broker_command(BrokerCommand::SocketPath).unwrap();
        broker_command(BrokerCommand::Status).unwrap();
        broker_command(BrokerCommand::Stop).unwrap();

        let root = tempfile::tempdir().unwrap();
        worktrees_command(WorktreesCommand::AllowRoot {
            project: "demo".to_string(),
            path: root.path().to_path_buf(),
        })
        .unwrap();
        worktrees_command(WorktreesCommand::List {
            project: "demo".to_string(),
        })
        .unwrap();
        worktrees_command(WorktreesCommand::RemoveRoot {
            project: "demo".to_string(),
            path: root.path().to_path_buf(),
        })
        .unwrap();
        worktrees_command(WorktreesCommand::RemoveRoot {
            project: "demo".to_string(),
            path: root.path().to_path_buf(),
        })
        .unwrap();
        worktrees_command(WorktreesCommand::Approve {
            request_id: uuid::Uuid::new_v4(),
            json: false,
        })
        .unwrap();
        worktrees_command(WorktreesCommand::Deny {
            request_id: uuid::Uuid::new_v4(),
            json: false,
        })
        .unwrap();

        std::env::remove_var("WARD_HOME");
    }

    #[test]
    fn verified_agent_key_id_extracts_optional_context() {
        assert_eq!(verified_agent_key_id(None), None);
        let context = context::VerifiedContext {
            project: "demo".to_string(),
            agent: "codex".to_string(),
            agent_key_id: "agent:demo".to_string(),
            worktree: PathBuf::from("/tmp/demo"),
            branch: "main".to_string(),
            git_remote: "https://example.test/demo.git".to_string(),
            commit: "abc123".to_string(),
            git_common_dir: None,
        };
        assert_eq!(verified_agent_key_id(Some(&context)), Some("agent:demo"));
    }

    #[test]
    #[serial_test::serial]
    fn non_interactive_context_can_auto_approve_without_prompt_or_grant() {
        let _guard = cwd_lock();
        let home = tempfile::tempdir().unwrap();
        std::env::set_var("WARD_HOME", home.path());

        let context = context::VerifiedContext {
            project: "demo".to_string(),
            agent: "codex".to_string(),
            agent_key_id: "agent:demo".to_string(),
            worktree: PathBuf::from("/tmp/demo"),
            branch: "main".to_string(),
            git_remote: "https://example.test/demo.git".to_string(),
            commit: "abc123".to_string(),
            git_common_dir: None,
        };
        let decision = non_interactive_decision_with_context(
            &access(),
            &evaluation(ApprovalMode::Auto, false),
            Some(&context),
        )
        .unwrap()
        .unwrap();
        assert!(decision.approved);
        assert_eq!(decision.source, approvals::ApprovalSource::PolicyAuto);

        std::env::remove_var("WARD_HOME");
    }

    fn access() -> AccessRequest {
        AccessRequest {
            project: "demo".to_string(),
            agent: None,
            branch: None,
            action: None,
            command: "pnpm dev".to_string(),
            env: vec!["DATABASE_URL".to_string()],
        }
    }

    fn evaluation(mode: ApprovalMode, requires_prompt: bool) -> PolicyEvaluation {
        PolicyEvaluation {
            matched_profile: None,
            matched_preset: None,
            matched_mode: None,
            approval_mode: mode,
            requested_env: vec!["DATABASE_URL".to_string()],
            approved_env: vec!["DATABASE_URL".to_string()],
            denied_env: Vec::new(),
            requires_prompt,
            findings: Vec::new(),
        }
    }

    fn setup_test_signing_unlock(home: &std::path::Path, project: &str) -> PathBuf {
        std::env::set_var("WARD_HOME", home);
        std::env::set_var("WARD_UNSAFE_TEST_KEYRING", "1");
        let vault = home.join(format!("{project}.env.vault"));
        unlock::create_run_unlock(
            project,
            &vault,
            "coverage passphrase",
            chrono::Duration::hours(1),
        )
        .unwrap();
        vault
    }

    fn clear_test_signing_unlock() {
        std::env::remove_var("WARD_HOME");
        std::env::remove_var("WARD_UNSAFE_TEST_KEYRING");
    }

    #[test]
    fn prepare_git_context_reads_current_branch_when_not_supplied() {
        let _guard = cwd_lock();
        let project = tempfile::tempdir().unwrap();
        let context = prepare_git_context(project.path(), "codex", None);
        assert!(!context.branch.as_deref().unwrap_or_default().is_empty());
    }

    #[test]
    #[serial_test::serial]
    fn no_prompt_run_and_non_interactive_helpers_cover_json_edges() {
        let _guard = cwd_lock();
        let old_cwd = std::env::current_dir().unwrap();
        let keep_project = tempfile::tempdir().unwrap();
        let project = tempfile::tempdir().unwrap();
        let home = tempfile::tempdir().unwrap();
        std::env::set_current_dir(keep_project.path()).unwrap();
        std::env::set_var("WARD_HOME", home.path());
        std::env::set_var("WARD_UNSAFE_TEST_KEYRING", "1");
        std::env::set_var("WARD_UNSAFE_TEST_PASSPHRASE", "coverage passphrase");
        std::fs::write(keep_project.path().join(".gitignore"), ".env\n.env.*\n").unwrap();
        std::fs::write(
            keep_project.path().join(".env"),
            "DATABASE_URL=postgres://kept\n",
        )
        .unwrap();

        dispatch(Cli {
            command: Commands::Setup {
                yes: true,
                project: Some("kept".to_string()),
                source: ".env".into(),
                vault: ".env.vault".into(),
                commit_vault: false,
                ignore_vault: false,
                remove_plaintext: false,
                keep_plaintext: true,
                unlock_ttl: "8h".to_string(),
                no_unlock: false,
            },
        })
        .unwrap();
        assert!(keep_project.path().join(".env").exists());

        std::env::set_current_dir(project.path()).unwrap();
        std::fs::write(project.path().join(".gitignore"), ".env\n.env.*\n").unwrap();
        std::fs::write(
            project.path().join(".env"),
            "DATABASE_URL=postgres://coverage\n",
        )
        .unwrap();

        setup(SetupOptions {
            yes: true,
            project: Some("demo".to_string()),
            source: ".env".into(),
            vault: ".env.vault".into(),
            commit_vault: false,
            ignore_vault: false,
            remove_plaintext: false,
            keep_plaintext: false,
            unlock_ttl: "8h".to_string(),
            no_unlock: false,
        })
        .unwrap();

        let no_json_error = run(RunOptions {
            profile: None,
            project: None,
            agent: Some("codex".to_string()),
            branch: None,
            action: Some("No JSON".to_string()),
            env_names: vec!["DATABASE_URL".to_string()],
            command: vec!["sh".to_string(), "-c".to_string(), "true".to_string()],
            json: false,
            no_prompt: true,
        })
        .unwrap_err()
        .to_string();
        assert!(no_json_error.contains("--no-prompt requires --json"));

        run(RunOptions {
            profile: None,
            project: None,
            agent: Some("codex".to_string()),
            branch: None,
            action: Some("Needs approval".to_string()),
            env_names: vec!["DATABASE_URL".to_string()],
            command: vec!["sh".to_string(), "-c".to_string(), "true".to_string()],
            json: true,
            no_prompt: true,
        })
        .unwrap();

        let mut project_config = config::read_project_config(project.path()).unwrap();
        project_config.presets.push(config::PresetConfig {
            name: "Deny shell".to_string(),
            match_commands: vec!["sh -c false".to_string()],
            allowed_env: Vec::new(),
            approval: ApprovalMode::Deny,
        });
        config::write_project_config(project.path(), &project_config, true).unwrap();
        run(RunOptions {
            profile: None,
            project: None,
            agent: Some("codex".to_string()),
            branch: None,
            action: Some("Denied no prompt".to_string()),
            env_names: vec!["DATABASE_URL".to_string()],
            command: vec!["sh".to_string(), "-c".to_string(), "false".to_string()],
            json: true,
            no_prompt: true,
        })
        .unwrap();

        let access = access();
        let mut denied = evaluation(ApprovalMode::Deny, false);
        denied.denied_env = vec!["DATABASE_URL".to_string()];
        let denied_decision = non_interactive_decision(&access, &denied).unwrap().unwrap();
        assert!(!denied_decision.approved);
        print_run_denied(&access, &denied).unwrap();
        assert_eq!(run_risk_summary(&denied), "warning");

        let mut critical = evaluation(ApprovalMode::Prompt, true);
        critical.findings.push(crate::detection::Finding::critical(
            "critical.test",
            "critical finding",
        ));
        assert_eq!(run_risk_summary(&critical), "critical");

        let clean = evaluation(ApprovalMode::Auto, false);
        assert_eq!(run_risk_summary(&clean), "low");
        assert!(
            non_interactive_decision(&access, &clean)
                .unwrap()
                .unwrap()
                .approved
        );

        std::env::set_current_dir(old_cwd).unwrap();
        std::env::remove_var("WARD_HOME");
        std::env::remove_var("WARD_UNSAFE_TEST_KEYRING");
        std::env::remove_var("WARD_UNSAFE_TEST_PASSPHRASE");
    }

    #[test]
    #[serial_test::serial]
    fn doctor_reports_stale_locked_env_and_env_state_errors() {
        let _guard = cwd_lock();
        let old_cwd = std::env::current_dir().unwrap();
        let project = tempfile::tempdir().unwrap();
        let home = tempfile::tempdir().unwrap();
        std::env::set_current_dir(project.path()).unwrap();
        std::env::set_var("WARD_HOME", home.path());
        std::env::set_var("WARD_UNSAFE_TEST_KEYRING", "1");
        std::env::set_var("WARD_UNSAFE_TEST_PASSPHRASE", "coverage passphrase");
        std::fs::write(project.path().join(".gitignore"), ".env\n.env.*\n").unwrap();
        std::fs::write(
            project.path().join(".env"),
            "DATABASE_URL=postgres://coverage\n",
        )
        .unwrap();

        setup(SetupOptions {
            yes: true,
            project: Some("demo".to_string()),
            source: ".env".into(),
            vault: ".env.vault".into(),
            commit_vault: false,
            ignore_vault: false,
            remove_plaintext: false,
            keep_plaintext: false,
            unlock_ttl: "8h".to_string(),
            no_unlock: false,
        })
        .unwrap();
        std::fs::write(project.path().join(".env.vault"), "changed").unwrap();
        doctor().unwrap();

        std::fs::remove_file(project.path().join(".env")).unwrap();
        std::fs::create_dir(project.path().join(".env")).unwrap();
        doctor().unwrap();

        std::env::set_current_dir(old_cwd).unwrap();
        std::env::remove_var("WARD_HOME");
        std::env::remove_var("WARD_UNSAFE_TEST_KEYRING");
        std::env::remove_var("WARD_UNSAFE_TEST_PASSPHRASE");
    }

    #[test]
    fn remove_agent_instruction_section_handles_marker_edges() {
        let tempdir = tempfile::tempdir().unwrap();
        let missing = tempdir.path().join("missing.md");
        assert!(!remove_agent_instruction_section(&missing).unwrap());
        let mut removed_files = Vec::new();
        remove_project_file_if_exists(&missing, &mut removed_files).unwrap();
        assert!(removed_files.is_empty());
        remove_locked_env_if_needed(&missing, &missing, &mut removed_files).unwrap();
        assert!(removed_files.is_empty());

        let remove_me = tempdir.path().join("remove-me");
        std::fs::write(&remove_me, "temporary").unwrap();
        remove_project_file_if_exists(&remove_me, &mut removed_files).unwrap();
        assert!(!remove_me.exists());
        assert_eq!(removed_files.len(), 1);

        let vault = tempdir.path().join(".env.vault");
        std::fs::write(&vault, "encrypted").unwrap();
        let locked_env = tempdir.path().join(".env");
        env_file::lock_env_file(&locked_env, &vault).unwrap();
        remove_locked_env_if_needed(
            &locked_env,
            &tempdir.path().join(".env.export"),
            &mut removed_files,
        )
        .unwrap();
        assert!(!locked_env.exists());

        let no_marker = tempdir.path().join("no-marker.md");
        std::fs::write(&no_marker, "Intro\n").unwrap();
        assert!(!remove_agent_instruction_section(&no_marker).unwrap());

        let retained = tempdir.path().join("retained.md");
        std::fs::write(
            &retained,
            "Intro\n\n<!-- ward-agent-instructions -->\nGenerated\n",
        )
        .unwrap();
        assert!(remove_agent_instruction_section(&retained).unwrap());
        assert_eq!(std::fs::read_to_string(&retained).unwrap(), "Intro\n");
    }

    #[test]
    #[serial_test::serial]
    fn setup_reports_missing_source_and_registry_failures() {
        let _guard = cwd_lock();
        let old_cwd = std::env::current_dir().unwrap();
        let project = tempfile::tempdir().unwrap();
        std::env::set_current_dir(project.path()).unwrap();

        let dispatch_conflict = dispatch(Cli {
            command: Commands::Setup {
                yes: true,
                project: Some("demo".to_string()),
                source: "missing.env".into(),
                vault: "missing.vault".into(),
                commit_vault: true,
                ignore_vault: true,
                remove_plaintext: false,
                keep_plaintext: false,
                unlock_ttl: "8h".to_string(),
                no_unlock: true,
            },
        })
        .unwrap_err()
        .to_string();
        assert!(dispatch_conflict.contains("choose either --commit-vault or --ignore-vault"));

        let plaintext_conflict = setup(SetupOptions {
            yes: true,
            project: Some("demo".to_string()),
            source: "missing.env".into(),
            vault: "missing.vault".into(),
            commit_vault: false,
            ignore_vault: false,
            remove_plaintext: true,
            keep_plaintext: true,
            unlock_ttl: "8h".to_string(),
            no_unlock: false,
        })
        .unwrap_err()
        .to_string();
        assert!(plaintext_conflict.contains("choose either --remove-plaintext or --keep-plaintext"));

        let missing = setup(SetupOptions {
            yes: false,
            project: Some("demo".to_string()),
            source: "missing.env".into(),
            vault: "missing.vault".into(),
            commit_vault: false,
            ignore_vault: false,
            remove_plaintext: false,
            keep_plaintext: false,
            unlock_ttl: "8h".to_string(),
            no_unlock: false,
        })
        .unwrap_err()
        .to_string();
        assert!(missing.contains("missing.env does not exist"));

        let absolute_vault = project.path().join("absolute.env.vault");
        std::fs::write(&absolute_vault, "placeholder").unwrap();
        let bad_home = project.path().join("not-a-dir");
        std::fs::write(&bad_home, "file").unwrap();
        std::env::set_var("WARD_HOME", &bad_home);

        let registry_error = setup(SetupOptions {
            yes: false,
            project: Some("demo".to_string()),
            source: "missing.env".into(),
            vault: absolute_vault,
            commit_vault: false,
            ignore_vault: false,
            remove_plaintext: false,
            keep_plaintext: false,
            unlock_ttl: "8h".to_string(),
            no_unlock: false,
        })
        .unwrap_err()
        .to_string();
        assert!(registry_error.contains("failed to create"));

        std::env::set_current_dir(old_cwd).unwrap();
        std::env::remove_var("WARD_HOME");
    }

    #[test]
    #[serial_test::serial]
    fn setup_updates_existing_config_without_yes_output() {
        let _guard = cwd_lock();
        let old_cwd = std::env::current_dir().unwrap();
        let project = tempfile::tempdir().unwrap();
        let home = tempfile::tempdir().unwrap();
        std::env::set_current_dir(project.path()).unwrap();
        std::env::set_var("WARD_HOME", home.path());
        std::env::set_var("WARD_UNSAFE_TEST_KEYRING", "1");
        std::env::set_var("WARD_UNSAFE_TEST_PASSPHRASE", "coverage passphrase");

        let config =
            ProjectConfig::default_for_dir(project.path(), Some("old-demo".to_string())).unwrap();
        config::write_project_config(project.path(), &config, false).unwrap();
        let seed_env = project.path().join("seed.env");
        std::fs::write(&seed_env, "DATABASE_URL=postgres://coverage\n").unwrap();
        vault::import_env_file(
            &seed_env,
            &project.path().join(".env.vault"),
            "coverage passphrase",
        )
        .unwrap();

        setup(SetupOptions {
            yes: false,
            project: Some("new-demo".to_string()),
            source: "missing.env".into(),
            vault: ".env.vault".into(),
            commit_vault: false,
            ignore_vault: false,
            remove_plaintext: false,
            keep_plaintext: false,
            unlock_ttl: "8h".to_string(),
            no_unlock: false,
        })
        .unwrap();
        assert_eq!(
            config::read_project_config(project.path()).unwrap().project,
            "new-demo"
        );

        std::env::set_current_dir(old_cwd).unwrap();
        std::env::remove_var("WARD_HOME");
        std::env::remove_var("WARD_UNSAFE_TEST_KEYRING");
        std::env::remove_var("WARD_UNSAFE_TEST_PASSPHRASE");
    }

    #[test]
    #[serial_test::serial]
    fn setup_imports_source_env_in_unit_flow() {
        let _guard = cwd_lock();
        let old_cwd = std::env::current_dir().unwrap();
        let project = tempfile::tempdir().unwrap();
        let home = tempfile::tempdir().unwrap();
        std::env::set_current_dir(project.path()).unwrap();
        std::env::set_var("WARD_HOME", home.path());
        std::env::set_var("WARD_UNSAFE_TEST_KEYRING", "1");
        std::env::set_var("WARD_UNSAFE_TEST_PASSPHRASE", "coverage passphrase");
        std::fs::write(
            project.path().join(".env"),
            "DATABASE_URL=postgres://coverage\nPAYLOAD_SECRET=payload\n",
        )
        .unwrap();

        setup(SetupOptions {
            yes: true,
            project: Some("demo".to_string()),
            source: ".env".into(),
            vault: ".env.vault".into(),
            commit_vault: false,
            ignore_vault: false,
            remove_plaintext: false,
            keep_plaintext: false,
            unlock_ttl: "8h".to_string(),
            no_unlock: false,
        })
        .unwrap();
        assert!(env_file::is_locked_env_file(&project.path().join(".env")).unwrap());
        assert!(project.path().join(".env.vault").exists());
        setup(SetupOptions {
            yes: true,
            project: Some("demo".to_string()),
            source: ".env".into(),
            vault: ".env.vault".into(),
            commit_vault: false,
            ignore_vault: false,
            remove_plaintext: false,
            keep_plaintext: false,
            unlock_ttl: "8h".to_string(),
            no_unlock: false,
        })
        .unwrap();
        assert!(vault::decrypt_vault_file(
            &project.path().join(".env.vault"),
            "coverage passphrase"
        )
        .unwrap()
        .contains("postgres://coverage"));
        std::fs::remove_file(project.path().join(".env.vault")).unwrap();
        let missing_vault = setup(SetupOptions {
            yes: true,
            project: Some("demo".to_string()),
            source: ".env".into(),
            vault: ".env.vault".into(),
            commit_vault: false,
            ignore_vault: false,
            remove_plaintext: false,
            keep_plaintext: false,
            unlock_ttl: "8h".to_string(),
            no_unlock: false,
        })
        .unwrap_err()
        .to_string();
        assert!(missing_vault.contains("Ward locked marker"));

        std::env::set_current_dir(old_cwd).unwrap();
        std::env::remove_var("WARD_HOME");
        std::env::remove_var("WARD_UNSAFE_TEST_KEYRING");
        std::env::remove_var("WARD_UNSAFE_TEST_PASSPHRASE");
    }

    #[test]
    #[serial_test::serial]
    fn setup_can_still_remove_plaintext_when_deprecated_flag_is_explicit() {
        let _guard = cwd_lock();
        let old_cwd = std::env::current_dir().unwrap();
        let project = tempfile::tempdir().unwrap();
        let home = tempfile::tempdir().unwrap();
        std::env::set_current_dir(project.path()).unwrap();
        std::env::set_var("WARD_HOME", home.path());
        std::env::set_var("WARD_UNSAFE_TEST_KEYRING", "1");
        std::env::set_var("WARD_UNSAFE_TEST_PASSPHRASE", "coverage passphrase");
        std::fs::write(project.path().join(".gitignore"), ".env\n.env.*\n").unwrap();
        std::fs::write(
            project.path().join(".env"),
            "DATABASE_URL=postgres://coverage\n",
        )
        .unwrap();

        setup(SetupOptions {
            yes: true,
            project: Some("demo".to_string()),
            source: ".env".into(),
            vault: ".env.vault".into(),
            commit_vault: false,
            ignore_vault: false,
            remove_plaintext: true,
            keep_plaintext: false,
            unlock_ttl: "8h".to_string(),
            no_unlock: false,
        })
        .unwrap();

        assert!(!project.path().join(".env").exists());
        assert!(project.path().join(".env.vault").exists());

        std::env::set_current_dir(old_cwd).unwrap();
        std::env::remove_var("WARD_HOME");
        std::env::remove_var("WARD_UNSAFE_TEST_KEYRING");
        std::env::remove_var("WARD_UNSAFE_TEST_PASSPHRASE");
    }

    #[test]
    #[serial_test::serial]
    fn dispatch_covers_projects_env_unlock_required_and_teardown_paths() {
        let _guard = cwd_lock();
        let old_cwd = std::env::current_dir().unwrap();
        let project = tempfile::tempdir().unwrap();
        let home = tempfile::tempdir().unwrap();
        std::env::set_current_dir(project.path()).unwrap();
        std::env::set_var("WARD_HOME", home.path());
        std::env::set_var("WARD_UNSAFE_TEST_KEYRING", "1");
        std::env::set_var("WARD_UNSAFE_TEST_PASSPHRASE", "coverage passphrase");
        std::fs::write(project.path().join(".gitignore"), ".env\n.env.*\n").unwrap();
        std::fs::write(
            project.path().join(".env"),
            "DATABASE_URL=postgres://coverage\nPAYLOAD_SECRET=payload\n",
        )
        .unwrap();

        dispatch(Cli {
            command: Commands::Setup {
                yes: true,
                project: Some("demo".to_string()),
                source: ".env".into(),
                vault: ".env.vault".into(),
                commit_vault: false,
                ignore_vault: false,
                remove_plaintext: false,
                keep_plaintext: false,
                unlock_ttl: "8h".to_string(),
                no_unlock: true,
            },
        })
        .unwrap();
        dispatch(Cli {
            command: Commands::Projects {
                command: ProjectsCommand::List,
            },
        })
        .unwrap();
        dispatch(Cli {
            command: Commands::Projects {
                command: ProjectsCommand::Show {
                    project: Some("demo".to_string()),
                },
            },
        })
        .unwrap();
        dispatch(Cli {
            command: Commands::Projects {
                command: ProjectsCommand::Use {
                    project: "demo".to_string(),
                },
            },
        })
        .unwrap();
        dispatch(Cli {
            command: Commands::Projects {
                command: ProjectsCommand::Register {
                    project: "temporary".to_string(),
                    path: Some(project.path().to_path_buf()),
                    vault: Some(".env.vault".into()),
                },
            },
        })
        .unwrap();
        dispatch(Cli {
            command: Commands::Projects {
                command: ProjectsCommand::Remove {
                    project: "temporary".to_string(),
                },
            },
        })
        .unwrap();
        dispatch(Cli {
            command: Commands::Projects {
                command: ProjectsCommand::Remove {
                    project: "missing".to_string(),
                },
            },
        })
        .unwrap();

        for command in [
            EnvCommand::List { project: None },
            EnvCommand::Set {
                project: None,
                assignment: "OPENAI_API_KEY=sk-test".to_string(),
            },
            EnvCommand::Unset {
                project: None,
                key: "OPENAI_API_KEY".to_string(),
            },
            EnvCommand::Unset {
                project: None,
                key: "MISSING_ENV".to_string(),
            },
            EnvCommand::Unlock {
                project: None,
                output: ".env.manual".into(),
                force: false,
            },
            EnvCommand::Lock {
                project: None,
                source: ".env.manual".into(),
            },
            EnvCommand::Export {
                project: None,
                output: None,
                force: true,
                unsafe_stdout: false,
            },
            EnvCommand::Export {
                project: None,
                output: Some(".env.dispatch.export".into()),
                force: false,
                unsafe_stdout: false,
            },
        ] {
            dispatch(Cli {
                command: Commands::Env { command },
            })
            .unwrap();
        }

        let mut project_config = config::read_project_config(project.path()).unwrap();
        project_config
            .profiles
            .get_mut("dev")
            .expect("setup creates the dev profile")
            .command = "sh -c true".to_string();
        config::write_project_config(project.path(), &project_config, true).unwrap();

        unlock_vault("1h", None).unwrap();
        let agent_context = prepare_git_context(project.path(), "codex", Some("feature/dispatch"));

        dispatch(Cli {
            command: Commands::Allow {
                profile: Some("dev".to_string()),
                scope: Some(ApprovalScope::Always),
                agent: Some("codex".to_string()),
                branch: None,
                command: None,
                env_names: Vec::new(),
            },
        })
        .unwrap();
        dispatch(Cli {
            command: Commands::Run {
                profile: Some("dev".to_string()),
                project: None,
                agent: Some("codex".to_string()),
                agent_key_id: agent_context.agent_key_id.clone(),
                worktree: agent_context.worktree.clone(),
                git_remote: agent_context.git_remote.clone(),
                commit: agent_context.commit.clone(),
                branch: agent_context.branch.clone(),
                action: None,
                env_names: Vec::new(),
                json: true,
                no_prompt: true,
                command: Vec::new(),
            },
        })
        .unwrap();
        dispatch(Cli {
            command: Commands::Request {
                profile: None,
                agent: Some("codex".to_string()),
                agent_key_id: None,
                worktree: None,
                git_remote: None,
                commit: None,
                branch: None,
                action: Some("Leave pending".to_string()),
                command: Some("pnpm test".to_string()),
                env_names: vec!["DATABASE_URL".to_string()],
                json: true,
                no_prompt: true,
            },
        })
        .unwrap();
        dispatch(Cli {
            command: Commands::Teardown {
                project: None,
                export_path: ".env.final".into(),
                yes: true,
                restore_env: false,
            },
        })
        .unwrap();

        std::env::set_current_dir(old_cwd).unwrap();
        std::env::remove_var("WARD_HOME");
        std::env::remove_var("WARD_UNSAFE_TEST_KEYRING");
        std::env::remove_var("WARD_UNSAFE_TEST_PASSPHRASE");
    }

    #[test]
    #[serial_test::serial]
    fn setup_reports_source_config_import_and_log_failures() {
        let _guard = cwd_lock();
        let old_cwd = std::env::current_dir().unwrap();
        let home = tempfile::tempdir().unwrap();
        std::env::set_var("WARD_HOME", home.path());
        std::env::set_var("WARD_UNSAFE_TEST_KEYRING", "1");
        std::env::set_var("WARD_UNSAFE_TEST_PASSPHRASE", "coverage passphrase");

        let invalid_project = tempfile::tempdir().unwrap();
        std::env::set_current_dir(invalid_project.path()).unwrap();
        std::fs::write(
            invalid_project.path().join(".env"),
            "DATABASE_URL='unterminated\n",
        )
        .unwrap();
        let invalid_source = setup(SetupOptions {
            yes: true,
            project: Some("demo".to_string()),
            source: ".env".into(),
            vault: ".env.vault".into(),
            commit_vault: false,
            ignore_vault: false,
            remove_plaintext: false,
            keep_plaintext: true,
            unlock_ttl: "8h".to_string(),
            no_unlock: false,
        })
        .expect_err("invalid dotenv should fail setup")
        .to_string();

        let config_blocked = tempfile::tempdir().unwrap();
        std::env::set_current_dir(config_blocked.path()).unwrap();
        std::fs::write(config_blocked.path().join(".env.vault"), "placeholder").unwrap();
        std::fs::create_dir(config_blocked.path().join(".ward.json")).unwrap();
        let config_error = setup(SetupOptions {
            yes: true,
            project: Some("demo".to_string()),
            source: "missing.env".into(),
            vault: ".env.vault".into(),
            commit_vault: false,
            ignore_vault: false,
            remove_plaintext: false,
            keep_plaintext: false,
            unlock_ttl: "8h".to_string(),
            no_unlock: false,
        })
        .expect_err("blocked config path should fail setup")
        .to_string();

        let import_blocked = tempfile::tempdir().unwrap();
        std::env::set_current_dir(import_blocked.path()).unwrap();
        std::fs::write(
            import_blocked.path().join(".env"),
            "DATABASE_URL=postgres://coverage\n",
        )
        .unwrap();
        std::fs::create_dir(import_blocked.path().join(".env.vault")).unwrap();
        let import_error = setup(SetupOptions {
            yes: true,
            project: Some("demo".to_string()),
            source: ".env".into(),
            vault: ".env.vault".into(),
            commit_vault: false,
            ignore_vault: false,
            remove_plaintext: false,
            keep_plaintext: true,
            unlock_ttl: "8h".to_string(),
            no_unlock: false,
        })
        .expect_err("directory vault path should fail setup")
        .to_string();

        let env_example_blocked = tempfile::tempdir().unwrap();
        std::env::set_current_dir(env_example_blocked.path()).unwrap();
        std::fs::write(env_example_blocked.path().join(".env.vault"), "placeholder").unwrap();
        std::fs::create_dir(env_example_blocked.path().join(".env.example")).unwrap();
        let env_example_error = setup(SetupOptions {
            yes: true,
            project: Some("demo".to_string()),
            source: "missing.env".into(),
            vault: ".env.vault".into(),
            commit_vault: false,
            ignore_vault: false,
            remove_plaintext: false,
            keep_plaintext: false,
            unlock_ttl: "8h".to_string(),
            no_unlock: false,
        })
        .expect_err("directory .env.example should fail setup")
        .to_string();

        let instructions_blocked = tempfile::tempdir().unwrap();
        std::env::set_current_dir(instructions_blocked.path()).unwrap();
        std::fs::write(
            instructions_blocked.path().join(".env.vault"),
            "placeholder",
        )
        .unwrap();
        std::fs::create_dir(instructions_blocked.path().join("AGENTS.md")).unwrap();
        let instructions_error = setup(SetupOptions {
            yes: true,
            project: Some("demo".to_string()),
            source: "missing.env".into(),
            vault: ".env.vault".into(),
            commit_vault: false,
            ignore_vault: false,
            remove_plaintext: false,
            keep_plaintext: false,
            unlock_ttl: "8h".to_string(),
            no_unlock: false,
        })
        .expect_err("directory AGENTS.md should fail setup")
        .to_string();

        let gitignore_blocked = tempfile::tempdir().unwrap();
        std::env::set_current_dir(gitignore_blocked.path()).unwrap();
        std::fs::write(gitignore_blocked.path().join(".env.vault"), "placeholder").unwrap();
        std::fs::create_dir(gitignore_blocked.path().join(".gitignore")).unwrap();
        let gitignore_error = setup(SetupOptions {
            yes: true,
            project: Some("demo".to_string()),
            source: "missing.env".into(),
            vault: ".env.vault".into(),
            commit_vault: false,
            ignore_vault: false,
            remove_plaintext: false,
            keep_plaintext: false,
            unlock_ttl: "8h".to_string(),
            no_unlock: false,
        })
        .expect_err("directory .gitignore should fail setup")
        .to_string();

        #[cfg(unix)]
        let log_error = {
            let log_blocked = tempfile::tempdir().unwrap();
            std::env::set_current_dir(log_blocked.path()).unwrap();
            std::fs::write(
                log_blocked.path().join(".env"),
                "DATABASE_URL=postgres://coverage\n",
            )
            .unwrap();
            std::fs::create_dir_all(home.path().join("logs/sessions.jsonl")).unwrap();
            let error = setup(SetupOptions {
                yes: true,
                project: Some("demo".to_string()),
                source: ".env".into(),
                vault: ".env.vault".into(),
                commit_vault: false,
                ignore_vault: false,
                remove_plaintext: false,
                keep_plaintext: true,
                unlock_ttl: "8h".to_string(),
                no_unlock: false,
            })
            .expect_err("directory log file should fail setup")
            .to_string();
            std::fs::remove_dir_all(home.path().join("logs/sessions.jsonl")).unwrap();
            error
        };

        std::env::set_current_dir(old_cwd).unwrap();
        std::env::remove_var("WARD_HOME");
        std::env::remove_var("WARD_UNSAFE_TEST_KEYRING");
        std::env::remove_var("WARD_UNSAFE_TEST_PASSPHRASE");

        assert!(invalid_source.contains("failed to parse"));
        assert!(config_error.contains("failed to write"));
        assert!(import_error.contains("failed to write"));
        assert!(env_example_error.contains("failed to read"));
        assert!(instructions_error.contains("failed to read"));
        assert!(gitignore_error.contains("failed to read"));
        #[cfg(unix)]
        assert!(log_error.contains("failed to read"));
    }

    #[test]
    #[serial_test::serial]
    fn dispatch_and_stateful_commands_cover_cli_paths() {
        let _guard = cwd_lock();
        let old_cwd = std::env::current_dir().unwrap();
        let project = tempfile::tempdir().unwrap();
        let home = tempfile::tempdir().unwrap();
        std::env::set_var("WARD_HOME", home.path());
        std::env::set_var("WARD_UNSAFE_TEST_KEYRING", "1");
        std::env::set_var("WARD_UNSAFE_TEST_PASSPHRASE", "coverage passphrase");
        std::env::set_current_dir(project.path()).unwrap();
        std::fs::write(
            project.path().join(".env"),
            "DATABASE_URL=postgres://coverage\nPAYLOAD_SECRET=payload\n",
        )
        .unwrap();
        std::fs::write(project.path().join(".gitignore"), ".env\n.env.*\n").unwrap();

        dispatch(Cli {
            command: Commands::Init {
                project: Some("demo".to_string()),
                force: false,
                bare: true,
            },
        })
        .unwrap();
        dispatch(Cli {
            command: Commands::Import {
                source: ".env".into(),
                vault: None,
            },
        })
        .unwrap();
        std::fs::write(
            project.path().join(".env.alt"),
            "DATABASE_URL=postgres://coverage-alt\nPAYLOAD_SECRET=payload-alt\n",
        )
        .unwrap();
        dispatch(Cli {
            command: Commands::Import {
                source: ".env.alt".into(),
                vault: Some(".env.alt.vault".into()),
            },
        })
        .unwrap();
        let mut config_after_alt_import = config::read_project_config(project.path()).unwrap();
        config_after_alt_import.vault = ".env.vault".into();
        config::write_project_config(project.path(), &config_after_alt_import, true).unwrap();
        std::fs::remove_file(project.path().join(".env")).unwrap();
        dispatch(Cli {
            command: Commands::Register {
                project: "demo".to_string(),
                path: None,
                vault: None,
            },
        })
        .unwrap();
        dispatch(Cli {
            command: Commands::Register {
                project: "demo-alt".to_string(),
                path: None,
                vault: Some(project.path().join(".env.alt.vault")),
            },
        })
        .unwrap();
        dispatch(Cli {
            command: Commands::Use {
                project: "demo".to_string(),
            },
        })
        .unwrap();
        init(Some("demo".to_string()), true, true).unwrap();
        let mut project_config = config::read_project_config(project.path()).unwrap();
        let dev_profile = project_config.profiles.get_mut("dev").unwrap();
        dev_profile.command = "sh -c true".to_string();
        dev_profile.env = vec!["DATABASE_URL".to_string(), "PAYLOAD_SECRET".to_string()];
        let migrate_profile = project_config.profiles.get_mut("migrate").unwrap();
        migrate_profile.command = "sh -c true".to_string();
        migrate_profile.env = vec!["DATABASE_URL".to_string(), "PAYLOAD_SECRET".to_string()];
        migrate_profile.default_scope = ApprovalScope::Always;
        config::write_project_config(project.path(), &project_config, true).unwrap();
        unlock_vault("1h", None).unwrap();
        let agent_context = prepare_git_context(project.path(), "codex", Some("feature/dispatch"));

        assert!(request(
            None,
            AgentContextOptions {
                agent: Some("codex".to_string()),
                branch: None,
                ..AgentContextOptions::default()
            },
            Some("No prompt without json".to_string()),
            Some("sh -c true".to_string()),
            vec!["DATABASE_URL".to_string()],
            false,
            true,
        )
        .is_err());

        dispatch(Cli {
            command: Commands::Request {
                profile: None,
                agent: Some("codex".to_string()),
                agent_key_id: agent_context.agent_key_id.clone(),
                worktree: agent_context.worktree.clone(),
                git_remote: agent_context.git_remote.clone(),
                commit: agent_context.commit.clone(),
                branch: agent_context.branch.clone(),
                action: Some("Run request".to_string()),
                command: Some("sh -c true".to_string()),
                env_names: vec!["DATABASE_URL".to_string()],
                json: true,
                no_prompt: true,
            },
        })
        .unwrap();
        let pending_id = pending_requests::requests_dir()
            .read_dir()
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path()
            .file_stem()
            .unwrap()
            .to_string_lossy()
            .parse::<uuid::Uuid>()
            .unwrap();
        dispatch(Cli {
            command: Commands::Approve {
                request_id: pending_id,
                scope: ApprovalScope::Once,
                confirm_critical: false,
                agent_mediated: true,
                json: false,
            },
        })
        .unwrap();

        dispatch(Cli {
            command: Commands::Allow {
                profile: None,
                scope: Some(ApprovalScope::Always),
                agent: Some("codex".to_string()),
                branch: None,
                command: Some("sh -c true".to_string()),
                env_names: vec!["DATABASE_URL".to_string()],
            },
        })
        .unwrap();
        assert!(allow(
            None,
            Some(ApprovalScope::Deny),
            None,
            None,
            Some("sh -c true".to_string()),
            vec!["DATABASE_URL".to_string()],
        )
        .is_err());
        assert!(allow(
            None,
            None,
            None,
            None,
            Some("sh -c true".to_string()),
            vec!["DATABASE_URL".to_string()],
        )
        .is_err());
        assert!(allow(
            Some("dev".to_string()),
            Some(ApprovalScope::Always),
            None,
            None,
            Some("sh -c true".to_string()),
            Vec::new(),
        )
        .is_err());
        std::env::set_var("WARD_UNSAFE_TEST_APPROVAL", "deny");
        assert!(run(RunOptions {
            profile: None,
            project: None,
            agent: Some("codex".to_string()),
            branch: None,
            action: Some("Denied run".to_string()),
            env_names: vec!["DATABASE_URL".to_string()],
            command: vec!["sh".to_string(), "-c".to_string(), "false".to_string()],
            json: false,
            no_prompt: false,
        })
        .is_err());
        std::env::remove_var("WARD_UNSAFE_TEST_APPROVAL");
        allow(
            Some("dev".to_string()),
            None,
            Some("codex".to_string()),
            None,
            None,
            Vec::new(),
        )
        .unwrap();
        allow(
            Some("migrate".to_string()),
            None,
            Some("codex".to_string()),
            None,
            None,
            Vec::new(),
        )
        .unwrap();

        dispatch(Cli {
            command: Commands::Run {
                profile: None,
                project: None,
                agent: Some("codex".to_string()),
                agent_key_id: None,
                worktree: None,
                git_remote: None,
                commit: None,
                branch: None,
                action: Some("Run without cached unlock".to_string()),
                env_names: vec!["DATABASE_URL".to_string()],
                json: false,
                no_prompt: false,
                command: vec!["sh".to_string(), "-c".to_string(), "true".to_string()],
            },
        })
        .unwrap();
        dispatch(Cli {
            command: Commands::Unlock {
                ttl: "1h".to_string(),
                mode: None,
            },
        })
        .unwrap();
        dispatch(Cli {
            command: Commands::Run {
                profile: None,
                project: None,
                agent: Some("codex".to_string()),
                agent_key_id: None,
                worktree: None,
                git_remote: None,
                commit: None,
                branch: None,
                action: Some("Run allowed command".to_string()),
                env_names: vec!["DATABASE_URL".to_string()],
                json: false,
                no_prompt: false,
                command: vec!["sh".to_string(), "-c".to_string(), "true".to_string()],
            },
        })
        .unwrap();
        std::env::set_var("WARD_UNSAFE_TEST_APPROVAL", "once");
        run(RunOptions {
            profile: None,
            project: None,
            agent: Some("codex".to_string()),
            branch: None,
            action: Some("Echo secret for redaction".to_string()),
            env_names: vec!["DATABASE_URL".to_string()],
            command: vec![
                "sh".to_string(),
                "-c".to_string(),
                "printf '%s\\n' \"$DATABASE_URL\"".to_string(),
            ],
            json: false,
            no_prompt: false,
        })
        .unwrap();
        std::env::remove_var("WARD_UNSAFE_TEST_APPROVAL");
        std::env::set_var("WARD_UNSAFE_TEST_APPROVAL", "once");
        let child_error = run(RunOptions {
            profile: None,
            project: None,
            agent: Some("codex".to_string()),
            branch: None,
            action: Some("Child failure".to_string()),
            env_names: vec!["DATABASE_URL".to_string()],
            command: vec!["sh".to_string(), "-c".to_string(), "exit 7".to_string()],
            json: false,
            no_prompt: false,
        })
        .unwrap_err();
        assert_eq!(
            child_error.downcast_ref::<ChildExit>().unwrap().exit_code(),
            7
        );
        std::env::remove_var("WARD_UNSAFE_TEST_APPROVAL");
        dispatch(Cli {
            command: Commands::Dev {
                agent: Some("codex".to_string()),
                agent_key_id: None,
                worktree: None,
                git_remote: None,
                commit: None,
                branch: None,
                json: false,
                no_prompt: false,
            },
        })
        .unwrap();
        dispatch(Cli {
            command: Commands::Migrate {
                agent: Some("codex".to_string()),
                agent_key_id: None,
                worktree: None,
                git_remote: None,
                commit: None,
                branch: None,
                json: false,
                no_prompt: false,
            },
        })
        .unwrap();
        dispatch(Cli {
            command: Commands::Run {
                profile: None,
                project: None,
                agent: Some("codex".to_string()),
                agent_key_id: None,
                worktree: None,
                git_remote: None,
                commit: None,
                branch: Some("feature/dispatch".to_string()),
                action: Some("Run once command".to_string()),
                env_names: vec!["DATABASE_URL".to_string()],
                json: false,
                no_prompt: false,
                command: vec!["sh".to_string(), "-c".to_string(), "true".to_string()],
            },
        })
        .unwrap();

        dispatch(Cli {
            command: Commands::Grants {
                command: GrantsCommand::List,
            },
        })
        .unwrap();
        let grant_id = grants::load_grants().unwrap()[0].id;
        dispatch(Cli {
            command: Commands::Grants {
                command: GrantsCommand::Revoke { grant_id },
            },
        })
        .unwrap();
        dispatch(Cli {
            command: Commands::Grants {
                command: GrantsCommand::Revoke {
                    grant_id: uuid::Uuid::new_v4(),
                },
            },
        })
        .unwrap();
        dispatch(Cli {
            command: Commands::Grants {
                command: GrantsCommand::Prune,
            },
        })
        .unwrap();

        dispatch(Cli {
            command: Commands::Logs {
                command: None,
                kind: None,
            },
        })
        .unwrap();
        dispatch(Cli {
            command: Commands::Logs {
                command: None,
                kind: Some(LogKind::Requests),
            },
        })
        .unwrap();
        dispatch(Cli {
            command: Commands::Logs {
                command: Some(LogsCommand::View {
                    kind: LogKind::Executions,
                }),
                kind: None,
            },
        })
        .unwrap();
        dispatch(Cli {
            command: Commands::Logs {
                command: Some(LogsCommand::Unlock {
                    ttl: "15m".to_string(),
                }),
                kind: None,
            },
        })
        .unwrap();
        dispatch(Cli {
            command: Commands::Logs {
                command: Some(LogsCommand::Verify {
                    kind: None,
                    full: false,
                }),
                kind: None,
            },
        })
        .unwrap();

        let editor = project.path().join("edit-env.sh");
        std::fs::write(
            &editor,
            "#!/bin/sh\ncat > \"$1\" <<'EOF'\nDATABASE_URL=postgres://edited\nPAYLOAD_SECRET=payload\nEOF\n",
        )
        .unwrap();
        make_executable(&editor);
        std::env::set_var("EDITOR", &editor);
        dispatch(Cli {
            command: Commands::Edit,
        })
        .unwrap();

        dispatch(Cli {
            command: Commands::Doctor,
        })
        .unwrap();
        dispatch(Cli {
            command: Commands::Lock,
        })
        .unwrap();

        std::env::set_current_dir(old_cwd).unwrap();
        std::env::remove_var("EDITOR");
        std::env::remove_var("WARD_HOME");
        std::env::remove_var("WARD_UNSAFE_TEST_KEYRING");
        std::env::remove_var("WARD_UNSAFE_TEST_PASSPHRASE");
    }

    #[test]
    #[serial_test::serial]
    fn approve_deny_json_and_post_log_helpers_cover_edges() {
        let _guard = cwd_lock();
        let old_cwd = std::env::current_dir().unwrap();
        let project = tempfile::tempdir().unwrap();
        let home = tempfile::tempdir().unwrap();
        std::env::set_var("WARD_HOME", home.path());
        std::env::set_var("WARD_UNSAFE_TEST_KEYRING", "1");
        std::env::set_var("WARD_UNSAFE_TEST_PASSPHRASE", "coverage passphrase");
        std::env::set_var("WARD_UNSAFE_TEST_APPROVAL", "session");
        std::env::set_current_dir(project.path()).unwrap();
        std::fs::write(
            project.path().join(".env"),
            "DATABASE_URL=postgres://coverage\n",
        )
        .unwrap();

        init(Some("demo".to_string()), false, true).unwrap();
        import(".env".into(), None).unwrap();
        std::fs::remove_file(project.path().join(".env")).unwrap();
        register("demo".to_string(), None, None).unwrap();
        unlock_vault("1h", None).unwrap();
        ensure_logs_passphrase().unwrap();
        ensure_logs_passphrase().unwrap();
        request(
            None,
            AgentContextOptions {
                agent: Some("codex".to_string()),
                branch: None,
                ..AgentContextOptions::default()
            },
            Some("Prompt text".to_string()),
            Some("pnpm dev".to_string()),
            vec!["DATABASE_URL".to_string()],
            false,
            false,
        )
        .unwrap();
        request(
            None,
            AgentContextOptions {
                agent: Some("codex".to_string()),
                branch: None,
                ..AgentContextOptions::default()
            },
            Some("Prompt json".to_string()),
            Some("sh -c true".to_string()),
            vec!["DATABASE_URL".to_string()],
            true,
            false,
        )
        .unwrap();
        run(RunOptions {
            profile: None,
            project: None,
            agent: Some("codex".to_string()),
            branch: None,
            action: Some("Prompt run".to_string()),
            env_names: vec!["DATABASE_URL".to_string()],
            command: vec![
                "sh".to_string(),
                "-c".to_string(),
                "printf run >/dev/null".to_string(),
            ],
            json: false,
            no_prompt: false,
        })
        .unwrap();
        std::env::set_var("WARD_UNSAFE_TEST_APPROVAL", "deny");
        request(
            None,
            AgentContextOptions {
                agent: Some("codex".to_string()),
                branch: None,
                ..AgentContextOptions::default()
            },
            Some("Prompt deny".to_string()),
            Some("sh -c false".to_string()),
            vec!["DATABASE_URL".to_string()],
            false,
            false,
        )
        .unwrap();
        std::env::set_var("WARD_UNSAFE_TEST_APPROVAL", "session");
        let pending = pending_requests::create_pending_request(
            AccessRequest {
                project: "demo".to_string(),
                agent: Some("codex".to_string()),
                branch: None,
                action: Some("Deny pending".to_string()),
                command: "sh -c false".to_string(),
                env: vec!["DATABASE_URL".to_string()],
            },
            evaluation(ApprovalMode::Prompt, true),
            git_context::GitContext::default(),
        )
        .unwrap();
        assert!(approve(pending.id, ApprovalScope::Deny, false, false, false).is_err());
        deny(pending.id, false, false).unwrap();
        let missing_grant_id = ApprovalDecision {
            approved: true,
            scope: ApprovalScope::Once,
            approved_env: vec!["DATABASE_URL".to_string()],
            denied_env: Vec::new(),
            source: approvals::ApprovalSource::Grant,
            grant_id: None,
        };
        consume_once_grant_if_reused(&missing_grant_id).unwrap();
        let non_once_grant = ApprovalDecision {
            scope: ApprovalScope::Always,
            ..missing_grant_id.clone()
        };
        consume_once_grant_if_reused(&non_once_grant).unwrap();
        warn_anomaly_failure(Ok(()));
        warn_anomaly_failure(Err(anyhow::anyhow!("anomaly fail")));
        let pending = pending_requests::create_pending_request(
            AccessRequest {
                project: "demo".to_string(),
                agent: Some("codex".to_string()),
                branch: None,
                action: Some("Approve pending".to_string()),
                command: "sh -c true".to_string(),
                env: vec!["DATABASE_URL".to_string()],
            },
            evaluation(ApprovalMode::Prompt, true),
            git_context::GitContext::default(),
        )
        .unwrap();
        approve(pending.id, ApprovalScope::Session, false, false, false).unwrap();
        let mut critical_policy = evaluation(ApprovalMode::Prompt, true);
        critical_policy
            .findings
            .push(detection::Finding::critical("critical.test", "critical"));
        let critical_pending = pending_requests::create_pending_request(
            AccessRequest {
                project: "demo".to_string(),
                agent: Some("codex".to_string()),
                branch: None,
                action: Some("Critical pending".to_string()),
                command: "sh -c printenv".to_string(),
                env: vec!["DATABASE_URL".to_string()],
            },
            critical_policy,
            git_context::GitContext::default(),
        )
        .unwrap();
        assert!(approve(critical_pending.id, ApprovalScope::Once, false, true, false).is_err());
        assert!(pending_requests::load_pending_request(critical_pending.id).is_ok());
        assert!(approve(
            critical_pending.id,
            ApprovalScope::Session,
            true,
            true,
            false
        )
        .is_err());
        approve(critical_pending.id, ApprovalScope::Once, true, true, false).unwrap();
        let once_grant = grants::load_grants()
            .unwrap()
            .into_iter()
            .find(|grant| grant.scope == ApprovalScope::Once)
            .unwrap();
        let once_reuse = ApprovalDecision {
            approved: true,
            scope: ApprovalScope::Once,
            approved_env: vec!["DATABASE_URL".to_string()],
            denied_env: Vec::new(),
            source: approvals::ApprovalSource::Grant,
            grant_id: Some(once_grant.id),
        };
        consume_once_grant_if_reused(&once_reuse).unwrap();
        grants_command(GrantsCommand::List).unwrap();
        let signed_grant = grants::load_grants()
            .unwrap()
            .into_iter()
            .find(|grant| grant.receipt.is_some())
            .unwrap();
        let mut legacy_grant = signed_grant.clone();
        legacy_grant.id = uuid::Uuid::new_v4();
        legacy_grant.receipt = None;
        grants::append_grant_to_path(&grants::grants_path(), &legacy_grant).unwrap();
        let mut invalid_grant = signed_grant;
        invalid_grant.id = uuid::Uuid::new_v4();
        invalid_grant.command = "sh -c tampered".to_string();
        grants::append_grant_to_path(&grants::grants_path(), &invalid_grant).unwrap();
        doctor().unwrap();
        let pending = pending_requests::create_pending_request(
            AccessRequest {
                project: "demo".to_string(),
                agent: Some("codex".to_string()),
                branch: None,
                action: Some("Deny pending via dispatch".to_string()),
                command: "sh -c true".to_string(),
                env: vec!["DATABASE_URL".to_string()],
            },
            evaluation(ApprovalMode::Prompt, true),
            git_context::GitContext::default(),
        )
        .unwrap();
        dispatch(Cli {
            command: Commands::Deny {
                request_id: pending.id,
                agent_mediated: true,
                json: false,
            },
        })
        .unwrap();
        assert!(handle_post_run_logging_result(0, Err(anyhow::anyhow!("log fail"))).is_err());
        assert!(handle_post_run_logging_result(7, Err(anyhow::anyhow!("log fail"))).is_ok());
        assert!(allow(
            None,
            Some(ApprovalScope::Always),
            None,
            None,
            Some("sh -c printenv".to_string()),
            vec!["DATABASE_URL".to_string()],
        )
        .is_err());
        std::env::set_var("WARD_UNSAFE_TEST_PASSPHRASE", "wrong passphrase");
        assert!(unlock_vault("1h", None).is_err());
        std::env::set_current_dir(old_cwd).unwrap();
        std::env::remove_var("WARD_UNSAFE_TEST_APPROVAL");
        std::env::remove_var("WARD_HOME");
        std::env::remove_var("WARD_UNSAFE_TEST_KEYRING");
        std::env::remove_var("WARD_UNSAFE_TEST_PASSPHRASE");
    }

    #[test]
    fn decide_access_handles_policy_deny_auto_and_no_grant_lookup() {
        let access = access();

        let denied = decide_access(&access, &evaluation(ApprovalMode::Deny, false), true).unwrap();
        assert!(!denied.approved);
        assert_eq!(denied.source, approvals::ApprovalSource::PolicyDeny);

        let auto = decide_access(&access, &evaluation(ApprovalMode::Auto, false), false).unwrap();
        assert!(auto.approved);
        assert_eq!(auto.source, approvals::ApprovalSource::PolicyAuto);
    }

    #[test]
    #[serial_test::serial]
    fn decide_access_reuses_matching_grant_and_prompts_without_grant() {
        let _guard = cwd_lock();
        let tempdir = tempfile::tempdir().unwrap();
        let vault = setup_test_signing_unlock(tempdir.path(), "demo");

        let access = access();
        let decision = ApprovalDecision {
            approved: true,
            scope: ApprovalScope::Always,
            approved_env: vec!["DATABASE_URL".to_string()],
            denied_env: Vec::new(),
            source: approvals::ApprovalSource::LocalTty,
            grant_id: None,
        };
        grants::persist_grant(
            &access,
            &decision,
            &vault,
            Some(grants::GrantReceiptContext::synthetic(false)),
        )
        .unwrap();

        let reused = decide_access(&access, &evaluation(ApprovalMode::Prompt, true), true).unwrap();
        assert_eq!(reused.source, approvals::ApprovalSource::Grant);

        std::env::set_var("WARD_UNSAFE_TEST_APPROVAL", "once");
        let prompted =
            decide_access(&access, &evaluation(ApprovalMode::Prompt, true), false).unwrap();
        assert_eq!(prompted.source, approvals::ApprovalSource::LocalTty);

        std::env::remove_var("WARD_UNSAFE_TEST_APPROVAL");
        clear_test_signing_unlock();
    }

    #[test]
    #[serial_test::serial]
    fn decide_access_bypasses_durable_grants_for_critical_findings() {
        let _guard = cwd_lock();
        let tempdir = tempfile::tempdir().unwrap();
        let vault = setup_test_signing_unlock(tempdir.path(), "demo");
        std::env::set_var("WARD_UNSAFE_TEST_APPROVAL", "once");

        let mut access = access();
        access.command = "sh -c printenv".to_string();
        let durable = ApprovalDecision {
            approved: true,
            scope: ApprovalScope::Always,
            approved_env: vec!["DATABASE_URL".to_string()],
            denied_env: Vec::new(),
            source: approvals::ApprovalSource::LocalTty,
            grant_id: None,
        };
        grants::persist_grant(
            &access,
            &durable,
            &vault,
            Some(grants::GrantReceiptContext::synthetic(false)),
        )
        .unwrap();
        let mut evaluation = evaluation(ApprovalMode::Prompt, true);
        evaluation
            .findings
            .push(detection::Finding::critical("critical.test", "critical"));

        let prompted = decide_access(&access, &evaluation, true).unwrap();
        assert_eq!(prompted.source, approvals::ApprovalSource::LocalTty);
        assert_eq!(prompted.scope, ApprovalScope::Once);

        let once = grants::persist_manual_grant(
            &access,
            ApprovalScope::Once,
            approvals::ApprovalSource::AgentMediated,
            &vault,
            Some(grants::GrantReceiptContext::synthetic(true)),
        )
        .unwrap();
        let reused_once = decide_access(&access, &evaluation, true).unwrap();
        assert_eq!(reused_once.source, approvals::ApprovalSource::Grant);
        assert_eq!(reused_once.grant_id, Some(once.id));

        std::env::remove_var("WARD_UNSAFE_TEST_APPROVAL");
        clear_test_signing_unlock();
    }

    #[test]
    #[serial_test::serial]
    fn decide_access_ignores_always_grants_for_suspicious_action_findings() {
        let _guard = cwd_lock();
        let tempdir = tempfile::tempdir().unwrap();
        let vault = setup_test_signing_unlock(tempdir.path(), "demo");

        let access = access();
        let always = ApprovalDecision {
            approved: true,
            scope: ApprovalScope::Always,
            approved_env: vec!["DATABASE_URL".to_string()],
            denied_env: Vec::new(),
            source: approvals::ApprovalSource::LocalTty,
            grant_id: None,
        };
        grants::persist_grant(
            &access,
            &always,
            &vault,
            Some(grants::GrantReceiptContext::synthetic(false)),
        )
        .unwrap();
        let session = ApprovalDecision {
            scope: ApprovalScope::Session,
            ..always
        };
        let session_grant = grants::persist_grant(
            &access,
            &session,
            &vault,
            Some(grants::GrantReceiptContext::synthetic(false)),
        )
        .unwrap()
        .unwrap();
        let mut evaluation = evaluation(ApprovalMode::Prompt, true);
        evaluation.findings.push(detection::Finding::warning(
            "action.prompt_injection",
            "suspicious action",
        ));

        let reused = decide_access(&access, &evaluation, true).unwrap();

        assert_eq!(reused.source, approvals::ApprovalSource::Grant);
        assert_eq!(reused.scope, ApprovalScope::Session);
        assert_eq!(reused.grant_id, Some(session_grant.id));

        clear_test_signing_unlock();
    }

    #[test]
    #[serial_test::serial]
    fn decide_access_reports_grant_lookup_errors() {
        let _guard = cwd_lock();
        let tempdir = tempfile::tempdir().unwrap();
        let grants_dir = tempdir.path().join("sessions");
        std::fs::create_dir_all(&grants_dir).unwrap();
        std::fs::write(grants_dir.join("grants.jsonl"), "{bad-json}\n").unwrap();
        std::env::set_var("WARD_HOME", tempdir.path());

        assert!(decide_access(&access(), &evaluation(ApprovalMode::Prompt, true), true).is_err());

        std::env::remove_var("WARD_HOME");
    }

    #[test]
    #[serial_test::serial]
    fn decide_access_continues_when_no_grant_matches() {
        let _guard = cwd_lock();
        let tempdir = tempfile::tempdir().unwrap();
        std::env::set_var("WARD_HOME", tempdir.path());

        let decision = decide_access(&access(), &evaluation(ApprovalMode::Auto, false), true)
            .expect("empty grant registry should not block auto approval");

        assert_eq!(decision.source, approvals::ApprovalSource::PolicyAuto);
        std::env::remove_var("WARD_HOME");
    }

    #[test]
    fn gitignore_contains_ignores_comments_and_whitespace() {
        let contents = "\n# .env\n .env \n.env.*\n";

        assert!(gitignore_contains(contents, ".env"));
        assert!(gitignore_contains(contents, ".env.*"));
        assert!(!gitignore_contains(contents, ".env.local"));
    }

    #[test]
    fn likely_secret_env_files_finds_variants_except_example() {
        let tempdir = tempfile::tempdir().unwrap();
        std::fs::write(tempdir.path().join(".env.local"), "SECRET=value\n").unwrap();
        std::fs::write(tempdir.path().join(".env.example"), "SECRET=\n").unwrap();
        std::fs::write(tempdir.path().join(".env.vault"), "encrypted\n").unwrap();

        let files = likely_secret_env_files(tempdir.path()).unwrap();

        assert_eq!(files.len(), 1);
        assert!(files[0].ends_with(".env.local"));
    }

    #[test]
    fn likely_secret_env_files_reports_read_dir_errors() {
        let tempdir = tempfile::tempdir().unwrap();
        let file = tempdir.path().join("not-a-directory");
        std::fs::write(&file, "").unwrap();

        assert!(likely_secret_env_files(&file).is_err());
    }

    #[test]
    fn check_gitignore_reports_read_errors() {
        let tempdir = tempfile::tempdir().unwrap();
        std::fs::create_dir(tempdir.path().join(".gitignore")).unwrap();

        assert!(check_gitignore(tempdir.path()).is_err());
    }

    #[test]
    fn check_gitignore_allows_missing_file() {
        let tempdir = tempfile::tempdir().unwrap();

        assert!(check_gitignore(tempdir.path()).is_ok());
    }

    #[test]
    fn check_gitignore_reads_complete_and_partial_files() {
        let tempdir = tempfile::tempdir().unwrap();
        let gitignore = tempdir.path().join(".gitignore");

        std::fs::write(&gitignore, ".env\n.env.*\n").unwrap();
        assert!(check_gitignore(tempdir.path()).is_ok());

        std::fs::write(&gitignore, ".env\n").unwrap();
        assert!(check_gitignore(tempdir.path()).is_ok());

        std::fs::write(&gitignore, ".env.*\n").unwrap();
        assert!(check_gitignore(tempdir.path()).is_ok());

        std::fs::write(&gitignore, ".env\n.env.*\n!.env.vault\n").unwrap();
        assert!(check_gitignore(tempdir.path()).is_ok());
    }

    #[test]
    #[serial_test::serial]
    fn init_handles_existing_env_example() {
        let _guard = cwd_lock();
        let tempdir = tempfile::tempdir().unwrap();
        let original = std::env::current_dir().unwrap();
        std::fs::write(tempdir.path().join(".env.example"), "DATABASE_URL=\n").unwrap();
        std::env::set_current_dir(tempdir.path()).unwrap();

        let result = init(Some("demo".to_string()), false, true);

        std::env::set_current_dir(original).unwrap();
        assert!(result.is_ok());
        assert!(tempdir
            .path()
            .join(config::AGENT_INSTRUCTIONS_FILE)
            .exists());
    }

    #[test]
    #[serial_test::serial]
    fn init_guided_setup_handles_plaintext_env() {
        let _guard = cwd_lock();
        let tempdir = tempfile::tempdir().unwrap();
        let home = tempfile::tempdir().unwrap();
        let original = std::env::current_dir().unwrap();
        std::env::set_var("WARD_HOME", home.path());
        std::env::set_var("WARD_UNSAFE_TEST_KEYRING", "1");
        std::env::set_var("WARD_UNSAFE_TEST_PASSPHRASE", "coverage passphrase");
        std::fs::write(
            tempdir.path().join(".env"),
            "DATABASE_URL=postgres://local\n",
        )
        .unwrap();
        std::env::set_current_dir(tempdir.path()).unwrap();

        let result = init(Some("demo".to_string()), false, false);

        std::env::set_current_dir(original).unwrap();
        std::env::remove_var("WARD_HOME");
        std::env::remove_var("WARD_UNSAFE_TEST_KEYRING");
        std::env::remove_var("WARD_UNSAFE_TEST_PASSPHRASE");
        assert!(result.is_ok());
        assert!(tempdir.path().join(".env.example").exists());
        assert!(env_file::is_locked_env_file(&tempdir.path().join(".env")).unwrap());
    }

    #[test]
    #[serial_test::serial]
    fn doctor_covers_missing_invalid_plaintext_and_alert_error_paths() {
        let _guard = cwd_lock();
        let original = std::env::current_dir().unwrap();
        let project = tempfile::tempdir().unwrap();
        let home = tempfile::tempdir().unwrap();
        std::env::set_var("WARD_HOME", home.path());
        std::env::set_current_dir(project.path()).unwrap();

        doctor().unwrap();

        std::fs::write(project.path().join(".ward.json"), "{").unwrap();
        std::fs::write(
            project.path().join(".env"),
            "DATABASE_URL=postgres://local\n",
        )
        .unwrap();
        std::fs::write(project.path().join(".env.local"), "SECRET_KEY=value\n").unwrap();
        std::fs::write(project.path().join(".gitignore"), ".env\n.env.*\n").unwrap();
        doctor().unwrap();

        let grants_dir = home.path().join("sessions");
        std::fs::create_dir_all(&grants_dir).unwrap();
        let now = chrono::Utc::now();
        let legacy_grant = grants::ApprovalGrant {
            id: uuid::Uuid::new_v4(),
            created_at: now,
            expires_at: None,
            project: "demo".to_string(),
            agent: None,
            branch: None,
            command: "pnpm dev".to_string(),
            approved_env: vec!["DATABASE_URL".to_string()],
            scope: approvals::ApprovalScope::Always,
            uses_remaining: None,
            receipt: None,
        };
        let mut invalid_grant = legacy_grant.clone();
        invalid_grant.id = uuid::Uuid::new_v4();
        invalid_grant.receipt = Some(crate::approval_receipts::ApprovalReceipt {
            payload: crate::approval_receipts::build_payload(
                &access(),
                invalid_grant.id,
                uuid::Uuid::new_v4(),
                &["DATABASE_URL".to_string()],
                approvals::ApprovalScope::Always,
                None,
                false,
                now,
                "missing-signer".to_string(),
            ),
            payload_hash: "bad".to_string(),
            signer_key_id: "missing-signer".to_string(),
            signature_algorithm: "ed25519".to_string(),
            signature: "bad".to_string(),
        });
        std::fs::write(
            grants_dir.join("grants.jsonl"),
            format!(
                "{}\n{}\n",
                serde_json::to_string(&legacy_grant).unwrap(),
                serde_json::to_string(&invalid_grant).unwrap()
            ),
        )
        .unwrap();
        doctor().unwrap();
        std::fs::write(grants_dir.join("grants.jsonl"), "{bad-json}\n").unwrap();
        doctor().unwrap();

        std::fs::create_dir_all(home.path().join("logs/alerts.jsonl")).unwrap();
        doctor().unwrap();

        std::env::set_current_dir(original).unwrap();
        std::env::remove_var("WARD_HOME");
    }

    #[test]
    fn marker_returns_expected_labels() {
        assert_eq!(marker(true), "[ok]");
        assert_eq!(marker(false), "!");
    }

    #[test]
    fn grant_integrity_messages_cover_ok_legacy_and_invalid_states() {
        assert_eq!(
            grant_integrity_messages(0, 0),
            vec!["[ok] Approval grants are signed and valid.".to_string()]
        );
        assert_eq!(
            grant_integrity_messages(1, 1),
            vec![
                "! Legacy unsigned approval grants: 1. Re-approve them.".to_string(),
                "! Invalid signed approval grants: 1. Revoke and re-approve them.".to_string(),
            ]
        );
    }

    #[test]
    fn grant_status_labels_cover_all_integrity_states() {
        assert_eq!(
            grant_status_label(grants::GrantIntegrityStatus::Valid),
            "valid-signed"
        );
        assert_eq!(
            grant_status_label(grants::GrantIntegrityStatus::Expired),
            "expired"
        );
        assert_eq!(
            grant_status_label(grants::GrantIntegrityStatus::LegacyUnsigned),
            "legacy-unsigned"
        );
        assert_eq!(
            grant_status_label(grants::GrantIntegrityStatus::Invalid),
            "invalid-signature"
        );
    }

    #[test]
    fn signing_lookup_messages_cover_warning_variants() {
        assert!(
            signing_lookup_message(Ok(unlock::RunSigningLookup::Missing))
                .contains("No active signing key session")
        );
        assert!(
            signing_lookup_message(Ok(unlock::RunSigningLookup::MaterialUnavailable {
                reason: "missing".to_string(),
            }))
            .contains("missing")
        );
        assert!(signing_lookup_message(Err(anyhow::anyhow!("boom"))).contains("boom"));
    }

    #[test]
    fn child_exit_formats_and_normalizes_exit_codes() {
        let exit = ChildExit::new(7);
        assert_eq!(exit.exit_code(), 7);
        assert_eq!(exit.to_string(), "child process exited with 7");

        let out_of_range = ChildExit::new(300);
        assert_eq!(out_of_range.exit_code(), 1);
    }

    #[test]
    fn render_log_events_handles_empty_and_multiline_output() {
        assert_eq!(render_log_events(&[]).unwrap(), "");

        let events = vec![
            serde_json::json!({ "payload": { "eventType": "one" } }),
            serde_json::json!({ "payload": { "eventType": "two" } }),
        ];
        let rendered = render_log_events(&events).unwrap();
        assert!(rendered.contains("\"eventType\":\"one\""));
        assert!(rendered.contains('\n'));
        assert!(rendered.contains("\"eventType\":\"two\""));
    }

    #[test]
    fn evaluate_access_combines_detection_and_policy() {
        let config = ProjectConfig {
            version: 1,
            project: "demo".to_string(),
            vault: ".env.vault".into(),
            presets: Vec::new(),
            profiles: std::collections::BTreeMap::new(),
            anomaly_detection: config::AnomalyDetectionConfig {
                enabled: true,
                working_hours_start: 8,
                working_hours_end: 20,
                max_runs_per_hour_per_grant: 20,
                max_branches_per_grant: 3,
            },
        };
        let mut access = access();
        access.action = Some("Run lint".to_string());

        let evaluation = evaluate_access(&config, &access);

        assert!(evaluation.requires_prompt);
        assert!(evaluation
            .findings
            .iter()
            .any(|finding| finding.code == "env.scope_deviation"));
    }

    #[test]
    fn profile_resolution_expands_short_commands_and_validates_conflicts() {
        let tempdir = tempfile::tempdir().unwrap();
        let config =
            ProjectConfig::default_for_dir(tempdir.path(), Some("demo".to_string())).unwrap();

        let resolved = resolve_profile(&config, Some("dev"), None, None, Vec::new()).unwrap();
        assert_eq!(resolved.command, "pnpm dev");
        assert_eq!(resolved.command_args, vec!["pnpm", "dev"]);
        assert_eq!(resolved.default_scope, ApprovalScope::Always);
        assert!(resolved.env_names.contains(&"DATABASE_URL".to_string()));

        let manual = resolve_profile(
            &config,
            None,
            Some("Manual".to_string()),
            Some("pnpm lint".to_string()),
            vec!["DATABASE_URL".to_string()],
        )
        .unwrap();
        assert_eq!(manual.command_args, vec!["pnpm", "lint"]);
        assert_eq!(manual.default_scope, ApprovalScope::Once);

        let run_profile =
            resolve_run_profile(&config, Some("migrate"), None, Vec::new(), Vec::new()).unwrap();
        assert_eq!(run_profile.command_args, vec!["pnpm", "payload", "migrate"]);
        assert_eq!(run_profile.default_scope, ApprovalScope::Branch);

        let missing_profile = resolve_profile(&config, Some("missing"), None, None, Vec::new())
            .unwrap_err()
            .to_string();
        assert!(missing_profile.contains("profile missing is not defined"));

        let explicit_run = resolve_run_profile(
            &config,
            None,
            Some("Run".to_string()),
            vec!["DATABASE_URL".to_string()],
            vec!["sh".to_string(), "-c".to_string(), "true".to_string()],
        )
        .unwrap();
        assert_eq!(explicit_run.command, "sh -c true");

        assert!(resolve_profile(
            &config,
            Some("dev"),
            None,
            Some("pnpm dev".to_string()),
            Vec::new(),
        )
        .is_err());
        assert!(resolve_profile(&config, None, None, None, Vec::new()).is_err());
        assert!(resolve_profile(
            &config,
            None,
            None,
            Some("pnpm dev".to_string()),
            Vec::new(),
        )
        .is_err());
        assert!(resolve_run_profile(
            &config,
            Some("dev"),
            None,
            vec!["DATABASE_URL".to_string()],
            Vec::new(),
        )
        .is_err());
        assert!(
            resolve_run_profile(&config, Some("missing"), None, Vec::new(), Vec::new()).is_err()
        );
        assert!(resolve_run_profile(&config, None, None, Vec::new(), Vec::new()).is_err());
        assert!(resolve_run_profile(
            &config,
            None,
            None,
            Vec::new(),
            vec!["pnpm".to_string(), "dev".to_string()],
        )
        .is_err());
    }

    #[test]
    fn effective_grant_id_prefers_reused_decision_then_persisted_grant() {
        let access = access();
        let grant = grants::ApprovalGrant {
            id: uuid::Uuid::new_v4(),
            created_at: chrono::Utc::now(),
            expires_at: None,
            project: access.project.clone(),
            agent: access.agent.clone(),
            branch: access.branch.clone(),
            command: access.command.clone(),
            approved_env: access.env.clone(),
            scope: ApprovalScope::Always,
            uses_remaining: None,
            receipt: None,
        };
        let decision = ApprovalDecision {
            approved: true,
            scope: ApprovalScope::Always,
            approved_env: access.env.clone(),
            denied_env: Vec::new(),
            source: approvals::ApprovalSource::LocalTty,
            grant_id: None,
        };

        assert_eq!(effective_grant_id(&decision, Some(&grant)), Some(grant.id));

        let reused_id = uuid::Uuid::new_v4();
        let reused = ApprovalDecision {
            grant_id: Some(reused_id),
            source: approvals::ApprovalSource::Grant,
            ..decision
        };
        assert_eq!(effective_grant_id(&reused, Some(&grant)), Some(reused_id));
        assert_eq!(effective_grant_id(&reused, None), Some(reused_id));
    }

    #[test]
    fn run_unlock_required_json_helper_renders_directly() {
        print_run_unlock_required(
            &access(),
            &evaluation(ApprovalMode::Prompt, true),
            Some("unlock_material_unavailable"),
        )
        .unwrap();
    }

    #[test]
    fn clap_help_renders_all_public_command_metadata() {
        let mut command = Cli::command();
        let help = command.render_long_help().to_string();
        assert!(help.contains("AI secret firewall for local development"));
        assert!(help.contains("Select an already registered project"));
        assert!(help.contains("Manage stored approval grants"));

        for subcommand in [
            "setup", "request", "allow", "grants", "approve", "deny", "run", "dev", "migrate",
            "logs", "unlock",
        ] {
            let rendered = command
                .find_subcommand_mut(subcommand)
                .unwrap()
                .render_long_help()
                .to_string();
            assert!(rendered.contains(subcommand));
            if subcommand == "run" {
                assert!(rendered.contains("Put all Ward flags before --"));
            }
        }
    }

    #[test]
    fn clap_parses_all_public_command_shapes() {
        let request_id = uuid::Uuid::nil().to_string();
        let command_sets = vec![
            vec![
                "ward",
                "setup",
                "--yes",
                "--project",
                "demo",
                "--source",
                ".env",
                "--vault",
                ".env.vault",
                "--commit-vault",
                "--remove-plaintext",
                "--unlock-ttl",
                "1h",
            ],
            vec!["ward", "init", "--project", "demo", "--force", "--bare"],
            vec!["ward", "import", ".env", "--vault", ".env.vault"],
            vec![
                "ward",
                "register",
                "demo",
                "--path",
                ".",
                "--vault",
                ".env.vault",
            ],
            vec!["ward", "use", "demo"],
            vec!["ward", "projects", "list"],
            vec!["ward", "projects", "show", "demo"],
            vec![
                "ward",
                "projects",
                "register",
                "demo",
                "--path",
                ".",
                "--vault",
                ".env.vault",
            ],
            vec!["ward", "projects", "use", "demo"],
            vec!["ward", "projects", "remove", "demo"],
            vec!["ward", "env", "list", "--project", "demo"],
            vec!["ward", "env", "set", "--project", "demo", "KEY=value"],
            vec!["ward", "env", "unset", "--project", "demo", "KEY"],
            vec![
                "ward",
                "env",
                "unlock",
                "--project",
                "demo",
                "--output",
                ".env",
                "--force",
            ],
            vec![
                "ward",
                "env",
                "lock",
                "--project",
                "demo",
                "--source",
                ".env",
            ],
            vec![
                "ward",
                "env",
                "export",
                "--project",
                "demo",
                "--output",
                ".env.export",
                "--force",
            ],
            vec![
                "ward",
                "env",
                "export",
                "--project",
                "demo",
                "--unsafe-stdout",
            ],
            vec![
                "ward",
                "request",
                "--profile",
                "dev",
                "--agent",
                "codex",
                "--branch",
                "main",
                "--action",
                "Run dev",
                "--command",
                "pnpm dev",
                "--env",
                "DATABASE_URL",
                "--json",
                "--no-prompt",
            ],
            vec![
                "ward",
                "allow",
                "--profile",
                "dev",
                "--scope",
                "always",
                "--agent",
                "codex",
                "--branch",
                "main",
                "--command",
                "pnpm dev",
                "--env",
                "DATABASE_URL",
            ],
            vec!["ward", "grants", "list"],
            vec!["ward", "grants", "revoke", &request_id],
            vec!["ward", "grants", "prune"],
            vec![
                "ward",
                "approve",
                &request_id,
                "--scope",
                "once",
                "--confirm-critical",
                "--agent-mediated",
            ],
            vec!["ward", "deny", &request_id, "--agent-mediated"],
            vec![
                "ward",
                "run",
                "--profile",
                "dev",
                "--project",
                "demo",
                "--agent",
                "codex",
                "--branch",
                "main",
                "--action",
                "Run dev",
                "--env",
                "DATABASE_URL",
                "--json",
                "--no-prompt",
                "--",
                "pnpm",
                "dev",
            ],
            vec![
                "ward",
                "dev",
                "--agent",
                "codex",
                "--branch",
                "main",
                "--json",
                "--no-prompt",
            ],
            vec![
                "ward",
                "migrate",
                "--agent",
                "codex",
                "--branch",
                "main",
                "--json",
                "--no-prompt",
            ],
            vec!["ward", "doctor"],
            vec!["ward", "logs", "requests"],
            vec!["ward", "logs", "view", "requests"],
            vec!["ward", "logs", "verify", "requests", "--full"],
            vec![
                "ward",
                "logs",
                "export",
                "requests",
                "--output",
                "requests.jsonl",
                "--force",
            ],
            vec!["ward", "logs", "unlock", "--ttl", "15m"],
            vec!["ward", "edit"],
            vec!["ward", "unlock", "--ttl", "1h"],
            vec!["ward", "lock"],
            vec![
                "ward",
                "teardown",
                "--project",
                "demo",
                "--export",
                ".env.export",
                "--yes",
                "--restore-env",
            ],
        ];

        for args in command_sets {
            assert!(Cli::try_parse_from(args).is_ok());
        }
    }

    #[test]
    fn debug_formats_all_cli_command_variants() {
        let request_id = uuid::Uuid::nil();
        let commands = vec![
            format!(
                "{:?}",
                Cli {
                    command: Commands::Lock
                }
            ),
            format!(
                "{:?}",
                Commands::Init {
                    project: Some("demo".to_string()),
                    force: true,
                    bare: false,
                }
            ),
            format!(
                "{:?}",
                Commands::Import {
                    source: ".env".into(),
                    vault: Some(".env.vault".into()),
                }
            ),
            format!(
                "{:?}",
                Commands::Register {
                    project: "demo".to_string(),
                    path: Some(".".into()),
                    vault: Some(".env.vault".into()),
                }
            ),
            format!(
                "{:?}",
                Commands::Use {
                    project: "demo".to_string(),
                }
            ),
            format!(
                "{:?}",
                Commands::Request {
                    profile: None,
                    agent: Some("codex".to_string()),
                    agent_key_id: None,
                    worktree: None,
                    git_remote: None,
                    commit: None,
                    branch: Some("main".to_string()),
                    action: Some("Run".to_string()),
                    command: Some("pnpm dev".to_string()),
                    env_names: vec!["DATABASE_URL".to_string()],
                    json: true,
                    no_prompt: true,
                }
            ),
            format!(
                "{:?}",
                Commands::Allow {
                    profile: None,
                    scope: Some(ApprovalScope::Always),
                    agent: Some("codex".to_string()),
                    branch: Some("main".to_string()),
                    command: Some("pnpm dev".to_string()),
                    env_names: vec!["DATABASE_URL".to_string()],
                }
            ),
            format!(
                "{:?}",
                Commands::Grants {
                    command: GrantsCommand::List,
                }
            ),
            format!(
                "{:?}",
                Commands::Approve {
                    request_id,
                    scope: ApprovalScope::Session,
                    confirm_critical: true,
                    agent_mediated: true,
                    json: false,
                }
            ),
            format!(
                "{:?}",
                Commands::Deny {
                    request_id,
                    agent_mediated: true,
                    json: false,
                }
            ),
            format!(
                "{:?}",
                Commands::Run {
                    profile: None,
                    project: Some("demo".to_string()),
                    agent: Some("codex".to_string()),
                    agent_key_id: None,
                    worktree: None,
                    git_remote: None,
                    commit: None,
                    branch: Some("main".to_string()),
                    action: Some("Run".to_string()),
                    env_names: vec!["DATABASE_URL".to_string()],
                    json: false,
                    no_prompt: false,
                    command: vec!["pnpm".to_string(), "dev".to_string()],
                }
            ),
            format!(
                "{:?}",
                Commands::Setup {
                    yes: true,
                    project: Some("demo".to_string()),
                    source: ".env".into(),
                    vault: ".env.vault".into(),
                    commit_vault: true,
                    ignore_vault: false,
                    remove_plaintext: true,
                    keep_plaintext: false,
                    unlock_ttl: "8h".to_string(),
                    no_unlock: false,
                }
            ),
            format!(
                "{:?}",
                Commands::Dev {
                    agent: Some("codex".to_string()),
                    agent_key_id: None,
                    worktree: None,
                    git_remote: None,
                    commit: None,
                    branch: Some("main".to_string()),
                    json: false,
                    no_prompt: false,
                }
            ),
            format!(
                "{:?}",
                Commands::Migrate {
                    agent: Some("codex".to_string()),
                    agent_key_id: None,
                    worktree: None,
                    git_remote: None,
                    commit: None,
                    branch: Some("main".to_string()),
                    json: false,
                    no_prompt: false,
                }
            ),
            format!("{:?}", Commands::Doctor),
            format!(
                "{:?}",
                Commands::Logs {
                    command: Some(LogsCommand::View {
                        kind: LogKind::Requests,
                    }),
                    kind: Some(LogKind::Requests),
                }
            ),
            format!("{:?}", Commands::Edit),
            format!(
                "{:?}",
                Commands::Unlock {
                    ttl: "1h".to_string(),
                    mode: None,
                }
            ),
            format!("{:?}", Commands::Lock),
            format!(
                "{:?}",
                GrantsCommand::Revoke {
                    grant_id: request_id
                }
            ),
            format!("{:?}", GrantsCommand::Prune),
            format!(
                "{:?}",
                LogsCommand::Verify {
                    kind: None,
                    full: false,
                }
            ),
            format!(
                "{:?}",
                LogsCommand::Unlock {
                    ttl: "15m".to_string(),
                }
            ),
        ];

        assert_eq!(commands.len(), 23);
        for value in commands {
            assert!(!value.is_empty());
        }
    }

    #[cfg(unix)]
    fn make_executable(path: &Path) {
        use std::os::unix::fs::PermissionsExt;

        let mut permissions = std::fs::metadata(path).unwrap().permissions();
        permissions.set_mode(0o700);
        std::fs::set_permissions(path, permissions).unwrap();
    }

    #[cfg(not(unix))]
    fn make_executable(_path: &Path) {}
}
