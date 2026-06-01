use std::{
    collections::{BTreeMap, HashMap},
    io::{BufRead, BufReader, Read, Write},
    os::unix::net::{UnixListener, UnixStream},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, AtomicU32, Ordering},
        Arc, Mutex,
    },
    thread,
    time::Duration as StdDuration,
};
#[cfg(not(test))]
use std::{
    process::{Command, Stdio},
    time::Instant,
};

use anyhow::{Context, Result};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

use crate::{
    agents::{self, AgentProof},
    approval_receipts::{self, ApprovalReceipt, ApprovalReceiptPayload},
    config, detection, env_file, fs_util, logs, modes, recovery, registry,
    runner::{self, RunCommandOutcome, RunCommandRequest},
    vault,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BrokerStatus {
    pub running: bool,
    pub socket: PathBuf,
    pub pid: Option<u32>,
    #[serde(default)]
    pub version: String,
    pub sessions: Vec<BrokerSessionStatus>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BrokerSessionStatus {
    pub project: String,
    pub vault: PathBuf,
    pub expires_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active_mode: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BrokerProjectSetupStatus {
    pub project: String,
    pub path: PathBuf,
    pub vault: PathBuf,
    pub created: bool,
    pub registered: bool,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum BrokerRequest {
    Ping,
    Stop,
    Unlock {
        project: String,
        vault: PathBuf,
        passphrase: String,
        ttl_seconds: i64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        mode: Option<String>,
    },
    Sign {
        project: String,
        vault: PathBuf,
        payload: ApprovalReceiptPayload,
    },
    RegisterHumanSession {
        shell_pid: u32,
        session_token: String,
        ttl_seconds: i64,
    },
    DeregisterHumanSession {
        shell_pid: u32,
        session_token: String,
    },
    Execute {
        project: String,
        vault: PathBuf,
        cwd: PathBuf,
        env_names: Vec<String>,
        command: Vec<String>,
        inherited_env: BTreeMap<String, String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        human_shell_pid: Option<u32>,
        agent_proof: Option<AgentProof>,
    },
    ListKeys {
        project: String,
        vault: PathBuf,
    },
    SetupProject {
        source_project: String,
        source_vault: PathBuf,
        target_path: PathBuf,
        project: Option<String>,
    },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum BrokerResponse {
    Ok,
    Status { status: BrokerStatus },
    Signed { receipt: ApprovalReceipt },
    Output { stream: String, line: String },
    Finished { outcome: RunCommandOutcome },
    Keys { names: Vec<String> },
    ProjectSetup { status: BrokerProjectSetupStatus },
    Error { reason: String, message: String },
}

#[derive(Debug, Clone)]
pub struct BrokerError {
    reason: String,
    message: String,
}

impl BrokerError {
    fn new(reason: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
            message: message.into(),
        }
    }

    pub fn reason(&self) -> &str {
        &self.reason
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

impl std::fmt::Display for BrokerError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}: {}", self.reason, self.message)
    }
}

impl std::error::Error for BrokerError {}

struct HumanSessionEntry {
    session_token: String,
    expires_at: DateTime<Utc>,
}

struct ActiveHumanCommand {
    cancellation: Arc<AtomicBool>,
    child_pid: Arc<AtomicU32>,
}

#[derive(Default)]
struct BrokerState {
    sessions: BTreeMap<String, BrokerSession>,
    human_sessions: HashMap<u32, HumanSessionEntry>,
    human_commands: HashMap<u32, BTreeMap<u64, ActiveHumanCommand>>,
    next_human_command_id: u64,
}

const BROKER_VERSION: &str = env!("CARGO_PKG_VERSION");

struct BrokerSession {
    project: String,
    vault: PathBuf,
    passphrase: String,
    /// Ephemeral key used to re-encrypt the vault on disk while the session is active.
    /// If Some, the vault file is encrypted with this key (not passphrase) until lock.
    session_key: Option<String>,
    expires_at: DateTime<Utc>,
    active_mode: Option<modes::ActiveMode>,
}

pub fn run_dir() -> PathBuf {
    logs::ward_home().join("run")
}

pub fn socket_path() -> PathBuf {
    run_dir().join("ward.sock")
}

pub fn pid_path() -> PathBuf {
    run_dir().join("broker.pid")
}

#[cfg(test)]
pub fn ensure_running() -> Result<()> {
    Ok(())
}

#[cfg(not(test))]
pub fn ensure_running() -> Result<()> {
    match ping_status() {
        Ok(status) if broker_is_current(&status) => return Ok(()),
        Ok(status) if status.running => {
            stop_existing_broker(&status);
            cleanup_stale_files()?;
        }
        _ => {
            cleanup_stale_files()?;
        }
    }
    fs_util::ensure_private_dir(&run_dir())?;
    let exe = std::env::current_exe().context("failed to resolve current executable")?;
    if !broker_process_supported(&exe) {
        return Ok(());
    }
    Command::new(exe)
        .arg("__broker")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .context("failed to start Ward broker")?;
    wait_until_ready(StdDuration::from_secs(2))
}

#[cfg(not(test))]
fn wait_until_ready(timeout: StdDuration) -> Result<()> {
    let started = Instant::now();
    while started.elapsed() < timeout {
        if ping().is_ok() {
            return Ok(());
        }
        thread::sleep(StdDuration::from_millis(25));
    }
    anyhow::bail!("Ward broker did not become ready");
}

#[cfg(not(test))]
fn broker_is_current(status: &BrokerStatus) -> bool {
    status.running && status.version == BROKER_VERSION
}

#[cfg(not(test))]
fn stop_existing_broker(status: &BrokerStatus) {
    let pid = status.pid.or_else(|| read_pid().ok());
    if send_simple(BrokerRequest::Stop).is_ok() {
        if let Some(pid) = pid {
            let deadline = Instant::now() + StdDuration::from_secs(2);
            while Instant::now() < deadline {
                if !process_exists(pid) {
                    return;
                }
                thread::sleep(StdDuration::from_millis(50));
            }
        } else {
            return;
        }
    }
    if let Some(pid) = pid {
        terminate_broker_process(pid);
    }
}

#[cfg(not(test))]
fn terminate_broker_process(pid: u32) {
    if !is_broker_process(pid) {
        return;
    }
    #[cfg(unix)]
    {
        // SAFETY: target pid is selected by command-line inspection.
        let _ = unsafe { libc::kill(pid as libc::pid_t, libc::SIGTERM) };
        let deadline = Instant::now() + StdDuration::from_secs(1);
        while Instant::now() < deadline {
            if !process_exists(pid) {
                return;
            }
            thread::sleep(StdDuration::from_millis(50));
        }
        // SAFETY: best-effort hard stop for the same broker process if SIGTERM was ignored.
        let _ = unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) };
    }
}

#[cfg(not(test))]
fn is_broker_process(pid: u32) -> bool {
    command_line(pid)
        .map(|line| line.contains("__broker") && line.contains("ward"))
        .unwrap_or(false)
}

#[cfg(not(test))]
fn command_line(pid: u32) -> Option<String> {
    let output = Command::new("ps")
        .args(["-p", &pid.to_string(), "-o", "command="])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

#[cfg(not(test))]
fn broker_process_supported(exe: &Path) -> bool {
    #[cfg(coverage)]
    if std::env::var_os("WARD_COVERAGE_ASSUME_BROKER_EXE").is_some() {
        return true;
    }
    exe.file_stem()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name == "ward")
}

#[cfg(test)]
fn broker_process_supported(_exe: &Path) -> bool {
    false
}

#[cfg(test)]
pub fn unlock_project(
    _project: &str,
    _vault: &Path,
    _passphrase: &str,
    _ttl: Duration,
) -> Result<()> {
    Ok(())
}

#[cfg(test)]
pub fn unlock_project_with_mode(
    _project: &str,
    _vault: &Path,
    _passphrase: &str,
    _ttl: Duration,
    _mode: Option<String>,
) -> Result<()> {
    Ok(())
}

#[cfg(not(test))]
pub fn unlock_project(project: &str, vault: &Path, passphrase: &str, ttl: Duration) -> Result<()> {
    unlock_project_with_mode(project, vault, passphrase, ttl, None)
}

#[cfg(not(test))]
pub fn unlock_project_with_mode(
    project: &str,
    vault: &Path,
    passphrase: &str,
    ttl: Duration,
    mode: Option<String>,
) -> Result<()> {
    ensure_running()?;
    let exe = std::env::current_exe().context("failed to resolve current executable")?;
    if !broker_process_supported(&exe) {
        return Ok(());
    }
    let ttl_seconds = ttl.num_seconds();
    match send_simple(BrokerRequest::Unlock {
        project: project.to_string(),
        vault: vault.to_path_buf(),
        passphrase: passphrase.to_string(),
        ttl_seconds,
        mode,
    })? {
        BrokerResponse::Ok => Ok(()),
        BrokerResponse::Error { message, .. } => anyhow::bail!("{message}"),
        other => anyhow::bail!("unexpected broker response: {other:?}"),
    }
}

#[cfg(test)]
pub fn sign_receipt(
    _project: &str,
    _vault: &Path,
    _payload: ApprovalReceiptPayload,
) -> Result<ApprovalReceipt> {
    anyhow::bail!("broker signing is disabled in unit tests")
}

#[cfg(not(test))]
pub fn sign_receipt(
    project: &str,
    vault: &Path,
    payload: ApprovalReceiptPayload,
) -> Result<ApprovalReceipt> {
    ensure_running()?;
    let exe = std::env::current_exe().context("failed to resolve current executable")?;
    if !broker_process_supported(&exe) {
        anyhow::bail!("Ward broker is unavailable from this executable");
    }
    match send_simple(BrokerRequest::Sign {
        project: project.to_string(),
        vault: vault.to_path_buf(),
        payload,
    })? {
        BrokerResponse::Signed { receipt } => Ok(receipt),
        BrokerResponse::Error { message, .. } => anyhow::bail!("{message}"),
        other => anyhow::bail!("unexpected broker response: {other:?}"),
    }
}

pub fn execute(
    project: &str,
    vault: &Path,
    cwd: &Path,
    env_names: Vec<String>,
    command: Vec<String>,
    human_shell_pid: Option<u32>,
    agent_proof: Option<AgentProof>,
) -> Result<RunCommandOutcome> {
    ensure_running()?;
    let exe = std::env::current_exe().context("failed to resolve current executable")?;
    if !broker_process_supported(&exe) {
        anyhow::bail!("Ward broker is unavailable from this executable");
    }
    let mut stream = connect()?;
    let inherited_env = inherited_execution_env();
    let request = BrokerRequest::Execute {
        project: project.to_string(),
        vault: vault.to_path_buf(),
        cwd: cwd.to_path_buf(),
        env_names,
        command,
        inherited_env,
        human_shell_pid,
        agent_proof,
    };
    write_request(&mut stream, &request)?;
    let mut reader = BufReader::new(stream);
    loop {
        let response = read_response(&mut reader)?;
        match response {
            BrokerResponse::Output { stream, line } if stream == "stderr" => eprintln!("{line}"),
            BrokerResponse::Output { line, .. } => println!("{line}"),
            BrokerResponse::Finished { outcome } => return Ok(outcome),
            BrokerResponse::Error { reason, message } => {
                return Err(BrokerError::new(reason, message).into());
            }
            other => anyhow::bail!("unexpected broker response: {other:?}"),
        }
    }
}

fn inherited_execution_env() -> BTreeMap<String, String> {
    ["PATH", "HOME", "SHELL", "USER", "TMPDIR"]
        .into_iter()
        .filter_map(|name| {
            std::env::var(name)
                .ok()
                .map(|value| (name.to_string(), value))
        })
        .collect()
}

pub fn status() -> Result<BrokerStatus> {
    match ping_status() {
        Ok(status) => Ok(status),
        Err(_) => Ok(BrokerStatus {
            running: false,
            socket: socket_path(),
            pid: read_pid().ok(),
            version: BROKER_VERSION.to_string(),
            sessions: Vec::new(),
        }),
    }
}

fn ping_status() -> Result<BrokerStatus> {
    match send_simple(BrokerRequest::Ping)? {
        BrokerResponse::Status { status } => Ok(status),
        other => anyhow::bail!("unexpected broker response: {other:?}"),
    }
}

pub fn active_session_expiry(project: &str, vault: &Path) -> Result<Option<DateTime<Utc>>> {
    let status = status()?;
    Ok(matching_session_expiry(&status, project, vault, Utc::now()))
}

fn matching_session_expiry(
    status: &BrokerStatus,
    project: &str,
    vault: &Path,
    now: DateTime<Utc>,
) -> Option<DateTime<Utc>> {
    if !status.running {
        return None;
    }
    status
        .sessions
        .iter()
        .filter(|session| {
            session.project == project
                && session.expires_at > now
                && same_vault_path(&session.vault, vault)
        })
        .map(|session| session.expires_at)
        .max()
}

fn same_vault_path(left: &Path, right: &Path) -> bool {
    if left == right {
        return true;
    }
    match (left.canonicalize(), right.canonicalize()) {
        (Ok(left), Ok(right)) => left == right,
        _ => false,
    }
}

pub fn stop() -> Result<()> {
    match send_simple(BrokerRequest::Stop) {
        Ok(BrokerResponse::Ok) | Err(_) => {
            cleanup_stale_files()?;
            Ok(())
        }
        Ok(BrokerResponse::Error { message, .. }) => anyhow::bail!("{message}"),
        Ok(other) => anyhow::bail!("unexpected broker response: {other:?}"),
    }
}

pub fn setup_project_with_active_passphrase(
    source_project: &str,
    source_vault: &Path,
    target_path: &Path,
    project: Option<String>,
) -> Result<BrokerProjectSetupStatus> {
    ensure_running()?;
    match send_simple(BrokerRequest::SetupProject {
        source_project: source_project.to_string(),
        source_vault: source_vault.to_path_buf(),
        target_path: target_path.to_path_buf(),
        project,
    })? {
        BrokerResponse::ProjectSetup { status } => Ok(status),
        BrokerResponse::Error { reason, message } => Err(BrokerError::new(reason, message).into()),
        other => anyhow::bail!("unexpected broker response: {other:?}"),
    }
}

#[cfg(test)]
pub fn list_vault_keys(_project: &str, _vault: &Path) -> Result<Vec<String>> {
    Ok(Vec::new())
}

#[cfg(not(test))]
pub fn list_vault_keys(project: &str, vault: &Path) -> Result<Vec<String>> {
    ensure_running()?;
    let exe = std::env::current_exe().context("failed to resolve current executable")?;
    if !broker_process_supported(&exe) {
        anyhow::bail!("Ward broker is unavailable from this executable");
    }
    match send_simple(BrokerRequest::ListKeys {
        project: project.to_string(),
        vault: vault.to_path_buf(),
    })? {
        BrokerResponse::Keys { names } => Ok(names),
        BrokerResponse::Error { message, .. } => anyhow::bail!("{message}"),
        other => anyhow::bail!("unexpected broker response: {other:?}"),
    }
}

#[cfg(test)]
pub fn register_human_session(
    _shell_pid: u32,
    _session_token: &str,
    _ttl_seconds: i64,
) -> Result<()> {
    Ok(())
}

#[cfg(test)]
pub fn deregister_human_session(_shell_pid: u32, _session_token: &str) -> Result<()> {
    Ok(())
}

#[cfg(not(test))]
pub fn register_human_session(shell_pid: u32, session_token: &str, ttl_seconds: i64) -> Result<()> {
    match send_simple(BrokerRequest::RegisterHumanSession {
        shell_pid,
        session_token: session_token.to_string(),
        ttl_seconds,
    })? {
        BrokerResponse::Ok => Ok(()),
        BrokerResponse::Error { message, .. } => anyhow::bail!("{message}"),
        other => anyhow::bail!("unexpected broker response: {other:?}"),
    }
}

#[cfg(not(test))]
pub fn deregister_human_session(shell_pid: u32, session_token: &str) -> Result<()> {
    match send_simple(BrokerRequest::DeregisterHumanSession {
        shell_pid,
        session_token: session_token.to_string(),
    }) {
        Ok(BrokerResponse::Ok) | Err(_) => Ok(()),
        Ok(BrokerResponse::Error { message, .. }) => anyhow::bail!("{message}"),
        Ok(other) => anyhow::bail!("unexpected broker response: {other:?}"),
    }
}

pub fn serve() -> Result<()> {
    cleanup_stale_files()?;
    fs_util::ensure_private_dir(&run_dir())?;
    let listener = UnixListener::bind(socket_path()).context("failed to bind Ward broker")?;
    fs_util::set_private_file_permissions(&socket_path())
        .context("failed to restrict broker socket permissions")?;
    fs_util::write_private_file(&pid_path(), std::process::id().to_string().as_bytes())?;
    let state = Arc::new(Mutex::new(BrokerState::default()));
    install_shutdown_handler(Arc::clone(&state));
    for stream in listener.incoming() {
        let stream = stream.context("failed to accept broker client")?;
        let state = Arc::clone(&state);
        thread::spawn(move || {
            let stop = handle_client(stream, state).unwrap_or(false);
            if stop {
                let _ = cleanup_stale_files();
                std::process::exit(0);
            }
        });
    }
    Ok(())
}

fn handle_client(mut stream: UnixStream, state: Arc<Mutex<BrokerState>>) -> Result<bool> {
    let request = {
        let mut reader = BufReader::new(stream.try_clone()?);
        read_request(&mut reader)?
    };
    cleanup_inactive_human_sessions(&mut state.lock().expect("broker state poisoned"));
    match request {
        BrokerRequest::Ping => {
            let status = status_from_state(&state.lock().expect("broker state poisoned"));
            write_response(&mut stream, &BrokerResponse::Status { status })?;
        }
        BrokerRequest::Stop => {
            cancel_all_human_commands(&mut state.lock().expect("broker state poisoned"));
            if let Err(error) = restore_all_sessions(&state) {
                let response = broker_error(
                    "restore_failed",
                    format!("failed to restore vaults before broker shutdown: {error}"),
                );
                write_response(&mut stream, &response)?;
                return Ok(false);
            }
            write_response(&mut stream, &BrokerResponse::Ok)?;
            return Ok(true);
        }
        BrokerRequest::Unlock {
            project,
            vault,
            passphrase,
            ttl_seconds,
            mode,
        } => {
            // If the vault is currently session-encrypted (active session exists),
            // restore it to passphrase-encrypted form before attempting to decrypt.
            {
                let state = state.lock().expect("broker state poisoned");
                if let Some(session) = state.sessions.get(&session_key(&project, &vault)) {
                    if let Some(ref ek) = session.session_key {
                        if let Err(error) =
                            restore_vault_from_session(&vault, ek, &session.passphrase)
                        {
                            let response = broker_error(
                                "restore_failed",
                                format!("failed to restore active session before unlock: {error}"),
                            );
                            write_response(&mut stream, &response)?;
                            return Ok(false);
                        }
                    }
                }
            }
            match vault::decrypt_vault_file(&vault, &passphrase).and_then(|plaintext| {
                approval_receipts::ensure_project_key(&project, &passphrase).map(|_| plaintext)
            }) {
                Ok(plaintext) => {
                    let expires_at = Utc::now() + Duration::seconds(ttl_seconds);

                    // Re-encrypt vault with ephemeral key so passphrase-encrypted
                    // form does not exist on disk while the session is active.
                    let ephemeral_key = generate_session_key();
                    let ephemeral_key = match vault::encrypt_env(&plaintext, &ephemeral_key) {
                        Ok(envelope) => match vault::write_vault(&vault, &envelope) {
                            Ok(()) => Some(ephemeral_key),
                            Err(_) => None,
                        },
                        Err(_) => None,
                    };
                    let session_id = session_key(&project, &vault);
                    state
                        .lock()
                        .expect("broker state poisoned")
                        .sessions
                        .insert(
                            session_id.clone(),
                            BrokerSession {
                                project: project.clone(),
                                vault: vault.clone(),
                                passphrase: passphrase.clone(),
                                session_key: ephemeral_key.clone(),
                                expires_at,
                                active_mode: None,
                            },
                        );

                    // Load active mode config from broker vault if requested
                    let active_mode = if let Some(mode_name) = &mode {
                        match modes::load_broker_modes(&project, &passphrase) {
                            Ok(mode_configs) => match modes::find_mode(&mode_configs, mode_name) {
                                Some(config) => Some(modes::ActiveMode {
                                    config: config.clone(),
                                    expires_at,
                                }),
                                None => {
                                    if let Some(ref ek) = ephemeral_key {
                                        if let Err(error) =
                                            restore_vault_from_session(&vault, ek, &passphrase)
                                        {
                                            let response = broker_error(
                                                "restore_failed",
                                                format!(
                                                    "failed to restore vault after mode lookup failure: {error}"
                                                ),
                                            );
                                            write_response(&mut stream, &response)?;
                                            return Ok(false);
                                        }
                                    }
                                    state
                                        .lock()
                                        .expect("broker state poisoned")
                                        .sessions
                                        .remove(&session_id);
                                    let response = broker_error(
                                            "mode_not_found",
                                            format!("mode '{mode_name}' not found — run `ward modes push` first"),
                                        );
                                    write_response(&mut stream, &response)?;
                                    return Ok(false);
                                }
                            },
                            Err(error) => {
                                if let Some(ref ek) = ephemeral_key {
                                    if let Err(restore_error) =
                                        restore_vault_from_session(&vault, ek, &passphrase)
                                    {
                                        let response = broker_error(
                                            "restore_failed",
                                            format!(
                                                "failed to restore vault after mode load failure: {restore_error}"
                                            ),
                                        );
                                        write_response(&mut stream, &response)?;
                                        return Ok(false);
                                    }
                                }
                                state
                                    .lock()
                                    .expect("broker state poisoned")
                                    .sessions
                                    .remove(&session_id);
                                let response = broker_error(
                                    "modes_vault_unavailable",
                                    format!("could not load modes vault: {error} — run `ward modes push` first"),
                                );
                                write_response(&mut stream, &response)?;
                                return Ok(false);
                            }
                        }
                    } else {
                        None
                    };

                    if let Some(session) = state
                        .lock()
                        .expect("broker state poisoned")
                        .sessions
                        .get_mut(&session_id)
                    {
                        session.active_mode = active_mode;
                    }
                    write_response(&mut stream, &BrokerResponse::Ok)?;
                }
                Err(error) => {
                    let response = broker_error("unlock_failed", error.to_string());
                    write_response(&mut stream, &response)?;
                }
            }
        }
        BrokerRequest::Sign {
            project,
            vault,
            payload,
        } => {
            let result = {
                let state = state.lock().expect("broker state poisoned");
                active_session(&state, &project, &vault)
                    .and_then(|session| sign_with_session(session, payload))
            };
            match result {
                Ok(receipt) => write_response(&mut stream, &BrokerResponse::Signed { receipt })?,
                Err(error) => {
                    let response = broker_error("signing_key_unavailable", error.to_string());
                    write_response(&mut stream, &response)?;
                }
            }
        }
        BrokerRequest::RegisterHumanSession {
            shell_pid,
            session_token,
            ttl_seconds,
        } => {
            let expires_at = Utc::now() + Duration::seconds(ttl_seconds);
            state
                .lock()
                .expect("broker state poisoned")
                .human_sessions
                .insert(
                    shell_pid,
                    HumanSessionEntry {
                        session_token,
                        expires_at,
                    },
                );
            write_response(&mut stream, &BrokerResponse::Ok)?;
        }
        BrokerRequest::DeregisterHumanSession {
            shell_pid,
            session_token,
        } => {
            let mut state = state.lock().expect("broker state poisoned");
            match state.human_sessions.get(&shell_pid) {
                Some(entry) if entry.session_token == session_token => {
                    state.human_sessions.remove(&shell_pid);
                    cancel_human_commands(&mut state, shell_pid);
                    write_response(&mut stream, &BrokerResponse::Ok)?;
                }
                Some(_) => {
                    let response = broker_error("invalid_token", "session token mismatch");
                    write_response(&mut stream, &response)?;
                }
                None => {
                    write_response(&mut stream, &BrokerResponse::Ok)?;
                }
            }
        }
        BrokerRequest::Execute {
            project,
            vault,
            cwd,
            env_names,
            command,
            inherited_env,
            human_shell_pid,
            agent_proof,
        } => {
            let cancellation = Arc::new(AtomicBool::new(false));
            let child_pid = Arc::new(AtomicU32::new(0));
            if let Some(shell_pid) = human_shell_pid {
                let mut broker_state = state.lock().expect("broker state poisoned");
                cleanup_inactive_human_sessions(&mut broker_state);
                if let Err(message) = validate_human_session(&broker_state, shell_pid) {
                    let response = broker_error("human_session_required", message);
                    write_response(&mut stream, &response)?;
                    return Ok(false);
                }
            }

            if let Some(proof) = &agent_proof {
                if !agents::verify_proof(&project, proof)? {
                    let response =
                        broker_error("agent_proof_invalid", "agent proof verification failed");
                    write_response(&mut stream, &response)?;
                    return Ok(false);
                }
            }
            let passphrase = {
                let state = state.lock().expect("broker state poisoned");
                active_session(&state, &project, &vault).map(|session| {
                    // Use ephemeral session key if vault is currently session-encrypted
                    session
                        .session_key
                        .clone()
                        .unwrap_or_else(|| session.passphrase.clone())
                })
            };
            let (passphrase, active_mode) = match passphrase {
                Ok(passphrase) => {
                    let active_mode = {
                        let state = state.lock().expect("broker state poisoned");
                        active_session(&state, &project, &vault)
                            .ok()
                            .and_then(|s| s.active_mode.clone())
                    };
                    (passphrase, active_mode)
                }
                Err(error) => {
                    let response = broker_error("unlock_required", error.to_string());
                    write_response(&mut stream, &response)?;
                    return Ok(false);
                }
            };

            // Mode enforcement — runs before any env decryption
            if let Some(ref mode) = active_mode {
                // Env scope is always enforced regardless of mode level
                for env_name in &env_names {
                    if !modes::mode_allows_env(mode, env_name) {
                        let response = broker_error(
                            "mode_env_violation",
                            format!(
                                "{env_name} is not allowed by active mode '{}' (allowedEnv: {})",
                                mode.config.name,
                                mode.config.allowed_env.join(", ")
                            ),
                        );
                        write_response(&mut stream, &response)?;
                        return Ok(false);
                    }
                }
                // Command blocking only applies in supervised mode
                if mode.config.level == modes::ModeLevel::Supervised
                    && !modes::mode_allows_command(mode, &command.join(" "))
                {
                    let response = broker_error(
                        "mode_confirmation_required",
                        format!(
                            "supervised mode '{}': command not in allowedCommands — explicit confirmation required",
                            mode.config.name
                        ),
                    );
                    write_response(&mut stream, &response)?;
                    return Ok(false);
                }
            }

            // Block commands with critical security findings regardless of caller.
            // Policy prompts live in the CLI but this last-resort check runs in the broker
            // so that raw-socket callers cannot bypass exfiltration detection.
            let cmd_str = command.join(" ");
            let security_findings = detection::preflight_findings(&cmd_str, &env_names, None);
            if detection::has_critical_findings(&security_findings) {
                let codes: Vec<&str> = security_findings
                    .iter()
                    .filter(|f| f.severity == detection::Severity::Critical)
                    .map(|f| f.code.as_str())
                    .collect();
                let response = broker_error(
                    "security_policy_violation",
                    format!(
                        "command blocked by security policy: {}",
                        codes.join(", ")
                    ),
                );
                write_response(&mut stream, &response)?;
                return Ok(false);
            }

            let output = Arc::new(Mutex::new(stream.try_clone()?));
            monitor_client_disconnect(stream.try_clone()?, Arc::clone(&cancellation));
            let emitter = {
                let output = Arc::clone(&output);
                let cancellation = Arc::clone(&cancellation);
                Arc::new(move |stream_name: &str, line: &str| {
                    if let Ok(mut stream) = output.lock() {
                        if write_response(
                            &mut stream,
                            &BrokerResponse::Output {
                                stream: stream_name.to_string(),
                                line: line.to_string(),
                            },
                        )
                        .is_err()
                        {
                            cancellation.store(true, Ordering::SeqCst);
                        }
                    }
                })
            };
            let outcome = runner::run_command_with_emitter(
                {
                    if let Some(shell_pid) = human_shell_pid {
                        register_human_command(
                            &mut state.lock().expect("broker state poisoned"),
                            shell_pid,
                            Arc::clone(&cancellation),
                            Arc::clone(&child_pid),
                        );
                    }
                    RunCommandRequest {
                        cwd,
                        vault,
                        env_names,
                        command,
                        passphrase,
                        inherited_env,
                        cancellation: Some(Arc::clone(&cancellation)),
                        human_shell_pid,
                        child_pid: Some(Arc::clone(&child_pid)),
                    }
                },
                emitter,
            );
            if let Some(shell_pid) = human_shell_pid {
                let mut broker_state = state.lock().expect("broker state poisoned");
                unregister_human_command(&mut broker_state, shell_pid, &cancellation);
            }
            match outcome {
                Ok(outcome) => {
                    let mut stream = output.lock().expect("broker output stream poisoned");
                    write_response(&mut stream, &BrokerResponse::Finished { outcome })?;
                }
                Err(error) => {
                    let mut stream = output.lock().expect("broker output stream poisoned");
                    let response = if let Some(missing) = runner::missing_vault_envs(&error) {
                        broker_error("vault_key_missing", missing.join(", "))
                    } else {
                        broker_error("execution_failed", error.to_string())
                    };
                    write_response(&mut stream, &response)?;
                }
            }
        }
        BrokerRequest::ListKeys { project, vault } => {
            let key_result = {
                let state = state.lock().expect("broker state poisoned");
                active_session(&state, &project, &vault).and_then(|session| {
                    let decrypt_key = session
                        .session_key
                        .clone()
                        .unwrap_or_else(|| session.passphrase.clone());
                    let plaintext = vault::decrypt_vault_file(&vault, &decrypt_key)?;
                    let names = plaintext
                        .lines()
                        .filter_map(|line| {
                            let line = line.trim();
                            if line.is_empty() || line.starts_with('#') {
                                return None;
                            }
                            line.splitn(2, '=').next().map(str::to_string)
                        })
                        .collect::<Vec<_>>();
                    Ok(names)
                })
            };
            match key_result {
                Ok(names) => write_response(&mut stream, &BrokerResponse::Keys { names })?,
                Err(e) => {
                    let response = broker_error("list_keys_failed", e.to_string());
                    write_response(&mut stream, &response)?;
                }
            }
        }
        BrokerRequest::SetupProject {
            source_project,
            source_vault,
            target_path,
            project,
        } => {
            let (passphrase, expires_at) = {
                let state = state.lock().expect("broker state poisoned");
                match active_session(&state, &source_project, &source_vault) {
                    Ok(session) => (session.passphrase.clone(), session.expires_at),
                    Err(error) => {
                        let response = broker_error("unlock_required", error.to_string());
                        write_response(&mut stream, &response)?;
                        return Ok(false);
                    }
                }
            };

            match setup_project_with_passphrase(&target_path, project.as_deref(), &passphrase) {
                Ok(status) => {
                    let new_session_key =
                        match vault::decrypt_vault_file(&status.vault, &passphrase).and_then(
                            |plaintext| {
                                let ephemeral_key = generate_session_key();
                                let envelope = vault::encrypt_env(&plaintext, &ephemeral_key)?;
                                vault::write_vault(&status.vault, &envelope)?;
                                Ok(ephemeral_key)
                            },
                        ) {
                            Ok(ephemeral_key) => Some(ephemeral_key),
                            Err(_) => None,
                        };
                    state
                        .lock()
                        .expect("broker state poisoned")
                        .sessions
                        .insert(
                            session_key(&status.project, &status.vault),
                            BrokerSession {
                                project: status.project.clone(),
                                vault: status.vault.clone(),
                                passphrase,
                                session_key: new_session_key,
                                expires_at,
                                active_mode: None,
                            },
                        );
                    write_response(&mut stream, &BrokerResponse::ProjectSetup { status })?;
                }
                Err(error) => {
                    let response = broker_error("project_setup_failed", error.to_string());
                    write_response(&mut stream, &response)?;
                }
            }
        }
    }
    Ok(false)
}

fn sign_with_session(
    session: &BrokerSession,
    mut payload: ApprovalReceiptPayload,
) -> Result<ApprovalReceipt> {
    let passphrase = &session.passphrase;
    let project = &session.project;
    let ciphertext =
        approval_receipts::session_signing_key_ciphertext(project, passphrase, passphrase)?;
    let signing_key = approval_receipts::decrypt_session_signing_key(&ciphertext, passphrase)?;
    payload.signer_key_id = signing_key.signer_key_id.clone();
    approval_receipts::sign_payload(payload, &signing_key)
}

pub(crate) fn setup_project_with_passphrase(
    target_path: &Path,
    project: Option<&str>,
    passphrase: &str,
) -> Result<BrokerProjectSetupStatus> {
    let target_path = target_path
        .canonicalize()
        .unwrap_or_else(|_| target_path.to_path_buf());
    if !target_path.is_dir() {
        anyhow::bail!(
            "selected path is not a directory: {}",
            target_path.display()
        );
    }

    if let Ok(config) = config::read_project_config(&target_path) {
        let project_name = project.unwrap_or(&config.project).to_string();
        let vault_path =
            config::resolve_vault_path_with_passphrase(&target_path, &config, passphrase);
        registry::update_project_vault(&project_name, target_path.clone(), vault_path.clone())?;
        return Ok(BrokerProjectSetupStatus {
            project: project_name,
            path: target_path,
            vault: vault_path,
            created: false,
            registered: true,
        });
    }

    let source = target_path.join(".env");
    if !source.exists() {
        anyhow::bail!(
            "selected folder has no .env file; add a dotenv file or run ward setup in that project"
        );
    }
    if env_file::is_locked_env_file(&source)? {
        anyhow::bail!(
            "{} is already a Ward locked marker but no .ward.json exists",
            source.display()
        );
    }

    let project_name = project
        .map(str::to_string)
        .or_else(|| {
            target_path
                .file_name()
                .and_then(|name| name.to_str())
                .map(str::to_string)
        })
        .context("could not infer project name from selected folder")?;
    let env_keys = config::env_keys_from_dotenv_file(&source)?;
    let mut project_config =
        config::ProjectConfig::default_for_dir(&target_path, Some(project_name.clone()))?;
    project_config.vault = PathBuf::from(config::DEFAULT_VAULT_FILE);
    project_config.profiles = config::default_profiles(&env_keys, &target_path);

    config::write_project_config(&target_path, &project_config, true)?;
    config::ensure_env_example(&target_path)?;
    config::ensure_agent_instructions(&target_path, &project_config.project)?;
    config::ensure_gitignore(&target_path, true)?;

    let vault_path = target_path.join(config::DEFAULT_VAULT_FILE);
    vault::import_env_file(&source, &vault_path, passphrase)?;
    let plaintext = vault::decrypt_vault_file(&vault_path, passphrase)?;
    env_file::lock_env_file(&source, &vault_path)?;
    approval_receipts::ensure_project_key(&project_config.project, passphrase)?;

    if recovery::create_recovery_files_with_material(
        &project_config.project,
        passphrase,
        passphrase,
        Some(&plaintext),
    )
    .is_ok()
    {
        project_config.recovery_created = true;
        let _ = config::write_project_config(&target_path, &project_config, true);
    }

    registry::update_project_vault(
        &project_config.project,
        target_path.clone(),
        vault_path.clone(),
    )?;
    Ok(BrokerProjectSetupStatus {
        project: project_config.project,
        path: target_path,
        vault: vault_path,
        created: true,
        registered: true,
    })
}

fn active_session<'a>(
    state: &'a BrokerState,
    project: &str,
    vault: &Path,
) -> Result<&'a BrokerSession> {
    let key = session_key(project, vault);
    let session = state
        .sessions
        .get(&key)
        .context("missing broker unlock session")?;
    if session.expires_at <= Utc::now() {
        anyhow::bail!("expired broker unlock session");
    }
    Ok(session)
}

fn validate_human_session(state: &BrokerState, shell_pid: u32) -> std::result::Result<(), String> {
    let Some(entry) = state.human_sessions.get(&shell_pid) else {
        return Err(format!(
            "Ward human mode is not active for this terminal; run ward human (shell pid: {shell_pid})"
        ));
    };
    if entry.expires_at <= Utc::now() {
        return Err(format!(
            "Ward human mode expired for this terminal; run ward human (shell pid: {shell_pid})"
        ));
    }
    if !process_exists(shell_pid) {
        return Err(format!(
            "Ward human shell is no longer running; run ward human in the active terminal (shell pid: {shell_pid})"
        ));
    }
    Ok(())
}

fn register_human_command(
    state: &mut BrokerState,
    shell_pid: u32,
    cancellation: Arc<AtomicBool>,
    child_pid: Arc<AtomicU32>,
) {
    let command_id = state.next_human_command_id;
    state.next_human_command_id = state.next_human_command_id.saturating_add(1);
    state.human_commands.entry(shell_pid).or_default().insert(
        command_id,
        ActiveHumanCommand {
            cancellation,
            child_pid,
        },
    );
}

fn unregister_human_command(
    state: &mut BrokerState,
    shell_pid: u32,
    cancellation: &Arc<AtomicBool>,
) {
    let Some(commands) = state.human_commands.get_mut(&shell_pid) else {
        return;
    };
    let remove_id = commands.iter().find_map(|(id, active)| {
        if Arc::ptr_eq(&active.cancellation, cancellation) {
            Some(*id)
        } else {
            None
        }
    });
    if let Some(id) = remove_id {
        commands.remove(&id);
    }
    if commands.is_empty() {
        state.human_commands.remove(&shell_pid);
    }
}

fn cancel_human_commands(state: &mut BrokerState, shell_pid: u32) {
    if let Some(commands) = state.human_commands.remove(&shell_pid) {
        for command in commands.values() {
            command.cancellation.store(true, Ordering::SeqCst);
            let child_pid = command.child_pid.load(Ordering::SeqCst);
            if child_pid != 0 {
                terminate_process_group(child_pid);
            }
        }
    }
}

fn cancel_all_human_commands(state: &mut BrokerState) {
    let shell_pids = state.human_commands.keys().copied().collect::<Vec<_>>();
    for shell_pid in shell_pids {
        cancel_human_commands(state, shell_pid);
    }
}

fn cleanup_inactive_human_sessions(state: &mut BrokerState) {
    let now = Utc::now();
    let stale = state
        .human_sessions
        .iter()
        .filter_map(|(shell_pid, entry)| {
            if entry.expires_at <= now || !process_exists(*shell_pid) {
                Some(*shell_pid)
            } else {
                None
            }
        })
        .collect::<Vec<_>>();
    for shell_pid in stale {
        state.human_sessions.remove(&shell_pid);
        cancel_human_commands(state, shell_pid);
    }
}

fn status_from_state(state: &BrokerState) -> BrokerStatus {
    BrokerStatus {
        running: true,
        socket: socket_path(),
        pid: Some(std::process::id()),
        version: BROKER_VERSION.to_string(),
        sessions: state
            .sessions
            .values()
            .filter(|session| session.expires_at > Utc::now())
            .map(|session| BrokerSessionStatus {
                project: session.project.clone(),
                vault: session.vault.clone(),
                expires_at: session.expires_at,
                active_mode: session.active_mode.as_ref().map(|m| m.config.name.clone()),
            })
            .collect(),
    }
}

fn session_key(project: &str, vault: &Path) -> String {
    format!("{}|{}", project, vault.display())
}

fn process_exists(pid: u32) -> bool {
    if pid == 0 {
        return false;
    }
    #[cfg(unix)]
    {
        // SAFETY: kill(pid, 0) checks process visibility without sending a signal.
        let result = unsafe { libc::kill(pid as libc::pid_t, 0) };
        result == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
    }
    #[cfg(not(unix))]
    {
        let _ = pid;
        true
    }
}

fn terminate_process_group(pid: u32) {
    #[cfg(unix)]
    {
        let pgid = pid as libc::pid_t;
        // SAFETY: sends SIGTERM to the process group created for a human-mode child.
        let _ = unsafe { libc::kill(-pgid, libc::SIGTERM) };
        thread::sleep(StdDuration::from_millis(100));
        // SAFETY: best-effort hard stop if the process group ignored SIGTERM.
        let _ = unsafe { libc::kill(-pgid, libc::SIGKILL) };
    }
    #[cfg(not(unix))]
    {
        let _ = pid;
    }
}

fn monitor_client_disconnect(mut stream: UnixStream, cancellation: Arc<AtomicBool>) {
    thread::spawn(move || {
        let mut buf = [0u8; 1];
        loop {
            match stream.read(&mut buf) {
                Ok(0) => {
                    cancellation.store(true, Ordering::SeqCst);
                    break;
                }
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(_) => {
                    cancellation.store(true, Ordering::SeqCst);
                    break;
                }
            }
        }
    });
}

fn generate_session_key() -> String {
    use rand::RngCore;
    let mut key = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut key);
    hex::encode(key)
}

fn install_shutdown_handler(state: Arc<Mutex<BrokerState>>) {
    #[cfg(test)]
    {
        let _ = state;
    }
    #[cfg(not(test))]
    {
        if let Err(error) = ctrlc::set_handler(move || {
            let _ = restore_all_sessions(&state);
            let _ = cleanup_stale_files();
            std::process::exit(0);
        }) {
            eprintln!("ward broker warning: failed to install shutdown handler: {error}");
        }
    }
}

fn restore_all_sessions(state: &Arc<Mutex<BrokerState>>) -> Result<()> {
    let state = state.lock().expect("broker state poisoned");
    for session in state.sessions.values() {
        if let Some(ref ek) = session.session_key {
            restore_vault_from_session(&session.vault, ek, &session.passphrase).context(
                format!(
                    "failed to restore {} before broker shutdown",
                    session.vault.display()
                ),
            )?;
        }
    }
    Ok(())
}

/// Decrypts the session-encrypted vault and re-writes it with the original passphrase.
fn restore_vault_from_session(vault: &Path, session_key: &str, passphrase: &str) -> Result<()> {
    let plaintext = vault::decrypt_vault_file(vault, session_key)?;
    let envelope = vault::encrypt_env(&plaintext, passphrase)?;
    vault::write_vault(vault, &envelope)
}

fn send_simple(request: BrokerRequest) -> Result<BrokerResponse> {
    let mut stream = connect()?;
    write_request(&mut stream, &request)?;
    let mut reader = BufReader::new(stream);
    read_response(&mut reader)
}

fn broker_error(reason: impl Into<String>, message: impl Into<String>) -> BrokerResponse {
    BrokerResponse::Error {
        reason: reason.into(),
        message: message.into(),
    }
}

#[cfg(not(test))]
fn ping() -> Result<()> {
    ping_status().map(|_| ())
}

fn connect() -> Result<UnixStream> {
    UnixStream::connect(socket_path()).context("failed to connect to Ward broker")
}

fn read_request(reader: &mut BufReader<UnixStream>) -> Result<BrokerRequest> {
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .context("failed to read broker request")?;
    serde_json::from_str(line.trim()).context("failed to parse broker request")
}

fn read_response(reader: &mut BufReader<UnixStream>) -> Result<BrokerResponse> {
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .context("failed to read broker response")?;
    if line.is_empty() {
        anyhow::bail!("broker closed the connection");
    }
    serde_json::from_str(line.trim()).context("failed to parse broker response")
}

fn write_request(stream: &mut UnixStream, request: &BrokerRequest) -> Result<()> {
    let line = serde_json::to_string(request).expect("broker request should serialize");
    writeln!(stream, "{line}").context("failed to write broker request")
}

fn write_response(stream: &mut UnixStream, response: &BrokerResponse) -> Result<()> {
    let line = serde_json::to_string(response).expect("broker response should serialize");
    writeln!(stream, "{line}").context("failed to write broker response")
}

fn cleanup_stale_files() -> Result<()> {
    let socket = socket_path();
    if socket.exists() {
        let _ = std::fs::remove_file(&socket);
    }
    let pid = pid_path();
    if pid.exists() {
        let _ = std::fs::remove_file(pid);
    }
    Ok(())
}

fn read_pid() -> Result<u32> {
    let contents = std::fs::read_to_string(pid_path()).context("failed to read broker pid")?;
    contents
        .trim()
        .parse::<u32>()
        .context("failed to parse broker pid")
}

#[cfg(all(coverage, not(test)))]
#[doc(hidden)]
pub fn coverage_exercise_broker_edges() -> Result<()> {
    let home = tempfile::tempdir()?;
    std::env::set_var("WARD_HOME", home.path());
    cleanup_stale_files()?;
    assert!(execute(
        "demo",
        &home.path().join(".env.vault"),
        home.path(),
        Vec::new(),
        vec!["sh".to_string(), "-c".to_string(), "true".to_string()],
        None,
        None,
    )
    .is_err());
    assert!(wait_until_ready(StdDuration::from_millis(0)).is_err());

    let broker_status = BrokerStatus {
        running: true,
        socket: socket_path(),
        pid: Some(1),
        version: BROKER_VERSION.to_string(),
        sessions: Vec::new(),
    };
    let ping_result = with_fake_broker(vec![vec![BrokerResponse::Ok]], ping)?;
    assert!(ping_result.is_err());
    let responses = vec![vec![BrokerResponse::Status {
        status: broker_status.clone(),
    }]];
    let status_result = with_fake_broker(responses, status)?;
    assert!(status_result?.running);
    let status_result = with_fake_broker(vec![vec![BrokerResponse::Ok]], status)?;
    assert!(status_result.is_err());
    let responses = vec![vec![BrokerResponse::Error {
        reason: "stop_failed".to_string(),
        message: "stop failed".to_string(),
    }]];
    let stop_result = with_fake_broker(responses, stop)?;
    assert!(stop_result.is_err());
    let responses = vec![vec![BrokerResponse::Status {
        status: broker_status.clone(),
    }]];
    let stop_result = with_fake_broker(responses, stop)?;
    assert!(stop_result.is_err());

    std::env::set_var("WARD_COVERAGE_ASSUME_BROKER_EXE", "1");
    let vault_path = home.path().join(".env.vault");
    let payload = ApprovalReceiptPayload {
        schema_version: 1,
        grant_id: uuid::Uuid::new_v4(),
        request_id: uuid::Uuid::new_v4(),
        project: "demo".to_string(),
        agent: Some("codex".to_string()),
        branch: Some("main".to_string()),
        command_hash: approval_receipts::command_hash("pnpm dev"),
        requested_env: vec!["DATABASE_URL".to_string()],
        approved_env: vec!["DATABASE_URL".to_string()],
        scope: crate::approvals::ApprovalScope::Session,
        expires_at: None,
        critical_confirmation: false,
        created_at: Utc::now(),
        signer_key_id: String::new(),
        agent_key_id: None,
        verified_worktree: None,
        verified_git_remote: None,
        verified_commit: None,
    };
    let responses = vec![
        vec![BrokerResponse::Status {
            status: broker_status.clone(),
        }],
        vec![BrokerResponse::Error {
            reason: "unlock_failed".to_string(),
            message: "unlock failed".to_string(),
        }],
    ];
    let action = || unlock_project("demo", &vault_path, "1234", Duration::hours(1));
    let unlock_result = with_fake_broker(responses, action)?;
    assert!(unlock_result.is_err());
    let responses = vec![
        vec![BrokerResponse::Status {
            status: broker_status.clone(),
        }],
        vec![BrokerResponse::Status {
            status: broker_status.clone(),
        }],
    ];
    let action = || unlock_project("demo", &vault_path, "1234", Duration::hours(1));
    let unlock_result = with_fake_broker(responses, action)?;
    assert!(unlock_result.is_err());
    let responses = vec![
        vec![BrokerResponse::Status {
            status: broker_status.clone(),
        }],
        vec![BrokerResponse::Error {
            reason: "signing_key_unavailable".to_string(),
            message: "sign failed".to_string(),
        }],
    ];
    let action = || sign_receipt("demo", &vault_path, payload.clone());
    let sign_result = with_fake_broker(responses, action)?;
    assert!(sign_result.is_err());
    let responses = vec![
        vec![BrokerResponse::Status {
            status: broker_status.clone(),
        }],
        vec![BrokerResponse::Ok],
    ];
    let action = || sign_receipt("demo", &vault_path, payload);
    let sign_result = with_fake_broker(responses, action)?;
    assert!(sign_result.is_err());
    let responses = vec![
        vec![BrokerResponse::Status {
            status: broker_status.clone(),
        }],
        vec![
            BrokerResponse::Output {
                stream: "stderr".to_string(),
                line: "coverage stderr".to_string(),
            },
            BrokerResponse::Error {
                reason: "execution_failed".to_string(),
                message: "execution failed".to_string(),
            },
        ],
    ];
    let command = vec!["sh".to_string(), "-c".to_string(), "true".to_string()];
    let action = || {
        execute(
            "demo",
            &vault_path,
            home.path(),
            Vec::new(),
            command,
            None,
            None,
        )
    };
    let execute_result = with_fake_broker(responses, action)?;
    assert!(execute_result.is_err());
    let responses = vec![
        vec![BrokerResponse::Status {
            status: broker_status.clone(),
        }],
        vec![BrokerResponse::Finished {
            outcome: RunCommandOutcome {
                exit_code: 0,
                duration_ms: 0,
                redaction_alerts: 0,
                output_alerts: Vec::new(),
            },
        }],
    ];
    let command = vec!["sh".to_string(), "-c".to_string(), "true".to_string()];
    let action = || {
        execute(
            "demo",
            &vault_path,
            home.path(),
            Vec::new(),
            command,
            None,
            None,
        )
    };
    let execute_result = with_fake_broker(responses, action)?;
    let _ = execute_result?;
    let responses = vec![
        vec![BrokerResponse::Status {
            status: broker_status,
        }],
        vec![BrokerResponse::Ok],
    ];
    let command = vec!["sh".to_string(), "-c".to_string(), "true".to_string()];
    let action = || {
        execute(
            "demo",
            &vault_path,
            home.path(),
            Vec::new(),
            command,
            None,
            None,
        )
    };
    let execute_result = with_fake_broker(responses, action)?;
    assert!(execute_result.is_err());

    std::env::remove_var("WARD_COVERAGE_ASSUME_BROKER_EXE");
    std::env::remove_var("WARD_HOME");
    Ok(())
}

#[cfg(all(coverage, not(test)))]
fn with_fake_broker<T>(
    responses: Vec<Vec<BrokerResponse>>,
    action: impl FnOnce() -> T,
) -> Result<T> {
    cleanup_stale_files()?;
    fs_util::ensure_private_dir(&run_dir())?;
    let listener = UnixListener::bind(socket_path()).context("failed to bind fake broker")?;
    let handle = thread::spawn(move || {
        for response_set in responses {
            let (mut stream, _) = listener.accept().expect("fake broker accept failed");
            {
                let mut reader = BufReader::new(stream.try_clone().expect("clone fake stream"));
                let _request = read_request(&mut reader).expect("fake broker request");
            }
            for response in response_set {
                write_response(&mut stream, &response).expect("fake broker response");
            }
        }
    });
    let result = action();
    handle.join().expect("fake broker thread panicked");
    cleanup_stale_files()?;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{agents, approval_receipts, approvals::ApprovalScope, policy::AccessRequest};
    use serial_test::serial;

    fn broker_pair(
        request: BrokerRequest,
        state: Arc<Mutex<BrokerState>>,
    ) -> (bool, BrokerResponse) {
        let (mut client, server) = UnixStream::pair().unwrap();
        write_request(&mut client, &request).unwrap();
        let stop = handle_client(server, state).unwrap();
        let mut reader = BufReader::new(client);
        let response = read_response(&mut reader).unwrap();
        (stop, response)
    }

    fn test_vault(passphrase: &str) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let vault_path = dir.path().join(".env.vault");
        let envelope = vault::encrypt_env("DATABASE_URL=postgres://broker\n", passphrase).unwrap();
        vault::write_vault(&vault_path, &envelope).unwrap();
        (dir, vault_path)
    }

    #[test]
    #[serial]
    fn setup_project_with_passphrase_creates_project_without_exposing_secret_values() {
        let home = tempfile::tempdir().unwrap();
        std::env::set_var("WARD_HOME", home.path());
        let project = tempfile::tempdir().unwrap();
        std::fs::write(
            project.path().join(".env"),
            "DATABASE_URL=postgres://dashboard\nPAYLOAD_SECRET=payload\n",
        )
        .unwrap();

        let status =
            setup_project_with_passphrase(project.path(), Some("dashboard-demo"), "1234").unwrap();

        assert_eq!(status.project, "dashboard-demo");
        assert!(project.path().join(".ward.json").exists());
        assert!(status.vault.exists());
        let cfg = config::read_project_config(project.path()).unwrap();
        assert!(cfg.recovery_created);
        assert!(cfg.profiles["dev"]
            .env
            .contains(&"PAYLOAD_SECRET".to_string()));
        let locked = std::fs::read_to_string(project.path().join(".env")).unwrap();
        assert!(locked.contains("Ward managed locked .env"));
        assert!(!locked.contains("postgres://dashboard"));
        std::env::remove_var("WARD_HOME");
    }

    #[test]
    #[serial]
    fn setup_project_request_requires_active_source_session() {
        let home = tempfile::tempdir().unwrap();
        std::env::set_var("WARD_HOME", home.path());
        let state = Arc::new(Mutex::new(BrokerState::default()));
        let (_, response) = broker_pair(
            BrokerRequest::SetupProject {
                source_project: "demo".to_string(),
                source_vault: home.path().join(".env.vault"),
                target_path: home.path().join("target"),
                project: None,
            },
            state,
        );
        assert!(matches!(
            response,
            BrokerResponse::Error {
                reason,
                ..
            } if reason == "unlock_required"
        ));
        std::env::remove_var("WARD_HOME");
    }

    #[test]
    #[serial]
    fn setup_project_with_existing_config_registers_without_overwriting() {
        let home = tempfile::tempdir().unwrap();
        std::env::set_var("WARD_HOME", home.path());
        let project = tempfile::tempdir().unwrap();
        let mut cfg =
            config::ProjectConfig::default_for_dir(project.path(), Some("existing".to_string()))
                .unwrap();
        cfg.profiles.get_mut("dev").unwrap().command = "custom dev".to_string();
        config::write_project_config(project.path(), &cfg, true).unwrap();

        let status = setup_project_with_passphrase(project.path(), None, "1234").unwrap();
        let after = config::read_project_config(project.path()).unwrap();

        assert_eq!(status.project, "existing");
        assert_eq!(after.profiles["dev"].command, "custom dev");
        assert!(registry::load_registry()
            .unwrap()
            .projects
            .contains_key("existing"));
        std::env::remove_var("WARD_HOME");
    }

    #[test]
    #[serial]
    fn setup_project_with_missing_env_is_rejected() {
        let home = tempfile::tempdir().unwrap();
        std::env::set_var("WARD_HOME", home.path());
        let project = tempfile::tempdir().unwrap();
        let error = setup_project_with_passphrase(project.path(), Some("missing"), "1234")
            .unwrap_err()
            .to_string();
        assert!(error.contains("no .env"));
        std::env::remove_var("WARD_HOME");
    }

    #[test]
    #[serial]
    fn setup_project_request_reuses_active_session_passphrase() {
        let home = tempfile::tempdir().unwrap();
        std::env::set_var("WARD_HOME", home.path());
        let source_vault = home.path().join("source.env.vault");
        let envelope = vault::encrypt_env("DATABASE_URL=postgres://source\n", "1234").unwrap();
        vault::write_vault(&source_vault, &envelope).unwrap();
        let target = tempfile::tempdir().unwrap();
        std::fs::write(
            target.path().join(".env"),
            "DATABASE_URL=postgres://target\nPAYLOAD_SECRET=payload\n",
        )
        .unwrap();
        let mut state = BrokerState::default();
        state.sessions.insert(
            session_key("demo", &source_vault),
            BrokerSession {
                project: "demo".to_string(),
                vault: source_vault.clone(),
                passphrase: "1234".to_string(),
                session_key: None,
                expires_at: Utc::now() + Duration::hours(1),
                active_mode: None,
            },
        );
        let state = Arc::new(Mutex::new(state));
        let (_, response) = broker_pair(
            BrokerRequest::SetupProject {
                source_project: "demo".to_string(),
                source_vault,
                target_path: target.path().to_path_buf(),
                project: Some("target-demo".to_string()),
            },
            Arc::clone(&state),
        );
        let BrokerResponse::ProjectSetup { status } = response else {
            panic!("unexpected setup response");
        };
        assert_eq!(status.project, "target-demo");
        assert!(state
            .lock()
            .unwrap()
            .sessions
            .contains_key(&session_key("target-demo", &status.vault)));
        std::env::remove_var("WARD_HOME");
    }

    #[test]
    #[serial]
    fn broker_paths_live_under_ward_run_dir() {
        let home = tempfile::tempdir().unwrap();
        std::env::set_var("WARD_HOME", home.path());
        assert!(socket_path().ends_with("run/ward.sock"));
        assert!(pid_path().ends_with("run/broker.pid"));
        ensure_running().unwrap();
        assert!(!broker_process_supported(Path::new(
            "target/debug/cli-test"
        )));
        std::env::remove_var("WARD_HOME");
    }

    #[test]
    #[serial]
    fn status_reports_not_running_without_socket() {
        let home = tempfile::tempdir().unwrap();
        std::env::set_var("WARD_HOME", home.path());
        let status = status().unwrap();
        assert!(!status.running);
        assert_eq!(status.version, BROKER_VERSION);
        assert!(status.sessions.is_empty());
        std::env::remove_var("WARD_HOME");
    }

    #[test]
    fn broker_status_accepts_legacy_ping_without_version() {
        let body = serde_json::json!({
            "type": "status",
            "status": {
                "running": true,
                "socket": "/tmp/ward.sock",
                "pid": 123,
                "sessions": []
            }
        });
        let response: BrokerResponse = serde_json::from_value(body).unwrap();
        let BrokerResponse::Status { status } = response else {
            panic!("expected status response");
        };
        assert_eq!(status.version, "");
    }

    #[test]
    fn matching_session_expiry_filters_project_vault_and_expiry() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().join(".env.vault");
        std::fs::write(&vault, "vault").unwrap();
        let same_vault = dir.path().join(".").join(".env.vault");
        let now = Utc::now();
        let expires_at = now + Duration::minutes(30);
        let status = BrokerStatus {
            running: true,
            socket: socket_path(),
            pid: Some(123),
            version: BROKER_VERSION.to_string(),
            sessions: vec![
                BrokerSessionStatus {
                    project: "other".to_string(),
                    vault: vault.clone(),
                    expires_at,
                    active_mode: None,
                },
                BrokerSessionStatus {
                    project: "demo".to_string(),
                    vault: PathBuf::from("/missing/.env.vault"),
                    expires_at,
                    active_mode: None,
                },
                BrokerSessionStatus {
                    project: "demo".to_string(),
                    vault: same_vault,
                    expires_at,
                    active_mode: None,
                },
                BrokerSessionStatus {
                    project: "demo".to_string(),
                    vault: vault.clone(),
                    expires_at: now - Duration::minutes(1),
                    active_mode: None,
                },
            ],
        };

        assert_eq!(
            matching_session_expiry(&status, "demo", &vault, now),
            Some(expires_at)
        );

        let stopped = BrokerStatus {
            running: false,
            ..status
        };
        assert_eq!(matching_session_expiry(&stopped, "demo", &vault, now), None);
    }

    #[test]
    #[serial]
    fn broker_client_protocol_handles_ping_stop_unlock_sign_and_execute() {
        let home = tempfile::tempdir().unwrap();
        std::env::set_var("WARD_HOME", home.path());
        let passphrase = "coverage passphrase";
        let (_vault_dir, vault_path) = test_vault(passphrase);
        let state = Arc::new(Mutex::new(BrokerState::default()));

        let (stop, response) = broker_pair(BrokerRequest::Ping, Arc::clone(&state));
        assert!(!stop);
        assert!(matches!(response, BrokerResponse::Status { .. }));
        let (stop, response) = broker_pair(BrokerRequest::Stop, Arc::clone(&state));
        assert!(stop);
        assert!(matches!(response, BrokerResponse::Ok));

        let (_, response) = broker_pair(
            BrokerRequest::Unlock {
                project: "demo".to_string(),
                vault: vault_path.clone(),
                passphrase: "wrong".to_string(),
                ttl_seconds: 60,
                mode: None,
            },
            Arc::clone(&state),
        );
        assert!(matches!(
            response,
            BrokerResponse::Error {
                reason,
                ..
            } if reason == "unlock_failed"
        ));

        let (_, response) = broker_pair(
            BrokerRequest::Unlock {
                project: "demo".to_string(),
                vault: vault_path.clone(),
                passphrase: passphrase.to_string(),
                ttl_seconds: 60,
                mode: None,
            },
            Arc::clone(&state),
        );
        assert!(matches!(response, BrokerResponse::Ok));
        assert_eq!(
            status_from_state(&state.lock().unwrap()).sessions[0].project,
            "demo"
        );

        let (_, response) = broker_pair(
            BrokerRequest::Sign {
                project: "missing".to_string(),
                vault: vault_path.clone(),
                payload: approval_receipts::build_payload(
                    &AccessRequest {
                        project: "missing".to_string(),
                        agent: Some("codex".to_string()),
                        branch: Some("main".to_string()),
                        action: Some("Missing session".to_string()),
                        command: "sh -c true".to_string(),
                        env: vec!["DATABASE_URL".to_string()],
                    },
                    uuid::Uuid::new_v4(),
                    uuid::Uuid::new_v4(),
                    &["DATABASE_URL".to_string()],
                    ApprovalScope::Session,
                    None,
                    false,
                    Utc::now(),
                    String::new(),
                ),
            },
            Arc::clone(&state),
        );
        assert!(matches!(
            response,
            BrokerResponse::Error {
                reason,
                ..
            } if reason == "signing_key_unavailable"
        ));

        state.lock().unwrap().sessions.insert(
            session_key("expired", &vault_path),
            BrokerSession {
                project: "expired".to_string(),
                vault: vault_path.clone(),
                passphrase: passphrase.to_string(),
                session_key: None,
                expires_at: Utc::now() - Duration::seconds(1),
                active_mode: None,
            },
        );
        let (_, response) = broker_pair(
            BrokerRequest::Execute {
                project: "expired".to_string(),
                vault: vault_path.clone(),
                cwd: std::env::current_dir().unwrap(),
                env_names: vec!["DATABASE_URL".to_string()],
                command: vec!["sh".to_string(), "-c".to_string(), "true".to_string()],
                inherited_env: inherited_execution_env(),
                human_shell_pid: None,
                agent_proof: None,
            },
            Arc::clone(&state),
        );
        assert!(matches!(
            response,
            BrokerResponse::Error {
                reason,
                ..
            } if reason == "unlock_required"
        ));

        let access = AccessRequest {
            project: "demo".to_string(),
            agent: Some("codex".to_string()),
            branch: Some("main".to_string()),
            action: Some("Coverage sign".to_string()),
            command: "sh -c true".to_string(),
            env: vec!["DATABASE_URL".to_string()],
        };
        let payload = approval_receipts::build_payload(
            &access,
            uuid::Uuid::new_v4(),
            uuid::Uuid::new_v4(),
            &access.env,
            ApprovalScope::Session,
            Some(Utc::now() + Duration::hours(1)),
            false,
            Utc::now(),
            String::new(),
        );
        let (_, response) = broker_pair(
            BrokerRequest::Sign {
                project: "demo".to_string(),
                vault: vault_path.clone(),
                payload,
            },
            Arc::clone(&state),
        );
        assert!(matches!(response, BrokerResponse::Signed { .. }));

        let proof = agents::sign_payload("demo", "codex", "payload").unwrap();
        let mut bad_proof = proof.clone();
        bad_proof.payload = "tampered".to_string();
        let (_, response) = broker_pair(
            BrokerRequest::Execute {
                project: "demo".to_string(),
                vault: vault_path.clone(),
                cwd: std::env::current_dir().unwrap(),
                env_names: access.env.clone(),
                command: vec!["sh".to_string(), "-c".to_string(), "true".to_string()],
                inherited_env: inherited_execution_env(),
                human_shell_pid: None,
                agent_proof: Some(bad_proof),
            },
            Arc::clone(&state),
        );
        assert!(matches!(
            response,
            BrokerResponse::Error {
                reason,
                ..
            } if reason == "agent_proof_invalid"
        ));

        let (_, response) = broker_pair(
            BrokerRequest::Execute {
                project: "other".to_string(),
                vault: vault_path.clone(),
                cwd: std::env::current_dir().unwrap(),
                env_names: access.env.clone(),
                command: vec!["sh".to_string(), "-c".to_string(), "true".to_string()],
                inherited_env: inherited_execution_env(),
                human_shell_pid: None,
                agent_proof: None,
            },
            Arc::clone(&state),
        );
        assert!(matches!(
            response,
            BrokerResponse::Error {
                reason,
                ..
            } if reason == "unlock_required"
        ));

        let (_, response) = broker_pair(
            BrokerRequest::Execute {
                project: "demo".to_string(),
                vault: vault_path.clone(),
                cwd: std::env::current_dir().unwrap(),
                env_names: vec!["MISSING_ENV".to_string()],
                command: vec!["sh".to_string(), "-c".to_string(), "true".to_string()],
                inherited_env: inherited_execution_env(),
                human_shell_pid: None,
                agent_proof: None,
            },
            Arc::clone(&state),
        );
        assert!(matches!(
            response,
            BrokerResponse::Error {
                reason,
                ..
            } if reason == "vault_key_missing"
        ));

        let (mut client, server) = UnixStream::pair().unwrap();
        write_request(
            &mut client,
            &BrokerRequest::Execute {
                project: "demo".to_string(),
                vault: vault_path,
                cwd: std::env::current_dir().unwrap(),
                env_names: access.env,
                command: vec![
                    "sh".to_string(),
                    "-c".to_string(),
                    "printf '%s\\n' \"$DATABASE_URL\"".to_string(),
                ],
                inherited_env: inherited_execution_env(),
                human_shell_pid: None,
                agent_proof: Some(proof),
            },
        )
        .unwrap();
        assert!(!handle_client(server, state).unwrap());
        let mut reader = BufReader::new(client);
        let output = read_response(&mut reader).unwrap();
        assert!(matches!(output, BrokerResponse::Output { .. }));
        let finished = read_response(&mut reader).unwrap();
        assert!(matches!(finished, BrokerResponse::Finished { .. }));

        std::env::remove_var("WARD_HOME");
    }

    #[test]
    #[serial]
    fn broker_helpers_report_closed_and_invalid_messages() {
        let home = tempfile::tempdir().unwrap();
        std::env::set_var("WARD_HOME", home.path());
        let access = AccessRequest {
            project: "demo".to_string(),
            agent: Some("codex".to_string()),
            branch: Some("main".to_string()),
            action: Some("Unit broker stub".to_string()),
            command: "sh -c true".to_string(),
            env: vec!["DATABASE_URL".to_string()],
        };
        let payload = approval_receipts::build_payload(
            &access,
            uuid::Uuid::new_v4(),
            uuid::Uuid::new_v4(),
            &access.env,
            ApprovalScope::Session,
            None,
            false,
            Utc::now(),
            String::new(),
        );
        assert!(sign_receipt("demo", Path::new(".env.vault"), payload).is_err());

        fs_util::ensure_private_dir(&run_dir()).unwrap();
        fs_util::write_private_file(&pid_path(), b"bad-pid").unwrap();
        assert!(read_pid().is_err());
        cleanup_stale_files().unwrap();

        let (client, server) = UnixStream::pair().unwrap();
        drop(client);
        let mut reader = BufReader::new(server);
        assert!(read_response(&mut reader).is_err());

        let (mut client, server) = UnixStream::pair().unwrap();
        writeln!(client, "not json").unwrap();
        let mut reader = BufReader::new(server);
        assert!(read_request(&mut reader).is_err());
        std::env::remove_var("WARD_HOME");
    }
}
