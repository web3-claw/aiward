pub mod display;

use std::{
    io::{BufRead, BufReader, Write},
    os::unix::net::{UnixListener, UnixStream},
    path::PathBuf,
    thread,
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use base64::Engine as _;
use crate::{broker, fs_util, logs};

// ── Path helpers ─────────────────────────────────────────────────────────────

pub fn human_run_dir(shell_pid: u32) -> PathBuf {
    logs::ward_home().join("run").join(format!("human-{shell_pid}"))
}

pub fn guardian_socket_path(shell_pid: u32) -> PathBuf {
    human_run_dir(shell_pid).join("guardian.sock")
}

fn ready_marker_path(shell_pid: u32) -> PathBuf {
    human_run_dir(shell_pid).join("ready")
}

// ── Terminal identity ─────────────────────────────────────────────────────────

pub fn parent_pid() -> u32 {
    #[cfg(unix)]
    {
        // SAFETY: getppid() is always safe; reads a process attribute only.
        unsafe { libc::getppid() as u32 }
    }
    #[cfg(not(unix))]
    {
        0
    }
}

pub fn is_human_terminal() -> bool {
    guardian_socket_path(parent_pid()).exists()
}

// ── Guardian protocol ─────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum GuardianRequest {
    Shutdown,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum GuardianResponse {
    Ok,
    Error { reason: String, message: String },
}

fn write_guardian_response(stream: &mut UnixStream, resp: &GuardianResponse) -> Result<()> {
    let mut line = serde_json::to_string(resp)?;
    line.push('\n');
    stream.write_all(line.as_bytes())?;
    Ok(())
}

// ── Guardian subprocess ───────────────────────────────────────────────────────

pub fn serve_guardian(shell_pid: u32, session_token: &str, ttl_seconds: i64) -> Result<()> {
    let dir = human_run_dir(shell_pid);
    let socket_path = guardian_socket_path(shell_pid);
    let ready_path = ready_marker_path(shell_pid);

    // Clean up any stale socket from a previous crashed guardian.
    if socket_path.exists() {
        let _ = std::fs::remove_file(&socket_path);
    }

    fs_util::ensure_private_dir(&dir)?;
    let listener = UnixListener::bind(&socket_path)
        .with_context(|| format!("failed to bind guardian socket at {}", socket_path.display()))?;
    listener.set_nonblocking(true)?;

    broker::ensure_running()?;
    broker::register_human_session(shell_pid, session_token, ttl_seconds)?;

    fs_util::write_private_file(&ready_path, b"")?;

    let deadline = Instant::now() + Duration::from_secs(ttl_seconds.max(0) as u64);

    'accept: loop {
        if Instant::now() >= deadline {
            break;
        }
        match listener.accept() {
            Ok((mut stream, _)) => {
                let mut reader = BufReader::new(stream.try_clone()?);
                let mut line = String::new();
                if reader.read_line(&mut line).is_ok() {
                    match serde_json::from_str::<GuardianRequest>(line.trim()) {
                        Ok(GuardianRequest::Shutdown) => {
                            let _ = write_guardian_response(&mut stream, &GuardianResponse::Ok);
                            break 'accept;
                        }
                        Err(_) => {
                            let _ = write_guardian_response(
                                &mut stream,
                                &GuardianResponse::Error {
                                    reason: "unknown_request".into(),
                                    message: "unrecognised guardian request".into(),
                                },
                            );
                        }
                    }
                }
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(100));
            }
            Err(_) => break,
        }
    }

    // Cleanup
    let _ = broker::deregister_human_session(shell_pid, session_token);
    let _ = std::fs::remove_file(&socket_path);
    let _ = std::fs::remove_file(&ready_path);
    let _ = std::fs::remove_dir(&dir);

    Ok(())
}

// ── Shutdown from lock() ──────────────────────────────────────────────────────

pub fn send_guardian_shutdown() -> Result<()> {
    let socket_path = guardian_socket_path(parent_pid());
    if !socket_path.exists() {
        return Ok(());
    }
    let mut stream = UnixStream::connect(&socket_path)
        .context("failed to connect to human guardian socket")?;
    let mut msg = serde_json::to_string(&GuardianRequest::Shutdown)?;
    msg.push('\n');
    stream.write_all(msg.as_bytes())?;
    // Best-effort read response; ignore errors.
    let mut reader = BufReader::new(stream);
    let mut _line = String::new();
    let _ = reader.read_line(&mut _line);
    Ok(())
}

// ── Activation (ward human command handler) ───────────────────────────────────

pub fn activate_human_mode(ttl: &str) -> Result<()> {
    use crate::{logs::LogKind, registry, unlock, vault};

    let cwd = std::env::current_dir()?;
    let resolved = registry::resolve_project(None, &cwd)?;

    let passphrase = vault::read_existing_passphrase()?;
    vault::decrypt_vault_file(&resolved.vault, &passphrase)
        .context("incorrect passphrase — human mode not activated")?;

    let duration = unlock::parse_ttl(ttl)?;
    let ttl_seconds = duration.num_seconds();

    // Unlock vault in broker so ward run/dev/migrate work from this terminal.
    crate::cli::create_run_unlock_session(&resolved.name, &resolved.vault, &passphrase, ttl, None)?;

    // Generate a random session token.
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    let session_token = base64::engine::general_purpose::STANDARD.encode(bytes);

    let shell_pid = parent_pid();

    // Clean up any stale previous session for this terminal.
    let stale_socket = guardian_socket_path(shell_pid);
    if stale_socket.exists() {
        let _ = std::fs::remove_file(&stale_socket);
        let _ = std::fs::remove_dir(human_run_dir(shell_pid));
    }

    // Spawn guardian subprocess.
    let exe = std::env::current_exe().context("cannot locate ward binary")?;
    std::process::Command::new(&exe)
        .arg("__human-guardian")
        .arg("--shell-pid")
        .arg(shell_pid.to_string())
        .arg("--session-token")
        .arg(&session_token)
        .arg("--ttl-seconds")
        .arg(ttl_seconds.to_string())
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .context("failed to spawn human guardian")?;

    // Wait up to 2 seconds for ready-marker.
    let ready = ready_marker_path(shell_pid);
    let deadline = Instant::now() + Duration::from_secs(2);
    while !ready.exists() {
        if Instant::now() >= deadline {
            anyhow::bail!("human guardian did not become ready in time");
        }
        thread::sleep(Duration::from_millis(25));
    }

    display::print_padlock_opening();

    let expires_at = (chrono::Utc::now() + duration).to_rfc3339();
    let ttl_label = format_ttl_label(ttl_seconds);
    println!("{}", display::format_session_prefix(&resolved.name, &ttl_label));

    #[derive(serde::Serialize)]
    struct HumanModeEvent {
        event_type: &'static str,
        shell_pid: u32,
        expires_at: String,
    }
    crate::logs::append_event(
        LogKind::Sessions,
        HumanModeEvent {
            event_type: "human_mode.activated",
            shell_pid,
            expires_at,
        },
    )?;

    Ok(())
}

fn format_ttl_label(ttl_seconds: i64) -> String {
    let h = ttl_seconds / 3600;
    let m = (ttl_seconds % 3600) / 60;
    if m == 0 {
        format!("{h}h")
    } else if h == 0 {
        format!("{m}m")
    } else {
        format!("{h}h {m}m")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_helpers_use_shell_pid() {
        let dir = human_run_dir(4821);
        assert!(dir.to_string_lossy().contains("human-4821"));
        let sock = guardian_socket_path(4821);
        assert!(sock.to_string_lossy().ends_with("human-4821/guardian.sock"));
    }

    #[test]
    fn is_human_terminal_false_when_no_socket() {
        // With a random PID that certainly has no socket file.
        assert!(!guardian_socket_path(9999999).exists());
    }

    #[test]
    fn ttl_label_formatting() {
        assert_eq!(format_ttl_label(28800), "8h");
        assert_eq!(format_ttl_label(3600), "1h");
        assert_eq!(format_ttl_label(5400), "1h 30m");
        assert_eq!(format_ttl_label(1800), "30m");
    }
}
