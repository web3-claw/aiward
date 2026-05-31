use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Cursor,
    net::TcpStream,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tiny_http::{Header, Method, Response, Server, StatusCode};

use crate::{
    broker,
    config::{self, ProfileConfig},
    fs_util, human,
    logs::{self, LogKind},
    registry::{self, RegisteredProject},
};

const DEFAULT_PORT: u16 = 7777;
const PORT_SCAN_WIDTH: u16 = 20;
const DASHBOARD_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Clone)]
pub struct DashboardStartOptions {
    pub port: Option<u16>,
    pub open_browser: bool,
    pub foreground: bool,
    pub json: bool,
}

#[derive(Debug, Clone)]
pub struct DashboardStopOptions {
    pub all: bool,
    pub pid: Option<u32>,
    pub port: Option<u16>,
    pub json: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DashboardInstance {
    pub pid: u32,
    pub port: u16,
    pub url: String,
    pub token: String,
    pub started_project: Option<String>,
    pub started_path: PathBuf,
    pub started_at: String,
    pub version: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct DashboardStartResult {
    reused: bool,
    instance: DashboardInstance,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct DashboardStopResult {
    stopped: Vec<DashboardInstance>,
    stale_removed: usize,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct DashboardStatus {
    instances: Vec<DashboardInstance>,
    broker: broker::BrokerStatus,
    human: HumanRuntimeView,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct HumanRuntimeView {
    shell_pid: u32,
    shell_hooks_loaded: bool,
    guardian_socket_exists: bool,
    socket_path: PathBuf,
    stale_guardian_pids: Vec<u32>,
    stale_run_dirs: Vec<PathBuf>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ProjectView {
    name: String,
    path: PathBuf,
    vault: PathBuf,
    active: bool,
    config_status: String,
    profiles: Vec<ProfileView>,
    env_names: Vec<String>,
    vault_keys_verified: bool,
    broker_session_active: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ProfileView {
    name: String,
    command: String,
    env: Vec<String>,
    default_scope: crate::approvals::ApprovalScope,
    action: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct UpdateProfileEnvRequest {
    env: Vec<String>,
}

pub fn start_dashboard(options: DashboardStartOptions) -> Result<()> {
    cleanup_stale_instances()?;
    let requested_port = options.port;

    if !options.foreground {
        if let Some(existing) = running_instances()?
            .into_iter()
            .find(|instance| requested_port.is_none_or(|port| port == instance.port))
        {
            let result = DashboardStartResult {
                reused: true,
                instance: existing,
            };
            if options.open_browser {
                open_browser_best_effort(&result.instance.url);
            }
            print_start_result(&result, options.json)?;
            return Ok(());
        }
    }

    let port = requested_port.unwrap_or_else(|| find_available_port(DEFAULT_PORT));
    let token = generate_token();

    if options.foreground {
        let instance = current_instance(port, token.clone())?;
        write_instance(&instance)?;
        if options.open_browser {
            open_browser_best_effort(&instance.url);
        }
        print_start_result(
            &DashboardStartResult {
                reused: false,
                instance: instance.clone(),
            },
            options.json,
        )?;
        let result = serve_blocking(port, token);
        let _ = remove_instance(instance.pid);
        return result;
    }

    let exe = std::env::current_exe().context("cannot locate ward binary")?;
    let mut child = Command::new(exe)
        .arg("__dashboard-server")
        .arg("--port")
        .arg(port.to_string())
        .arg("--token")
        .arg(&token)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .context("failed to start Ward dashboard")?;

    let mut instance = current_instance(port, token)?;
    instance.pid = child.id();
    write_instance(&instance)?;

    let deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < deadline {
        if port_accepts_connections(port) {
            let result = DashboardStartResult {
                reused: false,
                instance,
            };
            if options.open_browser {
                open_browser_best_effort(&result.instance.url);
            }
            print_start_result(&result, options.json)?;
            return Ok(());
        }
        if child.try_wait()?.is_some() {
            let _ = remove_instance(instance.pid);
            anyhow::bail!("Ward dashboard exited before it became ready");
        }
        thread::sleep(Duration::from_millis(50));
    }

    let _ = remove_instance(instance.pid);
    anyhow::bail!("Ward dashboard did not become ready on port {port}");
}

pub fn serve_standalone(port: u16, token: String) -> Result<()> {
    let instance = current_instance(port, token.clone())?;
    write_instance(&instance)?;
    let result = serve_blocking(port, token);
    let _ = remove_instance(instance.pid);
    result
}

pub fn stop_dashboards(options: DashboardStopOptions) -> Result<()> {
    let stale_removed = cleanup_stale_instances()?;
    let mut targets = select_stop_targets(&options)?;
    targets.sort_by_key(|instance| instance.pid);
    targets.dedup_by_key(|instance| instance.pid);

    for instance in &targets {
        terminate_dashboard_process(instance.pid);
        let _ = remove_instance(instance.pid);
    }

    let result = DashboardStopResult {
        stopped: targets,
        stale_removed,
    };
    if options.json {
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else if result.stopped.is_empty() {
        println!("No standalone Ward dashboard instances were running.");
    } else {
        println!(
            "Stopped {} standalone Ward dashboard instance(s).",
            result.stopped.len()
        );
    }
    Ok(())
}

pub fn print_dashboard_status(json_output: bool) -> Result<()> {
    cleanup_stale_instances()?;
    let status = dashboard_status()?;
    if json_output {
        println!("{}", serde_json::to_string_pretty(&status)?);
        return Ok(());
    }

    if status.instances.is_empty() {
        println!("No standalone Ward dashboards are running.");
    } else {
        for instance in &status.instances {
            println!(
                "pid={} port={} project={} url={}",
                instance.pid,
                instance.port,
                instance.started_project.as_deref().unwrap_or("-"),
                instance.url
            );
        }
    }
    Ok(())
}

pub fn dashboard_diagnostics() -> Result<Vec<DashboardInstance>> {
    cleanup_stale_instances()?;
    running_instances()
}

fn serve_blocking(port: u16, token: String) -> Result<()> {
    let stop = Arc::new(AtomicBool::new(false));
    let stop_for_handler = Arc::clone(&stop);
    let _ = ctrlc::set_handler(move || {
        stop_for_handler.store(true, Ordering::SeqCst);
    });

    let server = Server::http(format!("127.0.0.1:{port}"))
        .map_err(|error| anyhow::anyhow!("failed to start dashboard server: {error}"))?;
    while !stop.load(Ordering::SeqCst) {
        match server.recv_timeout(Duration::from_millis(200)) {
            Ok(Some(req)) => handle(req, &token),
            Ok(None) => {}
            Err(_) => break,
        }
    }
    Ok(())
}

fn handle(mut req: tiny_http::Request, token: &str) {
    let method = req.method().clone();
    let url = req.url().to_string();
    let (path, query) = split_url(&url);

    if method == Method::Options {
        respond_empty(req, StatusCode(204));
        return;
    }

    if path.starts_with("/api/") && !authorized(&req, &query, token) {
        respond_json(
            req,
            StatusCode(403),
            &json!({ "error": "unauthorized", "message": "dashboard token required" }),
        );
        return;
    }

    match (method, path.as_str()) {
        (Method::Get, "/") => serve_html(req),
        (Method::Get, "/api/projects") => respond_json_result(req, dashboard_projects()),
        (Method::Get, "/api/events") => {
            let project = query_param(&query, "project");
            respond_json_result(req, Ok(load_all_events(project.as_deref())))
        }
        (Method::Get, "/api/dashboard/status") => respond_json_result(req, dashboard_status()),
        (Method::Patch, _) | (Method::Post, _) => {
            if let Some((project, profile)) = profile_env_route(&path) {
                let result = update_profile_env(&project, &profile, &mut req);
                respond_json_result(req, result);
            } else {
                respond_not_found(req);
            }
        }
        _ => respond_not_found(req),
    }
}

fn serve_html(req: tiny_http::Request) {
    let html = DASHBOARD_HTML.as_bytes();
    let response = Response::new(
        StatusCode(200),
        vec![
            Header::from_bytes("Content-Type", "text/html; charset=utf-8").unwrap(),
            Header::from_bytes("Cache-Control", "no-cache").unwrap(),
        ],
        Cursor::new(html),
        Some(html.len()),
        None,
    );
    let _ = req.respond(response);
}

fn respond_json_result<T: Serialize>(req: tiny_http::Request, result: Result<T>) {
    match result {
        Ok(value) => respond_json(req, StatusCode(200), &value),
        Err(error) => respond_json(
            req,
            StatusCode(500),
            &json!({ "error": "dashboard_error", "message": error.to_string() }),
        ),
    }
}

fn respond_json<T: Serialize>(req: tiny_http::Request, status: StatusCode, value: &T) {
    let body = serde_json::to_vec(value).unwrap_or_else(|_| b"{}".to_vec());
    let response = Response::new(
        status,
        vec![
            Header::from_bytes("Content-Type", "application/json").unwrap(),
            Header::from_bytes("Cache-Control", "no-cache").unwrap(),
        ],
        Cursor::new(body.clone()),
        Some(body.len()),
        None,
    );
    let _ = req.respond(response);
}

fn respond_empty(req: tiny_http::Request, status: StatusCode) {
    let _ = req.respond(Response::new(
        status,
        Vec::new(),
        Cursor::new(Vec::new()),
        Some(0),
        None,
    ));
}

fn respond_not_found(req: tiny_http::Request) {
    let _ = req.respond(Response::new(
        StatusCode(404),
        Vec::new(),
        Cursor::new(b"not found".to_vec()),
        Some(9),
        None,
    ));
}

fn split_url(url: &str) -> (String, String) {
    match url.split_once('?') {
        Some((path, query)) => (path.to_string(), query.to_string()),
        None => (url.to_string(), String::new()),
    }
}

fn authorized(req: &tiny_http::Request, query: &str, token: &str) -> bool {
    if token.is_empty() {
        return true;
    }
    if query_param(query, "token").as_deref() == Some(token) {
        return true;
    }
    req.headers().iter().any(|header| {
        let name = header
            .field
            .to_string()
            .eq_ignore_ascii_case("authorization");
        let value = header.value.as_str();
        (name && value == format!("Bearer {token}"))
            || (header
                .field
                .to_string()
                .eq_ignore_ascii_case("x-ward-dashboard-token")
                && value == token)
    })
}

fn query_param(query: &str, name: &str) -> Option<String> {
    query.split('&').find_map(|pair| {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        (key == name).then(|| value.to_string())
    })
}

fn profile_env_route(path: &str) -> Option<(String, String)> {
    let parts = path.trim_matches('/').split('/').collect::<Vec<_>>();
    match parts.as_slice() {
        ["api", "projects", project, "profiles", profile, "env"] => {
            Some((project.to_string(), profile.to_string()))
        }
        _ => None,
    }
}

fn update_profile_env(
    project: &str,
    profile: &str,
    req: &mut tiny_http::Request,
) -> Result<ProjectView> {
    let mut body = String::new();
    std::io::Read::read_to_string(req.as_reader(), &mut body)
        .context("failed to read request body")?;
    let requested: UpdateProfileEnvRequest =
        serde_json::from_str(&body).context("failed to parse profile env update")?;
    let env = normalize_env_names(requested.env)?;
    update_profile_env_for_project(project, profile, env)
}

fn update_profile_env_for_project(
    project: &str,
    profile: &str,
    env: Vec<String>,
) -> Result<ProjectView> {
    let env = normalize_env_names(env)?;
    let registry = registry::list_projects()?;
    let registered = registry
        .projects
        .get(project)
        .with_context(|| format!("project {project} is not registered"))?;
    let mut cfg = config::read_project_config(&registered.path)?;
    let profile_cfg = cfg
        .profiles
        .get_mut(profile)
        .with_context(|| format!("profile {profile} not found in project {project}"))?;
    profile_cfg.env = env;
    config::write_project_config(&registered.path, &cfg, true)?;

    project_view(
        project,
        registered,
        registry.active_project.as_deref(),
        broker::status().ok().as_ref(),
    )
}

fn normalize_env_names(names: Vec<String>) -> Result<Vec<String>> {
    let mut normalized = BTreeSet::new();
    for name in names {
        let trimmed = name.trim();
        if !is_valid_env_name(trimmed) {
            anyhow::bail!("invalid env name: {trimmed}");
        }
        normalized.insert(trimmed.to_string());
    }
    Ok(normalized.into_iter().collect())
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

fn dashboard_status() -> Result<DashboardStatus> {
    Ok(DashboardStatus {
        instances: running_instances()?,
        broker: broker::status()?,
        human: human_runtime_view(),
    })
}

fn dashboard_projects() -> Result<Vec<ProjectView>> {
    let registry = registry::list_projects()?;
    let broker_status = broker::status().ok();
    registry
        .projects
        .iter()
        .map(|(name, project)| {
            project_view(
                name,
                project,
                registry.active_project.as_deref(),
                broker_status.as_ref(),
            )
        })
        .collect()
}

fn project_view(
    name: &str,
    project: &RegisteredProject,
    active_project: Option<&str>,
    broker_status: Option<&broker::BrokerStatus>,
) -> Result<ProjectView> {
    let config_result = config::read_project_config(&project.path);
    let mut env_names = BTreeSet::new();
    let mut profiles = Vec::new();
    let config_status = match config_result {
        Ok(cfg) => {
            for (profile_name, profile) in cfg.profiles {
                collect_profile_env(&profile, &mut env_names);
                profiles.push(ProfileView {
                    name: profile_name,
                    command: profile.command,
                    env: profile.env,
                    default_scope: profile.default_scope,
                    action: profile.action,
                });
            }
            "ok".to_string()
        }
        Err(error) => format!("unavailable: {error}"),
    };

    let broker_session_active = broker_status
        .map(|status| {
            status
                .sessions
                .iter()
                .any(|session| session.project == name && same_path(&session.vault, &project.vault))
        })
        .unwrap_or(false);

    let mut vault_keys_verified = false;
    if broker_session_active {
        if let Ok(vault_keys) = broker::list_vault_keys(name, &project.vault) {
            vault_keys_verified = true;
            env_names.extend(vault_keys);
        }
    }

    profiles.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(ProjectView {
        name: name.to_string(),
        path: project.path.clone(),
        vault: project.vault.clone(),
        active: active_project == Some(name),
        config_status,
        profiles,
        env_names: env_names.into_iter().collect(),
        vault_keys_verified,
        broker_session_active,
    })
}

fn collect_profile_env(profile: &ProfileConfig, names: &mut BTreeSet<String>) {
    names.extend(profile.env.iter().cloned());
}

fn load_all_events(project_filter: Option<&str>) -> Vec<Value> {
    let registry = registry::list_projects().unwrap_or_default();
    let mut all = Vec::new();
    for &kind in LogKind::all() {
        if let Ok(events) = logs::decrypt_events(kind) {
            for mut event in events {
                scrub_sensitive_fields(&mut event);
                let project = infer_event_project(&event, &registry.projects);
                if let Some(filter) = project_filter {
                    if project.as_deref() != Some(filter) {
                        continue;
                    }
                }
                if let Some(obj) = event.as_object_mut() {
                    obj.insert(
                        "_kind".to_string(),
                        Value::String(kind.as_str().to_string()),
                    );
                    if let Some(project) = project {
                        obj.insert("_project".to_string(), Value::String(project));
                    }
                }
                all.push(event);
            }
        }
    }
    all.sort_by(|a, b| {
        let ta = a.get("timestamp").and_then(Value::as_str).unwrap_or("");
        let tb = b.get("timestamp").and_then(Value::as_str).unwrap_or("");
        tb.cmp(ta)
    });
    all
}

fn infer_event_project(
    event: &Value,
    projects: &BTreeMap<String, RegisteredProject>,
) -> Option<String> {
    let payload = event.get("payload").unwrap_or(event);
    for path in [
        vec!["project"],
        vec!["access", "project"],
        vec!["payload", "project"],
    ] {
        if let Some(project) = nested_str(payload, &path) {
            return Some(project.to_string());
        }
    }

    for path in [
        vec!["cwd"],
        vec!["worktree"],
        vec!["git", "worktreePath"],
        vec!["access", "worktree"],
    ] {
        if let Some(candidate) = nested_str(payload, &path) {
            if let Some(project) = project_for_path(candidate, projects) {
                return Some(project);
            }
        }
    }
    None
}

fn nested_str<'a>(value: &'a Value, path: &[&str]) -> Option<&'a str> {
    path.iter()
        .try_fold(value, |current, key| current.get(*key))
        .and_then(Value::as_str)
}

fn project_for_path(path: &str, projects: &BTreeMap<String, RegisteredProject>) -> Option<String> {
    let candidate = Path::new(path);
    projects.iter().find_map(|(name, project)| {
        if candidate.starts_with(&project.path) {
            Some(name.clone())
        } else {
            None
        }
    })
}

fn scrub_sensitive_fields(value: &mut Value) {
    match value {
        Value::Object(map) => {
            for (key, nested) in map.iter_mut() {
                if should_redact_key(key) {
                    *nested = Value::String("[redacted]".to_string());
                } else {
                    scrub_sensitive_fields(nested);
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                scrub_sensitive_fields(item);
            }
        }
        _ => {}
    }
}

fn should_redact_key(key: &str) -> bool {
    let lower = key.to_ascii_lowercase();
    lower.contains("passphrase")
        || lower.contains("sessiontoken")
        || lower == "token"
        || lower.contains("plaintext")
        || lower == "secret"
}

fn current_instance(port: u16, token: String) -> Result<DashboardInstance> {
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let started_project = registry::resolve_project(None, &cwd)
        .ok()
        .map(|project| project.name);
    let url = dashboard_url(port, &token);
    Ok(DashboardInstance {
        pid: std::process::id(),
        port,
        url,
        token,
        started_project,
        started_path: cwd,
        started_at: chrono::Utc::now().to_rfc3339(),
        version: DASHBOARD_VERSION.to_string(),
    })
}

fn print_start_result(result: &DashboardStartResult, json_output: bool) -> Result<()> {
    if json_output {
        println!("{}", serde_json::to_string_pretty(result)?);
    } else if result.reused {
        println!("Ward dashboard already running: {}", result.instance.url);
    } else {
        println!("Ward dashboard running: {}", result.instance.url);
    }
    Ok(())
}

fn select_stop_targets(options: &DashboardStopOptions) -> Result<Vec<DashboardInstance>> {
    let target_all = options.all || (options.pid.is_none() && options.port.is_none());
    let mut targets = running_instances()?
        .into_iter()
        .filter(|instance| {
            target_all || options.pid == Some(instance.pid) || options.port == Some(instance.port)
        })
        .collect::<Vec<_>>();

    if let Some(pid) = options.pid {
        if targets.is_empty() && is_dashboard_process(pid) {
            targets.push(transient_instance(pid));
        }
    }

    Ok(targets)
}

fn transient_instance(pid: u32) -> DashboardInstance {
    DashboardInstance {
        pid,
        port: 0,
        url: String::new(),
        token: String::new(),
        started_project: None,
        started_path: PathBuf::new(),
        started_at: String::new(),
        version: DASHBOARD_VERSION.to_string(),
    }
}

fn dashboard_url(port: u16, token: &str) -> String {
    format!("http://127.0.0.1:{port}/?token={token}")
}

fn generate_token() -> String {
    let mut bytes = [0u8; 24];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

fn find_available_port(start: u16) -> u16 {
    for port in start..start + PORT_SCAN_WIDTH {
        if std::net::TcpListener::bind(format!("127.0.0.1:{port}")).is_ok() {
            return port;
        }
    }
    start
}

fn port_accepts_connections(port: u16) -> bool {
    TcpStream::connect(("127.0.0.1", port)).is_ok()
}

fn metadata_dir() -> PathBuf {
    logs::ward_home().join("run").join("dashboard")
}

fn metadata_path(pid: u32) -> PathBuf {
    metadata_dir().join(format!("{pid}.json"))
}

fn write_instance(instance: &DashboardInstance) -> Result<()> {
    fs_util::ensure_private_dir(&metadata_dir())?;
    let body = serde_json::to_vec_pretty(instance)?;
    fs_util::write_private_file(&metadata_path(instance.pid), &body)
}

fn remove_instance(pid: u32) -> Result<()> {
    let path = metadata_path(pid);
    if path.exists() {
        fs::remove_file(path)?;
    }
    Ok(())
}

fn running_instances() -> Result<Vec<DashboardInstance>> {
    Ok(load_instances()?
        .into_iter()
        .filter(|instance| {
            human::process_exists(instance.pid) && is_dashboard_process(instance.pid)
        })
        .collect())
}

fn load_instances() -> Result<Vec<DashboardInstance>> {
    let dir = metadata_dir();
    let Ok(entries) = fs::read_dir(dir) else {
        return Ok(Vec::new());
    };
    let mut instances = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
            continue;
        }
        let Ok(contents) = fs::read_to_string(&path) else {
            continue;
        };
        if let Ok(instance) = serde_json::from_str::<DashboardInstance>(&contents) {
            instances.push(instance);
        }
    }
    instances.sort_by_key(|instance| instance.pid);
    Ok(instances)
}

fn cleanup_stale_instances() -> Result<usize> {
    let mut removed = 0;
    for instance in load_instances()? {
        if !human::process_exists(instance.pid) || !is_dashboard_process(instance.pid) {
            let _ = remove_instance(instance.pid);
            removed += 1;
        }
    }
    Ok(removed)
}

fn human_runtime_view() -> HumanRuntimeView {
    let diagnostics = human::runtime_diagnostics();
    HumanRuntimeView {
        shell_pid: diagnostics.shell_pid,
        shell_hooks_loaded: diagnostics.shell_hooks_loaded,
        guardian_socket_exists: diagnostics.guardian_socket_exists,
        socket_path: diagnostics.socket_path,
        stale_guardian_pids: diagnostics.stale_guardian_pids,
        stale_run_dirs: diagnostics.stale_run_dirs,
    }
}

fn same_path(left: &Path, right: &Path) -> bool {
    if left == right {
        return true;
    }
    match (left.canonicalize(), right.canonicalize()) {
        (Ok(left), Ok(right)) => left == right,
        _ => false,
    }
}

fn open_browser_best_effort(url: &str) {
    #[cfg(target_os = "macos")]
    let command = ("open", vec![url]);
    #[cfg(target_os = "linux")]
    let command = ("xdg-open", vec![url]);
    #[cfg(target_os = "windows")]
    let command = ("cmd", vec!["/C", "start", "", url]);

    #[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
    {
        let _ = Command::new(command.0)
            .args(command.1)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn();
    }
}

fn terminate_dashboard_process(pid: u32) {
    #[cfg(unix)]
    {
        if !is_dashboard_process(pid) {
            return;
        }
        // SAFETY: target pid is selected by dashboard command-line inspection.
        let _ = unsafe { libc::kill(pid as libc::pid_t, libc::SIGTERM) };
        let deadline = Instant::now() + Duration::from_secs(1);
        while Instant::now() < deadline {
            if !human::process_exists(pid) {
                return;
            }
            thread::sleep(Duration::from_millis(50));
        }
        // SAFETY: best-effort stop for the same dashboard process if SIGTERM was ignored.
        let _ = unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) };
    }
    #[cfg(not(unix))]
    {
        let _ = pid;
    }
}

fn is_dashboard_process(pid: u32) -> bool {
    command_line(pid)
        .map(|line| {
            line.contains("__dashboard-server")
                || (line.contains("dashboard")
                    && line.contains("--foreground")
                    && line.contains("ward"))
        })
        .unwrap_or(false)
}

fn command_line(pid: u32) -> Option<String> {
    #[cfg(unix)]
    {
        let output = Command::new("ps")
            .args(["-p", &pid.to_string(), "-o", "command="])
            .output()
            .ok()?;
        if !output.status.success() {
            return None;
        }
        Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
    }
    #[cfg(not(unix))]
    {
        let _ = pid;
        None
    }
}

const DASHBOARD_HTML: &str = r##"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Ward Dashboard</title>
<style>
  * { box-sizing: border-box; }
  :root {
    --bg: #0f1115;
    --panel: #171a20;
    --panel-2: #1d222a;
    --line: #2b323c;
    --text: #e7ecf2;
    --muted: #91a0ae;
    --faint: #64717f;
    --accent: #34d399;
    --blue: #60a5fa;
    --warn: #f59e0b;
    --danger: #fb7185;
    --radius: 8px;
    --font: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    --mono: "SF Mono", "Cascadia Code", "Roboto Mono", monospace;
  }
  body {
    margin: 0;
    min-height: 100vh;
    background: var(--bg);
    color: var(--text);
    font: 13px/1.4 var(--font);
    overflow: hidden;
  }
  button, input { font: inherit; }
  .shell { display: grid; grid-template-columns: 260px 1fr; height: 100vh; }
  aside {
    border-right: 1px solid var(--line);
    background: #12151a;
    display: flex;
    flex-direction: column;
    min-width: 0;
  }
  .brand {
    height: 52px;
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 0 16px;
    border-bottom: 1px solid var(--line);
    font-weight: 700;
    letter-spacing: 0;
  }
  .status-dot { width: 8px; height: 8px; border-radius: 50%; background: var(--accent); }
  .project-list { overflow: auto; padding: 8px; }
  .project {
    width: 100%;
    text-align: left;
    border: 1px solid transparent;
    background: transparent;
    color: var(--text);
    padding: 9px 10px;
    border-radius: var(--radius);
    cursor: pointer;
  }
  .project:hover { background: var(--panel); }
  .project.active { background: var(--panel-2); border-color: var(--line); }
  .project-name { font-weight: 650; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .project-path { color: var(--faint); font: 11px var(--mono); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; margin-top: 2px; }
  main { display: grid; grid-template-rows: 52px 1fr; min-width: 0; }
  header {
    display: flex;
    align-items: center;
    gap: 16px;
    padding: 0 18px;
    border-bottom: 1px solid var(--line);
    background: var(--panel);
  }
  .title { font-weight: 700; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .header-meta { margin-left: auto; color: var(--muted); font-size: 12px; display: flex; align-items: center; gap: 12px; }
  .btn {
    border: 1px solid var(--line);
    border-radius: 6px;
    background: #20252d;
    color: var(--text);
    padding: 5px 10px;
    cursor: pointer;
  }
  .btn:hover { border-color: var(--muted); }
  .content {
    display: grid;
    grid-template-columns: minmax(460px, 1fr) minmax(360px, 0.8fr);
    gap: 0;
    min-height: 0;
  }
  .left, .right { overflow: auto; padding: 16px 18px; }
  .right { border-left: 1px solid var(--line); background: #111419; }
  section { margin-bottom: 18px; }
  .section-head { display: flex; align-items: center; justify-content: space-between; margin-bottom: 8px; }
  h2 { margin: 0; font-size: 12px; color: var(--muted); text-transform: uppercase; letter-spacing: .08em; }
  .subtle { color: var(--faint); font-size: 12px; }
  .panel {
    border: 1px solid var(--line);
    border-radius: var(--radius);
    background: var(--panel);
    overflow: hidden;
  }
  .kv { display: grid; grid-template-columns: 140px 1fr; border-bottom: 1px solid var(--line); }
  .kv:last-child { border-bottom: 0; }
  .kv div { padding: 8px 10px; min-width: 0; }
  .kv div:first-child { color: var(--muted); }
  .mono { font-family: var(--mono); font-size: 12px; overflow-wrap: anywhere; }
  table { width: 100%; border-collapse: collapse; }
  th, td { text-align: left; padding: 8px 10px; border-bottom: 1px solid var(--line); vertical-align: top; }
  th { color: var(--muted); font-size: 11px; text-transform: uppercase; letter-spacing: .06em; background: #15191f; position: sticky; top: 0; }
  tr:last-child td { border-bottom: 0; }
  .check { display: flex; align-items: center; gap: 6px; margin: 2px 0; color: var(--text); font-family: var(--mono); font-size: 12px; }
  .env-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(160px, 1fr)); gap: 3px 10px; }
  .input-row { display: flex; gap: 8px; padding: 10px; border-top: 1px solid var(--line); }
  .input-row input { flex: 1; min-width: 0; background: #101318; color: var(--text); border: 1px solid var(--line); border-radius: 6px; padding: 6px 8px; }
  .pill { display: inline-flex; align-items: center; min-height: 22px; padding: 2px 8px; border: 1px solid var(--line); border-radius: 999px; color: var(--muted); font-size: 12px; }
  .pill.ok { color: var(--accent); border-color: rgba(52,211,153,.35); }
  .pill.warn { color: var(--warn); border-color: rgba(245,158,11,.35); }
  .events { max-height: 460px; overflow: auto; }
  .event-row { cursor: pointer; }
  .event-row:hover { background: #1b2027; }
  .kind { color: var(--blue); font-family: var(--mono); font-size: 11px; }
  pre { margin: 0; white-space: pre-wrap; word-break: break-word; font: 11px/1.45 var(--mono); color: var(--muted); }
  @media (max-width: 900px) {
    body { overflow: auto; }
    .shell, main, .content { display: block; height: auto; }
    aside { border-right: 0; border-bottom: 1px solid var(--line); }
    .project-list { display: flex; overflow-x: auto; }
    .project { min-width: 220px; }
    .right { border-left: 0; border-top: 1px solid var(--line); }
  }
</style>
</head>
<body>
<div class="shell">
  <aside>
    <div class="brand"><span class="status-dot"></span><span>Ward Dashboard</span></div>
    <div class="project-list" id="projects"></div>
  </aside>
  <main>
    <header>
      <div class="title" id="title">Projects</div>
      <div class="header-meta">
        <span id="lastRefresh"></span>
        <button class="btn" id="refresh">Refresh</button>
      </div>
    </header>
    <div class="content">
      <div class="left">
        <section>
          <div class="section-head"><h2>Project</h2><span class="pill" id="configState">-</span></div>
          <div class="panel" id="projectMeta"></div>
        </section>
        <section>
          <div class="section-head"><h2>Profile Env Policy</h2><span class="subtle" id="vaultState"></span></div>
          <div class="panel" id="profiles"></div>
        </section>
      </div>
      <div class="right">
        <section>
          <div class="section-head"><h2>Runtime</h2><span class="pill" id="brokerState">-</span></div>
          <div class="panel" id="runtime"></div>
        </section>
        <section>
          <div class="section-head"><h2>Logs</h2><span class="subtle" id="eventCount"></span></div>
          <div class="panel events"><table><thead><tr><th>Time</th><th>Kind</th><th>Event</th></tr></thead><tbody id="events"></tbody></table></div>
        </section>
        <section>
          <div class="section-head"><h2>Event Detail</h2></div>
          <div class="panel" style="padding:10px"><pre id="eventDetail">Select an event</pre></div>
        </section>
      </div>
    </div>
  </main>
</div>
<script>
const token = new URLSearchParams(location.search).get('token') || '';
let projects = [];
let status = null;
let events = [];
let selectedProject = null;

function withToken(path) {
  const sep = path.includes('?') ? '&' : '?';
  return `${path}${sep}token=${encodeURIComponent(token)}`;
}

async function api(path, options = {}) {
  const response = await fetch(withToken(path), {
    ...options,
    headers: { 'Content-Type': 'application/json', ...(options.headers || {}) }
  });
  if (!response.ok) throw new Error(await response.text());
  return response.json();
}

async function load() {
  [projects, status] = await Promise.all([
    api('/api/projects'),
    api('/api/dashboard/status')
  ]);
  if (!selectedProject && projects.length) {
    selectedProject = (projects.find(p => p.active) || projects[0]).name;
  }
  await loadEvents();
  render();
}

async function loadEvents() {
  const suffix = selectedProject ? `?project=${encodeURIComponent(selectedProject)}` : '';
  events = await api(`/api/events${suffix}`);
}

function render() {
  renderProjects();
  renderProject();
  renderRuntime();
  renderEvents();
  document.getElementById('lastRefresh').textContent = new Date().toLocaleTimeString();
}

function currentProject() {
  return projects.find(p => p.name === selectedProject) || projects[0] || null;
}

function renderProjects() {
  const host = document.getElementById('projects');
  host.innerHTML = '';
  projects.forEach(project => {
    const btn = document.createElement('button');
    btn.className = `project ${project.name === selectedProject ? 'active' : ''}`;
    btn.innerHTML = `<div class="project-name">${esc(project.name)}</div><div class="project-path">${esc(project.path)}</div>`;
    btn.addEventListener('click', async () => {
      selectedProject = project.name;
      await loadEvents();
      render();
    });
    host.appendChild(btn);
  });
}

function renderProject() {
  const project = currentProject();
  document.getElementById('title').textContent = project ? project.name : 'Projects';
  if (!project) {
    document.getElementById('projectMeta').innerHTML = '<div class="kv"><div>Status</div><div>No projects registered</div></div>';
    document.getElementById('profiles').innerHTML = '';
    return;
  }
  document.getElementById('configState').textContent = project.configStatus;
  document.getElementById('configState').className = `pill ${project.configStatus === 'ok' ? 'ok' : 'warn'}`;
  document.getElementById('vaultState').textContent = project.vaultKeysVerified ? 'vault keys verified' : 'vault keys unavailable';
  document.getElementById('projectMeta').innerHTML = [
    kv('path', project.path),
    kv('vault', project.vault),
    kv('broker session', project.brokerSessionActive ? 'active' : 'inactive'),
    kv('env names', String(project.envNames.length))
  ].join('');
  renderProfiles(project);
}

function renderProfiles(project) {
  const host = document.getElementById('profiles');
  if (!project.profiles.length) {
    host.innerHTML = '<div class="kv"><div>Profiles</div><div>None</div></div>';
    return;
  }
  host.innerHTML = project.profiles.map(profile => `
    <div style="border-bottom:1px solid var(--line)">
      <div class="kv"><div>${esc(profile.name)}</div><div class="mono">${esc(profile.command)}</div></div>
      <div style="padding:10px">
        <div class="env-grid">
          ${project.envNames.map(name => checkbox(project.name, profile.name, name, profile.env.includes(name))).join('')}
        </div>
      </div>
      <div class="input-row">
        <input data-add-env="${esc(project.name)}:${esc(profile.name)}" placeholder="ENV_NAME">
        <button class="btn" data-add-btn="${esc(project.name)}:${esc(profile.name)}">Add</button>
      </div>
    </div>
  `).join('');
  host.querySelectorAll('input[type="checkbox"]').forEach(input => {
    input.addEventListener('change', () => toggleEnv(project.name, input.dataset.profile, input.dataset.env, input.checked));
  });
  host.querySelectorAll('[data-add-btn]').forEach(btn => {
    btn.addEventListener('click', () => {
      const [projectName, profileName] = btn.dataset.addBtn.split(':');
      const input = host.querySelector(`[data-add-env="${cssEsc(projectName)}:${cssEsc(profileName)}"]`);
      addEnv(projectName, profileName, input.value);
      input.value = '';
    });
  });
}

function checkbox(project, profile, env, checked) {
  return `<label class="check"><input type="checkbox" data-project="${esc(project)}" data-profile="${esc(profile)}" data-env="${esc(env)}" ${checked ? 'checked' : ''}>${esc(env)}</label>`;
}

async function toggleEnv(projectName, profileName, envName, enabled) {
  const project = projects.find(p => p.name === projectName);
  const profile = project.profiles.find(p => p.name === profileName);
  const env = new Set(profile.env);
  enabled ? env.add(envName) : env.delete(envName);
  await saveProfileEnv(projectName, profileName, [...env]);
}

async function addEnv(projectName, profileName, envName) {
  envName = envName.trim();
  if (!envName) return;
  const project = projects.find(p => p.name === projectName);
  const profile = project.profiles.find(p => p.name === profileName);
  const env = new Set([...profile.env, envName]);
  await saveProfileEnv(projectName, profileName, [...env]);
}

async function saveProfileEnv(projectName, profileName, env) {
  const updated = await api(`/api/projects/${encodeURIComponent(projectName)}/profiles/${encodeURIComponent(profileName)}/env`, {
    method: 'PATCH',
    body: JSON.stringify({ env })
  });
  projects = projects.map(project => project.name === projectName ? updated : project);
  renderProject();
}

function renderRuntime() {
  const broker = status && status.broker;
  document.getElementById('brokerState').textContent = broker && broker.running ? 'broker active' : 'broker inactive';
  document.getElementById('brokerState').className = `pill ${broker && broker.running ? 'ok' : 'warn'}`;
  const rows = [];
  rows.push(kv('dashboards', String((status && status.instances || []).length)));
  rows.push(kv('guardian', status && status.human.guardianSocketExists ? 'active' : 'inactive'));
  rows.push(kv('shell pid', status ? String(status.human.shellPid) : '-'));
  rows.push(kv('sessions', broker ? String(broker.sessions.length) : '0'));
  document.getElementById('runtime').innerHTML = rows.join('');
}

function renderEvents() {
  document.getElementById('eventCount').textContent = `${events.length} events`;
  const body = document.getElementById('events');
  body.innerHTML = events.slice(0, 250).map((event, index) => {
    const payload = event.payload || event;
    const label = payload.eventType || payload.requestedCommand || payload.declaredAction || payload.status || '-';
    return `<tr class="event-row" data-event-index="${index}">
      <td class="mono">${esc((event.timestamp || '').slice(11, 19))}</td>
      <td class="kind">${esc(event._kind || '-')}</td>
      <td>${esc(String(label))}</td>
    </tr>`;
  }).join('');
  body.querySelectorAll('.event-row').forEach(row => {
    row.addEventListener('click', () => {
      const event = events[Number(row.dataset.eventIndex)];
      document.getElementById('eventDetail').textContent = JSON.stringify(event, null, 2);
    });
  });
}

function kv(label, value) {
  return `<div class="kv"><div>${esc(label)}</div><div class="mono">${esc(value)}</div></div>`;
}

function esc(value) {
  return String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}

function cssEsc(value) {
  return String(value).replace(/["\\]/g, '\\$&');
}

document.getElementById('refresh').addEventListener('click', load);
load().catch(error => {
  document.getElementById('title').textContent = 'Dashboard error';
  document.getElementById('projectMeta').innerHTML = `<div class="kv"><div>Error</div><div>${esc(error.message)}</div></div>`;
});
</script>
</body>
</html>"##;

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    struct WardHomeGuard {
        previous: Option<std::ffi::OsString>,
    }

    impl WardHomeGuard {
        fn set(path: &Path) -> Self {
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
    fn env_names_are_normalized_and_validated() {
        let names = normalize_env_names(vec![
            "PAYLOAD_SECRET".to_string(),
            "DATABASE_URL".to_string(),
            "PAYLOAD_SECRET".to_string(),
        ])
        .unwrap();
        assert_eq!(names, vec!["DATABASE_URL", "PAYLOAD_SECRET"]);
        assert!(normalize_env_names(vec!["bad-name".to_string()]).is_err());
        assert!(normalize_env_names(vec!["1BAD".to_string()]).is_err());
    }

    #[test]
    fn sensitive_event_fields_are_scrubbed_without_redacting_env_names() {
        let mut event = json!({
            "payload": {
                "sessionToken": "token",
                "requestedEnv": ["PAYLOAD_SECRET"],
                "nested": { "passphrase": "secret" }
            }
        });
        scrub_sensitive_fields(&mut event);
        assert_eq!(event["payload"]["sessionToken"], "[redacted]");
        assert_eq!(event["payload"]["nested"]["passphrase"], "[redacted]");
        assert_eq!(event["payload"]["requestedEnv"][0], "PAYLOAD_SECRET");
    }

    #[test]
    fn profile_env_route_matches_expected_api_shape() {
        assert_eq!(
            profile_env_route("/api/projects/demo/profiles/dev/env"),
            Some(("demo".to_string(), "dev".to_string()))
        );
        assert!(profile_env_route("/api/projects/demo").is_none());
    }

    #[test]
    fn dashboard_url_carries_local_token() {
        assert_eq!(
            dashboard_url(7777, "abc"),
            "http://127.0.0.1:7777/?token=abc"
        );
    }

    #[test]
    #[serial]
    fn project_api_reads_and_updates_profile_env_policy_without_values() {
        let home = tempfile::tempdir().unwrap();
        let _guard = WardHomeGuard::set(home.path());
        let project = tempfile::tempdir().unwrap();
        let mut cfg =
            config::ProjectConfig::default_for_dir(project.path(), Some("demo".to_string()))
                .unwrap();
        for profile in cfg.profiles.values_mut() {
            profile.env.clear();
        }
        cfg.profiles.get_mut("dev").unwrap().env = vec!["DATABASE_URL".to_string()];
        config::write_project_config(project.path(), &cfg, true).unwrap();
        registry::register_project(
            "demo".to_string(),
            project.path().to_path_buf(),
            project.path().join(".env.vault"),
        )
        .unwrap();

        let projects = dashboard_projects().unwrap();
        assert_eq!(projects.len(), 1);
        assert_eq!(projects[0].env_names, vec!["DATABASE_URL"]);
        assert!(!projects[0].vault_keys_verified);

        let updated = update_profile_env_for_project(
            "demo",
            "dev",
            vec!["PAYLOAD_SECRET".to_string(), "DATABASE_URL".to_string()],
        )
        .unwrap();
        let dev = updated
            .profiles
            .iter()
            .find(|profile| profile.name == "dev")
            .unwrap();
        assert_eq!(dev.env, vec!["DATABASE_URL", "PAYLOAD_SECRET"]);

        let serialized = serde_json::to_string(&updated).unwrap();
        assert!(serialized.contains("PAYLOAD_SECRET"));
        assert!(!serialized.contains("payload-secret-value"));
    }

    #[test]
    #[serial]
    fn cleanup_stale_instances_removes_dead_metadata() {
        let home = tempfile::tempdir().unwrap();
        let _guard = WardHomeGuard::set(home.path());
        let instance = DashboardInstance {
            pid: 999_999,
            port: 7777,
            url: dashboard_url(7777, "token"),
            token: "token".to_string(),
            started_project: Some("demo".to_string()),
            started_path: PathBuf::from("/tmp/demo"),
            started_at: chrono::Utc::now().to_rfc3339(),
            version: DASHBOARD_VERSION.to_string(),
        };
        write_instance(&instance).unwrap();
        assert!(metadata_path(instance.pid).exists());
        assert_eq!(cleanup_stale_instances().unwrap(), 1);
        assert!(!metadata_path(instance.pid).exists());
    }
}
