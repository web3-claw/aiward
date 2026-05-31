use std::{
    io::Cursor,
    sync::{Arc, Mutex},
    thread,
    time::Duration,
};

use anyhow::Result;
use tiny_http::{Header, Response, Server, StatusCode};

use crate::logs::{self, LogKind};

const DEFAULT_PORT: u16 = 7777;
const ALL_KINDS: [LogKind; 5] = [
    LogKind::Executions,
    LogKind::Requests,
    LogKind::Approvals,
    LogKind::Alerts,
    LogKind::Sessions,
];

pub struct WebUiHandle {
    pub port: u16,
}

pub fn start(stop: Arc<Mutex<bool>>) -> Result<WebUiHandle> {
    let port = find_port(DEFAULT_PORT);
    let server = Server::http(format!("127.0.0.1:{port}"))
        .map_err(|e| anyhow::anyhow!("failed to start web UI server: {e}"))?;
    let server = Arc::new(server);

    let server_clone = Arc::clone(&server);
    let stop_clone = Arc::clone(&stop);
    thread::spawn(move || {
        run_server(server_clone, stop_clone);
    });

    Ok(WebUiHandle { port })
}

fn find_port(start: u16) -> u16 {
    for port in start..start + 20 {
        if std::net::TcpListener::bind(format!("127.0.0.1:{port}")).is_ok() {
            return port;
        }
    }
    start
}

fn run_server(server: Arc<Server>, stop: Arc<Mutex<bool>>) {
    loop {
        if *stop.lock().unwrap() {
            break;
        }
        match server.recv_timeout(Duration::from_millis(200)) {
            Ok(Some(req)) => handle(req),
            Ok(None) => {}
            Err(_) => break,
        }
    }
}

fn handle(req: tiny_http::Request) {
    let path = req.url().split('?').next().unwrap_or("/").to_string();
    match path.as_str() {
        "/" => serve_html(req),
        "/api/events" => serve_events(req),
        "/api/stream" => serve_sse(req),
        _ => {
            let _ = req.respond(Response::new(
                StatusCode(404),
                vec![],
                Cursor::new(b"not found" as &[u8]),
                Some(9),
                None,
            ));
        }
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

fn serve_events(req: tiny_http::Request) {
    let events = load_all_events();
    let body = serde_json::to_vec(&events).unwrap_or_else(|_| b"[]".to_vec());
    let response = Response::new(
        StatusCode(200),
        vec![
            Header::from_bytes("Content-Type", "application/json").unwrap(),
            Header::from_bytes("Access-Control-Allow-Origin", "*").unwrap(),
        ],
        Cursor::new(body.clone()),
        Some(body.len()),
        None,
    );
    let _ = req.respond(response);
}

fn serve_sse(req: tiny_http::Request) {
    // Upgrade to a streaming response for Server-Sent Events.
    // tiny_http doesn't natively support streaming, so we write the full
    // current snapshot and let the client poll every few seconds instead.
    let events = load_all_events();
    let data = serde_json::to_string(&events).unwrap_or_else(|_| "[]".to_string());
    let body = format!("data: {}\n\n", data);
    let bytes = body.into_bytes();
    let response = Response::new(
        StatusCode(200),
        vec![
            Header::from_bytes("Content-Type", "text/event-stream").unwrap(),
            Header::from_bytes("Cache-Control", "no-cache").unwrap(),
            Header::from_bytes("Access-Control-Allow-Origin", "*").unwrap(),
        ],
        Cursor::new(bytes.clone()),
        Some(bytes.len()),
        None,
    );
    let _ = req.respond(response);
}

fn load_all_events() -> Vec<serde_json::Value> {
    let mut all = Vec::new();
    for &kind in &ALL_KINDS {
        if let Ok(events) = logs::decrypt_events(kind) {
            for mut v in events {
                // Tag with kind so the frontend can color-code
                if let Some(obj) = v.as_object_mut() {
                    obj.insert(
                        "_kind".to_string(),
                        serde_json::Value::String(kind_str(kind).to_string()),
                    );
                }
                all.push(v);
            }
        }
    }
    // Sort newest first by timestamp
    all.sort_by(|a, b| {
        let ta = a.get("timestamp").and_then(|v| v.as_str()).unwrap_or("");
        let tb = b.get("timestamp").and_then(|v| v.as_str()).unwrap_or("");
        tb.cmp(ta)
    });
    all
}

fn kind_str(k: LogKind) -> &'static str {
    match k {
        LogKind::Executions => "execution",
        LogKind::Requests => "request",
        LogKind::Approvals => "approval",
        LogKind::Alerts => "alert",
        LogKind::Sessions => "session",
    }
}

// ── Embedded dashboard HTML ───────────────────────────────────────────────────

const DASHBOARD_HTML: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ward · logs</title>
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

  :root {
    --bg:       #0d0d0f;
    --surface:  #141416;
    --border:   #1e1e22;
    --text:     #e2e2e6;
    --muted:    #5a5a6a;
    --accent:   #7c6ef5;
    --green:    #4ade80;
    --yellow:   #fbbf24;
    --red:      #f87171;
    --cyan:     #22d3ee;
    --blue:     #60a5fa;
    --magenta:  #c084fc;
    --radius:   6px;
    --font:     "SF Mono", "Fira Code", "Cascadia Code", monospace;
  }

  body {
    background: var(--bg);
    color: var(--text);
    font-family: var(--font);
    font-size: 12px;
    height: 100vh;
    display: flex;
    flex-direction: column;
    overflow: hidden;
  }

  /* ── Header ── */
  header {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 10px 20px;
    border-bottom: 1px solid var(--border);
    background: var(--surface);
    flex-shrink: 0;
  }

  .logo {
    font-weight: 700;
    font-size: 13px;
    color: var(--text);
    letter-spacing: 0.04em;
  }
  .logo span { color: var(--accent); }

  .dot {
    width: 7px; height: 7px;
    border-radius: 50%;
    background: var(--green);
    box-shadow: 0 0 6px var(--green);
    animation: pulse 2s ease-in-out infinite;
  }
  @keyframes pulse {
    0%, 100% { opacity: 1; }
    50%       { opacity: 0.4; }
  }

  .header-right {
    margin-left: auto;
    display: flex;
    align-items: center;
    gap: 12px;
    color: var(--muted);
    font-size: 11px;
  }

  #refresh-btn {
    background: none;
    border: 1px solid var(--border);
    color: var(--muted);
    border-radius: var(--radius);
    padding: 3px 10px;
    cursor: pointer;
    font-family: var(--font);
    font-size: 11px;
    transition: color 0.15s, border-color 0.15s;
  }
  #refresh-btn:hover { color: var(--text); border-color: var(--muted); }

  /* ── Filter bar ── */
  .filters {
    display: flex;
    align-items: center;
    gap: 6px;
    padding: 8px 20px;
    border-bottom: 1px solid var(--border);
    background: var(--surface);
    flex-shrink: 0;
    flex-wrap: wrap;
  }

  .filter-label { color: var(--muted); font-size: 11px; margin-right: 4px; }

  .chip {
    padding: 2px 10px;
    border-radius: 99px;
    border: 1px solid var(--border);
    background: transparent;
    color: var(--muted);
    cursor: pointer;
    font-family: var(--font);
    font-size: 11px;
    transition: all 0.15s;
  }
  .chip:hover   { border-color: var(--muted); color: var(--text); }
  .chip.active  { background: var(--accent); border-color: var(--accent); color: #fff; }

  .chip[data-kind="execution"] { --k: var(--cyan); }
  .chip[data-kind="request"]   { --k: var(--blue); }
  .chip[data-kind="approval"]  { --k: var(--green); }
  .chip[data-kind="alert"]     { --k: var(--yellow); }
  .chip[data-kind="session"]   { --k: var(--magenta); }
  .chip[data-kind].active      { background: var(--k); border-color: var(--k); }

  .separator { width: 1px; height: 16px; background: var(--border); margin: 0 4px; }

  .agent-select-wrap {
    position: relative;
    display: inline-flex;
    align-items: center;
  }
  .agent-select-wrap::after {
    content: '▾';
    position: absolute;
    right: 8px;
    color: var(--muted);
    font-size: 10px;
    pointer-events: none;
  }
  #agent-filter {
    appearance: none;
    -webkit-appearance: none;
    background: var(--bg);
    border: 1px solid var(--border);
    color: var(--text);
    border-radius: var(--radius);
    padding: 3px 24px 3px 8px;
    font-family: var(--font);
    font-size: 11px;
    outline: none;
    cursor: pointer;
    transition: border-color 0.15s;
  }
  #agent-filter:hover  { border-color: var(--muted); }
  #agent-filter:focus  { border-color: var(--accent); }
  #agent-filter option {
    background: #1a1a1e;
    color: var(--text);
  }

  /* ── Body: table + detail ── */
  .body {
    display: flex;
    flex: 1;
    overflow: hidden;
  }

  /* ── Event table ── */
  .table-pane {
    flex: 0 0 58%;
    display: flex;
    flex-direction: column;
    border-right: 1px solid var(--border);
    overflow: hidden;
  }

  .table-scroll { overflow-y: auto; flex: 1; }
  .table-scroll::-webkit-scrollbar { width: 4px; }
  .table-scroll::-webkit-scrollbar-track { background: transparent; }
  .table-scroll::-webkit-scrollbar-thumb { background: var(--border); border-radius: 4px; }

  table { width: 100%; border-collapse: collapse; }

  thead th {
    position: sticky; top: 0;
    background: var(--surface);
    color: var(--muted);
    font-weight: 500;
    text-align: left;
    padding: 6px 10px;
    border-bottom: 1px solid var(--border);
    font-size: 10px;
    letter-spacing: 0.06em;
    text-transform: uppercase;
    white-space: nowrap;
  }

  tbody tr {
    border-bottom: 1px solid #1a1a1e;
    cursor: pointer;
    transition: background 0.1s;
  }
  tbody tr:hover    { background: #18181c; }
  tbody tr.selected { background: #1c1a2e; border-left: 2px solid var(--accent); }

  td {
    padding: 6px 10px;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
    max-width: 200px;
    color: var(--text);
  }

  .td-time  { color: var(--muted); font-size: 11px; width: 60px; }
  .td-kind  { width: 80px; }
  .td-sev   { width: 44px; }
  .td-agent { width: 90px; color: var(--muted); }
  .td-cmd   { color: var(--text); }

  .badge {
    display: inline-block;
    padding: 1px 7px;
    border-radius: 99px;
    font-size: 10px;
    font-weight: 600;
    letter-spacing: 0.04em;
  }
  .badge-execution { background: #0e3a42; color: var(--cyan); }
  .badge-request   { background: #0e1e3a; color: var(--blue); }
  .badge-approval  { background: #0e3020; color: var(--green); }
  .badge-alert     { background: #3a2a0e; color: var(--yellow); }
  .badge-session   { background: #2a1a3a; color: var(--magenta); }

  .sev-info { color: var(--muted); }
  .sev-warn { color: var(--yellow); }
  .sev-crit { color: var(--red); font-weight: 700; }

  /* ── Detail pane ── */
  .detail-pane {
    flex: 1;
    overflow-y: auto;
    padding: 16px 20px;
  }
  .detail-pane::-webkit-scrollbar { width: 4px; }
  .detail-pane::-webkit-scrollbar-thumb { background: var(--border); border-radius: 4px; }

  .detail-empty {
    color: var(--muted);
    font-size: 11px;
    margin-top: 40px;
    text-align: center;
  }

  .detail-header {
    display: flex;
    align-items: center;
    gap: 8px;
    margin-bottom: 16px;
  }

  .detail-title {
    font-size: 13px;
    font-weight: 600;
    color: var(--text);
  }

  .detail-ts {
    font-size: 10px;
    color: var(--muted);
    margin-left: auto;
  }

  .field-group { margin-bottom: 14px; }

  .field-label {
    font-size: 10px;
    color: var(--muted);
    text-transform: uppercase;
    letter-spacing: 0.08em;
    margin-bottom: 4px;
  }

  .field-value {
    font-size: 12px;
    color: var(--text);
    word-break: break-all;
  }

  .env-chip {
    display: inline-block;
    background: #0e2a3a;
    color: var(--cyan);
    border-radius: 4px;
    padding: 2px 8px;
    font-size: 11px;
    margin: 2px 3px 2px 0;
  }

  .finding {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 8px 10px;
    margin-bottom: 6px;
  }
  .finding-header {
    display: flex;
    align-items: center;
    gap: 8px;
    margin-bottom: 4px;
  }
  .finding-msg { color: var(--muted); font-size: 11px; }

  .outcome-success { color: var(--green); font-weight: 600; }
  .outcome-failure { color: var(--red); font-weight: 600; }

  /* ── Status bar ── */
  footer {
    border-top: 1px solid var(--border);
    padding: 4px 20px;
    display: flex;
    gap: 16px;
    align-items: center;
    background: var(--surface);
    color: var(--muted);
    font-size: 10px;
    flex-shrink: 0;
  }

  .count { color: var(--text); }
</style>
</head>
<body>

<header>
  <div class="dot"></div>
  <div class="logo">◆ <span>ward</span> · logs</div>
  <div class="header-right">
    <span id="last-refresh">–</span>
    <button id="refresh-btn">↻ refresh</button>
  </div>
</header>

<div class="filters">
  <span class="filter-label">kind</span>
  <button class="chip active" data-kind="all">all</button>
  <button class="chip" data-kind="execution">exec</button>
  <button class="chip" data-kind="request">req</button>
  <button class="chip" data-kind="approval">approval</button>
  <button class="chip" data-kind="alert">alert</button>
  <button class="chip" data-kind="session">session</button>

  <div class="separator"></div>
  <span class="filter-label">agent</span>
  <div class="agent-select-wrap">
    <select id="agent-filter"><option value="">all agents</option></select>
  </div>

  <div class="separator"></div>
  <span class="filter-label">severity</span>
  <button class="chip active" data-sev="all">all</button>
  <button class="chip" data-sev="warn">warn</button>
  <button class="chip" data-sev="crit">critical</button>
</div>

<div class="body">
  <div class="table-pane">
    <div class="table-scroll">
      <table>
        <thead>
          <tr>
            <th class="td-time">time</th>
            <th class="td-kind">kind</th>
            <th class="td-sev">sev</th>
            <th class="td-agent">agent</th>
            <th class="td-cmd">command / action</th>
          </tr>
        </thead>
        <tbody id="event-body"></tbody>
      </table>
    </div>
  </div>

  <div class="detail-pane" id="detail-pane">
    <div class="detail-empty">← select an event</div>
  </div>
</div>

<footer>
  <span>ward human mode</span>
  <span class="count" id="event-count">0 events</span>
  <span id="filter-count"></span>
</footer>

<script>
  let allEvents = [];
  let selected = null;
  let kindFilter = 'all';
  let sevFilter  = 'all';
  let agentFilter = '';

  // ── Fetch ─────────────────────────────────────────────────────────────────

  async function load() {
    try {
      const r = await fetch('/api/events');
      allEvents = await r.json();
      updateAgentSelect();
      render();
      document.getElementById('last-refresh').textContent =
        new Date().toLocaleTimeString();
    } catch(e) {
      console.error('fetch failed', e);
    }
  }

  // ── Filter & render ───────────────────────────────────────────────────────

  function filtered() {
    return allEvents.filter(e => {
      const p = e.payload || e;
      if (kindFilter !== 'all' && e._kind !== kindFilter) return false;
      const agent = p.agent || (p.access && p.access.agent) || '';
      if (agentFilter && agent !== agentFilter) return false;
      if (sevFilter === 'warn' && severity(e) === 'info') return false;
      if (sevFilter === 'crit' && severity(e) !== 'crit') return false;
      return true;
    });
  }

  function severity(e) {
    const p = e.payload || e;
    if (e._kind === 'alert') return 'warn';
    const findings = p.policyFindings || [];
    if (findings.some(f => f.severity === 'critical')) return 'crit';
    if (findings.some(f => f.severity === 'warning'))  return 'warn';
    const decision = p.decision || '';
    if (decision === 'deny') return 'warn';
    return 'info';
  }

  function render() {
    const rows = filtered();
    const tbody = document.getElementById('event-body');
    tbody.innerHTML = '';

    rows.forEach((e, i) => {
      const p = e.payload || e;
      const ts = (e.timestamp || '').slice(11, 19);
      const agent = p.agent || (p.access && p.access.agent) || '–';
      const cmd = p.requestedCommand || (p.access && p.access.command)
                || p.declaredAction   || (p.access && p.access.action)
                || '–';
      const sev = severity(e);

      const tr = document.createElement('tr');
      if (selected === i) tr.classList.add('selected');
      tr.innerHTML = `
        <td class="td-time">${ts}</td>
        <td class="td-kind"><span class="badge badge-${e._kind}">${e._kind}</span></td>
        <td class="td-sev"><span class="sev-${sev}">${sev}</span></td>
        <td class="td-agent">${esc(agent)}</td>
        <td class="td-cmd">${esc(cmd.length > 60 ? cmd.slice(0,59)+'…' : cmd)}</td>
      `;
      tr.addEventListener('click', () => { selected = i; render(); renderDetail(e); });
      tbody.appendChild(tr);
    });

    document.getElementById('event-count').textContent =
      `${allEvents.length} events`;
    document.getElementById('filter-count').textContent =
      rows.length < allEvents.length ? `${rows.length} shown` : '';
  }

  // ── Detail panel ──────────────────────────────────────────────────────────

  function renderDetail(e) {
    const p = e.payload || e;
    const pane = document.getElementById('detail-pane');
    const sev = severity(e);
    const agent = p.agent || (p.access && p.access.agent) || null;
    const branch = p.branch || (p.git && p.git.branch) || (p.access && p.access.branch) || null;
    const worktree = (p.git && p.git.worktreePath) || p.cwd || null;
    const commit  = p.git && p.git.commit ? p.git.commit.slice(0,12) : null;
    const cmd = p.requestedCommand || (p.access && p.access.command) || null;
    const action = p.declaredAction || (p.access && p.access.action) || null;
    const envVars = p.injectedEnv || p.requestedEnv || (p.access && p.access.env) || [];
    const findings = p.policyFindings || [];
    const outcome = p.outcome || null;
    const scope = p.approvalScope || null;
    const source = p.approvalSource || null;

    let html = `<div class="detail-header">
      <span class="badge badge-${e._kind}">${e._kind}</span>
      <span class="sev-${sev}">${sev}</span>
      <span class="detail-ts">${e.timestamp || ''}</span>
    </div>`;

    if (agent)   html += field('agent', esc(agent));
    if (branch)  html += field('branch', esc(branch));
    if (worktree) html += field('worktree', esc(shortenPath(worktree)));
    if (cmd)     html += field('command', esc(cmd));
    if (action)  html += field('action', esc(action));
    if (commit)  html += field('commit', esc(commit));
    if (scope)   html += field('approval scope', esc(scope));
    if (source)  html += field('approval source', esc(source));

    if (outcome) {
      const code = typeof outcome === 'object' ? outcome.exitCode ?? outcome.exit_code : outcome;
      const ok = code === 0 || code === 'success';
      const cls = ok ? 'outcome-success' : 'outcome-failure';
      const label = typeof code === 'number' ? (ok ? `exit 0` : `exit ${code}`) : String(code);
      html += field('outcome', `<span class="${cls}">${esc(label)}</span>`);
    }

    if (envVars.length) {
      html += `<div class="field-group"><div class="field-label">env vars</div><div class="field-value">`;
      envVars.forEach(v => { html += `<span class="env-chip">${esc(v)}</span>`; });
      html += `</div></div>`;
    }

    if (findings.length) {
      html += `<div class="field-group"><div class="field-label">findings</div>`;
      findings.forEach(f => {
        const sc = f.severity === 'critical' ? 'sev-crit' : f.severity === 'warning' ? 'sev-warn' : 'sev-info';
        html += `<div class="finding">
          <div class="finding-header">
            <span class="${sc}">${f.severity}</span>
            <span style="color:var(--muted);font-size:10px">${esc(f.code)}</span>
          </div>
          <div class="finding-msg">${esc(f.message)}</div>
        </div>`;
      });
      html += `</div>`;
    }

    pane.innerHTML = html;
  }

  function field(label, value) {
    return `<div class="field-group">
      <div class="field-label">${label}</div>
      <div class="field-value">${value}</div>
    </div>`;
  }

  function shortenPath(p) {
    return p.length > 50 ? '…' + p.slice(p.length - 49) : p;
  }

  function esc(s) {
    return String(s)
      .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
      .replace(/"/g,'&quot;');
  }

  // ── Agent select ──────────────────────────────────────────────────────────

  function updateAgentSelect() {
    const agents = [...new Set(
      allEvents.map(e => {
        const p = e.payload || e;
        return p.agent || (p.access && p.access.agent) || '';
      }).filter(Boolean)
    )].sort();

    const sel = document.getElementById('agent-filter');
    const current = sel.value;
    sel.innerHTML = '<option value="">all agents</option>';
    agents.forEach(a => {
      const opt = document.createElement('option');
      opt.value = a; opt.textContent = a;
      if (a === current) opt.selected = true;
      sel.appendChild(opt);
    });
  }

  // ── Controls ──────────────────────────────────────────────────────────────

  document.querySelectorAll('.chip[data-kind]').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.chip[data-kind]').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      kindFilter = btn.dataset.kind;
      selected = null;
      render();
    });
  });

  document.querySelectorAll('.chip[data-sev]').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.chip[data-sev]').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      sevFilter = btn.dataset.sev;
      selected = null;
      render();
    });
  });

  document.getElementById('agent-filter').addEventListener('change', e => {
    agentFilter = e.target.value;
    selected = null;
    render();
  });

  document.getElementById('refresh-btn').addEventListener('click', load);

  // ── Auto-refresh every 5 seconds ─────────────────────────────────────────

  load();
  setInterval(load, 5000);
</script>
</body>
</html>"#;
