use std::time::{Duration, Instant};

use anyhow::Result;
use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use ratatui::{
    layout::{Alignment, Constraint, Direction, Layout, Margin},
    style::{Color, Style, Stylize},
    text::{Line, Span, Text},
    widgets::{
        Block, BorderType, Borders, Cell, Clear, Paragraph, Row, Scrollbar,
        ScrollbarOrientation, ScrollbarState, Table, TableState, Tabs, Wrap,
    },
    DefaultTerminal, Frame,
};
use serde_json::Value;

use crate::logs::{self, LogKind};

const POLL_INTERVAL: Duration = Duration::from_secs(5);
const ALL_KINDS: [LogKind; 5] = [
    LogKind::Executions,
    LogKind::Requests,
    LogKind::Approvals,
    LogKind::Alerts,
    LogKind::Sessions,
];

#[derive(Debug, Clone)]
struct LogEntry {
    timestamp: String,
    kind: LogKind,
    agent: Option<String>,
    command: Option<String>,
    action: Option<String>,
    branch: Option<String>,
    worktree: Option<String>,
    env_vars: Vec<String>,
    severity: Severity,
    raw: Value,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Severity {
    Info,
    Warning,
    Critical,
}

impl Severity {
    fn color(&self) -> Color {
        match self {
            Severity::Info => Color::White,
            Severity::Warning => Color::Yellow,
            Severity::Critical => Color::Red,
        }
    }

    fn label(&self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Warning => "warn",
            Severity::Critical => "crit",
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Focus {
    Table,
    Detail,
}

struct App {
    entries: Vec<LogEntry>,
    filtered: Vec<usize>,
    table_state: TableState,
    detail_scroll: u16,
    kind_filter: Option<LogKind>,
    agent_filter: Option<String>,
    severity_filter: Option<Severity>,
    kind_tab: usize,
    focus: Focus,
    last_refresh: Instant,
    show_help: bool,
    known_agents: Vec<String>,
    agent_tab: usize,
}

impl App {
    fn new() -> Self {
        App {
            entries: Vec::new(),
            filtered: Vec::new(),
            table_state: TableState::default(),
            detail_scroll: 0,
            kind_filter: None,
            agent_filter: None,
            severity_filter: None,
            kind_tab: 0,
            focus: Focus::Table,
            last_refresh: Instant::now(),
            show_help: false,
            known_agents: Vec::new(),
            agent_tab: 0,
        }
    }

    fn load_logs(&mut self) {
        self.entries.clear();
        for &kind in &ALL_KINDS {
            if let Ok(events) = logs::decrypt_events(kind) {
                for v in events {
                    if let Some(entry) = parse_entry(kind, v) {
                        self.entries.push(entry);
                    }
                }
            }
        }
        self.entries
            .sort_by(|a, b| a.timestamp.cmp(&b.timestamp));
        self.entries.reverse();

        let mut agents: Vec<String> = self
            .entries
            .iter()
            .filter_map(|e| e.agent.clone())
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect();
        agents.insert(0, "all".to_string());
        self.known_agents = agents;

        self.rebuild_filter();
    }

    fn rebuild_filter(&mut self) {
        self.filtered = self
            .entries
            .iter()
            .enumerate()
            .filter(|(_, e)| {
                if let Some(k) = self.kind_filter {
                    if e.kind != k {
                        return false;
                    }
                }
                if let Some(ref a) = self.agent_filter {
                    if e.agent.as_deref() != Some(a.as_str()) {
                        return false;
                    }
                }
                if let Some(ref s) = self.severity_filter {
                    if &e.severity != s {
                        return false;
                    }
                }
                true
            })
            .map(|(i, _)| i)
            .collect();

        if self.filtered.is_empty() {
            self.table_state.select(None);
        } else if self.table_state.selected().is_none() {
            self.table_state.select(Some(0));
        } else {
            let sel = self.table_state.selected().unwrap_or(0);
            if sel >= self.filtered.len() {
                self.table_state.select(Some(self.filtered.len() - 1));
            }
        }
        self.detail_scroll = 0;
    }

    fn selected_entry(&self) -> Option<&LogEntry> {
        let idx = self.table_state.selected()?;
        let entry_idx = *self.filtered.get(idx)?;
        self.entries.get(entry_idx)
    }

    fn move_selection(&mut self, delta: i32) {
        let len = self.filtered.len();
        if len == 0 {
            return;
        }
        let current = self.table_state.selected().unwrap_or(0) as i32;
        let next = (current + delta).clamp(0, (len as i32) - 1) as usize;
        self.table_state.select(Some(next));
        self.detail_scroll = 0;
    }

    fn cycle_kind_tab(&mut self, forward: bool) {
        // 0 = all, 1-5 = kinds
        let max = ALL_KINDS.len();
        if forward {
            self.kind_tab = (self.kind_tab + 1) % (max + 1);
        } else {
            self.kind_tab = (self.kind_tab + max) % (max + 1);
        }
        self.kind_filter = if self.kind_tab == 0 {
            None
        } else {
            Some(ALL_KINDS[self.kind_tab - 1])
        };
        self.rebuild_filter();
    }

    fn cycle_agent_tab(&mut self, forward: bool) {
        let len = self.known_agents.len();
        if len == 0 {
            return;
        }
        if forward {
            self.agent_tab = (self.agent_tab + 1) % len;
        } else {
            self.agent_tab = (self.agent_tab + len - 1) % len;
        }
        let selected = &self.known_agents[self.agent_tab];
        self.agent_filter = if selected == "all" {
            None
        } else {
            Some(selected.clone())
        };
        self.rebuild_filter();
    }

    fn cycle_severity(&mut self) {
        self.severity_filter = match &self.severity_filter {
            None => Some(Severity::Info),
            Some(Severity::Info) => Some(Severity::Warning),
            Some(Severity::Warning) => Some(Severity::Critical),
            Some(Severity::Critical) => None,
        };
        self.rebuild_filter();
    }
}

fn parse_entry(kind: LogKind, raw: Value) -> Option<LogEntry> {
    let payload = raw.get("payload").unwrap_or(&raw);
    let timestamp = raw
        .get("timestamp")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let agent = extract_str(payload, &["agent", "access", "agent"]);
    let command = extract_str(payload, &["requestedCommand", "command"])
        .or_else(|| extract_nested_str(payload, &["access", "command"]));
    let action = extract_str(payload, &["declaredAction"])
        .or_else(|| extract_nested_str(payload, &["access", "action"]));
    let branch = extract_str(payload, &["branch"])
        .or_else(|| extract_nested_str(payload, &["git", "branch"]))
        .or_else(|| extract_nested_str(payload, &["access", "branch"]));
    let worktree = extract_nested_str(payload, &["git", "worktreePath"])
        .or_else(|| extract_str(payload, &["cwd"]));

    let env_vars = extract_str_array(payload, "injectedEnv")
        .or_else(|| extract_str_array(payload, "requestedEnv"))
        .or_else(|| extract_nested_str_array(payload, &["access", "env"]))
        .unwrap_or_default();

    let severity = detect_severity(payload, kind);

    Some(LogEntry {
        timestamp,
        kind,
        agent,
        command,
        action,
        branch,
        worktree,
        env_vars,
        severity,
        raw,
    })
}

fn extract_str(v: &Value, keys: &[&str]) -> Option<String> {
    for key in keys {
        if let Some(s) = v.get(key).and_then(|v| v.as_str()) {
            return Some(s.to_string());
        }
    }
    None
}

fn extract_nested_str(v: &Value, path: &[&str]) -> Option<String> {
    let mut cur = v;
    for key in path {
        cur = cur.get(key)?;
    }
    cur.as_str().map(|s| s.to_string())
}

fn extract_str_array(v: &Value, key: &str) -> Option<Vec<String>> {
    let arr = v.get(key)?.as_array()?;
    let result: Vec<String> = arr
        .iter()
        .filter_map(|e| e.as_str().map(|s| s.to_string()))
        .collect();
    if result.is_empty() {
        None
    } else {
        Some(result)
    }
}

fn extract_nested_str_array(v: &Value, path: &[&str]) -> Option<Vec<String>> {
    let mut cur = v;
    for key in path {
        cur = cur.get(key)?;
    }
    let arr = cur.as_array()?;
    let result: Vec<String> = arr
        .iter()
        .filter_map(|e| e.as_str().map(|s| s.to_string()))
        .collect();
    if result.is_empty() {
        None
    } else {
        Some(result)
    }
}

fn detect_severity(payload: &Value, kind: LogKind) -> Severity {
    // Alerts are always at least warning
    if kind == LogKind::Alerts {
        return Severity::Warning;
    }
    // Check findings for critical
    if let Some(findings) = payload.get("policyFindings").and_then(|v| v.as_array()) {
        for f in findings {
            if f.get("severity").and_then(|s| s.as_str()) == Some("critical") {
                return Severity::Critical;
            }
        }
        for f in findings {
            if f.get("severity").and_then(|s| s.as_str()) == Some("warning") {
                return Severity::Warning;
            }
        }
    }
    // Denied approvals are warnings
    if kind == LogKind::Approvals {
        if let Some(decision) = payload.get("decision").and_then(|v| v.as_str()) {
            if decision == "deny" {
                return Severity::Warning;
            }
        }
    }
    Severity::Info
}

fn kind_label(k: LogKind) -> &'static str {
    match k {
        LogKind::Executions => "exec",
        LogKind::Requests => "req",
        LogKind::Approvals => "approve",
        LogKind::Alerts => "alert",
        LogKind::Sessions => "session",
    }
}

fn kind_color(k: LogKind) -> Color {
    match k {
        LogKind::Executions => Color::Cyan,
        LogKind::Requests => Color::Blue,
        LogKind::Approvals => Color::Green,
        LogKind::Alerts => Color::Yellow,
        LogKind::Sessions => Color::Magenta,
    }
}

pub fn run_dashboard() -> Result<()> {
    let mut terminal = ratatui::init();
    let result = run_app(&mut terminal);
    ratatui::restore();
    result
}

fn run_app(terminal: &mut DefaultTerminal) -> Result<()> {
    let mut app = App::new();
    app.load_logs();

    loop {
        terminal.draw(|f| draw(f, &mut app))?;

        if app.last_refresh.elapsed() >= POLL_INTERVAL {
            app.load_logs();
            app.last_refresh = Instant::now();
        }

        if event::poll(Duration::from_millis(200))? {
            if let Event::Key(key) = event::read()? {
                if key.kind != KeyEventKind::Press {
                    continue;
                }
                if app.show_help {
                    app.show_help = false;
                    continue;
                }
                match key.code {
                    KeyCode::Char('q') | KeyCode::Esc => return Ok(()),
                    KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                        return Ok(())
                    }
                    KeyCode::Char('?') | KeyCode::Char('h') => {
                        app.show_help = !app.show_help;
                    }
                    KeyCode::Char('r') => {
                        app.load_logs();
                        app.last_refresh = Instant::now();
                    }
                    KeyCode::Tab => app.cycle_kind_tab(true),
                    KeyCode::BackTab => app.cycle_kind_tab(false),
                    KeyCode::Char('a') => app.cycle_agent_tab(true),
                    KeyCode::Char('A') => app.cycle_agent_tab(false),
                    KeyCode::Char('s') => app.cycle_severity(),
                    KeyCode::Down | KeyCode::Char('j') => {
                        if app.focus == Focus::Detail {
                            app.detail_scroll = app.detail_scroll.saturating_add(1);
                        } else {
                            app.move_selection(1);
                        }
                    }
                    KeyCode::Up | KeyCode::Char('k') => {
                        if app.focus == Focus::Detail {
                            app.detail_scroll = app.detail_scroll.saturating_sub(1);
                        } else {
                            app.move_selection(-1);
                        }
                    }
                    KeyCode::PageDown => app.move_selection(20),
                    KeyCode::PageUp => app.move_selection(-20),
                    KeyCode::Enter | KeyCode::Char('l') => {
                        app.focus = if app.focus == Focus::Table {
                            Focus::Detail
                        } else {
                            Focus::Table
                        };
                    }
                    KeyCode::Char(' ') | KeyCode::Char('b') => {
                        app.focus = Focus::Table;
                    }
                    _ => {}
                }
            }
        }
    }
}

fn draw(f: &mut Frame, app: &mut App) {
    let area = f.area();

    // Main layout: header + kind tabs + body
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1), // title bar
            Constraint::Length(3), // kind tabs
            Constraint::Length(3), // agent + severity filters
            Constraint::Min(0),    // table + detail split
            Constraint::Length(1), // status bar
        ])
        .split(area);

    // Title bar
    let title = Paragraph::new(Line::from(vec![
        Span::styled(" ward ", Style::default().fg(Color::Black).bg(Color::White).bold()),
        Span::raw("  logs dashboard  "),
        Span::styled(
            format!("  {} events  ", app.filtered.len()),
            Style::default().fg(Color::DarkGray),
        ),
    ]));
    f.render_widget(title, chunks[0]);

    // Kind tabs
    let kind_titles: Vec<Line> = std::iter::once(Line::from("all"))
        .chain(ALL_KINDS.iter().map(|&k| {
            Line::from(Span::styled(kind_label(k), Style::default().fg(kind_color(k))))
        }))
        .collect();
    let kind_tabs = Tabs::new(kind_titles)
        .block(Block::default().borders(Borders::ALL).title(" kind "))
        .select(app.kind_tab)
        .highlight_style(Style::default().bold().bg(Color::DarkGray));
    f.render_widget(kind_tabs, chunks[1]);

    // Agent + severity filter bar
    let filter_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(70), Constraint::Percentage(30)])
        .split(chunks[2]);

    let agent_titles: Vec<Line> = app
        .known_agents
        .iter()
        .map(|a| Line::from(a.as_str()))
        .collect();
    let agent_tabs = if agent_titles.is_empty() {
        Tabs::new(vec![Line::from("all")])
            .block(Block::default().borders(Borders::ALL).title(" agent [a/A] "))
            .select(0)
            .highlight_style(Style::default().bold().bg(Color::DarkGray))
    } else {
        Tabs::new(agent_titles)
            .block(Block::default().borders(Borders::ALL).title(" agent [a/A] "))
            .select(app.agent_tab)
            .highlight_style(Style::default().bold().bg(Color::DarkGray))
    };
    f.render_widget(agent_tabs, filter_chunks[0]);

    let sev_label = match &app.severity_filter {
        None => "all".to_string(),
        Some(s) => s.label().to_string(),
    };
    let sev_color = match &app.severity_filter {
        None => Color::White,
        Some(s) => s.color(),
    };
    let sev_widget = Paragraph::new(Line::from(vec![
        Span::raw("  filter: "),
        Span::styled(sev_label, Style::default().fg(sev_color).bold()),
        Span::styled("  [s] cycle", Style::default().fg(Color::DarkGray)),
    ]))
    .block(Block::default().borders(Borders::ALL).title(" severity "));
    f.render_widget(sev_widget, filter_chunks[1]);

    // Body: table | detail
    let body_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
        .split(chunks[3]);

    draw_table(f, app, body_chunks[0]);
    draw_detail(f, app, body_chunks[1]);

    // Status bar
    let status = Paragraph::new(Line::from(vec![
        Span::styled(" q", Style::default().fg(Color::Yellow)),
        Span::raw(" quit  "),
        Span::styled("Tab", Style::default().fg(Color::Yellow)),
        Span::raw(" kind  "),
        Span::styled("a", Style::default().fg(Color::Yellow)),
        Span::raw(" agent  "),
        Span::styled("s", Style::default().fg(Color::Yellow)),
        Span::raw(" severity  "),
        Span::styled("Enter", Style::default().fg(Color::Yellow)),
        Span::raw(" detail  "),
        Span::styled("r", Style::default().fg(Color::Yellow)),
        Span::raw(" refresh  "),
        Span::styled("?", Style::default().fg(Color::Yellow)),
        Span::raw(" help"),
    ]))
    .style(Style::default().bg(Color::DarkGray));
    f.render_widget(status, chunks[4]);

    if app.show_help {
        draw_help(f, area);
    }
}

fn draw_table(f: &mut Frame, app: &mut App, area: ratatui::layout::Rect) {
    let is_focused = app.focus == Focus::Table;
    let block_style = if is_focused {
        Style::default().fg(Color::White)
    } else {
        Style::default().fg(Color::DarkGray)
    };

    let header = Row::new(vec![
        Cell::from("time").style(Style::default().bold()),
        Cell::from("kind").style(Style::default().bold()),
        Cell::from("sev").style(Style::default().bold()),
        Cell::from("agent").style(Style::default().bold()),
        Cell::from("command / action").style(Style::default().bold()),
    ])
    .height(1)
    .style(Style::default().bg(Color::DarkGray));

    let rows: Vec<Row> = app
        .filtered
        .iter()
        .map(|&idx| {
            let e = &app.entries[idx];
            let ts = e
                .timestamp
                .get(11..19)
                .unwrap_or(e.timestamp.get(..8).unwrap_or(&e.timestamp));
            let label = e
                .command
                .as_deref()
                .or(e.action.as_deref())
                .unwrap_or("-");
            // truncate label
            let label = if label.len() > 35 {
                format!("{}…", &label[..34])
            } else {
                label.to_string()
            };
            Row::new(vec![
                Cell::from(ts),
                Cell::from(Span::styled(
                    kind_label(e.kind),
                    Style::default().fg(kind_color(e.kind)),
                )),
                Cell::from(Span::styled(
                    e.severity.label(),
                    Style::default().fg(e.severity.color()),
                )),
                Cell::from(e.agent.as_deref().unwrap_or("-")),
                Cell::from(label),
            ])
        })
        .collect();

    let widths = [
        Constraint::Length(8),
        Constraint::Length(7),
        Constraint::Length(4),
        Constraint::Length(10),
        Constraint::Min(0),
    ];

    let table = Table::new(rows, widths)
        .header(header)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(block_style)
                .title(if is_focused {
                    " events [↑↓ navigate] "
                } else {
                    " events "
                }),
        )
        .row_highlight_style(Style::default().bg(Color::Blue).fg(Color::White).bold());

    f.render_stateful_widget(table, area, &mut app.table_state);
}

fn draw_detail(f: &mut Frame, app: &mut App, area: ratatui::layout::Rect) {
    let is_focused = app.focus == Focus::Detail;
    let block_style = if is_focused {
        Style::default().fg(Color::White)
    } else {
        Style::default().fg(Color::DarkGray)
    };

    // Clone to avoid holding a borrow on app while we later mutate app.detail_scroll
    let entry: LogEntry = match app.selected_entry() {
        Some(e) => e.clone(),
        None => {
            let p = Paragraph::new("select an event")
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .border_style(block_style)
                        .title(" detail "),
                )
                .alignment(Alignment::Center);
            f.render_widget(p, area);
            return;
        }
    };

    let mut lines: Vec<Line> = Vec::new();

    let ts_date = entry.timestamp.get(..10).unwrap_or("-");
    let ts_time = entry.timestamp.get(11..19).unwrap_or("-");
    lines.push(Line::from(vec![
        Span::styled("time     ", Style::default().fg(Color::DarkGray)),
        Span::raw(format!("{} {}", ts_date, ts_time)),
    ]));
    lines.push(Line::from(vec![
        Span::styled("kind     ", Style::default().fg(Color::DarkGray)),
        Span::styled(
            kind_label(entry.kind),
            Style::default().fg(kind_color(entry.kind)).bold(),
        ),
    ]));
    lines.push(Line::from(vec![
        Span::styled("severity ", Style::default().fg(Color::DarkGray)),
        Span::styled(
            entry.severity.label(),
            Style::default().fg(entry.severity.color()).bold(),
        ),
    ]));

    lines.push(Line::from(""));

    if let Some(ref a) = entry.agent {
        lines.push(Line::from(vec![
            Span::styled("agent    ", Style::default().fg(Color::DarkGray)),
            Span::raw(a.clone()),
        ]));
    }
    if let Some(ref b) = entry.branch {
        lines.push(Line::from(vec![
            Span::styled("branch   ", Style::default().fg(Color::DarkGray)),
            Span::raw(b.clone()),
        ]));
    }
    if let Some(ref w) = entry.worktree {
        let wt = if w.len() > 40 {
            format!("…{}", &w[w.len() - 39..])
        } else {
            w.clone()
        };
        lines.push(Line::from(vec![
            Span::styled("worktree ", Style::default().fg(Color::DarkGray)),
            Span::raw(wt),
        ]));
    }
    if let Some(ref cmd) = entry.command {
        lines.push(Line::from(vec![
            Span::styled("command  ", Style::default().fg(Color::DarkGray)),
            Span::raw(cmd.clone()),
        ]));
    }
    if let Some(ref act) = entry.action {
        lines.push(Line::from(vec![
            Span::styled("action   ", Style::default().fg(Color::DarkGray)),
            Span::raw(act.clone()),
        ]));
    }

    if !entry.env_vars.is_empty() {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "env vars",
            Style::default().fg(Color::DarkGray),
        )));
        for var in &entry.env_vars {
            lines.push(Line::from(vec![
                Span::raw("  "),
                Span::styled(var.clone(), Style::default().fg(Color::Cyan)),
            ]));
        }
    }

    // Findings from payload
    let payload = entry.raw.get("payload").unwrap_or(&entry.raw);
    if let Some(findings) = payload.get("policyFindings").and_then(|v| v.as_array()) {
        if !findings.is_empty() {
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                "findings",
                Style::default().fg(Color::DarkGray),
            )));
            for f in findings {
                let sev = f
                    .get("severity")
                    .and_then(|s| s.as_str())
                    .unwrap_or("info");
                let code = f.get("code").and_then(|s| s.as_str()).unwrap_or("?");
                let msg = f.get("message").and_then(|s| s.as_str()).unwrap_or("");
                let sev_color = match sev {
                    "critical" => Color::Red,
                    "warning" => Color::Yellow,
                    _ => Color::White,
                };
                lines.push(Line::from(vec![
                    Span::raw("  "),
                    Span::styled(
                        format!("[{}] ", sev),
                        Style::default().fg(sev_color).bold(),
                    ),
                    Span::styled(code, Style::default().fg(Color::DarkGray)),
                    Span::raw(format!("  {}", msg)),
                ]));
            }
        }
    }

    // Commit if available
    if let Some(commit) = payload
        .get("git")
        .and_then(|g| g.get("commit"))
        .and_then(|s| s.as_str())
    {
        lines.push(Line::from(""));
        lines.push(Line::from(vec![
            Span::styled("commit   ", Style::default().fg(Color::DarkGray)),
            Span::raw(commit.get(..12).unwrap_or(commit)),
        ]));
    }

    // Approval scope if present
    if let Some(scope) = payload.get("approvalScope").and_then(|s| s.as_str()) {
        lines.push(Line::from(vec![
            Span::styled("scope    ", Style::default().fg(Color::DarkGray)),
            Span::raw(scope),
        ]));
    }
    if let Some(source) = payload.get("approvalSource").and_then(|s| s.as_str()) {
        lines.push(Line::from(vec![
            Span::styled("source   ", Style::default().fg(Color::DarkGray)),
            Span::raw(source),
        ]));
    }
    if let Some(outcome) = payload.get("outcome").and_then(|o| o.as_str()) {
        lines.push(Line::from(vec![
            Span::styled("outcome  ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                outcome,
                Style::default().fg(if outcome == "success" {
                    Color::Green
                } else {
                    Color::Red
                }),
            ),
        ]));
    }

    let total_lines = lines.len() as u16;
    let visible = area.height.saturating_sub(2);
    let max_scroll = total_lines.saturating_sub(visible);
    let scroll = app.detail_scroll.min(max_scroll);
    app.detail_scroll = scroll;

    let text = Text::from(lines);
    let detail = Paragraph::new(text)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(block_style)
                .title(if is_focused {
                    " detail [↑↓ scroll / b back] "
                } else {
                    " detail [Enter] "
                }),
        )
        .scroll((scroll, 0))
        .wrap(Wrap { trim: false });

    f.render_widget(detail, area);

    if total_lines > visible {
        let mut scrollbar_state = ScrollbarState::new(total_lines as usize)
            .position(scroll as usize)
            .viewport_content_length(visible as usize);
        let scrollbar = Scrollbar::new(ScrollbarOrientation::VerticalRight);
        f.render_stateful_widget(
            scrollbar,
            area.inner(Margin {
                vertical: 1,
                horizontal: 0,
            }),
            &mut scrollbar_state,
        );
    }
}

fn draw_help(f: &mut Frame, area: ratatui::layout::Rect) {
    let width = 50u16.min(area.width.saturating_sub(4));
    let height = 20u16.min(area.height.saturating_sub(4));
    let x = (area.width.saturating_sub(width)) / 2;
    let y = (area.height.saturating_sub(height)) / 2;
    let popup = ratatui::layout::Rect { x, y, width, height };

    f.render_widget(Clear, popup);

    let lines = vec![
        Line::from(Span::styled(
            "  Keyboard Shortcuts",
            Style::default().bold().fg(Color::White),
        )),
        Line::from(""),
        Line::from(vec![
            Span::styled("  q / Esc     ", Style::default().fg(Color::Yellow)),
            Span::raw("quit"),
        ]),
        Line::from(vec![
            Span::styled("  Tab / BkTab ", Style::default().fg(Color::Yellow)),
            Span::raw("cycle log kind"),
        ]),
        Line::from(vec![
            Span::styled("  a / A       ", Style::default().fg(Color::Yellow)),
            Span::raw("cycle agent filter"),
        ]),
        Line::from(vec![
            Span::styled("  s           ", Style::default().fg(Color::Yellow)),
            Span::raw("cycle severity filter"),
        ]),
        Line::from(vec![
            Span::styled("  ↑ / k       ", Style::default().fg(Color::Yellow)),
            Span::raw("move up"),
        ]),
        Line::from(vec![
            Span::styled("  ↓ / j       ", Style::default().fg(Color::Yellow)),
            Span::raw("move down"),
        ]),
        Line::from(vec![
            Span::styled("  PgUp/PgDn   ", Style::default().fg(Color::Yellow)),
            Span::raw("jump 20 rows"),
        ]),
        Line::from(vec![
            Span::styled("  Enter / l   ", Style::default().fg(Color::Yellow)),
            Span::raw("focus detail panel"),
        ]),
        Line::from(vec![
            Span::styled("  Space / b   ", Style::default().fg(Color::Yellow)),
            Span::raw("back to table"),
        ]),
        Line::from(vec![
            Span::styled("  r           ", Style::default().fg(Color::Yellow)),
            Span::raw("refresh logs"),
        ]),
        Line::from(vec![
            Span::styled("  ? / h       ", Style::default().fg(Color::Yellow)),
            Span::raw("toggle this help"),
        ]),
        Line::from(""),
        Line::from(Span::styled(
            "  Auto-refreshes every 5 seconds",
            Style::default().fg(Color::DarkGray),
        )),
        Line::from(""),
        Line::from(Span::styled(
            "  Press any key to close",
            Style::default().fg(Color::DarkGray),
        )),
    ];

    let help = Paragraph::new(Text::from(lines))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .title(" help ")
                .title_style(Style::default().bold()),
        )
        .style(Style::default().bg(Color::Black));
    f.render_widget(help, popup);
}
