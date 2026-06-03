use anyhow::Result;
use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use ratatui::{
    layout::{Constraint, Direction, Layout, Margin},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, Paragraph, Wrap},
    Frame,
};

use crate::{detection, policy::AccessRequest};

use super::{ApprovalScope, PolicyEvaluation};

// ── Ward design system ────────────────────────────────────────────────────────

const BG: Color = Color::Rgb(13, 13, 15);
const SURFACE: Color = Color::Rgb(20, 20, 22);
const BORDER: Color = Color::Rgb(30, 30, 34);
const TEXT: Color = Color::Rgb(226, 226, 230);
const MUTED: Color = Color::Rgb(90, 90, 106);
const ACCENT: Color = Color::Rgb(124, 110, 245);
const RED: Color = Color::Rgb(248, 113, 113);
const CYAN: Color = Color::Rgb(34, 211, 238);
const MAGENTA: Color = Color::Rgb(192, 132, 252);
const SEL_BG: Color = Color::Rgb(28, 26, 46);

struct State<'a> {
    request: &'a AccessRequest,
    evaluation: &'a PolicyEvaluation,
    choices: Vec<ApprovalScope>,
    selected: usize,
}

impl<'a> State<'a> {
    fn new(
        request: &'a AccessRequest,
        evaluation: &'a PolicyEvaluation,
        choices: Vec<ApprovalScope>,
    ) -> Self {
        Self {
            request,
            evaluation,
            choices,
            selected: 0,
        }
    }

    fn move_up(&mut self) {
        if self.selected > 0 {
            self.selected -= 1;
        }
    }

    fn move_down(&mut self) {
        if self.selected + 1 < self.choices.len() {
            self.selected += 1;
        }
    }

    fn current(&self) -> ApprovalScope {
        self.choices[self.selected]
    }

    fn is_critical(&self) -> bool {
        detection::has_critical_findings(&self.evaluation.findings)
    }
}

pub fn run_approval_tui(
    request: &AccessRequest,
    evaluation: &PolicyEvaluation,
    choices: Vec<ApprovalScope>,
) -> Result<ApprovalScope> {
    let mut terminal = ratatui::init();
    let mut state = State::new(request, evaluation, choices);
    let result = run_loop(&mut terminal, &mut state);
    ratatui::restore();
    result
}

fn run_loop(terminal: &mut ratatui::DefaultTerminal, state: &mut State) -> Result<ApprovalScope> {
    loop {
        terminal.draw(|f| draw(f, state))?;

        if let Event::Key(key) = event::read()? {
            if key.kind != KeyEventKind::Press {
                continue;
            }
            match key.code {
                KeyCode::Up | KeyCode::Char('k') => state.move_up(),
                KeyCode::Down | KeyCode::Char('j') => state.move_down(),
                KeyCode::Enter | KeyCode::Char(' ') => return Ok(state.current()),
                KeyCode::Esc | KeyCode::Char('q') => {
                    // Return Deny on escape/quit if it's in the list, otherwise first choice.
                    let deny = state
                        .choices
                        .iter()
                        .position(|s| *s == ApprovalScope::Deny)
                        .unwrap_or(0);
                    return Ok(state.choices[deny]);
                }
                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    let deny = state
                        .choices
                        .iter()
                        .position(|s| *s == ApprovalScope::Deny)
                        .unwrap_or(0);
                    return Ok(state.choices[deny]);
                }
                _ => {}
            }
        }
    }
}

fn draw(f: &mut Frame, state: &State) {
    let area = f.area();
    f.render_widget(
        ratatui::widgets::Block::default().style(Style::default().bg(BG)),
        area,
    );

    // Title bar
    let title_bar_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(1), Constraint::Min(0)])
        .split(area);

    let title = Paragraph::new(Line::from(vec![
        Span::styled(" ward ", Style::default().fg(TEXT).bold()),
        Span::styled("· access request", Style::default().fg(MUTED)),
    ]))
    .style(Style::default().bg(SURFACE));
    f.render_widget(title, title_bar_chunks[0]);

    // Horizontal split: left command panel / right details panel
    let body = title_bar_chunks[1];
    let panels = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(40), Constraint::Percentage(60)])
        .split(body);

    draw_left(f, state, panels[0]);
    draw_right(f, state, panels[1]);
}

fn draw_left(f: &mut Frame, state: &State, area: ratatui::layout::Rect) {
    let block = Block::default()
        .borders(Borders::RIGHT)
        .border_type(BorderType::Plain)
        .border_style(Style::default().fg(BORDER))
        .style(Style::default().bg(BG));
    f.render_widget(block, area);

    let inner = area.inner(Margin {
        horizontal: 2,
        vertical: 1,
    });

    let agent_label = state.request.agent.as_deref().unwrap_or("agent");
    let badge = Line::from(vec![Span::styled(
        format!(" ● {agent_label} "),
        Style::default()
            .fg(MAGENTA)
            .bg(Color::Rgb(42, 26, 58))
            .add_modifier(Modifier::BOLD),
    )]);

    let cmd_lines = build_command_lines(state.request);

    let mut all_lines = vec![badge, Line::raw("")];
    all_lines.extend(cmd_lines);

    let paragraph = Paragraph::new(all_lines).wrap(Wrap { trim: false });
    f.render_widget(paragraph, inner);
}

fn build_command_lines(request: &AccessRequest) -> Vec<Line<'static>> {
    let agent = request.agent.clone().unwrap_or_default();
    let env_list = request.env.join(" ");
    let action = request.action.clone().unwrap_or_default();
    let command = request.command.clone();

    let prompt = Span::styled("❯ ", Style::default().fg(ACCENT).bold());
    let plain = |s: &str| Span::styled(s.to_string(), Style::default().fg(TEXT));
    let cyan_span = |s: &str| Span::styled(s.to_string(), Style::default().fg(CYAN));
    let muted_span = |s: &str| Span::styled(s.to_string(), Style::default().fg(MUTED));
    let cont = || muted_span(" \\");

    let mut lines: Vec<Line<'static>> = vec![Line::from(vec![prompt, plain("ward run"), cont()])];

    if !agent.is_empty() {
        lines.push(Line::from(vec![
            plain("    --agent "),
            cyan_span(&format!("\"{agent}\"")),
            cont(),
        ]));
    }

    if !env_list.is_empty() {
        lines.push(Line::from(vec![
            plain("    --env "),
            cyan_span(&env_list),
            cont(),
        ]));
    }

    if !action.is_empty() {
        lines.push(Line::from(vec![
            plain("    --action "),
            plain(&format!("\"{action}\"")),
            cont(),
        ]));
    }

    // Final line: -- command (no trailing backslash)
    lines.push(Line::from(vec![plain("    -- "), plain(&command)]));

    lines
}

fn draw_right(f: &mut Frame, state: &State, area: ratatui::layout::Rect) {
    let block = Block::default().style(Style::default().bg(BG));
    f.render_widget(block, area);

    let inner = area.inner(Margin {
        horizontal: 2,
        vertical: 1,
    });

    // Stack: title, blank, info table, blank, [warning], scope list
    let critical = state.is_critical();
    let warning_height: u16 = if critical { 3 } else { 0 };
    let info_rows = info_row_count(state.request);
    let scope_height = state.choices.len() as u16;

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),              // "Ward access request" title
            Constraint::Length(1),              // blank
            Constraint::Length(info_rows),      // info table
            Constraint::Length(1),              // blank
            Constraint::Length(warning_height), // critical warning (0 if none)
            Constraint::Length(scope_height),   // scope list
            Constraint::Min(0),
        ])
        .split(inner);

    // Title
    let title = Paragraph::new(Line::from(Span::styled(
        "Ward access request",
        Style::default().fg(ACCENT).bold(),
    )));
    f.render_widget(title, chunks[0]);

    // Info table
    draw_info_table(f, state.request, chunks[2]);

    // Critical warning
    if critical {
        draw_critical_warning(f, chunks[4]);
    }

    // Scope list
    draw_scope_list(f, state, chunks[5]);
}

fn info_row_count(request: &AccessRequest) -> u16 {
    let mut count = 2u16; // project + command always present
    if request.agent.is_some() {
        count += 1;
    }
    if request.branch.is_some() {
        count += 1;
    }
    if request.action.is_some() {
        count += 1;
    }
    if !request.env.is_empty() {
        count += 1;
    }
    count
}

fn draw_info_table(f: &mut Frame, request: &AccessRequest, area: ratatui::layout::Rect) {
    let label_style = Style::default().fg(MUTED).add_modifier(Modifier::BOLD);
    let value_style = Style::default().fg(TEXT);

    let mut lines: Vec<Line<'static>> = Vec::new();

    lines.push(info_row(
        "PROJECT",
        &request.project,
        label_style,
        value_style,
    ));

    if let Some(agent) = &request.agent {
        lines.push(info_row("AGENT", agent, label_style, value_style));
    }
    if let Some(branch) = &request.branch {
        lines.push(info_row("BRANCH", branch, label_style, value_style));
    }
    if let Some(action) = &request.action {
        lines.push(info_row("ACTION", action, label_style, value_style));
    }

    lines.push(info_row(
        "COMMAND",
        &request.command,
        label_style,
        value_style,
    ));

    if !request.env.is_empty() {
        let mut spans: Vec<Span<'static>> = vec![Span::styled(
            format!("{:<14}", "REQUESTED ENV"),
            label_style,
        )];
        for key in &request.env {
            spans.push(Span::styled(
                format!(" {key} "),
                Style::default()
                    .fg(CYAN)
                    .bg(Color::Rgb(14, 42, 58))
                    .add_modifier(Modifier::BOLD),
            ));
            spans.push(Span::raw(" "));
        }
        lines.push(Line::from(spans));
    }

    let paragraph = Paragraph::new(lines);
    f.render_widget(paragraph, area);
}

fn info_row(label: &str, value: &str, label_style: Style, value_style: Style) -> Line<'static> {
    Line::from(vec![
        Span::styled(format!("{:<14}", label), label_style),
        Span::styled(value.to_string(), value_style),
    ])
}

fn draw_critical_warning(f: &mut Frame, area: ratatui::layout::Rect) {
    let warning = Paragraph::new(vec![
        Line::from(Span::styled(
            "CRITICAL  This command matched known secret-exfiltration patterns.",
            Style::default().fg(RED).bold(),
        )),
        Line::from(Span::styled(
            "          Deny unless you explicitly expect this command to inspect secrets.",
            Style::default().fg(RED),
        )),
    ]);
    f.render_widget(warning, area);
}

fn draw_scope_list(f: &mut Frame, state: &State, area: ratatui::layout::Rect) {
    let lines: Vec<Line<'static>> = state
        .choices
        .iter()
        .enumerate()
        .map(|(i, scope)| {
            let is_selected = i == state.selected;
            let is_deny = *scope == ApprovalScope::Deny;
            let label = scope.to_string();

            if is_selected {
                let bg_block =
                    ratatui::widgets::Block::default().style(Style::default().bg(SEL_BG));
                let row_area = ratatui::layout::Rect {
                    x: area.x,
                    y: area.y + i as u16,
                    width: area.width,
                    height: 1,
                };
                // We'll render the highlight as part of the paragraph style below
                let _ = bg_block;
                let _ = row_area;

                Line::from(vec![
                    Span::styled("  ▶ ", Style::default().fg(ACCENT).bold()),
                    Span::styled(
                        label,
                        Style::default()
                            .fg(if is_deny { RED } else { TEXT })
                            .bold()
                            .bg(SEL_BG),
                    ),
                    // Pad the rest of the line to fill the selection highlight
                    Span::styled(" ".repeat(60), Style::default().bg(SEL_BG)),
                ])
            } else {
                Line::from(vec![
                    Span::raw("    "),
                    Span::styled(label, Style::default().fg(if is_deny { RED } else { TEXT })),
                ])
            }
        })
        .collect();

    let paragraph = Paragraph::new(lines);
    f.render_widget(paragraph, area);
}
