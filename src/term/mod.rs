use std::time::Duration;

use indicatif::{ProgressBar, ProgressStyle};

const SPINNER_FRAMES: &str = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏";
const TICK_MS: u64 = 80;
const PAD: &str = "  ";

pub fn header(project: &str) {
    eprintln!();
    eprintln!("{}◆ ward  ·  {}", PAD, project);
    eprintln!();
}

pub fn header_cmd(cmd: &str, project: &str) {
    eprintln!();
    eprintln!("{}◆ ward {}  ·  {}", PAD, cmd, project);
    eprintln!();
}

pub fn guided_header(command: &str, project: &str, path: &std::path::Path, body: &str) {
    eprint!("{}", render_guided_header(command, project, path, body));
}

pub fn render_guided_header(
    command: &str,
    project: &str,
    path: &std::path::Path,
    body: &str,
) -> String {
    format!(
        "\n{PAD}◬ ward {command}\n{PAD}Project: {project}\n{PAD}Path: {}\n\n{PAD}{body}\n\n",
        short_path(path)
    )
}

pub fn section(label: &str) {
    eprintln!();
    eprintln!("{}  {}", PAD, label);
}

pub fn spinner(msg: &str) -> ProgressBar {
    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::with_template(&format!("{}{{spinner:.cyan}} {{msg}}", PAD))
            .unwrap()
            .tick_chars(SPINNER_FRAMES),
    );
    pb.set_message(msg.to_string());
    pb.enable_steady_tick(Duration::from_millis(TICK_MS));
    pb
}

pub fn done(pb: ProgressBar, msg: &str) {
    pb.finish_and_clear();
    eprintln!("{}✓ {}", PAD, msg);
}

pub fn warn_step(pb: ProgressBar, msg: &str) {
    pb.finish_and_clear();
    eprintln!("{}! {}", PAD, msg);
}

pub fn ok(msg: &str) {
    eprintln!("{}✓ {}", PAD, msg);
}

pub fn fail(msg: &str) {
    eprintln!("{}✗ {}", PAD, msg);
}

pub fn info(msg: &str) {
    eprintln!("{}  {}", PAD, msg);
}

pub fn warn(msg: &str) {
    eprintln!("{}! {}", PAD, msg);
}

pub fn blank() {
    eprintln!();
}

pub fn next(msg: &str) {
    eprintln!("{}→ {}", PAD, msg);
}

pub fn command_hint(command: &str) {
    eprintln!("{}  {}", PAD, command);
}

/// Shorten an absolute path for display — keep last 2 segments.
pub fn short_path(p: &std::path::Path) -> String {
    let parts: Vec<_> = p.components().collect();
    if parts.len() <= 3 {
        return p.display().to_string();
    }
    let tail: std::path::PathBuf = parts[parts.len() - 2..].iter().collect();
    format!("…/{}", tail.display())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_path_keeps_tail_segments() {
        assert_eq!(
            short_path(std::path::Path::new("/Users/me/project")),
            "…/me/project"
        );
    }

    #[test]
    fn guided_header_includes_command_project_path_and_body() {
        let rendered = render_guided_header(
            "setup",
            "demo",
            std::path::Path::new("/Users/me/demo"),
            "Ward will encrypt your local env, create a vault, and prepare this project for safe human and agent access.",
        );

        assert!(rendered.contains("◬ ward setup"));
        assert!(rendered.contains("Project: demo"));
        assert!(rendered.contains("Path: …/me/demo"));
        assert!(rendered.contains("encrypt your local env"));
    }

    #[test]
    fn guided_copy_fragments_are_stable() {
        let setup = "Ward will encrypt your local env, create a vault, and prepare this project for safe human and agent access.";
        let human = "This terminal is now protected. Normal commands in this Ward project will receive vault envs through Ward while this session is active.";

        assert!(setup.contains("encrypt your local env"));
        assert!(setup.contains("safe human and agent access"));
        assert!(human.contains("This terminal is now protected"));
        assert!(human.contains("while this session is active"));
    }
}
