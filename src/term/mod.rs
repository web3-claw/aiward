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

/// Shorten an absolute path for display — keep last 2 segments.
pub fn short_path(p: &std::path::Path) -> String {
    let parts: Vec<_> = p.components().collect();
    if parts.len() <= 3 {
        return p.display().to_string();
    }
    let tail: std::path::PathBuf = parts[parts.len() - 2..].iter().collect();
    format!("…/{}", tail.display())
}
