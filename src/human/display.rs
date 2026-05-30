use std::fmt::Write as FmtWrite;

const PADLOCK_CLOSED: &[&str] = &[
    "  \x1b[33m████\x1b[0m    ",
    " \x1b[33m█    █\x1b[0m   ",
    " \x1b[32m█ ██ █\x1b[0m   ",
    " \x1b[32m█    █\x1b[0m   ",
    " \x1b[32m██████\x1b[0m   ",
];

const PADLOCK_OPEN: &[&str] = &[
    "        \x1b[33m████\x1b[0m",
    "       \x1b[33m█\x1b[0m    ",
    " \x1b[32m█      \x1b[0m    ",
    " \x1b[32m█    █\x1b[0m     ",
    " \x1b[32m██████\x1b[0m     ",
];

fn print_frame(frame: &[&str]) {
    for line in frame {
        println!("{line}");
    }
}

fn clear_lines(n: usize) {
    print!("\x1b[{n}A");
}

pub fn print_padlock_opening() {
    print_frame(PADLOCK_CLOSED);
    #[cfg(not(test))]
    std::thread::sleep(std::time::Duration::from_millis(250));
    clear_lines(PADLOCK_CLOSED.len());
    print_frame(PADLOCK_OPEN);
}

pub fn print_padlock_closing() {
    print_frame(PADLOCK_OPEN);
    #[cfg(not(test))]
    std::thread::sleep(std::time::Duration::from_millis(250));
    clear_lines(PADLOCK_OPEN.len());
    print_frame(PADLOCK_CLOSED);
}

pub fn format_session_prefix(project: &str, ttl_label: &str) -> String {
    format!(
        "\x1b[32mᗝ\x1b[0m  \x1b[1m{project}\x1b[0m · \x1b[36mhuman mode\x1b[0m · {ttl_label}"
    )
}

pub fn format_human_table(headers: &[&str], rows: &[Vec<String>]) -> String {
    let col_count = headers.len();
    let mut widths: Vec<usize> = headers.iter().map(|h| h.len()).collect();
    for row in rows {
        for (i, cell) in row.iter().enumerate() {
            if i < col_count {
                widths[i] = widths[i].max(cell.len());
            }
        }
    }
    let mut out = String::new();
    for (i, h) in headers.iter().enumerate() {
        let _ = write!(out, "  {:<width$}", h, width = widths[i]);
    }
    out.push('\n');
    let sep: String = widths.iter().map(|w| "─".repeat(w + 2)).collect::<Vec<_>>().join("");
    out.push_str(&format!("  {sep}\n"));
    for row in rows {
        for (i, cell) in row.iter().enumerate() {
            if i < col_count {
                let _ = write!(out, "  {:<width$}", cell, width = widths[i]);
            }
        }
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_prefix_contains_project_and_mode() {
        let s = format_session_prefix("myproject", "7h");
        assert!(s.contains("myproject"));
        assert!(s.contains("human mode"));
        assert!(s.contains("7h"));
    }

    #[test]
    fn table_formats_columns() {
        let s = format_human_table(&["agent", "cmd"], &[vec!["codex".into(), "pnpm dev".into()]]);
        assert!(s.contains("codex"));
        assert!(s.contains("pnpm dev"));
    }
}
