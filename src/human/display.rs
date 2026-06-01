use std::fmt::Write as FmtWrite;

pub fn format_session_prefix(project: &str, ttl_label: &str) -> String {
    let p = "\x1b[38;5;135m";
    let r = "\x1b[0m";
    format!(
        "{p}◬{r}  \x1b[1mward\x1b[0m · \x1b[1m{project}\x1b[0m · \x1b[36mhuman mode\x1b[0m · {ttl_label}"
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
    let sep: String = widths
        .iter()
        .map(|w| "─".repeat(w + 2))
        .collect::<Vec<_>>()
        .join("");
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
        let s = format_human_table(
            &["agent", "cmd"],
            &[vec!["codex".into(), "pnpm dev".into()]],
        );
        assert!(s.contains("codex"));
        assert!(s.contains("pnpm dev"));
    }
}
