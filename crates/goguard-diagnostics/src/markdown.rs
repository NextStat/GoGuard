//! Markdown audit report formatter.
//!
//! Produces a checklist-style `.md` file that serves as a TODO for both
//! humans and AI agents. Each diagnostic is a `- [ ]` item grouped by file.

use crate::diagnostic::{Diagnostic, Severity};
use std::collections::{BTreeMap, HashSet};

/// Format diagnostics as a Markdown audit report with checkboxes.
///
/// `project_dir` is used to strip absolute paths into relative ones.
/// Pass `None` to keep paths as-is.
pub fn format_markdown(
    diags: &[Diagnostic],
    project_name: &str,
    project_dir: Option<&str>,
) -> String {
    if diags.is_empty() {
        return format!("# GoGuard Audit: {project_name}\n\nNo issues found.\n");
    }

    // Deduplicate by (rule, file, line, column)
    let mut seen = HashSet::new();
    let deduped: Vec<&Diagnostic> = diags
        .iter()
        .filter(|d| {
            seen.insert((
                d.rule.as_str(),
                d.location.file.as_str(),
                d.location.line,
                d.location.column,
            ))
        })
        .collect();

    let mut out = String::new();

    // Header
    let today = chrono_free_date();
    out.push_str(&format!(
        "# GoGuard Audit: {project_name}\n\n> {today} | {} findings | goguard v{}\n\n",
        deduped.len(),
        env!("CARGO_PKG_VERSION"),
    ));

    // Summary table: rule → (count, severity)
    let mut rule_counts: BTreeMap<&str, (usize, Severity)> = BTreeMap::new();
    for d in &deduped {
        let entry = rule_counts.entry(&d.rule).or_insert((0, d.severity));
        entry.0 += 1;
        if d.severity > entry.1 {
            entry.1 = d.severity;
        }
    }

    out.push_str("## Summary\n\n");
    out.push_str("| Rule | Count | Severity |\n");
    out.push_str("|------|------:|----------|\n");

    let mut sorted_rules: Vec<_> = rule_counts.iter().collect();
    sorted_rules.sort_by(|a, b| b.1 .0.cmp(&a.1 .0));

    for (rule, (count, severity)) in &sorted_rules {
        out.push_str(&format!("| {rule} | {count} | {severity} |\n"));
    }
    out.push('\n');

    // Group by file (relative paths, alphabetical)
    let strip_prefix = project_dir.unwrap_or("");
    let rel_path = |file: &str| -> String {
        if !strip_prefix.is_empty() {
            file.strip_prefix(strip_prefix)
                .unwrap_or(file)
                .trim_start_matches('/')
                .to_string()
        } else {
            file.to_string()
        }
    };

    let mut by_file: BTreeMap<String, Vec<&&Diagnostic>> = BTreeMap::new();
    for d in &deduped {
        by_file
            .entry(rel_path(&d.location.file))
            .or_default()
            .push(d);
    }

    out.push_str("## Findings\n\n");

    for (file, file_diags) in &by_file {
        out.push_str(&format!("### {file} ({} findings)\n\n", file_diags.len()));

        for d in file_diags {
            out.push_str(&format!(
                "- [ ] **{}** L{}:{} — {}\n",
                d.rule, d.location.line, d.location.column, d.title,
            ));
        }
        out.push('\n');
    }

    out
}

/// Simple date string without pulling in chrono.
fn chrono_free_date() -> String {
    let now = std::time::SystemTime::now();
    let secs = now
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let days = secs / 86400;
    let (year, month, day) = days_to_ymd(days);
    format!("{year:04}-{month:02}-{day:02}")
}

/// Convert days since Unix epoch to (year, month, day).
fn days_to_ymd(days: u64) -> (u64, u64, u64) {
    // Civil calendar algorithm from Howard Hinnant
    let z = days + 719468;
    let era = z / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diagnostic::{DiagnosticBuilder, DiagnosticSource, Severity};

    fn make_diag(rule: &str, severity: Severity, file: &str, line: u32, title: &str) -> Diagnostic {
        DiagnosticBuilder::new(rule, severity, title, DiagnosticSource::Nil)
            .location(file, line, 5)
            .explanation(format!("explanation for {rule}"))
            .build()
    }

    #[test]
    fn test_empty_diagnostics() {
        let result = format_markdown(&[], "my-project", None);
        assert!(result.contains("# GoGuard Audit: my-project"));
        assert!(result.contains("No issues found"));
    }

    #[test]
    fn test_header_contains_project_and_count() {
        let diags = vec![make_diag(
            "NIL001",
            Severity::Critical,
            "main.go",
            10,
            "nil deref",
        )];
        let result = format_markdown(&diags, "go-crm", None);
        assert!(result.contains("# GoGuard Audit: go-crm"));
        assert!(result.contains("1 findings"));
        assert!(result.contains("goguard v"));
    }

    #[test]
    fn test_summary_table() {
        let diags = vec![
            make_diag("NIL001", Severity::Critical, "a.go", 1, "nil deref"),
            make_diag("NIL001", Severity::Critical, "b.go", 2, "nil deref"),
            make_diag("ERR001", Severity::Error, "a.go", 3, "error ignored"),
        ];
        let result = format_markdown(&diags, "test", None);
        assert!(result.contains("| NIL001 | 2 | critical |"));
        assert!(result.contains("| ERR001 | 1 | error |"));
    }

    #[test]
    fn test_findings_grouped_by_file() {
        let diags = vec![
            make_diag(
                "NIL001",
                Severity::Critical,
                "cmd/main.go",
                10,
                "nil deref of cfg",
            ),
            make_diag(
                "ERR001",
                Severity::Error,
                "cmd/main.go",
                20,
                "error ignored",
            ),
            make_diag(
                "NIL004",
                Severity::Warning,
                "internal/handler.go",
                5,
                "nil map write",
            ),
        ];
        let result = format_markdown(&diags, "test", None);

        assert!(result.contains("### cmd/main.go (2 findings)"));
        assert!(result.contains("### internal/handler.go (1 findings)"));
        assert!(result.contains("- [ ] **NIL001** L10:5 — nil deref of cfg"));
        assert!(result.contains("- [ ] **ERR001** L20:5 — error ignored"));
        assert!(result.contains("- [ ] **NIL004** L5:5 — nil map write"));
    }

    #[test]
    fn test_summary_sorted_by_count_descending() {
        let diags = vec![
            make_diag("ERR001", Severity::Error, "a.go", 1, "err"),
            make_diag("NIL001", Severity::Critical, "a.go", 2, "nil"),
            make_diag("NIL001", Severity::Critical, "b.go", 3, "nil"),
            make_diag("NIL001", Severity::Critical, "c.go", 4, "nil"),
        ];
        let result = format_markdown(&diags, "test", None);

        let nil_pos = result.find("| NIL001 |").unwrap();
        let err_pos = result.find("| ERR001 |").unwrap();
        assert!(
            nil_pos < err_pos,
            "NIL001 should come before ERR001 in summary"
        );
    }

    #[test]
    fn test_deduplicates_same_location() {
        let diags = vec![
            make_diag("NIL001", Severity::Critical, "main.go", 88, "nil deref"),
            make_diag("NIL001", Severity::Critical, "main.go", 88, "nil deref"),
        ];
        let result = format_markdown(&diags, "test", None);
        assert!(result.contains("1 findings"));
        // Only one checkbox line
        let checkbox_count = result.matches("- [ ]").count();
        assert_eq!(checkbox_count, 1);
    }

    #[test]
    fn test_relative_paths() {
        let diags = vec![make_diag(
            "NIL001",
            Severity::Critical,
            "/Users/dev/project/cmd/main.go",
            10,
            "nil deref",
        )];
        let result = format_markdown(&diags, "test", Some("/Users/dev/project"));
        assert!(result.contains("### cmd/main.go"));
        assert!(!result.contains("/Users/dev/project"));
    }

    #[test]
    fn test_date_conversion() {
        let (y, m, d) = days_to_ymd(19723);
        assert_eq!((y, m, d), (2024, 1, 1));
    }
}
