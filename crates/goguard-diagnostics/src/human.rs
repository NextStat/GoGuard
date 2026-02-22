//! Human-readable diagnostic output formatter.
//!
//! Uses ariadne for rich terminal output with source context.

use crate::diagnostic::{Diagnostic, Severity};
use ariadne::{Color, Config, Label, Report, ReportKind, Source};
use std::collections::HashMap;

/// Format diagnostics for human-readable terminal output.
pub fn format_human(diags: &[Diagnostic], use_color: bool) -> String {
    if diags.is_empty() {
        return "No issues found\n".to_string();
    }

    let mut output = Vec::new();
    let mut source_cache: HashMap<String, String> = HashMap::new();

    let config = Config::default().with_color(use_color);

    for diag in diags {
        let file = &diag.location.file;

        let source_text = source_cache
            .entry(file.clone())
            .or_insert_with(|| std::fs::read_to_string(file).unwrap_or_default());

        if source_text.is_empty() {
            output.push(format_fallback(diag));
            continue;
        }

        let kind = match diag.severity {
            Severity::Critical | Severity::Error => ReportKind::Error,
            Severity::Warning => ReportKind::Warning,
            Severity::Info => ReportKind::Advice,
        };

        let offset = line_col_to_offset(source_text, diag.location.line, diag.location.column);
        let label_end = (offset + 1).min(source_text.len());

        let color = match diag.severity {
            Severity::Critical | Severity::Error => Color::Red,
            Severity::Warning => Color::Yellow,
            Severity::Info => Color::Cyan,
        };

        let mut report = Report::build(kind, (file.as_str(), offset..label_end))
            .with_config(config)
            .with_code(&diag.rule)
            .with_message(&diag.title)
            .with_label(
                Label::new((file.as_str(), offset..label_end))
                    .with_message(&diag.explanation)
                    .with_color(color),
            );

        if let Some(ref root_cause) = diag.root_cause {
            report = report.with_note(format!("root cause: {}", root_cause.description));
        }
        if let Some(ref fix) = diag.fix {
            report = report.with_help(&fix.description);
        }

        let mut buf = Vec::new();
        report
            .finish()
            .write(
                (file.as_str(), Source::from(source_text.as_str())),
                &mut buf,
            )
            .ok();

        output.push(String::from_utf8_lossy(&buf).to_string());
    }

    // Summary line
    let critical = diags
        .iter()
        .filter(|d| d.severity == Severity::Critical)
        .count();
    let errors = diags
        .iter()
        .filter(|d| d.severity == Severity::Error)
        .count();
    let warnings = diags
        .iter()
        .filter(|d| d.severity == Severity::Warning)
        .count();

    output.push(format!(
        "\nFound {} issue(s): {} critical, {} error, {} warning\n",
        diags.len(),
        critical,
        errors,
        warnings,
    ));

    output.join("\n")
}

/// Convert 1-based line:column to byte offset in source text.
fn line_col_to_offset(source: &str, line: u32, col: u32) -> usize {
    let line = line.saturating_sub(1) as usize;
    let col = col.saturating_sub(1) as usize;

    let offset: usize = source
        .lines()
        .take(line)
        .map(|l| l.len() + 1) // +1 for newline
        .sum();

    (offset + col).min(source.len().saturating_sub(1))
}

/// Fallback format when source file is not available.
fn format_fallback(diag: &Diagnostic) -> String {
    format!(
        "{}:{}:{}: {} [{}] {}: {}\n",
        diag.location.file,
        diag.location.line,
        diag.location.column,
        diag.severity,
        diag.rule,
        diag.title,
        diag.explanation,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diagnostic::{DiagnosticSource, Location};

    fn make_diag(rule: &str, severity: Severity, file: &str, line: u32) -> Diagnostic {
        Diagnostic {
            id: format!("{rule}-{file}:{line}"),
            rule: rule.to_string(),
            severity,
            confidence: 0.95,
            title: format!("test issue {rule}"),
            explanation: format!("explanation for {rule}"),
            location: Location {
                file: file.to_string(),
                line,
                column: 1,
                end_line: line,
                end_column: 1,
            },
            root_cause: None,
            fix: None,
            related: vec![],
            blast_radius: None,
            pattern: None,
            source: DiagnosticSource::Nil,
            callee_key: None,
        }
    }

    #[test]
    fn test_empty_diagnostics() {
        let result = format_human(&[], false);
        assert_eq!(result, "No issues found\n");
    }

    #[test]
    fn test_fallback_no_source() {
        let diag = make_diag("NIL001", Severity::Critical, "/nonexistent/file.go", 10);
        let result = format_human(&[diag], false);
        assert!(result.contains("NIL001"));
        assert!(result.contains("/nonexistent/file.go"));
    }

    #[test]
    fn test_summary_counts() {
        let diags = vec![
            make_diag("NIL001", Severity::Critical, "/fake.go", 1),
            make_diag("ERR001", Severity::Error, "/fake.go", 2),
            make_diag("NIL004", Severity::Warning, "/fake.go", 3),
        ];
        let result = format_human(&diags, false);
        assert!(result.contains("Found 3 issue(s)"));
        assert!(result.contains("1 critical"));
        assert!(result.contains("1 error"));
        assert!(result.contains("1 warning"));
    }

    #[test]
    fn test_line_col_to_offset() {
        let src = "line1\nline2\nline3\n";
        assert_eq!(line_col_to_offset(src, 1, 1), 0);
        assert_eq!(line_col_to_offset(src, 2, 1), 6);
        assert_eq!(line_col_to_offset(src, 3, 1), 12);
        assert_eq!(line_col_to_offset(src, 2, 3), 8);
    }

    #[test]
    fn test_line_col_to_offset_bounds() {
        let src = "abc";
        // Out of bounds should clamp
        assert_eq!(line_col_to_offset(src, 100, 1), 2);
    }
}
