//! Ownership rules (OWN001-OWN004).
//!
//! Each rule corresponds to a specific resource lifecycle violation:
//! - OWN001: Resource opened but never closed
//! - OWN002: Use after close
//! - OWN003: Double close
//! - OWN004: Close not deferred (suggestion to use defer)

use goguard_diagnostics::diagnostic::*;
use goguard_ir::ir::Span;

use crate::state_machine::TrackedResource;

/// Extract file, line, and column from an optional span.
fn extract_span(span: &Option<Span>) -> (String, u32, u32) {
    match span {
        Some(s) => (s.file.clone(), s.start_line, s.start_col),
        None => ("unknown".into(), 0, 0),
    }
}

/// OWN001: Resource opened but never closed.
///
/// Emitted when a function opens a resource (e.g., os.Open) but never
/// calls Close on it before returning.
pub fn build_own001(resource: &TrackedResource, func_name: &str) -> Diagnostic {
    let (file, line, col) = extract_span(&resource.span);
    DiagnosticBuilder::new(
        "OWN001",
        Severity::Error,
        "resource opened but never closed",
        DiagnosticSource::Ownership,
    )
    .location(&file, line, col)
    .confidence(0.85)
    .explanation(format!(
        "In function `{func_name}`, `{}` opens a resource that is never closed. \
         This causes a resource leak.",
        resource.opener_callee
    ))
    .fix(
        "Add defer close after open",
        vec![Edit {
            file: file.clone(),
            range: EditRange {
                start_line: line + 1,
                end_line: line + 1,
            },
            old_text: None,
            new_text: "defer resource.Close()".to_string(),
        }],
    )
    .pattern(
        "missing-resource-close",
        Frequency::VeryCommon,
        "Always defer Close() immediately after opening a resource",
    )
    .build()
}

/// OWN002: Use after close.
///
/// Emitted when a resource is used after it has been closed.
pub fn build_own002(
    resource: &TrackedResource,
    func_name: &str,
    use_span: &Option<Span>,
) -> Diagnostic {
    let (file, line, col) = extract_span(use_span);
    let (open_file, open_line, _) = extract_span(&resource.span);
    DiagnosticBuilder::new(
        "OWN002",
        Severity::Critical,
        "use after close",
        DiagnosticSource::Ownership,
    )
    .location(&file, line, col)
    .confidence(0.9)
    .explanation(format!(
        "In function `{func_name}`, resource opened by `{}` is used after being closed",
        resource.opener_callee
    ))
    .root_cause(
        &open_file,
        open_line,
        format!("resource opened by `{}`", resource.opener_callee),
    )
    .pattern(
        "use-after-close",
        Frequency::Common,
        "Do not use a resource after calling Close()",
    )
    .build()
}

/// OWN003: Double close.
///
/// Emitted when Close() is called on a resource that is already closed.
pub fn build_own003(
    resource: &TrackedResource,
    func_name: &str,
    second_close_span: &Option<Span>,
) -> Diagnostic {
    let (file, line, col) = extract_span(second_close_span);
    let (open_file, open_line, _) = extract_span(&resource.span);
    DiagnosticBuilder::new(
        "OWN003",
        Severity::Warning,
        "double close on resource",
        DiagnosticSource::Ownership,
    )
    .location(&file, line, col)
    .confidence(0.85)
    .explanation(format!(
        "In function `{func_name}`, resource opened by `{}` is closed more than once. \
         This may cause a panic or return an error at runtime.",
        resource.opener_callee
    ))
    .root_cause(
        &open_file,
        open_line,
        format!("resource opened by `{}`", resource.opener_callee),
    )
    .pattern(
        "double-close",
        Frequency::Uncommon,
        "Close a resource exactly once; use defer to ensure single close",
    )
    .build()
}

/// OWN004: Close not deferred.
///
/// Emitted when a resource is closed via a direct Close() call rather than
/// via `defer`. This is informational — not a bug, but not idiomatic Go.
pub fn build_own004(
    resource: &TrackedResource,
    func_name: &str,
    close_span: &Option<Span>,
) -> Diagnostic {
    let (file, line, col) = extract_span(close_span);
    DiagnosticBuilder::new(
        "OWN004",
        Severity::Info,
        "resource close not deferred",
        DiagnosticSource::Ownership,
    )
    .location(&file, line, col)
    .confidence(0.8)
    .explanation(format!(
        "In function `{func_name}`, resource opened by `{}` is closed directly instead of \
         using `defer`. Using defer ensures the resource is closed even if a panic occurs.",
        resource.opener_callee
    ))
    .fix(
        "Use defer to close the resource",
        vec![Edit {
            file: file.clone(),
            range: EditRange {
                start_line: line,
                end_line: line,
            },
            old_text: None,
            new_text: "defer resource.Close()".to_string(),
        }],
    )
    .pattern(
        "close-not-deferred",
        Frequency::Common,
        "Use defer Close() immediately after opening a resource",
    )
    .build()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state_machine::TrackedResource;
    use goguard_ir::ir::Span;

    fn make_resource(callee: &str, line: u32) -> TrackedResource {
        TrackedResource::new(0, callee.to_string(), Some(Span::new("main.go", line, 1)))
    }

    #[test]
    fn test_own001_diagnostic() {
        let res = make_resource("os.Open", 10);
        let diag = build_own001(&res, "HandleFile");
        assert_eq!(diag.rule, "OWN001");
        assert_eq!(diag.severity, Severity::Error);
        assert_eq!(diag.location.file, "main.go");
        assert_eq!(diag.location.line, 10);
        assert!(diag.explanation.contains("os.Open"));
        assert!(diag.explanation.contains("HandleFile"));
        assert!(diag.explanation.contains("never closed"));
        assert!(diag.fix.is_some());
        assert!(diag.pattern.is_some());
    }

    #[test]
    fn test_own002_diagnostic() {
        let res = make_resource("sql.Open", 5);
        let use_span = Some(Span::new("db.go", 20, 3));
        let diag = build_own002(&res, "QueryDB", &use_span);
        assert_eq!(diag.rule, "OWN002");
        assert_eq!(diag.severity, Severity::Critical);
        assert_eq!(diag.location.file, "db.go");
        assert_eq!(diag.location.line, 20);
        assert!(diag.explanation.contains("sql.Open"));
        assert!(diag.explanation.contains("after being closed"));
        assert!(diag.root_cause.is_some());
    }

    #[test]
    fn test_own003_diagnostic() {
        let res = make_resource("net.Dial", 8);
        let close_span = Some(Span::new("conn.go", 25, 1));
        let diag = build_own003(&res, "Connect", &close_span);
        assert_eq!(diag.rule, "OWN003");
        assert_eq!(diag.severity, Severity::Warning);
        assert_eq!(diag.location.file, "conn.go");
        assert_eq!(diag.location.line, 25);
        assert!(diag.explanation.contains("net.Dial"));
        assert!(diag.explanation.contains("more than once"));
    }

    #[test]
    fn test_own004_diagnostic() {
        let res = make_resource("os.Create", 12);
        let close_span = Some(Span::new("main.go", 30, 1));
        let diag = build_own004(&res, "WriteFile", &close_span);
        assert_eq!(diag.rule, "OWN004");
        assert_eq!(diag.severity, Severity::Info);
        assert_eq!(diag.location.file, "main.go");
        assert_eq!(diag.location.line, 30);
        assert!(diag.explanation.contains("os.Create"));
        assert!(diag.explanation.contains("defer"));
        assert!(diag.fix.is_some());
    }

    #[test]
    fn test_own001_no_span() {
        let res = TrackedResource::new(0, "os.Open".to_string(), None);
        let diag = build_own001(&res, "NoSpan");
        assert_eq!(diag.location.file, "unknown");
        assert_eq!(diag.location.line, 0);
    }

    #[test]
    fn test_own002_no_use_span() {
        let res = make_resource("os.Open", 10);
        let diag = build_own002(&res, "NoSpan", &None);
        assert_eq!(diag.location.file, "unknown");
        assert_eq!(diag.location.line, 0);
    }
}
