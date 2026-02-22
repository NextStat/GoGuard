//! Taint sink definitions (SQL queries, command execution, etc.).
//!
//! Identifies Go functions that are dangerous when receiving tainted
//! (user-controlled) data, and sanitizers that break taint chains.

/// Categories of dangerous sinks.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SinkKind {
    /// SQL query execution (SQL injection risk).
    SqlQuery,
    /// OS command execution (command injection risk).
    CommandExec,
    /// File system path operations (path traversal risk).
    FilePath,
    /// HTML template rendering without escaping (XSS risk).
    HtmlOutput,
}

impl std::fmt::Display for SinkKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SqlQuery => write!(f, "SQL query"),
            Self::CommandExec => write!(f, "OS command execution"),
            Self::FilePath => write!(f, "file path operation"),
            Self::HtmlOutput => write!(f, "HTML output"),
        }
    }
}

/// Check if a callee is a sensitive sink.
/// Returns the sink kind and the indices of the dangerous arguments.
///
/// Argument indices are relative to the SSA call operands (receiver excluded
/// from index in Go SSA — the first operand after the receiver is index 0).
pub fn classify_sink(callee: &str) -> Option<(SinkKind, Vec<usize>)> {
    // SQL sinks — query string is the first argument (index 0).
    if (callee.contains("database/sql.DB") || callee.contains("database/sql.Tx"))
        && (callee.ends_with("Query")
            || callee.ends_with("Exec")
            || callee.ends_with("QueryRow")
            || callee.ends_with("QueryContext")
            || callee.ends_with("ExecContext")
            || callee.ends_with("QueryRowContext"))
    {
        // For Context variants the query is at index 1 (after context),
        // for non-Context variants it is at index 0.
        let idx = if callee.contains("Context") {
            vec![1]
        } else {
            vec![0]
        };
        return Some((SinkKind::SqlQuery, idx));
    }

    // Command execution sinks.
    if callee == "os/exec.Command" {
        return Some((SinkKind::CommandExec, vec![0]));
    }
    if callee == "os/exec.CommandContext" {
        return Some((SinkKind::CommandExec, vec![1]));
    }
    if callee == "syscall.Exec" {
        return Some((SinkKind::CommandExec, vec![0]));
    }

    // File path sinks — the path argument is at index 0.
    match callee {
        "os.Open" | "os.Create" | "os.OpenFile" | "os.ReadFile" | "os.WriteFile" | "os.Remove"
        | "os.RemoveAll" | "os.MkdirAll" | "os.Mkdir" | "os.Stat" | "os.Lstat" => {
            return Some((SinkKind::FilePath, vec![0]));
        }
        _ => {}
    }

    // XSS / HTML output sinks.
    if callee == "html/template.HTML" {
        return Some((SinkKind::HtmlOutput, vec![0]));
    }
    if callee.contains("html/template.Template") && callee.ends_with("Execute") {
        // The data argument is at index 1 (after io.Writer).
        return Some((SinkKind::HtmlOutput, vec![1]));
    }

    None
}

/// Check if a callee is a sanitizer that cleanses taint for a given sink kind.
pub fn is_sanitizer(callee: &str, sink_kind: &SinkKind) -> bool {
    match sink_kind {
        SinkKind::FilePath => matches!(
            callee,
            "path/filepath.Clean" | "path/filepath.Base" | "path.Clean" | "path.Base"
        ),
        SinkKind::HtmlOutput => matches!(
            callee,
            "html.EscapeString"
                | "html/template.HTMLEscapeString"
                | "url.QueryEscape"
                | "url.PathEscape"
        ),
        SinkKind::CommandExec => {
            // Converting to a number removes injection risk.
            matches!(
                callee,
                "strconv.Atoi" | "strconv.ParseInt" | "strconv.ParseUint" | "strconv.ParseFloat"
            )
        }
        SinkKind::SqlQuery => {
            // Parameterized queries are handled at the sink level (not as sanitizers),
            // but integer conversions also neutralize SQL injection.
            matches!(
                callee,
                "strconv.Atoi" | "strconv.ParseInt" | "strconv.ParseUint" | "strconv.ParseFloat"
            )
        }
    }
}

/// Check if a callee is a sanitizer for any sink kind.
pub fn is_any_sanitizer(callee: &str) -> bool {
    is_sanitizer(callee, &SinkKind::FilePath)
        || is_sanitizer(callee, &SinkKind::HtmlOutput)
        || is_sanitizer(callee, &SinkKind::CommandExec)
        || is_sanitizer(callee, &SinkKind::SqlQuery)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_classify_sql_query() {
        let result = classify_sink("(*database/sql.DB).Query");
        assert_eq!(result, Some((SinkKind::SqlQuery, vec![0])));

        let result2 = classify_sink("(*database/sql.DB).Exec");
        assert_eq!(result2, Some((SinkKind::SqlQuery, vec![0])));

        let result3 = classify_sink("(*database/sql.DB).QueryRow");
        assert_eq!(result3, Some((SinkKind::SqlQuery, vec![0])));

        let result4 = classify_sink("(*database/sql.Tx).Query");
        assert_eq!(result4, Some((SinkKind::SqlQuery, vec![0])));

        let result5 = classify_sink("(*database/sql.Tx).Exec");
        assert_eq!(result5, Some((SinkKind::SqlQuery, vec![0])));

        // Context variants have query at index 1.
        let result6 = classify_sink("(*database/sql.DB).QueryContext");
        assert_eq!(result6, Some((SinkKind::SqlQuery, vec![1])));
    }

    #[test]
    fn test_classify_exec_command() {
        let result = classify_sink("os/exec.Command");
        assert_eq!(result, Some((SinkKind::CommandExec, vec![0])));

        let result2 = classify_sink("os/exec.CommandContext");
        assert_eq!(result2, Some((SinkKind::CommandExec, vec![1])));

        let result3 = classify_sink("syscall.Exec");
        assert_eq!(result3, Some((SinkKind::CommandExec, vec![0])));
    }

    #[test]
    fn test_classify_os_open() {
        let result = classify_sink("os.Open");
        assert_eq!(result, Some((SinkKind::FilePath, vec![0])));

        let result2 = classify_sink("os.Create");
        assert_eq!(result2, Some((SinkKind::FilePath, vec![0])));

        let result3 = classify_sink("os.OpenFile");
        assert_eq!(result3, Some((SinkKind::FilePath, vec![0])));

        let result4 = classify_sink("os.ReadFile");
        assert_eq!(result4, Some((SinkKind::FilePath, vec![0])));

        let result5 = classify_sink("os.WriteFile");
        assert_eq!(result5, Some((SinkKind::FilePath, vec![0])));

        let result6 = classify_sink("os.Remove");
        assert_eq!(result6, Some((SinkKind::FilePath, vec![0])));

        let result7 = classify_sink("os.MkdirAll");
        assert_eq!(result7, Some((SinkKind::FilePath, vec![0])));
    }

    #[test]
    fn test_classify_html_template() {
        let result = classify_sink("html/template.HTML");
        assert_eq!(result, Some((SinkKind::HtmlOutput, vec![0])));

        let result2 = classify_sink("(*html/template.Template).Execute");
        assert_eq!(result2, Some((SinkKind::HtmlOutput, vec![1])));
    }

    #[test]
    fn test_is_sanitizer_filepath_clean() {
        assert!(is_sanitizer("path/filepath.Clean", &SinkKind::FilePath));
        assert!(is_sanitizer("path/filepath.Base", &SinkKind::FilePath));
        assert!(!is_sanitizer("path/filepath.Clean", &SinkKind::SqlQuery));
    }

    #[test]
    fn test_is_sanitizer_html_escape() {
        assert!(is_sanitizer("html.EscapeString", &SinkKind::HtmlOutput));
        assert!(is_sanitizer("url.QueryEscape", &SinkKind::HtmlOutput));
        assert!(!is_sanitizer("html.EscapeString", &SinkKind::FilePath));
    }

    #[test]
    fn test_is_sanitizer_strconv() {
        assert!(is_sanitizer("strconv.Atoi", &SinkKind::CommandExec));
        assert!(is_sanitizer("strconv.ParseInt", &SinkKind::SqlQuery));
    }

    #[test]
    fn test_classify_non_sink_returns_none() {
        assert_eq!(classify_sink("fmt.Println"), None);
        assert_eq!(classify_sink("strings.Join"), None);
        assert_eq!(classify_sink("log.Printf"), None);
    }

    #[test]
    fn test_sink_kind_display() {
        assert_eq!(SinkKind::SqlQuery.to_string(), "SQL query");
        assert_eq!(SinkKind::CommandExec.to_string(), "OS command execution");
        assert_eq!(SinkKind::FilePath.to_string(), "file path operation");
        assert_eq!(SinkKind::HtmlOutput.to_string(), "HTML output");
    }

    #[test]
    fn test_is_any_sanitizer() {
        assert!(is_any_sanitizer("path/filepath.Clean"));
        assert!(is_any_sanitizer("html.EscapeString"));
        assert!(is_any_sanitizer("strconv.Atoi"));
        assert!(!is_any_sanitizer("fmt.Sprintf"));
    }
}
