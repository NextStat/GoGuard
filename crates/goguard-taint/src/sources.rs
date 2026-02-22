//! Taint source definitions (user input, network, etc.).
//!
//! Identifies Go functions and instructions that produce tainted data
//! (data originating from untrusted external sources).

use goguard_ir::ir::{Instruction, ValueKind};

/// Categories of taint sources.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TaintSource {
    /// HTTP request data (body, query params, headers, URL).
    HttpRequest,
    /// Command-line arguments (os.Args).
    CommandLineArgs,
    /// Environment variables (os.Getenv).
    EnvironmentVar,
    /// Standard input (bufio.Scanner, os.Stdin).
    StdInput,
    /// File content read from user-controlled path.
    FileContent,
    /// Tainted by caller passing tainted argument (inter-procedural).
    CrossFunction,
}

impl std::fmt::Display for TaintSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::HttpRequest => write!(f, "HTTP request"),
            Self::CommandLineArgs => write!(f, "command-line arguments"),
            Self::EnvironmentVar => write!(f, "environment variable"),
            Self::StdInput => write!(f, "standard input"),
            Self::FileContent => write!(f, "file content"),
            Self::CrossFunction => write!(f, "cross-function taint"),
        }
    }
}

/// Check if a callee name corresponds to a known taint source.
/// Returns the source category if so.
pub fn classify_source(callee: &str) -> Option<TaintSource> {
    // HTTP request sources
    if callee.contains("net/http.Request") || callee.contains("net/http.Header") {
        return Some(TaintSource::HttpRequest);
    }
    // io.ReadAll is commonly used to read HTTP request bodies.
    if callee == "io.ReadAll" || callee == "io/ioutil.ReadAll" {
        return Some(TaintSource::HttpRequest);
    }

    // Environment variable sources
    if callee == "os.Getenv" || callee == "os.LookupEnv" {
        return Some(TaintSource::EnvironmentVar);
    }

    // Standard input sources
    if callee.contains("bufio.Scanner") && (callee.ends_with("Text") || callee.ends_with("Bytes")) {
        return Some(TaintSource::StdInput);
    }
    if callee.contains("bufio.Reader") && callee.ends_with("ReadString") {
        return Some(TaintSource::StdInput);
    }

    // File content sources
    if callee == "os.ReadFile" || callee == "io/ioutil.ReadFile" {
        return Some(TaintSource::FileContent);
    }
    if callee.contains("os.File") && callee.ends_with("Read") {
        return Some(TaintSource::FileContent);
    }

    None
}

/// Check if an instruction itself is a taint source (e.g., Global "os.Args"
/// or a Parameter with HTTP request type).
pub fn is_source_instruction(instr: &Instruction) -> Option<TaintSource> {
    match instr.kind {
        ValueKind::Global => {
            if instr.name == "os.Args" || instr.callee.as_deref() == Some("os.Args") {
                return Some(TaintSource::CommandLineArgs);
            }
            None
        }
        ValueKind::Parameter => {
            // Parameters whose type name indicates an HTTP request are taint sources.
            let name = &instr.name;
            if name.contains("http.Request")
                || name.contains("*net/http.Request")
                || name.contains("net/http.Request")
            {
                return Some(TaintSource::HttpRequest);
            }
            None
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use goguard_ir::ir::{Instruction, Span, ValueKind};

    fn make_instr(id: u32, kind: ValueKind, name: &str, type_id: u32) -> Instruction {
        Instruction {
            id,
            kind,
            name: name.into(),
            type_id,
            span: Some(Span::new("test.go", id + 10, 1)),
            operands: vec![],
            extract_index: 0,
            callee: None,
            callee_is_interface: false,
            assert_type_id: 0,
            comma_ok: false,
            const_value: None,
            is_nil: false,
            bin_op: None,
            nil_operand_indices: vec![],
            select_cases: vec![],
            channel_dir: None,
        }
    }

    #[test]
    fn test_classify_http_request_form_value() {
        let result = classify_source("(*net/http.Request).FormValue");
        assert_eq!(result, Some(TaintSource::HttpRequest));

        let result2 = classify_source("(*net/http.Request).PostFormValue");
        assert_eq!(result2, Some(TaintSource::HttpRequest));

        let result3 = classify_source("(*net/http.Request).Header.Get");
        assert_eq!(result3, Some(TaintSource::HttpRequest));

        let result4 = classify_source("(*net/http.Request).URL.Query");
        assert_eq!(result4, Some(TaintSource::HttpRequest));

        let result5 = classify_source("(*net/http.Request).Cookie");
        assert_eq!(result5, Some(TaintSource::HttpRequest));
    }

    #[test]
    fn test_classify_os_getenv() {
        let result = classify_source("os.Getenv");
        assert_eq!(result, Some(TaintSource::EnvironmentVar));

        let result2 = classify_source("os.LookupEnv");
        assert_eq!(result2, Some(TaintSource::EnvironmentVar));
    }

    #[test]
    fn test_classify_os_args_global() {
        let mut instr = make_instr(0, ValueKind::Global, "os.Args", 0);
        instr.callee = Some("os.Args".into());
        let result = is_source_instruction(&instr);
        assert_eq!(result, Some(TaintSource::CommandLineArgs));
    }

    #[test]
    fn test_classify_non_source_returns_none() {
        assert_eq!(classify_source("fmt.Println"), None);
        assert_eq!(classify_source("strings.Join"), None);
        assert_eq!(classify_source("math.Abs"), None);

        let instr = make_instr(0, ValueKind::Call, "t0", 0);
        assert_eq!(is_source_instruction(&instr), None);
    }

    #[test]
    fn test_parameter_http_request_is_source() {
        let instr = make_instr(0, ValueKind::Parameter, "*net/http.Request", 0);
        let result = is_source_instruction(&instr);
        assert_eq!(result, Some(TaintSource::HttpRequest));

        let instr2 = make_instr(1, ValueKind::Parameter, "net/http.Request", 0);
        let result2 = is_source_instruction(&instr2);
        assert_eq!(result2, Some(TaintSource::HttpRequest));
    }

    #[test]
    fn test_classify_stdin_sources() {
        let result = classify_source("(*bufio.Scanner).Text");
        assert_eq!(result, Some(TaintSource::StdInput));

        let result2 = classify_source("(*bufio.Scanner).Bytes");
        assert_eq!(result2, Some(TaintSource::StdInput));
    }

    #[test]
    fn test_classify_file_content_sources() {
        let result = classify_source("os.ReadFile");
        assert_eq!(result, Some(TaintSource::FileContent));

        let result2 = classify_source("(*os.File).Read");
        assert_eq!(result2, Some(TaintSource::FileContent));
    }

    #[test]
    fn test_classify_io_readall() {
        let result = classify_source("io.ReadAll");
        assert_eq!(result, Some(TaintSource::HttpRequest));
    }

    #[test]
    fn test_taint_source_display() {
        assert_eq!(TaintSource::HttpRequest.to_string(), "HTTP request");
        assert_eq!(
            TaintSource::CommandLineArgs.to_string(),
            "command-line arguments"
        );
        assert_eq!(
            TaintSource::EnvironmentVar.to_string(),
            "environment variable"
        );
        assert_eq!(TaintSource::StdInput.to_string(), "standard input");
        assert_eq!(TaintSource::FileContent.to_string(), "file content");
        assert_eq!(
            TaintSource::CrossFunction.to_string(),
            "cross-function taint"
        );
    }
}
