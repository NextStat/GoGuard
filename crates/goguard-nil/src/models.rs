//! Minimal external return models for nil analysis.
//!
//! These are conservative "never nil" facts for well-known functions whose
//! return types are nilable in Go (pointers/interfaces) but are documented to
//! never return nil in practice (e.g., `context.Background()`).

use std::collections::HashMap;
use std::sync::OnceLock;

use crate::summary::ReturnNilness;

static MODELS: OnceLock<HashMap<&'static str, HashMap<u32, ReturnNilness>>> = OnceLock::new();

/// Return model lookup keyed by (callee, return_index).
///
/// For single-return functions, `return_index` is `0`.
pub fn stdlib_return_model(callee: &str, return_index: u32) -> Option<ReturnNilness> {
    let models = MODELS.get_or_init(|| {
        let mut m: HashMap<&'static str, HashMap<u32, ReturnNilness>> = HashMap::new();

        let mut insert = |fqn: &'static str, idx: u32, nilness: ReturnNilness| {
            m.entry(fqn).or_default().insert(idx, nilness);
        };

        // context
        insert("context.Background", 0, ReturnNilness::Unconditional);
        insert("context.TODO", 0, ReturnNilness::Unconditional);
        insert("context.WithCancel", 0, ReturnNilness::Unconditional);
        insert("context.WithTimeout", 0, ReturnNilness::Unconditional);
        insert("context.WithValue", 0, ReturnNilness::Unconditional);
        insert("context.WithDeadline", 0, ReturnNilness::Unconditional);
        insert("context.WithCancelCause", 0, ReturnNilness::Unconditional);
        insert("context.WithTimeoutCause", 0, ReturnNilness::Unconditional);
        insert("context.WithDeadlineCause", 0, ReturnNilness::Unconditional);

        // bytes/strings/io
        insert("bytes.NewBuffer", 0, ReturnNilness::Unconditional);
        insert("bytes.NewBufferString", 0, ReturnNilness::Unconditional);
        insert("strings.NewReader", 0, ReturnNilness::Unconditional);
        insert("strings.NewReplacer", 0, ReturnNilness::Unconditional);
        insert("io.NopCloser", 0, ReturnNilness::Unconditional);

        // errors/fmt
        insert("errors.New", 0, ReturnNilness::Unconditional);
        insert("fmt.Errorf", 0, ReturnNilness::Unconditional);

        // encoding/json + xml
        insert("encoding/json.NewEncoder", 0, ReturnNilness::Unconditional);
        insert("encoding/json.NewDecoder", 0, ReturnNilness::Unconditional);
        insert("encoding/xml.NewEncoder", 0, ReturnNilness::Unconditional);
        insert("encoding/xml.NewDecoder", 0, ReturnNilness::Unconditional);

        // regexp (Must* variants panic on failure → never nil)
        insert("regexp.MustCompile", 0, ReturnNilness::Unconditional);
        insert("regexp.MustCompilePOSIX", 0, ReturnNilness::Unconditional);

        // bufio
        insert("bufio.NewReader", 0, ReturnNilness::Unconditional);
        insert("bufio.NewReaderSize", 0, ReturnNilness::Unconditional);
        insert("bufio.NewWriter", 0, ReturnNilness::Unconditional);
        insert("bufio.NewWriterSize", 0, ReturnNilness::Unconditional);
        insert("bufio.NewReadWriter", 0, ReturnNilness::Unconditional);
        insert("bufio.NewScanner", 0, ReturnNilness::Unconditional);

        // log
        insert("log.New", 0, ReturnNilness::Unconditional);
        insert("log.Default", 0, ReturnNilness::Unconditional);
        insert("log/slog.New", 0, ReturnNilness::Unconditional);
        insert("log/slog.Default", 0, ReturnNilness::Unconditional);

        // math/big
        insert("math/big.NewInt", 0, ReturnNilness::Unconditional);
        insert("math/big.NewFloat", 0, ReturnNilness::Unconditional);
        insert("math/big.NewRat", 0, ReturnNilness::Unconditional);

        // time
        insert("time.NewTicker", 0, ReturnNilness::Unconditional);
        insert("time.NewTimer", 0, ReturnNilness::Unconditional);

        // net/http
        insert("net/http.NewServeMux", 0, ReturnNilness::Unconditional);
        insert("net/http.NewRequest", 0, ReturnNilness::Unconditional); // non-nil even on error

        // template
        insert("text/template.New", 0, ReturnNilness::Unconditional);
        insert("html/template.New", 0, ReturnNilness::Unconditional);

        // sync
        insert("sync.NewCond", 0, ReturnNilness::Unconditional);

        // flag (all return non-nil pointers)
        insert("flag.String", 0, ReturnNilness::Unconditional);
        insert("flag.Bool", 0, ReturnNilness::Unconditional);
        insert("flag.Int", 0, ReturnNilness::Unconditional);
        insert("flag.Int64", 0, ReturnNilness::Unconditional);
        insert("flag.Uint", 0, ReturnNilness::Unconditional);
        insert("flag.Uint64", 0, ReturnNilness::Unconditional);
        insert("flag.Float64", 0, ReturnNilness::Unconditional);
        insert("flag.Duration", 0, ReturnNilness::Unconditional);

        m
    });

    models
        .get(callee)
        .and_then(|per_fn| per_fn.get(&return_index))
        .copied()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stdlib_model_context_background() {
        assert_eq!(
            stdlib_return_model("context.Background", 0),
            Some(ReturnNilness::Unconditional)
        );
    }

    #[test]
    fn test_stdlib_model_context_with_cancel_pos0() {
        assert_eq!(
            stdlib_return_model("context.WithCancel", 0),
            Some(ReturnNilness::Unconditional)
        );
    }

    #[test]
    fn test_stdlib_model_unknown_callee() {
        assert_eq!(stdlib_return_model("unknown.Foo", 0), None);
    }

    #[test]
    fn test_stdlib_model_wrong_index() {
        // context.Background only has pos 0 modeled
        assert_eq!(stdlib_return_model("context.Background", 1), None);
    }

    #[test]
    fn test_stdlib_model_regexp_must_compile() {
        assert_eq!(
            stdlib_return_model("regexp.MustCompile", 0),
            Some(ReturnNilness::Unconditional)
        );
    }

    #[test]
    fn test_stdlib_model_bufio() {
        assert_eq!(
            stdlib_return_model("bufio.NewReader", 0),
            Some(ReturnNilness::Unconditional)
        );
        assert_eq!(
            stdlib_return_model("bufio.NewScanner", 0),
            Some(ReturnNilness::Unconditional)
        );
    }

    #[test]
    fn test_stdlib_model_flag() {
        assert_eq!(
            stdlib_return_model("flag.String", 0),
            Some(ReturnNilness::Unconditional)
        );
        assert_eq!(
            stdlib_return_model("flag.Bool", 0),
            Some(ReturnNilness::Unconditional)
        );
    }

    #[test]
    fn test_stdlib_model_coverage() {
        // Verify all categories have at least one entry
        let categories = [
            "context.Background",
            "bytes.NewBuffer",
            "strings.NewReader",
            "io.NopCloser",
            "errors.New",
            "fmt.Errorf",
            "encoding/json.NewEncoder",
            "encoding/xml.NewDecoder",
            "regexp.MustCompile",
            "bufio.NewReader",
            "log.New",
            "log/slog.Default",
            "math/big.NewInt",
            "time.NewTicker",
            "net/http.NewServeMux",
            "text/template.New",
            "sync.NewCond",
            "flag.String",
        ];
        for callee in categories {
            assert_eq!(
                stdlib_return_model(callee, 0),
                Some(ReturnNilness::Unconditional),
                "missing model for {callee}"
            );
        }
    }
}
