//! JavaScript runtime for GoGuard "Code Mode" queries.
//!
//! Wraps [`boa_engine`] to execute arbitrary JavaScript code and return results
//! as [`serde_json::Value`]. This module provides the foundational JS execution
//! layer; GoGuard-specific API bindings (e.g., `goguard.diagnostics()`) are
//! added separately in the `js_api` module.

use std::time::{Duration, Instant};

use boa_engine::{Context, JsNativeErrorKind, Source};
use thiserror::Error;

/// Errors that can occur during JavaScript execution.
#[derive(Debug, Error)]
pub enum JsRuntimeError {
    /// The JavaScript code contains a syntax error.
    #[error("JavaScript syntax error: {0}")]
    SyntaxError(String),

    /// A runtime error occurred during execution (e.g., `TypeError`).
    #[error("JavaScript runtime error: {0}")]
    RuntimeError(String),

    /// Execution exceeded the configured timeout.
    #[error("Execution timeout after {0}ms")]
    Timeout(u64),

    /// The result could not be converted to JSON.
    #[error("Failed to convert result to JSON: {0}")]
    ConversionError(String),
}

/// Configuration for the JavaScript runtime.
#[derive(Debug, Clone)]
pub struct JsRuntimeConfig {
    /// Maximum execution time before timeout.
    pub timeout: Duration,
    /// Maximum number of loop iterations allowed (prevents infinite loops).
    pub loop_iteration_limit: u64,
    /// Maximum recursion depth allowed (prevents stack overflow).
    pub recursion_limit: usize,
}

impl Default for JsRuntimeConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(5),
            loop_iteration_limit: 1_000_000,
            recursion_limit: 512,
        }
    }
}

/// A JavaScript runtime powered by [`boa_engine`].
///
/// Each call to [`execute`](JsRuntime::execute) creates a fresh boa `Context`,
/// ensuring isolation between executions. Runtime limits (loop iterations,
/// recursion depth) are enforced to prevent runaway scripts.
///
/// # Examples
///
/// ```
/// use goguard_db::js_runtime::JsRuntime;
///
/// let rt = JsRuntime::new();
/// let result = rt.execute("1 + 2").unwrap();
/// assert_eq!(result, serde_json::json!(3));
/// ```
pub struct JsRuntime {
    config: JsRuntimeConfig,
}

impl JsRuntime {
    /// Create a new `JsRuntime` with default configuration (5s timeout).
    pub fn new() -> Self {
        Self {
            config: JsRuntimeConfig::default(),
        }
    }

    /// Create a new `JsRuntime` with a custom timeout.
    pub fn with_timeout(timeout: Duration) -> Self {
        Self {
            config: JsRuntimeConfig {
                timeout,
                ..Default::default()
            },
        }
    }

    /// Create a new `JsRuntime` with full custom configuration.
    pub fn with_config(config: JsRuntimeConfig) -> Self {
        Self { config }
    }

    /// Return the current configuration.
    pub fn config(&self) -> &JsRuntimeConfig {
        &self.config
    }

    /// Execute JavaScript code and return the result as JSON.
    ///
    /// The code should be a JavaScript expression or sequence of statements whose
    /// last expression value will be returned. For example:
    ///
    /// - `"1 + 2"` returns `3`
    /// - `"({name: 'test', count: 42})"` returns `{"name":"test","count":42}`
    /// - `"[1,2,3].map(x => x * 2)"` returns `[2,4,6]`
    ///
    /// `undefined` results are returned as `serde_json::Value::Null`.
    pub fn execute(&self, code: &str) -> Result<serde_json::Value, JsRuntimeError> {
        self.execute_with_setup(code, |_| Ok(()))
    }

    /// Execute JavaScript code with a setup closure that runs before eval.
    ///
    /// The `setup` closure receives a mutable reference to the boa [`Context`],
    /// allowing callers to register globals, APIs, or other pre-eval configuration.
    /// This is used by [`QueryEngine::execute_js`](crate::query_engine::QueryEngine::execute_js)
    /// to register the `goguard` global object.
    pub fn execute_with_setup<F>(
        &self,
        code: &str,
        setup: F,
    ) -> Result<serde_json::Value, JsRuntimeError>
    where
        F: FnOnce(&mut Context) -> Result<(), JsRuntimeError>,
    {
        let mut context = Context::default();

        // Enforce runtime limits to prevent infinite loops and deep recursion.
        context
            .runtime_limits_mut()
            .set_loop_iteration_limit(self.config.loop_iteration_limit);
        context
            .runtime_limits_mut()
            .set_recursion_limit(self.config.recursion_limit);

        // Run caller-provided setup (e.g., register APIs).
        setup(&mut context)?;

        let start = Instant::now();

        // Execute the JavaScript code.
        let result = context.eval(Source::from_bytes(code.as_bytes()));

        // Check wall-clock timeout (boa's runtime limits handle infinite loops,
        // but we also guard against long-running computations).
        if start.elapsed() > self.config.timeout {
            return Err(JsRuntimeError::Timeout(
                self.config.timeout.as_millis() as u64
            ));
        }

        match result {
            Ok(value) => {
                // Convert JsValue to serde_json::Value.
                // to_json returns JsResult<Option<Value>> — None means undefined.
                match value.to_json(&mut context) {
                    Ok(Some(json)) => Ok(json),
                    Ok(None) => {
                        // undefined → null in JSON
                        Ok(serde_json::Value::Null)
                    }
                    Err(e) => Err(JsRuntimeError::ConversionError(e.to_string())),
                }
            }
            Err(err) => {
                // Classify using boa's structured error types when available.
                if let Some(native) = err.as_native() {
                    match &native.kind {
                        JsNativeErrorKind::RuntimeLimit => Err(JsRuntimeError::Timeout(
                            self.config.timeout.as_millis() as u64,
                        )),
                        JsNativeErrorKind::Syntax => {
                            Err(JsRuntimeError::SyntaxError(err.to_string()))
                        }
                        _ => Err(JsRuntimeError::RuntimeError(err.to_string())),
                    }
                } else {
                    // Opaque throw (e.g., `throw "some string"`)
                    Err(JsRuntimeError::RuntimeError(err.to_string()))
                }
            }
        }
    }
}

impl Default for JsRuntime {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // -- Basic expression tests --

    #[test]
    fn test_execute_simple_expression() {
        let rt = JsRuntime::new();
        let result = rt.execute("1 + 2").unwrap();
        assert_eq!(result, json!(3));
    }

    #[test]
    fn test_execute_string_expression() {
        let rt = JsRuntime::new();
        let result = rt.execute("'hello' + ' world'").unwrap();
        assert_eq!(result, json!("hello world"));
    }

    #[test]
    fn test_execute_object_literal() {
        let rt = JsRuntime::new();
        let result = rt.execute("({name: 'test', count: 42})").unwrap();
        assert_eq!(result, json!({"name": "test", "count": 42}));
    }

    #[test]
    fn test_execute_array() {
        let rt = JsRuntime::new();
        let result = rt.execute("[1, 2, 3].map(x => x * 2)").unwrap();
        assert_eq!(result, json!([2, 4, 6]));
    }

    #[test]
    fn test_execute_filter_and_map() {
        let rt = JsRuntime::new();
        let result = rt
            .execute("([{s:'a',v:1},{s:'b',v:2}].filter(x => x.v > 1).map(x => x.s))")
            .unwrap();
        assert_eq!(result, json!(["b"]));
    }

    // -- Error tests --

    #[test]
    fn test_syntax_error() {
        let rt = JsRuntime::new();
        let result = rt.execute("function {}");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, JsRuntimeError::SyntaxError(_)),
            "Expected SyntaxError, got: {err:?}"
        );
    }

    #[test]
    fn test_runtime_error() {
        let rt = JsRuntime::new();
        let result = rt.execute("null.foo");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, JsRuntimeError::RuntimeError(_)),
            "Expected RuntimeError, got: {err:?}"
        );
    }

    // -- Null/undefined tests --

    #[test]
    fn test_undefined_result() {
        let rt = JsRuntime::new();
        let result = rt.execute("undefined").unwrap();
        assert_eq!(result, json!(null));
    }

    #[test]
    fn test_null_result() {
        let rt = JsRuntime::new();
        let result = rt.execute("null").unwrap();
        assert_eq!(result, json!(null));
    }

    // -- Constructor / config tests --

    #[test]
    fn test_with_timeout_constructor() {
        let rt = JsRuntime::with_timeout(Duration::from_millis(100));
        assert_eq!(rt.config().timeout, Duration::from_millis(100));
    }

    #[test]
    fn test_default_timeout() {
        let rt = JsRuntime::new();
        assert_eq!(rt.config().timeout, Duration::from_secs(5));
    }

    #[test]
    fn test_with_config() {
        let config = JsRuntimeConfig {
            timeout: Duration::from_secs(10),
            loop_iteration_limit: 500,
            recursion_limit: 100,
        };
        let rt = JsRuntime::with_config(config.clone());
        assert_eq!(rt.config().timeout, Duration::from_secs(10));
        assert_eq!(rt.config().loop_iteration_limit, 500);
        assert_eq!(rt.config().recursion_limit, 100);
    }

    // -- IIFE and complex expression tests --

    #[test]
    fn test_execute_iife() {
        let rt = JsRuntime::new();
        let result = rt
            .execute("(function() { return {a: 1, b: [2, 3]}; })()")
            .unwrap();
        assert_eq!(result, json!({"a": 1, "b": [2, 3]}));
    }

    #[test]
    fn test_execute_multiline_statements() {
        let rt = JsRuntime::new();
        let result = rt
            .execute(
                r#"
                let items = [10, 20, 30];
                let sum = items.reduce((a, b) => a + b, 0);
                sum
                "#,
            )
            .unwrap();
        assert_eq!(result, json!(60));
    }

    #[test]
    fn test_execute_boolean_result() {
        let rt = JsRuntime::new();
        let result = rt.execute("true").unwrap();
        assert_eq!(result, json!(true));

        let result = rt.execute("false").unwrap();
        assert_eq!(result, json!(false));
    }

    #[test]
    fn test_execute_nested_objects() {
        let rt = JsRuntime::new();
        let result = rt.execute("({outer: {inner: [1, {deep: true}]}})").unwrap();
        assert_eq!(result, json!({"outer": {"inner": [1, {"deep": true}]}}));
    }

    // -- Runtime limits tests --

    #[test]
    fn test_infinite_loop_stopped_by_limit() {
        let rt = JsRuntime::with_config(JsRuntimeConfig {
            timeout: Duration::from_secs(5),
            loop_iteration_limit: 100,
            recursion_limit: 512,
        });
        let result = rt.execute("while(true) {}");
        assert!(result.is_err(), "Infinite loop should be stopped");
        let err = result.unwrap_err();
        assert!(
            matches!(err, JsRuntimeError::Timeout(_)),
            "Expected Timeout from RuntimeLimit, got: {err:?}"
        );
    }

    #[test]
    fn test_deep_recursion_stopped_by_limit() {
        let rt = JsRuntime::with_config(JsRuntimeConfig {
            timeout: Duration::from_secs(5),
            loop_iteration_limit: 1_000_000,
            recursion_limit: 10,
        });
        let result = rt.execute(
            r#"
            function recurse(n) { return recurse(n + 1); }
            recurse(0)
            "#,
        );
        assert!(result.is_err(), "Deep recursion should be stopped");
        let err = result.unwrap_err();
        assert!(
            matches!(err, JsRuntimeError::Timeout(_)),
            "Expected Timeout from RuntimeLimit, got: {err:?}"
        );
    }

    // -- Isolation test --

    #[test]
    fn test_execution_isolation() {
        let rt = JsRuntime::new();
        // First execution defines a variable.
        let _ = rt.execute("var x = 42; x");
        // Second execution should NOT see that variable (fresh context).
        let result = rt.execute("typeof x");
        assert_eq!(result.unwrap(), json!("undefined"));
    }

    // -- Opaque throw test --

    #[test]
    fn test_opaque_throw() {
        let rt = JsRuntime::new();
        let result = rt.execute(r#"throw "just a string""#);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, JsRuntimeError::RuntimeError(_)),
            "Opaque throw should be RuntimeError, got: {err:?}"
        );
    }
}
