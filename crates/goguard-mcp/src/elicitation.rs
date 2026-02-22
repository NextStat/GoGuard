//! MCP elicitation for interactive disambiguation with AI agents.
//!
//! When GoGuard encounters an ambiguous pattern (e.g., a function that
//! returns `(*T, error)` — is `*T` always nil when `error` is non-nil?),
//! it can generate an elicitation request for the AI agent to ask the user.

use serde::{Deserialize, Serialize};

/// An elicitation request to ask the user about an ambiguous pattern.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ElicitationRequest {
    /// Unique key identifying the pattern (used for caching decisions).
    pub pattern_key: String,
    /// The question to present to the user.
    pub question: String,
    /// Available options the user can choose from.
    pub options: Vec<ElicitationOption>,
    /// Optional additional context to help the user decide.
    pub context: Option<String>,
}

/// A single option in an elicitation request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ElicitationOption {
    /// Machine-readable value (e.g., "always_nil_on_error").
    pub value: String,
    /// Human-readable short label.
    pub label: String,
    /// Optional longer description of this choice.
    pub description: Option<String>,
}

/// A response to an elicitation request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ElicitationResponse {
    /// The pattern key this response is for.
    pub pattern_key: String,
    /// The chosen answer value.
    pub answer: String,
}

/// Create an elicitation request for a nil-return pattern.
///
/// Used when GoGuard encounters a function returning `(*T, error)` and
/// needs to know whether `*T` can be non-nil when `error` is also non-nil.
pub fn nil_return_elicitation(function_name: &str) -> ElicitationRequest {
    ElicitationRequest {
        pattern_key: format!("nil_return:{}", function_name),
        question: format!(
            "Function {} returns (*T, error). When err != nil, can *T still be non-nil?",
            function_name
        ),
        options: vec![
            ElicitationOption {
                value: "always_nil_on_error".into(),
                label: "Always nil on error".into(),
                description: Some("When error is non-nil, the pointer is always nil".into()),
            },
            ElicitationOption {
                value: "partial_result_possible".into(),
                label: "Partial result possible".into(),
                description: Some(
                    "The pointer may contain a partial result even when error is non-nil".into(),
                ),
            },
        ],
        context: None,
    }
}

/// Create an elicitation request for a resource lifecycle pattern.
///
/// Used when GoGuard encounters a resource that might be pool-managed
/// (returned to pool) rather than directly closed.
pub fn resource_lifecycle_elicitation(
    resource_type: &str,
    function_name: &str,
) -> ElicitationRequest {
    ElicitationRequest {
        pattern_key: format!("resource_lifecycle:{}:{}", resource_type, function_name),
        question: format!(
            "Resource of type {} in {} - is it managed by a pool (returned, not closed)?",
            resource_type, function_name
        ),
        options: vec![
            ElicitationOption {
                value: "owned".into(),
                label: "Owned - must be closed".into(),
                description: Some(
                    "This resource is owned by the caller and must be explicitly closed".into(),
                ),
            },
            ElicitationOption {
                value: "pooled".into(),
                label: "Pooled - returned to pool".into(),
                description: Some(
                    "This resource comes from a pool and should be returned, not closed".into(),
                ),
            },
        ],
        context: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nil_return_elicitation_has_two_options() {
        let req = nil_return_elicitation("example.com/pkg.GetUser");

        assert_eq!(req.pattern_key, "nil_return:example.com/pkg.GetUser");
        assert!(req.question.contains("example.com/pkg.GetUser"));
        assert!(req.question.contains("(*T, error)"));
        assert_eq!(req.options.len(), 2);
        assert_eq!(req.options[0].value, "always_nil_on_error");
        assert_eq!(req.options[1].value, "partial_result_possible");
        assert!(req.context.is_none());

        // Verify options have labels and descriptions
        for opt in &req.options {
            assert!(!opt.label.is_empty());
            assert!(opt.description.is_some());
        }
    }

    #[test]
    fn test_resource_lifecycle_elicitation() {
        let req = resource_lifecycle_elicitation("*sql.DB", "example.com/pkg.HandleRequest");

        assert_eq!(
            req.pattern_key,
            "resource_lifecycle:*sql.DB:example.com/pkg.HandleRequest"
        );
        assert!(req.question.contains("*sql.DB"));
        assert!(req.question.contains("example.com/pkg.HandleRequest"));
        assert_eq!(req.options.len(), 2);
        assert_eq!(req.options[0].value, "owned");
        assert_eq!(req.options[1].value, "pooled");

        // Verify labels
        assert!(req.options[0].label.contains("Owned"));
        assert!(req.options[1].label.contains("Pooled"));
    }

    #[test]
    fn test_elicitation_request_serialization() {
        let req = nil_return_elicitation("pkg.Foo");

        // Serialize to JSON
        let json = serde_json::to_string_pretty(&req).expect("should serialize");
        assert!(json.contains("nil_return:pkg.Foo"));
        assert!(json.contains("always_nil_on_error"));
        assert!(json.contains("partial_result_possible"));

        // Deserialize back
        let deserialized: ElicitationRequest =
            serde_json::from_str(&json).expect("should deserialize");
        assert_eq!(deserialized.pattern_key, req.pattern_key);
        assert_eq!(deserialized.question, req.question);
        assert_eq!(deserialized.options.len(), req.options.len());

        // Round-trip for ElicitationResponse too
        let resp = ElicitationResponse {
            pattern_key: "nil_return:pkg.Foo".into(),
            answer: "always_nil_on_error".into(),
        };
        let resp_json = serde_json::to_string(&resp).expect("should serialize response");
        let resp_back: ElicitationResponse =
            serde_json::from_str(&resp_json).expect("should deserialize response");
        assert_eq!(resp_back.pattern_key, "nil_return:pkg.Foo");
        assert_eq!(resp_back.answer, "always_nil_on_error");
    }
}
