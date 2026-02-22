//! Pattern database for storing and querying learned code patterns.
//!
//! Contains the built-in database of common Go patterns that GoGuard
//! recognizes, categorized by analysis domain.

use serde::{Deserialize, Serialize};

/// Category of a Go code pattern.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PatternCategory {
    /// Nil pointer return and dereference patterns.
    NilReturn,
    /// Error handling and propagation patterns.
    ErrorHandling,
    /// Resource acquisition, release, and lifecycle patterns.
    ResourceLifecycle,
    /// Goroutine and channel concurrency patterns.
    Concurrency,
}

/// Information about a known Go code pattern.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternInfo {
    /// Short identifier for the pattern (e.g., "partial_result_on_error").
    pub name: String,
    /// Human-readable description of the pattern.
    pub description: String,
    /// Which analysis domain this pattern belongs to.
    pub category: PatternCategory,
}

/// Returns the built-in database of common Go patterns.
///
/// These patterns represent well-known Go idioms that GoGuard uses
/// to inform its analysis and elicitation questions.
pub fn builtin_patterns() -> Vec<PatternInfo> {
    vec![
        PatternInfo {
            name: "partial_result_on_error".into(),
            description: "Function returns non-nil result alongside non-nil error".into(),
            category: PatternCategory::NilReturn,
        },
        PatternInfo {
            name: "error_sentinel".into(),
            description: "Package defines sentinel error values for comparison".into(),
            category: PatternCategory::ErrorHandling,
        },
        PatternInfo {
            name: "resource_pool".into(),
            description: "Resource acquired from pool, returned instead of closed".into(),
            category: PatternCategory::ResourceLifecycle,
        },
        PatternInfo {
            name: "worker_goroutine".into(),
            description: "Long-running goroutine with graceful shutdown via context".into(),
            category: PatternCategory::Concurrency,
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pattern_db_builtin_not_empty() {
        let patterns = builtin_patterns();
        assert!(
            !patterns.is_empty(),
            "builtin pattern database should not be empty"
        );
        assert_eq!(patterns.len(), 4);

        // Verify each pattern has non-empty fields
        for p in &patterns {
            assert!(!p.name.is_empty(), "pattern name should not be empty");
            assert!(
                !p.description.is_empty(),
                "pattern description should not be empty"
            );
        }
    }

    #[test]
    fn test_pattern_db_categories() {
        let patterns = builtin_patterns();

        let nil_patterns: Vec<_> = patterns
            .iter()
            .filter(|p| p.category == PatternCategory::NilReturn)
            .collect();
        assert!(!nil_patterns.is_empty(), "should have NilReturn patterns");
        assert_eq!(nil_patterns[0].name, "partial_result_on_error");

        let err_patterns: Vec<_> = patterns
            .iter()
            .filter(|p| p.category == PatternCategory::ErrorHandling)
            .collect();
        assert!(
            !err_patterns.is_empty(),
            "should have ErrorHandling patterns"
        );

        let resource_patterns: Vec<_> = patterns
            .iter()
            .filter(|p| p.category == PatternCategory::ResourceLifecycle)
            .collect();
        assert!(
            !resource_patterns.is_empty(),
            "should have ResourceLifecycle patterns"
        );

        let concurrency_patterns: Vec<_> = patterns
            .iter()
            .filter(|p| p.category == PatternCategory::Concurrency)
            .collect();
        assert!(
            !concurrency_patterns.is_empty(),
            "should have Concurrency patterns"
        );
    }
}
