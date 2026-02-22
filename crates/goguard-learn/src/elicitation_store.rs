//! Storage for elicitation responses and learned preferences.
//!
//! Tracks which patterns have been asked about and the user's decisions,
//! so GoGuard avoids re-asking the same questions.

use crate::annotations::AnnotationError;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// A recorded elicitation decision.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ElicitationDecision {
    /// Unique key identifying the pattern (e.g., "nil_return:pkg.Func").
    pub pattern_key: String,
    /// The question that was asked.
    pub question: String,
    /// The user's chosen answer.
    pub answer: String,
    /// When this decision was recorded (ISO 8601 string).
    pub timestamp: String,
    /// Return type fingerprint for invalidation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub return_type_fingerprint: Option<String>,
}

/// Tracks elicitation decisions to avoid re-asking the same questions.
///
/// Decisions are persisted as a JSON file in the store directory.
#[derive(Clone)]
pub struct ElicitationStore {
    pub decisions: HashMap<String, ElicitationDecision>,
    path: PathBuf,
}

impl ElicitationStore {
    /// Create or load an elicitation store from a directory.
    ///
    /// Creates the directory if it does not exist, then loads
    /// `elicitations.json` if present.
    pub fn new(dir: &Path) -> Result<Self, AnnotationError> {
        std::fs::create_dir_all(dir)?;

        let file_path = dir.join("elicitations.json");
        let decisions = if file_path.exists() {
            let content = std::fs::read_to_string(&file_path)?;
            let list: Vec<ElicitationDecision> = serde_json::from_str(&content)?;
            list.into_iter()
                .map(|d| (d.pattern_key.clone(), d))
                .collect()
        } else {
            HashMap::new()
        };

        Ok(Self {
            decisions,
            path: dir.to_path_buf(),
        })
    }

    /// Check if a decision has already been recorded for a pattern.
    pub fn has_decision(&self, pattern_key: &str) -> bool {
        self.decisions.contains_key(pattern_key)
    }

    /// Get a recorded decision by pattern key.
    pub fn get_decision(&self, pattern_key: &str) -> Option<&ElicitationDecision> {
        self.decisions.get(pattern_key)
    }

    /// Record a new decision and persist to disk.
    pub fn record_decision(
        &mut self,
        decision: ElicitationDecision,
    ) -> Result<(), AnnotationError> {
        self.decisions
            .insert(decision.pattern_key.clone(), decision);
        self.save()
    }

    /// Save all decisions to disk.
    pub fn save(&self) -> Result<(), AnnotationError> {
        let list: Vec<&ElicitationDecision> = self.decisions.values().collect();
        let json = serde_json::to_string_pretty(&list)?;
        let file_path = self.path.join("elicitations.json");
        std::fs::write(file_path, json)?;
        Ok(())
    }
}

/// Convert stored elicitation decisions into nil_models entries.
/// Returns Vec of (callee_key, nilness) suitable for merging into config.rules.nil.models.
pub fn decisions_to_nil_models(
    decisions: &HashMap<String, ElicitationDecision>,
) -> Vec<(String, String)> {
    decisions
        .values()
        .filter_map(|d| {
            let callee = d.pattern_key.strip_prefix("nil_return:")?;
            match d.answer.as_str() {
                "always_nil_on_error" | "nonnull" => {
                    Some((callee.to_string(), "nonnull".to_string()))
                }
                "nilable" | "partial_result_possible" => {
                    Some((callee.to_string(), "nilable".to_string()))
                }
                _ => None,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir() -> tempfile::TempDir {
        tempfile::tempdir().expect("Failed to create temp dir")
    }

    fn sample_decision(key: &str) -> ElicitationDecision {
        ElicitationDecision {
            pattern_key: key.to_string(),
            question: "Is *T nil when err != nil?".to_string(),
            answer: "always_nil_on_error".to_string(),
            timestamp: "2026-02-22T12:00:00Z".to_string(),
            return_type_fingerprint: None,
        }
    }

    #[test]
    fn test_elicitation_store_record_and_get() {
        let dir = temp_dir();
        let mut store = ElicitationStore::new(dir.path()).unwrap();

        let decision = sample_decision("nil_return:pkg.Foo");
        store.record_decision(decision).unwrap();

        let retrieved = store.get_decision("nil_return:pkg.Foo").unwrap();
        assert_eq!(retrieved.answer, "always_nil_on_error");
        assert_eq!(retrieved.question, "Is *T nil when err != nil?");

        // Verify persistence: reload from disk
        let store2 = ElicitationStore::new(dir.path()).unwrap();
        let retrieved2 = store2.get_decision("nil_return:pkg.Foo").unwrap();
        assert_eq!(retrieved2.answer, "always_nil_on_error");
    }

    #[test]
    fn test_elicitation_store_has_decision() {
        let dir = temp_dir();
        let mut store = ElicitationStore::new(dir.path()).unwrap();

        assert!(!store.has_decision("nil_return:pkg.Foo"));

        store
            .record_decision(sample_decision("nil_return:pkg.Foo"))
            .unwrap();

        assert!(store.has_decision("nil_return:pkg.Foo"));
        assert!(!store.has_decision("nil_return:pkg.Bar"));
    }

    #[test]
    fn test_decisions_to_nil_models_nonnull() {
        let mut decisions = HashMap::new();
        decisions.insert(
            "nil_return:db.Find#0".to_string(),
            ElicitationDecision {
                pattern_key: "nil_return:db.Find#0".to_string(),
                question: "Is *T nil when err != nil?".to_string(),
                answer: "always_nil_on_error".to_string(),
                timestamp: "2026-02-24T12:00:00Z".to_string(),
                return_type_fingerprint: None,
            },
        );
        let models = decisions_to_nil_models(&decisions);
        assert_eq!(models.len(), 1);
        assert_eq!(models[0].0, "db.Find#0");
        assert_eq!(models[0].1, "nonnull");
    }

    #[test]
    fn test_decisions_to_nil_models_nilable() {
        let mut decisions = HashMap::new();
        decisions.insert(
            "nil_return:pkg.Get".to_string(),
            ElicitationDecision {
                pattern_key: "nil_return:pkg.Get".to_string(),
                question: "test".to_string(),
                answer: "partial_result_possible".to_string(),
                timestamp: "2026-02-24T12:00:00Z".to_string(),
                return_type_fingerprint: None,
            },
        );
        let models = decisions_to_nil_models(&decisions);
        assert_eq!(models.len(), 1);
        assert_eq!(models[0].0, "pkg.Get");
        assert_eq!(models[0].1, "nilable");
    }

    #[test]
    fn test_decisions_to_nil_models_skips_non_nil_patterns() {
        let mut decisions = HashMap::new();
        decisions.insert(
            "resource_lifecycle:*sql.DB:handler".to_string(),
            ElicitationDecision {
                pattern_key: "resource_lifecycle:*sql.DB:handler".to_string(),
                question: "test".to_string(),
                answer: "owned".to_string(),
                timestamp: "2026-02-24T12:00:00Z".to_string(),
                return_type_fingerprint: None,
            },
        );
        let models = decisions_to_nil_models(&decisions);
        assert!(models.is_empty(), "non-nil patterns should be skipped");
    }

    #[test]
    fn test_fingerprint_serde_roundtrip() {
        let decision = ElicitationDecision {
            pattern_key: "nil_return:pkg.Foo#0".to_string(),
            question: "test".to_string(),
            answer: "nonnull".to_string(),
            timestamp: "2026-02-24T12:00:00Z".to_string(),
            return_type_fingerprint: Some("sha256:abc123".to_string()),
        };
        let json = serde_json::to_string(&decision).unwrap();
        assert!(json.contains("return_type_fingerprint"));
        let parsed: ElicitationDecision = serde_json::from_str(&json).unwrap();
        assert_eq!(
            parsed.return_type_fingerprint.as_deref(),
            Some("sha256:abc123")
        );

        // Without fingerprint — should omit from JSON
        let decision2 = ElicitationDecision {
            pattern_key: "nil_return:pkg.Bar".to_string(),
            question: "test".to_string(),
            answer: "nilable".to_string(),
            timestamp: "2026-02-24T12:00:00Z".to_string(),
            return_type_fingerprint: None,
        };
        let json2 = serde_json::to_string(&decision2).unwrap();
        assert!(!json2.contains("return_type_fingerprint"));

        // Deserialize old JSON without fingerprint field
        let old_json = r#"{"pattern_key":"test","question":"q","answer":"a","timestamp":"t"}"#;
        let parsed_old: ElicitationDecision = serde_json::from_str(old_json).unwrap();
        assert!(parsed_old.return_type_fingerprint.is_none());
    }
}
