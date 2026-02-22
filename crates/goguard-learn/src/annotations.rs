//! Code annotation parsing and learning (goguard:ignore, goguard:trust, etc.).
//!
//! Stores user annotations about specific code patterns, allowing GoGuard
//! to learn project-specific intent and reduce false positives over time.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// A user annotation about a specific code pattern.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Annotation {
    /// Function qualified name (e.g., "example.com/pkg.ProcessOrder").
    pub function: String,
    /// The question that was asked.
    pub question: String,
    /// User's answer.
    pub answer: String,
    /// When this was recorded (ISO 8601 string).
    pub timestamp: String,
}

/// Store for project-specific annotations.
///
/// Annotations are keyed by function name and persisted as JSON files
/// in the store directory (default: `~/.goguard/annotations/`).
pub struct AnnotationStore {
    path: PathBuf,
    annotations: HashMap<String, Vec<Annotation>>,
}

impl AnnotationStore {
    /// Create or load an annotation store from a directory.
    ///
    /// Creates the directory if it does not exist, then loads all `.json`
    /// files found within it.
    pub fn new(dir: &Path) -> Result<Self, AnnotationError> {
        std::fs::create_dir_all(dir)?;

        let mut annotations: HashMap<String, Vec<Annotation>> = HashMap::new();

        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("json") {
                let content = std::fs::read_to_string(&path)?;
                let file_annotations: Vec<Annotation> = serde_json::from_str(&content)?;
                for ann in file_annotations {
                    annotations
                        .entry(ann.function.clone())
                        .or_default()
                        .push(ann);
                }
            }
        }

        Ok(Self {
            path: dir.to_path_buf(),
            annotations,
        })
    }

    /// Add an annotation and persist to disk.
    pub fn add(&mut self, annotation: Annotation) -> Result<(), AnnotationError> {
        self.annotations
            .entry(annotation.function.clone())
            .or_default()
            .push(annotation);
        self.save()
    }

    /// Get annotations for a specific function.
    pub fn get_for_function(&self, function: &str) -> Vec<&Annotation> {
        self.annotations
            .get(function)
            .map(|v| v.iter().collect())
            .unwrap_or_default()
    }

    /// Get all annotations across all functions.
    pub fn all(&self) -> Vec<&Annotation> {
        self.annotations.values().flat_map(|v| v.iter()).collect()
    }

    /// Save all annotations to disk as a single `annotations.json` file.
    pub fn save(&self) -> Result<(), AnnotationError> {
        let all: Vec<&Annotation> = self.all();
        let json = serde_json::to_string_pretty(&all)?;
        let file_path = self.path.join("annotations.json");
        std::fs::write(file_path, json)?;
        Ok(())
    }
}

/// Errors that can occur in the annotation store.
#[derive(Debug, thiserror::Error)]
pub enum AnnotationError {
    /// IO error reading/writing annotation files.
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    /// JSON serialization/deserialization error.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir() -> tempfile::TempDir {
        tempfile::tempdir().expect("Failed to create temp dir")
    }

    fn sample_annotation(function: &str) -> Annotation {
        Annotation {
            function: function.to_string(),
            question: "Does this return partial results on error?".to_string(),
            answer: "always_nil_on_error".to_string(),
            timestamp: "2026-02-22T12:00:00Z".to_string(),
        }
    }

    #[test]
    fn test_annotation_store_create_and_load() {
        let dir = temp_dir();
        let store = AnnotationStore::new(dir.path()).unwrap();
        assert!(store.all().is_empty());

        // Creating again on same dir should succeed (idempotent)
        let store2 = AnnotationStore::new(dir.path()).unwrap();
        assert!(store2.all().is_empty());
    }

    #[test]
    fn test_annotation_store_add_and_get() {
        let dir = temp_dir();
        let mut store = AnnotationStore::new(dir.path()).unwrap();

        let ann = sample_annotation("example.com/pkg.ProcessOrder");
        store.add(ann.clone()).unwrap();

        let all = store.all();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].function, "example.com/pkg.ProcessOrder");
        assert_eq!(all[0].answer, "always_nil_on_error");
    }

    #[test]
    fn test_annotation_store_persist_to_disk() {
        let dir = temp_dir();

        // Write annotations
        {
            let mut store = AnnotationStore::new(dir.path()).unwrap();
            store
                .add(sample_annotation("example.com/pkg.FuncA"))
                .unwrap();
            store
                .add(sample_annotation("example.com/pkg.FuncB"))
                .unwrap();
        }

        // Reload from disk
        let store = AnnotationStore::new(dir.path()).unwrap();
        assert_eq!(store.all().len(), 2);
    }

    #[test]
    fn test_annotation_store_get_for_function() {
        let dir = temp_dir();
        let mut store = AnnotationStore::new(dir.path()).unwrap();

        store
            .add(sample_annotation("example.com/pkg.FuncA"))
            .unwrap();
        store
            .add(sample_annotation("example.com/pkg.FuncA"))
            .unwrap();
        store
            .add(sample_annotation("example.com/pkg.FuncB"))
            .unwrap();

        let func_a = store.get_for_function("example.com/pkg.FuncA");
        assert_eq!(func_a.len(), 2);

        let func_b = store.get_for_function("example.com/pkg.FuncB");
        assert_eq!(func_b.len(), 1);

        let func_c = store.get_for_function("example.com/pkg.FuncC");
        assert!(func_c.is_empty());
    }
}
