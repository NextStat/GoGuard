//! MCP task management for long-running analysis operations.
//!
//! Provides async task tracking so MCP clients can start analysis,
//! poll for progress, and retrieve results without blocking.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

/// Progress information for a running task.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskProgress {
    /// Current progress count.
    pub current: usize,
    /// Total expected count.
    pub total: usize,
    /// Unit of progress (e.g., "files", "packages").
    pub unit: String,
    /// Optional human-readable progress message.
    pub message: Option<String>,
}

/// Status of an analysis task.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TaskStatus {
    /// Task has been created but not yet started.
    Pending,
    /// Task is actively running.
    Working,
    /// Task completed successfully.
    Completed,
    /// Task failed with an error.
    Failed,
}

/// An async analysis task tracked by the task manager.
#[derive(Debug, Clone)]
pub struct AnalysisTask {
    /// Unique task identifier (e.g., "t-001").
    pub id: String,
    /// Current status of the task.
    pub status: TaskStatus,
    /// Progress information, if the task is working.
    pub progress: Option<TaskProgress>,
    /// Result payload, set when completed.
    pub result: Option<serde_json::Value>,
    /// Error message, set when failed.
    pub error: Option<String>,
}

/// Task manager for async analysis operations.
///
/// Thread-safe via `Arc<Mutex<...>>` — safe to clone and share
/// between MCP tool handlers.
pub struct TaskManager {
    tasks: Arc<Mutex<HashMap<String, AnalysisTask>>>,
    next_id: Arc<Mutex<u64>>,
}

impl TaskManager {
    /// Create a new empty task manager.
    pub fn new() -> Self {
        Self {
            tasks: Arc::new(Mutex::new(HashMap::new())),
            next_id: Arc::new(Mutex::new(1)),
        }
    }

    /// Create a new task and return its ID.
    pub async fn create_task(&self) -> String {
        let mut id_counter = self.next_id.lock().await;
        let id = format!("t-{:03}", *id_counter);
        *id_counter += 1;
        drop(id_counter);

        let task = AnalysisTask {
            id: id.clone(),
            status: TaskStatus::Pending,
            progress: None,
            result: None,
            error: None,
        };
        self.tasks.lock().await.insert(id.clone(), task);
        id
    }

    /// Update task progress. Sets status to `Working`.
    pub async fn update_progress(&self, task_id: &str, progress: TaskProgress) {
        if let Some(task) = self.tasks.lock().await.get_mut(task_id) {
            task.status = TaskStatus::Working;
            task.progress = Some(progress);
        }
    }

    /// Mark task as completed with a result payload.
    pub async fn complete_task(&self, task_id: &str, result: serde_json::Value) {
        if let Some(task) = self.tasks.lock().await.get_mut(task_id) {
            task.status = TaskStatus::Completed;
            task.result = Some(result);
        }
    }

    /// Mark task as failed with an error message.
    pub async fn fail_task(&self, task_id: &str, error: String) {
        if let Some(task) = self.tasks.lock().await.get_mut(task_id) {
            task.status = TaskStatus::Failed;
            task.error = Some(error);
        }
    }

    /// Get a task by ID, returning a clone.
    pub async fn get_task(&self, task_id: &str) -> Option<AnalysisTask> {
        self.tasks.lock().await.get(task_id).cloned()
    }

    /// List all tracked tasks.
    pub async fn list_tasks(&self) -> Vec<AnalysisTask> {
        self.tasks.lock().await.values().cloned().collect()
    }
}

impl Default for TaskManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_task_manager_create_task() {
        let manager = TaskManager::new();

        let id1 = manager.create_task().await;
        assert_eq!(id1, "t-001");

        let id2 = manager.create_task().await;
        assert_eq!(id2, "t-002");

        let tasks = manager.list_tasks().await;
        assert_eq!(tasks.len(), 2);

        // Both should be pending
        let task1 = manager.get_task("t-001").await.unwrap();
        assert!(matches!(task1.status, TaskStatus::Pending));
        assert!(task1.progress.is_none());
        assert!(task1.result.is_none());
        assert!(task1.error.is_none());
    }

    #[tokio::test]
    async fn test_task_manager_update_progress() {
        let manager = TaskManager::new();
        let id = manager.create_task().await;

        manager
            .update_progress(
                &id,
                TaskProgress {
                    current: 3,
                    total: 10,
                    unit: "files".to_string(),
                    message: Some("Analyzing handlers...".to_string()),
                },
            )
            .await;

        let task = manager.get_task(&id).await.unwrap();
        assert!(matches!(task.status, TaskStatus::Working));

        let progress = task.progress.unwrap();
        assert_eq!(progress.current, 3);
        assert_eq!(progress.total, 10);
        assert_eq!(progress.unit, "files");
        assert_eq!(progress.message.unwrap(), "Analyzing handlers...");
    }

    #[tokio::test]
    async fn test_task_manager_complete_and_get() {
        let manager = TaskManager::new();
        let id = manager.create_task().await;

        let result = serde_json::json!({
            "diagnostics": 5,
            "files_analyzed": 12
        });
        manager.complete_task(&id, result.clone()).await;

        let task = manager.get_task(&id).await.unwrap();
        assert!(matches!(task.status, TaskStatus::Completed));
        assert_eq!(task.result.unwrap(), result);
        assert!(task.error.is_none());
    }

    #[tokio::test]
    async fn test_task_manager_fail_task() {
        let manager = TaskManager::new();
        let id = manager.create_task().await;

        manager
            .fail_task(&id, "Bridge process exited with code 1".to_string())
            .await;

        let task = manager.get_task(&id).await.unwrap();
        assert!(matches!(task.status, TaskStatus::Failed));
        assert_eq!(task.error.unwrap(), "Bridge process exited with code 1");
        assert!(task.result.is_none());
    }

    #[tokio::test]
    async fn test_task_manager_get_nonexistent() {
        let manager = TaskManager::new();
        assert!(manager.get_task("t-999").await.is_none());
    }

    #[tokio::test]
    async fn test_task_manager_update_nonexistent_is_noop() {
        let manager = TaskManager::new();
        // These should not panic — just no-ops
        manager
            .update_progress(
                "t-999",
                TaskProgress {
                    current: 1,
                    total: 1,
                    unit: "files".into(),
                    message: None,
                },
            )
            .await;
        manager.complete_task("t-999", serde_json::json!({})).await;
        manager.fail_task("t-999", "error".to_string()).await;
        assert!(manager.get_task("t-999").await.is_none());
    }
}
