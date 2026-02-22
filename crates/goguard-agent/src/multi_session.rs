//! Multi-session management for concurrent agent interactions.
//!
//! When multiple AI agents (e.g., Claude in one terminal, Cursor in another)
//! work on the same project, they need isolated analysis state and conflict
//! detection to avoid stepping on each other's fixes.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

/// Unique session identifier.
pub type SessionId = String;

/// A session representing one agent's interaction with GoGuard.
#[derive(Debug, Clone)]
pub struct Session {
    pub id: SessionId,
    pub agent_name: Option<String>,
    pub created_at: Instant,
    pub last_active: Instant,
    /// Files this session is currently working on (has pending fixes).
    pub locked_files: HashSet<String>,
}

impl Session {
    fn new(id: SessionId, agent_name: Option<String>) -> Self {
        let now = Instant::now();
        Self {
            id,
            agent_name,
            created_at: now,
            last_active: now,
            locked_files: HashSet::new(),
        }
    }

    fn touch(&mut self) {
        self.last_active = Instant::now();
    }
}

/// Conflict information when two sessions try to modify the same file.
#[derive(Debug, Clone)]
pub struct Conflict {
    pub file: String,
    pub holding_session: SessionId,
    pub holding_agent: Option<String>,
    pub requesting_session: SessionId,
}

/// Manager for concurrent agent sessions with file-level locking.
#[derive(Clone)]
pub struct SessionManager {
    sessions: Arc<Mutex<HashMap<SessionId, Session>>>,
    /// Timeout after which inactive sessions are cleaned up.
    session_timeout: Duration,
}

impl std::fmt::Debug for SessionManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionManager")
            .field("session_timeout", &self.session_timeout)
            .finish()
    }
}

impl Default for SessionManager {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionManager {
    /// Create a new session manager with default 30-minute timeout.
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(Mutex::new(HashMap::new())),
            session_timeout: Duration::from_secs(30 * 60),
        }
    }

    /// Create a new session manager with a custom timeout.
    pub fn with_timeout(timeout: Duration) -> Self {
        Self {
            sessions: Arc::new(Mutex::new(HashMap::new())),
            session_timeout: timeout,
        }
    }

    /// Create or rejoin a session. Returns the session ID.
    pub async fn create_session(&self, agent_name: Option<&str>) -> SessionId {
        let id = generate_session_id();
        let session = Session::new(id.clone(), agent_name.map(String::from));
        self.sessions.lock().await.insert(id.clone(), session);
        id
    }

    /// Touch a session to keep it alive.
    pub async fn touch_session(&self, session_id: &str) -> bool {
        let mut sessions = self.sessions.lock().await;
        if let Some(session) = sessions.get_mut(session_id) {
            session.touch();
            true
        } else {
            false
        }
    }

    /// Remove a session and release all its file locks.
    pub async fn remove_session(&self, session_id: &str) {
        self.sessions.lock().await.remove(session_id);
    }

    /// Acquire a file lock for a session. Returns Ok(()) on success,
    /// or Err(Conflict) if another session holds the lock.
    pub async fn lock_file(&self, session_id: &str, file: &str) -> Result<(), Conflict> {
        let mut sessions = self.sessions.lock().await;

        // Check if another session holds this file
        for (id, session) in sessions.iter() {
            if id != session_id && session.locked_files.contains(file) {
                return Err(Conflict {
                    file: file.to_string(),
                    holding_session: id.clone(),
                    holding_agent: session.agent_name.clone(),
                    requesting_session: session_id.to_string(),
                });
            }
        }

        // Acquire the lock
        if let Some(session) = sessions.get_mut(session_id) {
            session.locked_files.insert(file.to_string());
            session.touch();
            Ok(())
        } else {
            // Session doesn't exist — create a transient error
            Err(Conflict {
                file: file.to_string(),
                holding_session: String::new(),
                holding_agent: None,
                requesting_session: session_id.to_string(),
            })
        }
    }

    /// Release a file lock for a session.
    pub async fn unlock_file(&self, session_id: &str, file: &str) {
        let mut sessions = self.sessions.lock().await;
        if let Some(session) = sessions.get_mut(session_id) {
            session.locked_files.remove(file);
            session.touch();
        }
    }

    /// Release all file locks for a session (e.g., after verify succeeds).
    pub async fn unlock_all(&self, session_id: &str) {
        let mut sessions = self.sessions.lock().await;
        if let Some(session) = sessions.get_mut(session_id) {
            session.locked_files.clear();
            session.touch();
        }
    }

    /// Check for conflicts: given a set of files, return any held by other sessions.
    pub async fn check_conflicts(&self, session_id: &str, files: &[String]) -> Vec<Conflict> {
        let sessions = self.sessions.lock().await;
        let mut conflicts = Vec::new();

        for (id, session) in sessions.iter() {
            if id == session_id {
                continue;
            }
            for file in files {
                if session.locked_files.contains(file.as_str()) {
                    conflicts.push(Conflict {
                        file: file.clone(),
                        holding_session: id.clone(),
                        holding_agent: session.agent_name.clone(),
                        requesting_session: session_id.to_string(),
                    });
                }
            }
        }

        conflicts
    }

    /// List all active sessions.
    pub async fn list_sessions(&self) -> Vec<SessionSummary> {
        let sessions = self.sessions.lock().await;
        sessions
            .values()
            .map(|s| SessionSummary {
                id: s.id.clone(),
                agent_name: s.agent_name.clone(),
                locked_files_count: s.locked_files.len(),
                idle_secs: s.last_active.elapsed().as_secs(),
            })
            .collect()
    }

    /// Clean up sessions that have been idle longer than the timeout.
    pub async fn cleanup_stale(&self) -> usize {
        let mut sessions = self.sessions.lock().await;
        let before = sessions.len();
        sessions.retain(|_, s| s.last_active.elapsed() < self.session_timeout);
        before - sessions.len()
    }

    /// Get the number of active sessions.
    pub async fn session_count(&self) -> usize {
        self.sessions.lock().await.len()
    }
}

/// Summary of a session for listing.
#[derive(Debug, Clone)]
pub struct SessionSummary {
    pub id: SessionId,
    pub agent_name: Option<String>,
    pub locked_files_count: usize,
    pub idle_secs: u64,
}

fn generate_session_id() -> String {
    use std::time::SystemTime;
    let ts = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("session-{:x}", ts)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_create_session() {
        let mgr = SessionManager::new();
        let id = mgr.create_session(Some("claude-code")).await;
        assert!(id.starts_with("session-"));
        assert_eq!(mgr.session_count().await, 1);
    }

    #[tokio::test]
    async fn test_remove_session() {
        let mgr = SessionManager::new();
        let id = mgr.create_session(Some("cursor")).await;
        assert_eq!(mgr.session_count().await, 1);
        mgr.remove_session(&id).await;
        assert_eq!(mgr.session_count().await, 0);
    }

    #[tokio::test]
    async fn test_lock_file_success() {
        let mgr = SessionManager::new();
        let id = mgr.create_session(Some("claude")).await;
        let result = mgr.lock_file(&id, "handler.go").await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_lock_file_conflict() {
        let mgr = SessionManager::new();
        let id1 = mgr.create_session(Some("claude")).await;
        let id2 = mgr.create_session(Some("cursor")).await;

        // Session 1 locks the file
        mgr.lock_file(&id1, "handler.go").await.unwrap();

        // Session 2 tries to lock the same file — conflict
        let result = mgr.lock_file(&id2, "handler.go").await;
        assert!(result.is_err());
        let conflict = result.unwrap_err();
        assert_eq!(conflict.file, "handler.go");
        assert_eq!(conflict.holding_session, id1);
        assert_eq!(conflict.holding_agent, Some("claude".to_string()));
        assert_eq!(conflict.requesting_session, id2);
    }

    #[tokio::test]
    async fn test_unlock_file_allows_relock() {
        let mgr = SessionManager::new();
        let id1 = mgr.create_session(Some("claude")).await;
        let id2 = mgr.create_session(Some("cursor")).await;

        mgr.lock_file(&id1, "handler.go").await.unwrap();
        mgr.unlock_file(&id1, "handler.go").await;

        // Now session 2 can lock it
        let result = mgr.lock_file(&id2, "handler.go").await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_unlock_all() {
        let mgr = SessionManager::new();
        let id = mgr.create_session(Some("claude")).await;
        mgr.lock_file(&id, "a.go").await.unwrap();
        mgr.lock_file(&id, "b.go").await.unwrap();
        mgr.lock_file(&id, "c.go").await.unwrap();

        mgr.unlock_all(&id).await;

        let id2 = mgr.create_session(Some("cursor")).await;
        assert!(mgr.lock_file(&id2, "a.go").await.is_ok());
        assert!(mgr.lock_file(&id2, "b.go").await.is_ok());
    }

    #[tokio::test]
    async fn test_check_conflicts() {
        let mgr = SessionManager::new();
        let id1 = mgr.create_session(Some("claude")).await;
        let id2 = mgr.create_session(Some("cursor")).await;

        mgr.lock_file(&id1, "handler.go").await.unwrap();
        mgr.lock_file(&id1, "main.go").await.unwrap();

        let conflicts = mgr
            .check_conflicts(
                &id2,
                &["handler.go".into(), "util.go".into(), "main.go".into()],
            )
            .await;
        assert_eq!(conflicts.len(), 2);
        let conflict_files: HashSet<String> = conflicts.iter().map(|c| c.file.clone()).collect();
        assert!(conflict_files.contains("handler.go"));
        assert!(conflict_files.contains("main.go"));
    }

    #[tokio::test]
    async fn test_list_sessions() {
        let mgr = SessionManager::new();
        mgr.create_session(Some("claude")).await;
        mgr.create_session(Some("cursor")).await;

        let list = mgr.list_sessions().await;
        assert_eq!(list.len(), 2);
        let agents: HashSet<Option<String>> = list.iter().map(|s| s.agent_name.clone()).collect();
        assert!(agents.contains(&Some("claude".to_string())));
        assert!(agents.contains(&Some("cursor".to_string())));
    }

    #[tokio::test]
    async fn test_cleanup_stale() {
        // Use a very short timeout
        let mgr = SessionManager::with_timeout(Duration::from_millis(1));
        mgr.create_session(Some("old-agent")).await;

        // Wait for the session to become stale
        tokio::time::sleep(Duration::from_millis(10)).await;

        let cleaned = mgr.cleanup_stale().await;
        assert_eq!(cleaned, 1);
        assert_eq!(mgr.session_count().await, 0);
    }

    #[tokio::test]
    async fn test_touch_keeps_alive() {
        let mgr = SessionManager::with_timeout(Duration::from_millis(50));
        let id = mgr.create_session(Some("agent")).await;

        // Touch before timeout
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(mgr.touch_session(&id).await);

        // Still alive after touch
        tokio::time::sleep(Duration::from_millis(20)).await;
        let cleaned = mgr.cleanup_stale().await;
        assert_eq!(cleaned, 0, "touched session should still be alive");
    }

    #[tokio::test]
    async fn test_same_session_can_lock_same_file() {
        let mgr = SessionManager::new();
        let id = mgr.create_session(Some("claude")).await;

        mgr.lock_file(&id, "handler.go").await.unwrap();
        // Same session re-locking the same file should work (idempotent)
        let result = mgr.lock_file(&id, "handler.go").await;
        assert!(result.is_ok());
    }
}
