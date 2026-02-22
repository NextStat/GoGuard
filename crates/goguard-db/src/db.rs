//! Salsa database definition and configuration.

/// The Salsa database trait for GoGuard incremental analysis.
#[salsa::db]
pub trait Db: salsa::Database {}

/// The concrete Salsa database that stores all incremental analysis state.
#[salsa::db]
#[derive(Default, Clone)]
pub struct GoGuardDatabase {
    storage: salsa::Storage<Self>,
}

#[salsa::db]
impl salsa::Database for GoGuardDatabase {}

#[salsa::db]
impl Db for GoGuardDatabase {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_db_creation() {
        let db = GoGuardDatabase::default();
        // Just verify it compiles and doesn't panic
        let _ = &db;
    }
}
