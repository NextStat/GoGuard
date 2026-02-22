//! Token and cost budget tracking for auto-fix loop.

use serde::Serialize;

/// Budget configuration for auto-fix loop.
#[derive(Debug, Clone, Serialize)]
pub struct AutoFixBudget {
    pub max_iterations: usize,
    pub max_fixes: usize,
    pub max_time_ms: u64,
    pub stop_on_regression: bool,
}

impl Default for AutoFixBudget {
    fn default() -> Self {
        Self {
            max_iterations: 10,
            max_fixes: 50,
            max_time_ms: 300_000, // 5 minutes
            stop_on_regression: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_budget_default() {
        let budget = AutoFixBudget::default();
        assert_eq!(budget.max_iterations, 10);
        assert_eq!(budget.max_fixes, 50);
        assert_eq!(budget.max_time_ms, 300_000);
        assert!(budget.stop_on_regression);
    }
}
