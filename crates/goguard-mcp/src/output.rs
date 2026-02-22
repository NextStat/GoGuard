//! MCP output formatting for structured analysis results.

pub use goguard_diagnostics::rules::{get_all_rules, RuleInfo};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rules_returns_all() {
        let rules = get_all_rules();
        assert_eq!(rules.len(), 23);
    }

    #[test]
    fn test_rules_filter_nil() {
        let rules = get_all_rules();
        let nil_rules: Vec<_> = rules.iter().filter(|r| r.category == "nil").collect();
        assert_eq!(nil_rules.len(), 4);
    }

    #[test]
    fn test_rules_filter_no_match() {
        let rules = get_all_rules();
        let none: Vec<_> = rules
            .iter()
            .filter(|r| r.category == "nonexistent")
            .collect();
        assert!(none.is_empty());
    }

    #[test]
    fn test_rule_serialization() {
        let rules = get_all_rules();
        let json = serde_json::to_string_pretty(&rules).unwrap();
        assert!(json.contains("NIL001"));
        assert!(json.contains("ERR001"));
    }
}
