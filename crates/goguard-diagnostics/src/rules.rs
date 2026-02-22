//! Rule catalog — all available GoGuard analysis rules.
//!
//! This module is the single source of truth for rule metadata.
//! Both `goguard-mcp` and `goguard-ecosystem` re-export from here.

use serde::Serialize;

/// Information about a single analysis rule.
#[derive(Debug, Clone, Serialize)]
pub struct RuleInfo {
    pub code: String,
    pub name: String,
    pub description: String,
    pub severity: String,
    pub category: String,
    /// Example Go code that triggers this rule.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub example_bad: Option<String>,
    /// Example Go code that is safe (does not trigger this rule).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub example_good: Option<String>,
    /// Go idiom or best practice for avoiding this issue.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub go_idiom: Option<String>,
}

/// Look up a single rule by code (e.g., "NIL001").
pub fn get_rule(code: &str) -> Option<RuleInfo> {
    get_all_rules().into_iter().find(|r| r.code == code)
}

/// Return all available analysis rules.
pub fn get_all_rules() -> Vec<RuleInfo> {
    vec![
        // --- Nil Safety ---
        RuleInfo {
            code: "NIL001".into(),
            name: "Nil pointer dereference".into(),
            description:
                "A value that may be nil is used in a context that would cause a runtime panic."
                    .into(),
            severity: "critical".into(),
            category: "nil".into(),
            example_bad: Some("user, err := GetUser(id)\nif err != nil { log.Print(err) }\nfmt.Println(user.Name) // user may be nil".into()),
            example_good: Some("user, err := GetUser(id)\nif err != nil { return err }\nfmt.Println(user.Name)".into()),
            go_idiom: Some("Always return after error check before using the result".into()),
        },
        RuleInfo {
            code: "NIL002".into(),
            name: "Unchecked type assertion".into(),
            description:
                "A type assertion without comma-ok pattern will panic if the assertion fails."
                    .into(),
            severity: "critical".into(),
            category: "nil".into(),
            example_bad: Some("s := val.(string) // panics if val is not string".into()),
            example_good: Some("s, ok := val.(string)\nif !ok { return errors.New(\"not a string\") }".into()),
            go_idiom: Some("Always use comma-ok pattern for type assertions".into()),
        },
        RuleInfo {
            code: "NIL004".into(),
            name: "Nil map access".into(),
            description:
                "A map that may be nil is accessed. Write to nil map causes runtime panic.".into(),
            severity: "critical".into(),
            category: "nil".into(),
            example_bad: Some("var m map[string]int\nm[\"key\"] = 1 // panic: assignment to nil map".into()),
            example_good: Some("m := make(map[string]int)\nm[\"key\"] = 1".into()),
            go_idiom: Some("Always initialize maps with make() before writing".into()),
        },
        RuleInfo {
            code: "NIL006".into(),
            name: "Nil channel operation".into(),
            description: "A send or receive on a nil channel blocks forever, causing deadlock."
                .into(),
            severity: "critical".into(),
            category: "nil".into(),
            example_bad: Some("var ch chan int\nch <- 1 // blocks forever".into()),
            example_good: Some("ch := make(chan int, 1)\nch <- 1".into()),
            go_idiom: Some("Always initialize channels with make() before use".into()),
        },
        // --- Error Checking ---
        RuleInfo {
            code: "ERR001".into(),
            name: "Error return value not checked".into(),
            description: "A function that returns an error has its error return value ignored."
                .into(),
            severity: "error".into(),
            category: "errcheck".into(),
            example_bad: Some("os.Remove(path) // error silently ignored".into()),
            example_good: Some("if err := os.Remove(path); err != nil {\n    return fmt.Errorf(\"remove %s: %w\", path, err)\n}".into()),
            go_idiom: Some("Handle every error; wrap with context using fmt.Errorf".into()),
        },
        RuleInfo {
            code: "ERR002".into(),
            name: "Error assigned to blank identifier".into(),
            description: "An error is explicitly discarded using the blank identifier _.".into(),
            severity: "warning".into(),
            category: "errcheck".into(),
            example_bad: Some("_ = json.Unmarshal(data, &obj)".into()),
            example_good: Some("if err := json.Unmarshal(data, &obj); err != nil {\n    return err\n}".into()),
            go_idiom: Some("Don't discard errors with _; handle or propagate them".into()),
        },
        // --- Concurrency: Data Races ---
        RuleInfo {
            code: "RACE001".into(),
            name: "Shared variable access in goroutine".into(),
            description:
                "A variable from enclosing scope is accessed in a goroutine without synchronization."
                    .into(),
            severity: "warning".into(),
            category: "concurrency".into(),
            example_bad: Some("count := 0\nfor i := 0; i < 10; i++ {\n    go func() { count++ }() // data race\n}".into()),
            example_good: Some("var mu sync.Mutex\ncount := 0\nfor i := 0; i < 10; i++ {\n    go func() { mu.Lock(); count++; mu.Unlock() }()\n}".into()),
            go_idiom: Some("Protect shared state with sync.Mutex or use channels".into()),
        },
        RuleInfo {
            code: "RACE002".into(),
            name: "Goroutine captures loop variable".into(),
            description: "A goroutine captures a loop variable by reference; all goroutines see the final value.".into(),
            severity: "critical".into(),
            category: "concurrency".into(),
            example_bad: Some("for _, v := range items {\n    go func() { process(v) }() // all see last v\n}".into()),
            example_good: Some("for _, v := range items {\n    go func(v Item) { process(v) }(v)\n}".into()),
            go_idiom: Some("Pass loop variables as goroutine function arguments".into()),
        },
        // --- Concurrency: Goroutine Leaks ---
        RuleInfo {
            code: "LEAK001".into(),
            name: "Goroutine may never terminate".into(),
            description:
                "A goroutine has no visible termination path, causing a resource leak.".into(),
            severity: "warning".into(),
            category: "concurrency".into(),
            example_bad: Some("go func() {\n    for { doWork() } // never exits\n}()".into()),
            example_good: Some("go func(ctx context.Context) {\n    for { select {\n    case <-ctx.Done(): return\n    default: doWork()\n    }}\n}(ctx)".into()),
            go_idiom: Some("Every goroutine must have a cancellation path via context.Context".into()),
        },
        RuleInfo {
            code: "LEAK002".into(),
            name: "Channel created but never used".into(),
            description: "A channel is created with make() but never sent to or received from."
                .into(),
            severity: "warning".into(),
            category: "concurrency".into(),
            example_bad: Some("ch := make(chan int) // allocated but never used".into()),
            example_good: None,
            go_idiom: Some("Remove unused channel allocations".into()),
        },
        // --- Concurrency: Channel Operations ---
        RuleInfo {
            code: "CHAN001".into(),
            name: "Send on possibly closed channel".into(),
            description: "A send on a channel that may be closed will panic at runtime.".into(),
            severity: "critical".into(),
            category: "concurrency".into(),
            example_bad: Some("close(ch)\nch <- 1 // panic: send on closed channel".into()),
            example_good: Some("// Use sync.Once for close, or check with select".into()),
            go_idiom: Some("Only the sender should close a channel; use sync.Once if multiple senders".into()),
        },
        RuleInfo {
            code: "CHAN002".into(),
            name: "Select without default case".into(),
            description: "A select statement has no default case and may block indefinitely.".into(),
            severity: "info".into(),
            category: "concurrency".into(),
            example_bad: None,
            example_good: None,
            go_idiom: Some("Add default case or timeout to prevent indefinite blocking".into()),
        },
        // --- Ownership / Resource Lifecycle ---
        RuleInfo {
            code: "OWN001".into(),
            name: "Resource opened but never closed".into(),
            description: "A resource (file, connection) is opened but never closed, causing a leak."
                .into(),
            severity: "error".into(),
            category: "ownership".into(),
            example_bad: Some("f, _ := os.Open(path)\n// f is never closed".into()),
            example_good: Some("f, err := os.Open(path)\nif err != nil { return err }\ndefer f.Close()".into()),
            go_idiom: Some("Always defer Close() immediately after opening a resource".into()),
        },
        RuleInfo {
            code: "OWN002".into(),
            name: "Use after close".into(),
            description: "A resource is used after it has been closed, causing undefined behavior."
                .into(),
            severity: "critical".into(),
            category: "ownership".into(),
            example_bad: Some("f.Close()\nf.Read(buf) // use after close".into()),
            example_good: Some("data, err := io.ReadAll(f)\nf.Close()".into()),
            go_idiom: Some("Complete all reads/writes before closing a resource".into()),
        },
        RuleInfo {
            code: "OWN003".into(),
            name: "Double close".into(),
            description: "A resource is closed more than once, which can cause panics.".into(),
            severity: "warning".into(),
            category: "ownership".into(),
            example_bad: Some("f.Close()\n// ... later\nf.Close() // double close".into()),
            example_good: Some("defer f.Close() // called exactly once".into()),
            go_idiom: Some("Use defer for single close; guard manual closes with sync.Once".into()),
        },
        RuleInfo {
            code: "OWN004".into(),
            name: "Resource close not deferred".into(),
            description:
                "A resource is closed explicitly but not via defer; panic between open and close leaks it."
                    .into(),
            severity: "info".into(),
            category: "ownership".into(),
            example_bad: Some("f, _ := os.Open(path)\n// ... work that might panic ...\nf.Close()".into()),
            example_good: Some("f, _ := os.Open(path)\ndefer f.Close()".into()),
            go_idiom: Some("Use defer f.Close() to guarantee cleanup even on panic".into()),
        },
        // --- Exhaustiveness ---
        RuleInfo {
            code: "EXH001".into(),
            name: "Type switch missing interface implementor".into(),
            description:
                "A type switch on an interface does not cover all types that implement it.".into(),
            severity: "error".into(),
            category: "exhaustive".into(),
            example_bad: Some("switch v := event.(type) {\ncase Created: // ...\ncase Deleted: // ...\n// Missing: Updated, Archived\n}".into()),
            example_good: Some("switch v := event.(type) {\ncase Created: // ...\ncase Deleted: // ...\ncase Updated: // ...\ncase Archived: // ...\n}".into()),
            go_idiom: Some("Cover all interface implementors in type switches".into()),
        },
        RuleInfo {
            code: "EXH002".into(),
            name: "Enum switch missing constant value".into(),
            description:
                "A switch on an enum-like const group does not cover all defined values.".into(),
            severity: "error".into(),
            category: "exhaustive".into(),
            example_bad: Some("switch status {\ncase Active: // ...\ncase Inactive: // ...\n// Missing: Suspended\n}".into()),
            example_good: Some("switch status {\ncase Active: // ...\ncase Inactive: // ...\ncase Suspended: // ...\n}".into()),
            go_idiom: Some("Cover all const/iota values in switches".into()),
        },
        RuleInfo {
            code: "EXH003".into(),
            name: "Missing default in non-exhaustive switch".into(),
            description: "A switch is not exhaustive and has no default case.".into(),
            severity: "info".into(),
            category: "exhaustive".into(),
            example_bad: None,
            example_good: None,
            go_idiom: Some("Add default case to handle unexpected values".into()),
        },
        // --- Taint Analysis ---
        RuleInfo {
            code: "TAINT001".into(),
            name: "SQL injection".into(),
            description:
                "Tainted data flows to a SQL query without sanitization.".into(),
            severity: "critical".into(),
            category: "taint".into(),
            example_bad: Some("db.Query(\"SELECT * FROM users WHERE id=\" + r.URL.Query().Get(\"id\"))".into()),
            example_good: Some("db.Query(\"SELECT * FROM users WHERE id=$1\", r.URL.Query().Get(\"id\"))".into()),
            go_idiom: Some("Always use parameterized queries; never concatenate user input into SQL".into()),
        },
        RuleInfo {
            code: "TAINT002".into(),
            name: "Command injection".into(),
            description:
                "Tainted data flows to command execution without sanitization.".into(),
            severity: "critical".into(),
            category: "taint".into(),
            example_bad: Some("exec.Command(\"sh\", \"-c\", userInput).Run()".into()),
            example_good: Some("exec.Command(\"ls\", \"-l\", filepath.Clean(userInput)).Run()".into()),
            go_idiom: Some("Avoid shell execution with user input; use exec.Command with explicit args".into()),
        },
        RuleInfo {
            code: "TAINT003".into(),
            name: "Path traversal".into(),
            description:
                "Tainted data flows to a file path operation, allowing directory traversal.".into(),
            severity: "critical".into(),
            category: "taint".into(),
            example_bad: Some("os.ReadFile(filepath.Join(baseDir, userInput)) // ../../../etc/passwd".into()),
            example_good: Some("clean := filepath.Clean(userInput)\nif !strings.HasPrefix(filepath.Join(baseDir, clean), baseDir) {\n    return errors.New(\"path traversal\")\n}".into()),
            go_idiom: Some("Validate cleaned paths stay within the base directory".into()),
        },
        RuleInfo {
            code: "TAINT004".into(),
            name: "Cross-site scripting (XSS)".into(),
            description:
                "Tainted data flows to HTML output without escaping.".into(),
            severity: "warning".into(),
            category: "taint".into(),
            example_bad: Some("fmt.Fprintf(w, \"<h1>%s</h1>\", userInput)".into()),
            example_good: Some("fmt.Fprintf(w, \"<h1>%s</h1>\", html.EscapeString(userInput))".into()),
            go_idiom: Some("Use html/template or html.EscapeString for user-provided HTML content".into()),
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rules_returns_all() {
        let rules = get_all_rules();
        assert_eq!(rules.len(), 23);
    }

    #[test]
    fn test_rules_have_required_fields() {
        let rules = get_all_rules();
        for rule in &rules {
            assert!(!rule.code.is_empty(), "rule code must not be empty");
            assert!(!rule.name.is_empty(), "rule name must not be empty");
            assert!(
                !rule.description.is_empty(),
                "rule description must not be empty"
            );
            assert!(!rule.severity.is_empty(), "rule severity must not be empty");
            assert!(!rule.category.is_empty(), "rule category must not be empty");
        }
    }

    #[test]
    fn test_rules_serializable() {
        let rules = get_all_rules();
        let json = serde_json::to_string(&rules);
        assert!(json.is_ok(), "rules must be serializable to JSON");
        let json_str = json.unwrap();
        assert!(json_str.contains("NIL001"));
        assert!(json_str.contains("ERR001"));
    }

    #[test]
    fn test_get_rule_found() {
        let rule = get_rule("NIL001");
        assert!(rule.is_some());
        let rule = rule.unwrap();
        assert_eq!(rule.code, "NIL001");
        assert_eq!(rule.category, "nil");
        assert!(rule.example_bad.is_some());
        assert!(rule.example_good.is_some());
        assert!(rule.go_idiom.is_some());
    }

    #[test]
    fn test_get_rule_not_found() {
        assert!(get_rule("NONEXISTENT").is_none());
    }

    #[test]
    fn test_rules_have_examples() {
        let rules = get_all_rules();
        let with_examples = rules.iter().filter(|r| r.example_bad.is_some()).count();
        // Most rules should have examples (at least the important ones)
        assert!(
            with_examples >= 18,
            "Expected at least 18 rules with examples, got {}",
            with_examples
        );
    }

    #[test]
    fn test_rule_detail_serialization() {
        let rule = get_rule("TAINT001").unwrap();
        let json = serde_json::to_string_pretty(&rule).unwrap();
        assert!(json.contains("example_bad"));
        assert!(json.contains("example_good"));
        assert!(json.contains("go_idiom"));
        assert!(json.contains("parameterized"));
    }
}
