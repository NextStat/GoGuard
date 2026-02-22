//! Well-known file discovery (.well-known/goguard, etc.).

/// Generate capabilities.json content for .well-known/goguard discovery.
pub fn capabilities_json() -> serde_json::Value {
    serde_json::json!({
        "name": "goguard",
        "version": env!("CARGO_PKG_VERSION"),
        "description": "Rust-level safety analyzer for Go",
        "capabilities": {
            "analysis": ["nil", "errcheck"],
            "mcp": true,
            "lsp": true
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_capabilities_json_structure() {
        let caps = capabilities_json();
        assert_eq!(caps["name"], "goguard");
        assert!(caps["version"].is_string());
        assert!(caps["capabilities"].is_object());
    }

    #[test]
    fn test_capabilities_has_analysis_passes() {
        let caps = capabilities_json();
        let analysis = caps["capabilities"]["analysis"].as_array().unwrap();
        let passes: Vec<&str> = analysis.iter().map(|v| v.as_str().unwrap()).collect();
        assert!(passes.contains(&"nil"));
        assert!(passes.contains(&"errcheck"));
    }
}
