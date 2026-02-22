//! Configuration loading from goguard.toml.

use serde::Deserialize;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct Config {
    pub goguard: GoguardConfig,
    pub rules: RulesConfig,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct GoguardConfig {
    pub severity_threshold: String,
    pub skip_generated: bool,
    pub max_diagnostics: usize,
    /// Explicit bridge cache directory. `None` = use platform default.
    pub cache_dir: Option<String>,
    /// Maximum number of cached bridge outputs to retain.
    pub max_cache_entries: usize,
    /// Disable bridge caching entirely.
    pub no_cache: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct RulesConfig {
    pub nil: NilConfig,
    pub errcheck: ErrcheckConfig,
    pub concurrency: RuleConfig,
    pub ownership: RuleConfig,
    pub exhaustive: RuleConfig,
    pub taint: RuleConfig,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct NilConfig {
    pub enabled: bool,
    /// If true, treat nilable parameters as `MaybeNil` by default (stricter, more findings).
    pub strict_params: bool,
    /// User-provided return nilness models.
    ///
    /// Keys are callee names as emitted by the bridge (e.g., "context.Background").
    /// For multi-return, append `#<index>` (e.g., "os.Open#0").
    ///
    /// Values:
    /// - "nonnull" / "never_nil"  => treat as non-nil
    /// - "nilable" / "can_be_nil" => treat as possibly nil
    #[serde(default)]
    pub models: std::collections::HashMap<String, String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct RuleConfig {
    pub enabled: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct ErrcheckConfig {
    pub enabled: bool,
    #[serde(default)]
    pub ignore: Vec<String>,
}

impl Default for GoguardConfig {
    fn default() -> Self {
        Self {
            severity_threshold: "warning".to_string(),
            skip_generated: true,
            max_diagnostics: 100,
            cache_dir: None,
            max_cache_entries: 20,
            no_cache: false,
        }
    }
}

/// Resolve the bridge cache directory.
/// Priority: explicit config > platform default > None (disabled).
pub fn resolve_bridge_cache_dir(config: &GoguardConfig) -> Option<PathBuf> {
    if config.no_cache {
        return None;
    }
    if let Some(ref dir) = config.cache_dir {
        return Some(PathBuf::from(dir));
    }
    // Platform default via the `dirs` crate.
    dirs::cache_dir().map(|d| d.join("goguard").join("bridge-cache"))
}

impl Default for RulesConfig {
    fn default() -> Self {
        Self {
            nil: NilConfig {
                enabled: true,
                strict_params: false,
                models: std::collections::HashMap::new(),
            },
            errcheck: ErrcheckConfig {
                enabled: true,
                ignore: vec!["fmt.Print*".to_string(), "fmt.Fprint*".to_string()],
            },
            concurrency: RuleConfig { enabled: true },
            ownership: RuleConfig { enabled: true },
            exhaustive: RuleConfig { enabled: true },
            taint: RuleConfig { enabled: true },
        }
    }
}

impl Default for RuleConfig {
    fn default() -> Self {
        Self { enabled: true }
    }
}

impl Default for NilConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            strict_params: false,
            models: std::collections::HashMap::new(),
        }
    }
}

impl Default for ErrcheckConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            ignore: vec![],
        }
    }
}

/// Find and load goguard.toml, walking up from `start_dir`.
/// Returns default config if no file found.
pub fn load_config(start_dir: &Path) -> Config {
    match find_config_file(start_dir) {
        Some(path) => {
            let content = std::fs::read_to_string(&path).unwrap_or_default();
            toml::from_str(&content).unwrap_or_default()
        }
        None => Config::default(),
    }
}

/// Walk up directories looking for goguard.toml.
fn find_config_file(start: &Path) -> Option<PathBuf> {
    let mut dir = start.to_path_buf();
    loop {
        let candidate = dir.join("goguard.toml");
        if candidate.exists() {
            return Some(candidate);
        }
        if !dir.pop() {
            return None;
        }
    }
}

/// Default TOML content for `goguard init`.
pub const DEFAULT_CONFIG_TOML: &str = r#"[goguard]
severity_threshold = "warning"
skip_generated = true
# cache_dir = "~/.cache/goguard/bridge-cache"  # auto-detected if omitted
# max_cache_entries = 20
# no_cache = false

[rules.nil]
enabled = true
# strict_params = false
# #
# # When true:
# # - Nilable parameters are seeded as MaybeNil (can catch real `Process(nil)` bugs)
# # - Known framework entrypoints (net/http, gin, echo, fiber, grpc, testing)
# #   seed their handler context/request params as NonNil to reduce noise
#
# [rules.nil.models]
# "mycompany/internal/db.GetDB" = "nonnull"
# "context.WithCancel#0" = "nonnull"

[rules.errcheck]
enabled = true
ignore = ["fmt.Print*", "fmt.Fprint*"]

[rules.concurrency]
enabled = true

[rules.ownership]
enabled = true

[rules.exhaustive]
enabled = true

[rules.taint]
enabled = true
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let cfg = Config::default();
        assert!(cfg.rules.nil.enabled);
        assert!(cfg.rules.errcheck.enabled);
        assert_eq!(cfg.goguard.severity_threshold, "warning");
        assert!(cfg.goguard.skip_generated);
        assert_eq!(cfg.goguard.max_diagnostics, 100);
    }

    #[test]
    fn test_parse_toml() {
        let toml_str = r#"
[goguard]
severity_threshold = "error"
skip_generated = false

[rules.nil]
enabled = true
strict_params = true

[rules.nil.models]
"ext.NewUser" = "nonnull"
"ext.Pair#0" = "nonnull"

[rules.errcheck]
enabled = true
ignore = ["fmt.Print*", "io.WriteString"]
"#;
        let cfg: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(cfg.goguard.severity_threshold, "error");
        assert!(!cfg.goguard.skip_generated);
        assert!(cfg.rules.nil.strict_params);
        assert_eq!(
            cfg.rules.nil.models.get("ext.NewUser").map(|s| s.as_str()),
            Some("nonnull")
        );
        assert_eq!(cfg.rules.errcheck.ignore.len(), 2);
    }

    #[test]
    fn test_partial_toml_uses_defaults() {
        let toml_str = r#"
[rules.nil]
enabled = false
"#;
        let cfg: Config = toml::from_str(toml_str).unwrap();
        assert!(!cfg.rules.nil.enabled);
        // errcheck should still be enabled (default)
        assert!(cfg.rules.errcheck.enabled);
        assert_eq!(cfg.goguard.severity_threshold, "warning");
    }

    #[test]
    fn test_load_config_no_file() {
        let cfg = load_config(Path::new("/nonexistent/path"));
        assert!(cfg.rules.nil.enabled);
        assert!(cfg.rules.errcheck.enabled);
    }

    #[test]
    fn test_find_config_file_tempdir() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("goguard.toml"), DEFAULT_CONFIG_TOML).unwrap();
        let found = find_config_file(dir.path());
        assert!(found.is_some());
        assert_eq!(found.unwrap(), dir.path().join("goguard.toml"));
    }

    #[test]
    fn test_find_config_walks_up() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("goguard.toml"), DEFAULT_CONFIG_TOML).unwrap();
        let subdir = dir.path().join("sub");
        std::fs::create_dir(&subdir).unwrap();
        let found = find_config_file(&subdir);
        assert!(found.is_some());
        assert_eq!(found.unwrap(), dir.path().join("goguard.toml"));
    }

    #[test]
    fn test_default_config_toml_parses() {
        let cfg: Config = toml::from_str(DEFAULT_CONFIG_TOML).unwrap();
        assert_eq!(cfg.goguard.severity_threshold, "warning");
        assert!(cfg.rules.errcheck.enabled);
        assert_eq!(cfg.rules.errcheck.ignore.len(), 2);
    }

    // ── Bridge cache config tests ──────────────────────────────

    #[test]
    fn test_config_cache_defaults() {
        let cfg = GoguardConfig::default();
        assert!(cfg.cache_dir.is_none());
        assert_eq!(cfg.max_cache_entries, 20);
        assert!(!cfg.no_cache);
    }

    #[test]
    fn test_config_cache_explicit_dir() {
        let toml_str = r#"
[goguard]
cache_dir = "/tmp/gc"
"#;
        let cfg: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(cfg.goguard.cache_dir, Some("/tmp/gc".to_string()));
        let resolved = resolve_bridge_cache_dir(&cfg.goguard);
        assert_eq!(resolved, Some(PathBuf::from("/tmp/gc")));
    }

    #[test]
    fn test_resolve_cache_dir_no_cache() {
        let cfg = GoguardConfig {
            no_cache: true,
            ..Default::default()
        };
        assert!(resolve_bridge_cache_dir(&cfg).is_none());
    }

    #[test]
    fn test_resolve_cache_dir_platform_default() {
        let cfg = GoguardConfig::default();
        let resolved = resolve_bridge_cache_dir(&cfg);
        // dirs::cache_dir() should return Some on all major platforms.
        let expected = dirs::cache_dir().map(|d| d.join("goguard").join("bridge-cache"));
        assert_eq!(resolved, expected);
        assert!(resolved.is_some());
    }
}
