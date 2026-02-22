# GoGuard Python SDK

Python SDK for [GoGuard](https://github.com/NextStat/GoGuard) — Rust-level safety analysis for Go.

## Requirements

- Python 3.10+
- GoGuard binary installed and on PATH

## Installation

```bash
pip install goguard
```

## Quick Start

```python
from goguard import GoGuard

g = GoGuard("/path/to/go/project")

# Analyze
result = g.analyze(severity="error")
for d in result.diagnostics:
    print(f"{d.rule} {d.location.file}:{d.location.line} — {d.title}")

# Get full details
detail = g.explain(result.diagnostics[0].id)

# Fix a diagnostic
fix = g.fix(result.diagnostics[0].id)
fix.apply()  # writes to disk

# Auto-fix all errors
report = g.auto_fix(severity="error", dry_run=True)
print(f"Would fix {report.fixes_applied} issues")

# Run JavaScript against analysis data
result = g.execute("goguard.diagnostics().length")
print(result.output)

# Query with GoGuard QL
result = g.query('diagnostics where severity == "critical"')
```

## API Reference

| Method | Returns | Description |
|--------|---------|-------------|
| `analyze()` | `AnalysisResult` | Run static analysis |
| `explain(id)` | `dict` | Full diagnostic details |
| `fix(id)` | `FixResult` | Generate and verify a fix |
| `batch(...)` | `BatchResult` | Batch-fix multiple diagnostics |
| `auto_fix(...)` | `AutoFixResult` | Full auto-fix orchestrator |
| `snapshot(...)` | `dict` | Save/compare analysis snapshots |
| `rules(...)` | `list[Rule]` | List available rules |
| `search(code)` | `SearchResult` | Explore API via JavaScript |
| `execute(code)` | `ExecuteResult` | Run JS against analysis data |
| `query(expr)` | `QueryResult` | GoGuard QL or JavaScript query |
