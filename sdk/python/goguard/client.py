"""GoGuard Python SDK client — wraps the goguard sdk call CLI subprocess."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

from .models import (
    AnalysisResult,
    AutoFixResult,
    BatchResult,
    ExecuteResult,
    FixResult,
    QueryResult,
    Rule,
    SearchResult,
)


class GoGuardError(Exception):
    """Raised when a goguard CLI invocation fails."""

    pass


class GoGuard:
    """Python SDK client for GoGuard static analysis.

    Wraps the ``goguard sdk call`` CLI subcommand, providing typed
    Pydantic models for all responses.

    Args:
        project_dir: Path to the Go project root. Resolved to an absolute path.
        binary: Name or path of the goguard binary.
    """

    def __init__(self, project_dir: str = ".", binary: str = "goguard") -> None:
        self.project_dir: str = str(Path(project_dir).resolve())
        self.binary: str = binary
        self._default_timeout: int = 300

    def _call(self, tool: str, params: dict[str, Any] | None = None) -> dict:
        """Invoke ``goguard sdk call <tool>`` and return parsed JSON.

        Args:
            tool: The SDK tool name (e.g. ``goguard_analyze``).
            params: Optional parameters dict serialized as JSON.

        Returns:
            Parsed JSON response as a dict.

        Raises:
            GoGuardError: If the subprocess exits with a non-zero code or
                stdout cannot be parsed as JSON.
        """
        cmd = [self.binary, "sdk", "call", tool]

        effective_params = params or {}
        cmd.extend(["--params", json.dumps(effective_params)])
        cmd.extend(["--project-dir", self.project_dir])

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self._default_timeout,
            )
        except FileNotFoundError:
            raise GoGuardError(
                f"goguard binary not found: {self.binary!r}. "
                "Install GoGuard or pass the correct binary path."
            )
        except subprocess.TimeoutExpired:
            raise GoGuardError(
                f"goguard sdk call {tool} timed out after {self._default_timeout} seconds."
            )

        if result.returncode != 0:
            stderr = result.stderr.strip()
            raise GoGuardError(
                f"goguard sdk call {tool} failed (exit {result.returncode}): {stderr}"
            )

        stdout = result.stdout.strip()
        if not stdout:
            raise GoGuardError(
                f"goguard sdk call {tool} returned empty output."
            )

        try:
            return json.loads(stdout)
        except json.JSONDecodeError as exc:
            raise GoGuardError(
                f"goguard sdk call {tool} returned invalid JSON: {exc}"
            ) from exc

    def analyze(
        self,
        packages: list[str] | None = None,
        severity: str | None = None,
    ) -> AnalysisResult:
        """Run static analysis on the project.

        Args:
            packages: Optional list of Go package patterns to analyze.
                Defaults to ``["./..."]`` (all packages).
            severity: Optional minimum severity filter (critical, error,
                warning, info).

        Returns:
            Typed AnalysisResult with diagnostics, summary, and bridge errors.
        """
        params: dict[str, Any] = {}
        if packages is not None:
            params["packages"] = packages
        if severity is not None:
            params["severity"] = severity

        data = self._call("goguard_analyze", params)
        return AnalysisResult.model_validate(data)

    def explain(self, diagnostic_id: str) -> dict:
        """Get full details for a diagnostic skeleton.

        Args:
            diagnostic_id: The diagnostic ID (e.g. ``NIL001-main.go:42``).

        Returns:
            Full diagnostic details as a dict.
        """
        return self._call("goguard_explain", {"diagnostic_id": diagnostic_id})

    def fix(
        self, diagnostic_id: str, auto_verify: bool = True
    ) -> FixResult:
        """Request and optionally verify a fix for a diagnostic.

        Args:
            diagnostic_id: The diagnostic ID to fix.
            auto_verify: Whether to re-analyze after applying edits.

        Returns:
            Typed FixResult with edits and optional verification.
        """
        params: dict[str, Any] = {
            "diagnostic_id": diagnostic_id,
            "auto_verify": auto_verify,
        }
        data = self._call("goguard_fix", params)
        return FixResult.model_validate(data)

    def batch(
        self,
        diagnostic_ids: list[str] | None = None,
        severity: str | None = None,
        rule_prefix: str | None = None,
        dry_run: bool = False,
    ) -> BatchResult:
        """Batch-fix multiple diagnostics.

        Args:
            diagnostic_ids: Specific diagnostic IDs to fix.
            severity: Fix all diagnostics at or above this severity.
            rule_prefix: Fix all diagnostics matching this rule prefix.
            dry_run: If True, return proposed edits without applying.

        Returns:
            Typed BatchResult with applied fixes and verification.
        """
        params: dict[str, Any] = {"dry_run": dry_run}
        if diagnostic_ids is not None:
            params["diagnostic_ids"] = diagnostic_ids
        if severity is not None:
            params["severity"] = severity
        if rule_prefix is not None:
            params["rule_prefix"] = rule_prefix

        data = self._call("goguard_batch", params)
        return BatchResult.model_validate(data)

    def snapshot(
        self,
        action: str,
        name: str | None = None,
        compare_to: str | None = None,
    ) -> dict:
        """Manage analysis snapshots.

        Args:
            action: One of ``save``, ``load``, ``compare``, ``list``.
            name: Snapshot name (required for save/load/compare).
            compare_to: Snapshot name to compare against.

        Returns:
            Snapshot operation result as a dict.
        """
        params: dict[str, Any] = {"action": action}
        if name is not None:
            params["name"] = name
        if compare_to is not None:
            params["compare_to"] = compare_to

        return self._call("goguard_snapshot", params)

    def rules(self, category: str | None = None) -> list[Rule]:
        """List available analysis rules.

        Args:
            category: Optional category filter (e.g. ``nil``, ``errcheck``).

        Returns:
            List of typed Rule objects.
        """
        params: dict[str, Any] = {}
        if category is not None:
            params["category"] = category

        data = self._call("goguard_rules", params)

        # The CLI returns either a list directly or a dict with a "rules" key.
        rule_list = data if isinstance(data, list) else data.get("rules", [])
        return [Rule.model_validate(r) for r in rule_list]

    def auto_fix(
        self,
        *,
        packages: list[str] | None = None,
        severity: str = "error",
        max_fixes: int = 50,
        max_iterations: int = 10,
        test: bool = False,
        dry_run: bool = False,
        timeout: int = 600,
    ) -> AutoFixResult:
        """Run the auto-fix orchestrator: analyze, fix, verify, repeat.

        Args:
            packages: Go package patterns (default: ``["./..."]``).
            severity: Minimum severity to fix (critical, error, warning, info).
            max_fixes: Maximum number of fixes per run.
            max_iterations: Maximum analysis-fix iterations.
            test: Run ``go test`` after each fix batch.
            dry_run: Propose fixes without writing to disk.
            timeout: Subprocess timeout in seconds (default 600).

        Returns:
            Typed AutoFixResult with fix counts, timing, and before/after summary.
        """
        params: dict[str, Any] = {
            "severity": severity,
            "max_fixes": max_fixes,
            "max_iterations": max_iterations,
            "test": test,
            "dry_run": dry_run,
        }
        if packages is not None:
            params["packages"] = packages

        # Auto-fix can take a long time — use a longer timeout
        old_timeout = self._default_timeout
        self._default_timeout = timeout
        try:
            data = self._call("goguard_autofix", params)
        finally:
            self._default_timeout = old_timeout

        return AutoFixResult.model_validate(data)

    def search(self, code: str) -> SearchResult:
        """Explore GoGuard analysis API via JavaScript (read-only).

        The ``spec`` and ``goguard`` globals are available in the JS sandbox.

        Args:
            code: JavaScript expression or statement to evaluate.

        Returns:
            Typed SearchResult with output or error.
        """
        data = self._call("goguard_search", {"code": code})
        return SearchResult.model_validate(data)

    def execute(self, code: str, timeout_ms: int = 5000) -> ExecuteResult:
        """Run JavaScript against GoGuard analysis data.

        The ``goguard`` global provides ``.diagnostics()``, ``.packages()``,
        ``.callGraph()``, ``.functions()``, ``.rules()``, ``.taintFlows()``,
        ``.config``.

        Args:
            code: JavaScript code to execute.
            timeout_ms: JS execution timeout in milliseconds.

        Returns:
            Typed ExecuteResult with output or error.
        """
        data = self._call("goguard_execute", {"code": code, "timeout_ms": timeout_ms})
        return ExecuteResult.model_validate(data)

    def query(self, expression: str) -> QueryResult:
        """Run a GoGuard QL query or JavaScript expression.

        Accepts GoGuard QL DSL (e.g. ``diagnostics where severity == "critical"``)
        or JavaScript code (detected by ``() =>``, ``async``, or ``goguard.`` prefix).

        Args:
            expression: GoGuard QL expression or JavaScript code.

        Returns:
            Typed QueryResult with output or error.
        """
        data = self._call("goguard_query", {"expression": expression})
        return QueryResult.model_validate(data)
