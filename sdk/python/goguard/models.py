"""GoGuard Pydantic v2 models for typed SDK responses."""

from __future__ import annotations

from enum import Enum
from pathlib import Path
from typing import Optional

from pydantic import BaseModel, Field


class Severity(str, Enum):
    """Diagnostic severity levels, ordered from most to least severe."""

    critical = "critical"
    error = "error"
    warning = "warning"
    info = "info"


class Location(BaseModel):
    """Source code location for a diagnostic."""

    file: str
    line: int
    column: int
    end_line: int = 0
    end_column: int = 0


class DiagnosticSkeleton(BaseModel):
    """Compact diagnostic representation returned by goguard_analyze.

    This is a skeleton -- use GoGuard.explain() to get full details.
    """

    id: str
    rule: str
    severity: Severity
    title: str
    location: Location
    confidence: float = 1.0


class TextEdit(BaseModel):
    """A single text edit to apply to a source file."""

    file: str
    start_line: int
    end_line: int
    old_text: str = ""
    new_text: str


class VerificationResult(BaseModel):
    """Result of re-analyzing after a fix is applied."""

    status: str
    remaining_in_file: int = 0
    new_issues_introduced: int = 0
    new_issues: list[dict] = Field(default_factory=list)
    affected_packages: list[str] = Field(default_factory=list)


class FixResult(BaseModel):
    """Result of requesting a fix for a diagnostic."""

    diagnostic_id: str
    description: str = ""
    edits: list[TextEdit] = Field(default_factory=list)
    verification: Optional[VerificationResult] = None
    no_fix: bool = False

    def apply(self, base_dir: str | Path = ".") -> list[str]:
        """Apply all edits to files on disk.

        Args:
            base_dir: Base directory to resolve relative file paths against.

        Returns:
            List of absolute paths of modified files.
        """
        base = Path(base_dir).resolve()
        modified: list[str] = []

        for edit in self.edits:
            file_path = base / edit.file
            if not file_path.exists():
                continue

            lines = file_path.read_text(encoding="utf-8").splitlines(keepends=True)

            # Convert to 0-based indices. start_line and end_line are 1-based.
            start_idx = edit.start_line - 1
            end_idx = edit.end_line  # end_line is inclusive, so slice up to end_line

            # Replace the line range with new_text
            new_lines = edit.new_text.splitlines(keepends=True)
            # Ensure the last line has a newline if the original did
            if new_lines and not new_lines[-1].endswith("\n"):
                new_lines[-1] += "\n"

            lines[start_idx:end_idx] = new_lines

            file_path.write_text("".join(lines), encoding="utf-8")
            abs_path = str(file_path.resolve())
            if abs_path not in modified:
                modified.append(abs_path)

        return modified


class AnalysisResult(BaseModel):
    """Result of running goguard_analyze."""

    diagnostics: list[DiagnosticSkeleton] = Field(default_factory=list)
    summary: dict = Field(default_factory=dict)
    bridge_errors: list[str] = Field(default_factory=list)

    def filter(
        self,
        *,
        severity: Severity | None = None,
        rule_prefix: str | None = None,
        file: str | None = None,
    ) -> list[DiagnosticSkeleton]:
        """Filter diagnostics by severity, rule prefix, or file path.

        All provided filters are ANDed together.

        Args:
            severity: Only include diagnostics with this exact severity.
            rule_prefix: Only include diagnostics whose rule starts with this prefix.
            file: Only include diagnostics in this file.

        Returns:
            Filtered list of DiagnosticSkeleton instances.
        """
        result = list(self.diagnostics)

        if severity is not None:
            result = [d for d in result if d.severity == severity]

        if rule_prefix is not None:
            result = [d for d in result if d.rule.startswith(rule_prefix)]

        if file is not None:
            result = [d for d in result if d.location.file == file]

        return result


class Rule(BaseModel):
    """A GoGuard analysis rule."""

    code: str
    category: str
    severity: str
    title: str
    description: str


class BatchResult(BaseModel):
    """Result of a batch fix operation."""

    applied: list[dict] = Field(default_factory=list)
    verification: dict = Field(default_factory=dict)
    remaining_diagnostics: list[dict] = Field(default_factory=list)


class SeveritySummary(BaseModel):
    """Count of diagnostics by severity level."""

    critical: int = 0
    error: int = 0
    warning: int = 0
    info: int = 0


class GoTestResult(BaseModel):
    """Result of a go test run during auto-fix verification."""

    success: bool = False
    passed: int = 0
    failed: int = 0
    skipped: int = 0
    failures: list[dict] = Field(default_factory=list)
    time_ms: int = 0


class AutoFixResult(BaseModel):
    """Result of the auto-fix orchestrator."""

    iterations: int = 0
    fixes_applied: int = 0
    fixes_skipped: int = 0
    skipped_reasons: list[str] = Field(default_factory=list)
    before: SeveritySummary = Field(default_factory=SeveritySummary)
    after: SeveritySummary = Field(default_factory=SeveritySummary)
    time_elapsed_ms: int = 0
    build_status: str = ""
    test_status: Optional[GoTestResult] = None


class SearchResult(BaseModel):
    """Result of goguard_search (JS code against spec API)."""

    output: str = ""
    error: Optional[str] = None


class ExecuteResult(BaseModel):
    """Result of goguard_execute (JS code against analysis data)."""

    output: str = ""
    error: Optional[str] = None


class QueryResult(BaseModel):
    """Result of goguard_query (GoGuard QL or JS expression)."""

    output: str = ""
    error: Optional[str] = None
