"""Tests for the GoGuard Python SDK.

These tests validate models and client logic without requiring the goguard
binary. Subprocess calls are mocked where needed.
"""

from __future__ import annotations

import json
import textwrap
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from pydantic import ValidationError

from goguard import GoGuard, GoGuardError
from goguard.models import (
    AnalysisResult,
    AutoFixResult,
    BatchResult,
    DiagnosticSkeleton,
    ExecuteResult,
    FixResult,
    Location,
    QueryResult,
    Rule,
    SearchResult,
    Severity,
    SeveritySummary,
    GoTestResult,
    TextEdit,
    VerificationResult,
)


# ---------------------------------------------------------------------------
# Model tests
# ---------------------------------------------------------------------------


class TestSeverityEnum:
    def test_values(self):
        assert Severity.critical == "critical"
        assert Severity.error == "error"
        assert Severity.warning == "warning"
        assert Severity.info == "info"

    def test_is_string(self):
        assert isinstance(Severity.critical, str)


class TestLocation:
    def test_defaults(self):
        loc = Location(file="main.go", line=10, column=5)
        assert loc.end_line == 0
        assert loc.end_column == 0

    def test_full(self):
        loc = Location(file="a.go", line=1, column=2, end_line=3, end_column=4)
        assert loc.end_line == 3
        assert loc.end_column == 4


class TestDiagnosticSkeleton:
    def test_construction(self):
        d = DiagnosticSkeleton(
            id="NIL001-main.go:10",
            rule="NIL001",
            severity=Severity.critical,
            title="nil pointer dereference",
            location=Location(file="main.go", line=10, column=5),
        )
        assert d.confidence == 1.0
        assert d.severity == Severity.critical

    def test_rejects_bad_severity(self):
        with pytest.raises(ValidationError):
            DiagnosticSkeleton(
                id="X",
                rule="X",
                severity="unknown",
                title="X",
                location=Location(file="x.go", line=1, column=1),
            )

    def test_from_dict(self):
        data = {
            "id": "ERR002-pkg.go:5",
            "rule": "ERR002",
            "severity": "error",
            "title": "unchecked error",
            "location": {"file": "pkg.go", "line": 5, "column": 1},
            "confidence": 0.9,
        }
        d = DiagnosticSkeleton.model_validate(data)
        assert d.confidence == 0.9
        assert d.location.file == "pkg.go"


class TestTextEdit:
    def test_defaults(self):
        e = TextEdit(file="a.go", start_line=1, end_line=1, new_text="fixed")
        assert e.old_text == ""

    def test_full(self):
        e = TextEdit(
            file="a.go",
            start_line=5,
            end_line=7,
            old_text="old code",
            new_text="new code",
        )
        assert e.start_line == 5
        assert e.end_line == 7


class TestVerificationResult:
    def test_defaults(self):
        v = VerificationResult(status="clean")
        assert v.remaining_in_file == 0
        assert v.new_issues_introduced == 0
        assert v.new_issues == []
        assert v.affected_packages == []

    def test_with_issues(self):
        v = VerificationResult(
            status="issues_found",
            remaining_in_file=2,
            new_issues_introduced=1,
            new_issues=[{"id": "NEW001"}],
            affected_packages=["./cmd/..."],
        )
        assert v.new_issues_introduced == 1


class TestFixResult:
    def test_no_fix(self):
        fix = FixResult(diagnostic_id="NIL001-x.go:1", no_fix=True)
        assert fix.no_fix is True
        assert fix.edits == []
        assert fix.verification is None
        assert fix.description == ""

    def test_with_edits(self):
        fix = FixResult(
            diagnostic_id="NIL001-main.go:10",
            description="Add nil check",
            edits=[
                TextEdit(file="main.go", start_line=10, end_line=10, new_text="if x != nil {"),
            ],
        )
        assert len(fix.edits) == 1
        assert fix.edits[0].new_text == "if x != nil {"

    def test_with_verification(self):
        fix = FixResult(
            diagnostic_id="NIL001-main.go:10",
            edits=[],
            verification=VerificationResult(status="clean"),
        )
        assert fix.verification is not None
        assert fix.verification.status == "clean"

    def test_apply_writes_file(self, tmp_path):
        """FixResult.apply() should modify files on disk."""
        go_file = tmp_path / "main.go"
        go_file.write_text("line1\nline2\nline3\n")

        fix = FixResult(
            diagnostic_id="test",
            edits=[
                TextEdit(
                    file="main.go",
                    start_line=2,
                    end_line=2,
                    old_text="line2",
                    new_text="replaced",
                ),
            ],
        )

        modified = fix.apply(base_dir=tmp_path)
        assert len(modified) == 1
        assert str(go_file.resolve()) in modified[0]

        content = go_file.read_text()
        assert "replaced" in content
        assert "line1" in content
        assert "line3" in content

    def test_apply_nonexistent_file_skips(self, tmp_path):
        """apply() should skip edits for files that do not exist."""
        fix = FixResult(
            diagnostic_id="test",
            edits=[
                TextEdit(
                    file="nonexistent.go",
                    start_line=1,
                    end_line=1,
                    new_text="x",
                ),
            ],
        )
        modified = fix.apply(base_dir=tmp_path)
        assert modified == []

    def test_apply_multiple_edits_same_file(self, tmp_path):
        """Multiple edits to the same file should produce one entry in modified."""
        go_file = tmp_path / "a.go"
        go_file.write_text("a\nb\nc\nd\ne\n")

        fix = FixResult(
            diagnostic_id="test",
            edits=[
                TextEdit(file="a.go", start_line=2, end_line=2, new_text="B"),
                TextEdit(file="a.go", start_line=4, end_line=4, new_text="D"),
            ],
        )

        # Note: applying sequential edits on already-modified content is
        # inherently tricky. The second edit's line numbers refer to the
        # file *after* the first edit. For this test the replacement is
        # same-length so line numbers remain stable.
        modified = fix.apply(base_dir=tmp_path)
        assert len(modified) == 1


class TestAnalysisResult:
    @pytest.fixture()
    def sample_result(self) -> AnalysisResult:
        return AnalysisResult(
            diagnostics=[
                DiagnosticSkeleton(
                    id="NIL001-a.go:10",
                    rule="NIL001",
                    severity=Severity.critical,
                    title="nil deref",
                    location=Location(file="a.go", line=10, column=1),
                ),
                DiagnosticSkeleton(
                    id="ERR001-b.go:20",
                    rule="ERR001",
                    severity=Severity.error,
                    title="err",
                    location=Location(file="b.go", line=20, column=1),
                ),
                DiagnosticSkeleton(
                    id="NIL004-a.go:30",
                    rule="NIL004",
                    severity=Severity.warning,
                    title="nil map",
                    location=Location(file="a.go", line=30, column=1),
                ),
            ]
        )

    def test_filter_by_severity(self, sample_result):
        critical = sample_result.filter(severity=Severity.critical)
        assert len(critical) == 1
        assert critical[0].rule == "NIL001"

    def test_filter_by_rule_prefix(self, sample_result):
        nil_diags = sample_result.filter(rule_prefix="NIL")
        assert len(nil_diags) == 2
        assert all(d.rule.startswith("NIL") for d in nil_diags)

    def test_filter_by_file(self, sample_result):
        a_file = sample_result.filter(file="a.go")
        assert len(a_file) == 2
        assert all(d.location.file == "a.go" for d in a_file)

    def test_filter_combined(self, sample_result):
        """Multiple filters should be ANDed."""
        result = sample_result.filter(severity=Severity.warning, rule_prefix="NIL")
        assert len(result) == 1
        assert result[0].id == "NIL004-a.go:30"

    def test_filter_no_match(self, sample_result):
        result = sample_result.filter(rule_prefix="CONCURRENCY")
        assert result == []

    def test_filter_none_returns_all(self, sample_result):
        result = sample_result.filter()
        assert len(result) == 3

    def test_defaults(self):
        r = AnalysisResult()
        assert r.diagnostics == []
        assert r.summary == {}
        assert r.bridge_errors == []

    def test_from_dict(self):
        data = {
            "diagnostics": [
                {
                    "id": "NIL001-main.go:1",
                    "rule": "NIL001",
                    "severity": "critical",
                    "title": "nil",
                    "location": {"file": "main.go", "line": 1, "column": 1},
                }
            ],
            "summary": {"total": 1},
            "bridge_errors": ["timeout on pkg X"],
        }
        r = AnalysisResult.model_validate(data)
        assert len(r.diagnostics) == 1
        assert r.summary["total"] == 1
        assert len(r.bridge_errors) == 1


class TestRule:
    def test_model_validate(self):
        rule = Rule.model_validate(
            {
                "code": "NIL001",
                "category": "nil",
                "severity": "critical",
                "title": "Nil deref",
                "description": "Bad",
            }
        )
        assert rule.code == "NIL001"
        assert rule.category == "nil"

    def test_missing_field_raises(self):
        with pytest.raises(ValidationError):
            Rule.model_validate({"code": "NIL001"})


class TestBatchResult:
    def test_defaults(self):
        b = BatchResult()
        assert b.applied == []
        assert b.verification == {}
        assert b.remaining_diagnostics == []


# ---------------------------------------------------------------------------
# Client tests
# ---------------------------------------------------------------------------


class TestGoGuardInit:
    def test_defaults(self):
        g = GoGuard()
        assert g.binary == "goguard"
        assert Path(g.project_dir).is_absolute()

    def test_custom_args(self):
        g = GoGuard("/tmp", "/usr/local/bin/goguard")
        assert g.binary == "/usr/local/bin/goguard"
        assert g.project_dir == str(Path("/tmp").resolve())

    def test_project_dir_resolved(self):
        g = GoGuard(".")
        assert Path(g.project_dir).is_absolute()


class TestGoGuardCall:
    """Tests for GoGuard._call() with mocked subprocess."""

    def _mock_run(self, stdout="", stderr="", returncode=0):
        """Create a mock subprocess.run result."""
        mock = MagicMock()
        mock.stdout = stdout
        mock.stderr = stderr
        mock.returncode = returncode
        return mock

    @patch("goguard.client.subprocess.run")
    def test_successful_call(self, mock_run):
        mock_run.return_value = self._mock_run(
            stdout='{"diagnostics": []}',
        )
        g = GoGuard()
        result = g._call("goguard_analyze", {"packages": ["./..."]})
        assert result == {"diagnostics": []}

        # Verify the command was constructed correctly
        args = mock_run.call_args[0][0]
        assert args[0] == "goguard"
        assert args[1] == "sdk"
        assert args[2] == "call"
        assert args[3] == "goguard_analyze"
        assert "--params" in args
        assert "--project-dir" in args

    @patch("goguard.client.subprocess.run")
    def test_nonzero_exit_raises(self, mock_run):
        mock_run.return_value = self._mock_run(
            returncode=1,
            stderr="analysis failed",
        )
        g = GoGuard()
        with pytest.raises(GoGuardError, match="failed.*exit 1"):
            g._call("goguard_analyze")

    @patch("goguard.client.subprocess.run")
    def test_empty_stdout_raises(self, mock_run):
        mock_run.return_value = self._mock_run(stdout="")
        g = GoGuard()
        with pytest.raises(GoGuardError, match="empty output"):
            g._call("goguard_analyze")

    @patch("goguard.client.subprocess.run")
    def test_invalid_json_raises(self, mock_run):
        mock_run.return_value = self._mock_run(stdout="not json")
        g = GoGuard()
        with pytest.raises(GoGuardError, match="invalid JSON"):
            g._call("goguard_analyze")

    @patch("goguard.client.subprocess.run")
    def test_binary_not_found_raises(self, mock_run):
        mock_run.side_effect = FileNotFoundError()
        g = GoGuard()
        with pytest.raises(GoGuardError, match="not found"):
            g._call("goguard_analyze")

    @patch("goguard.client.subprocess.run")
    def test_timeout_raises(self, mock_run):
        import subprocess as sp

        mock_run.side_effect = sp.TimeoutExpired(cmd="goguard", timeout=300)
        g = GoGuard()
        with pytest.raises(GoGuardError, match="timed out"):
            g._call("goguard_analyze")


class TestGoGuardAnalyze:
    @patch("goguard.client.subprocess.run")
    def test_analyze_returns_typed_result(self, mock_run):
        payload = {
            "diagnostics": [
                {
                    "id": "NIL001-main.go:5",
                    "rule": "NIL001",
                    "severity": "critical",
                    "title": "nil pointer dereference",
                    "location": {"file": "main.go", "line": 5, "column": 3},
                }
            ],
            "summary": {"total": 1, "critical": 1},
            "bridge_errors": [],
        }
        mock = MagicMock()
        mock.stdout = json.dumps(payload)
        mock.stderr = ""
        mock.returncode = 0
        mock_run.return_value = mock

        g = GoGuard()
        result = g.analyze(packages=["./cmd/..."], severity="critical")

        assert isinstance(result, AnalysisResult)
        assert len(result.diagnostics) == 1
        assert result.diagnostics[0].severity == Severity.critical

    @patch("goguard.client.subprocess.run")
    def test_analyze_no_params(self, mock_run):
        mock = MagicMock()
        mock.stdout = '{"diagnostics": [], "summary": {}, "bridge_errors": []}'
        mock.stderr = ""
        mock.returncode = 0
        mock_run.return_value = mock

        g = GoGuard()
        result = g.analyze()

        assert isinstance(result, AnalysisResult)
        assert result.diagnostics == []

        # Check that params were passed as empty dict
        args = mock_run.call_args[0][0]
        params_idx = args.index("--params")
        params_json = json.loads(args[params_idx + 1])
        assert params_json == {}


class TestGoGuardExplain:
    @patch("goguard.client.subprocess.run")
    def test_explain_returns_dict(self, mock_run):
        payload = {
            "diagnostic_id": "NIL001-main.go:5",
            "rule": "NIL001",
            "explanation": "Pointer x may be nil here",
            "code_context": "x.Method()",
        }
        mock = MagicMock()
        mock.stdout = json.dumps(payload)
        mock.stderr = ""
        mock.returncode = 0
        mock_run.return_value = mock

        g = GoGuard()
        result = g.explain("NIL001-main.go:5")

        assert result["diagnostic_id"] == "NIL001-main.go:5"
        assert "explanation" in result


class TestGoGuardFix:
    @patch("goguard.client.subprocess.run")
    def test_fix_returns_typed_result(self, mock_run):
        payload = {
            "diagnostic_id": "NIL001-main.go:5",
            "description": "Add nil check before dereference",
            "edits": [
                {
                    "file": "main.go",
                    "start_line": 5,
                    "end_line": 5,
                    "old_text": "x.Method()",
                    "new_text": "if x != nil {\n\tx.Method()\n}",
                }
            ],
            "verification": {"status": "clean", "remaining_in_file": 0},
        }
        mock = MagicMock()
        mock.stdout = json.dumps(payload)
        mock.stderr = ""
        mock.returncode = 0
        mock_run.return_value = mock

        g = GoGuard()
        result = g.fix("NIL001-main.go:5")

        assert isinstance(result, FixResult)
        assert len(result.edits) == 1
        assert result.verification is not None
        assert result.verification.status == "clean"


class TestGoGuardBatch:
    @patch("goguard.client.subprocess.run")
    def test_batch_returns_typed_result(self, mock_run):
        payload = {
            "applied": [{"diagnostic_id": "NIL001-main.go:5", "status": "fixed"}],
            "verification": {"clean": True},
            "remaining_diagnostics": [],
        }
        mock = MagicMock()
        mock.stdout = json.dumps(payload)
        mock.stderr = ""
        mock.returncode = 0
        mock_run.return_value = mock

        g = GoGuard()
        result = g.batch(diagnostic_ids=["NIL001-main.go:5"])

        assert isinstance(result, BatchResult)
        assert len(result.applied) == 1


class TestGoGuardSnapshot:
    @patch("goguard.client.subprocess.run")
    def test_snapshot_returns_dict(self, mock_run):
        payload = {"action": "save", "name": "baseline", "status": "saved"}
        mock = MagicMock()
        mock.stdout = json.dumps(payload)
        mock.stderr = ""
        mock.returncode = 0
        mock_run.return_value = mock

        g = GoGuard()
        result = g.snapshot("save", name="baseline")

        assert result["status"] == "saved"


class TestGoGuardRules:
    @patch("goguard.client.subprocess.run")
    def test_rules_returns_list_of_rule(self, mock_run):
        payload = [
            {
                "code": "NIL001",
                "category": "nil",
                "severity": "critical",
                "title": "Nil pointer dereference",
                "description": "Detects nil pointer dereferences",
            },
            {
                "code": "ERR001",
                "category": "errcheck",
                "severity": "error",
                "title": "Unchecked error",
                "description": "Detects unchecked error returns",
            },
        ]
        mock = MagicMock()
        mock.stdout = json.dumps(payload)
        mock.stderr = ""
        mock.returncode = 0
        mock_run.return_value = mock

        g = GoGuard()
        result = g.rules()

        assert len(result) == 2
        assert all(isinstance(r, Rule) for r in result)
        assert result[0].code == "NIL001"

    @patch("goguard.client.subprocess.run")
    def test_rules_dict_format(self, mock_run):
        """CLI may return {"rules": [...]} instead of a plain list."""
        payload = {
            "rules": [
                {
                    "code": "NIL001",
                    "category": "nil",
                    "severity": "critical",
                    "title": "Nil pointer dereference",
                    "description": "Detects nil pointer dereferences",
                },
            ]
        }
        mock = MagicMock()
        mock.stdout = json.dumps(payload)
        mock.stderr = ""
        mock.returncode = 0
        mock_run.return_value = mock

        g = GoGuard()
        result = g.rules(category="nil")

        assert len(result) == 1
        assert result[0].code == "NIL001"


# ---------------------------------------------------------------------------
# New model tests (auto_fix, search, execute, query)
# ---------------------------------------------------------------------------


class TestSeveritySummary:
    def test_defaults(self):
        s = SeveritySummary()
        assert s.critical == 0
        assert s.error == 0
        assert s.warning == 0
        assert s.info == 0

    def test_from_dict(self):
        s = SeveritySummary.model_validate(
            {"critical": 1, "error": 3, "warning": 5, "info": 0}
        )
        assert s.critical == 1
        assert s.error == 3
        assert s.warning == 5


class TestGoTestResult:
    def test_defaults(self):
        t = GoTestResult()
        assert t.success is False
        assert t.passed == 0
        assert t.failures == []

    def test_from_dict(self):
        t = GoTestResult.model_validate(
            {"success": True, "passed": 10, "failed": 0, "skipped": 2, "time_ms": 500}
        )
        assert t.success is True
        assert t.passed == 10
        assert t.skipped == 2


class TestAutoFixResult:
    def test_defaults(self):
        r = AutoFixResult()
        assert r.iterations == 0
        assert r.fixes_applied == 0
        assert r.fixes_skipped == 0
        assert r.skipped_reasons == []
        assert r.build_status == ""
        assert r.test_status is None

    def test_from_dict(self):
        data = {
            "iterations": 3,
            "fixes_applied": 5,
            "fixes_skipped": 2,
            "skipped_reasons": ["NIL001: build regression"],
            "before": {"critical": 2, "error": 5, "warning": 10, "info": 0},
            "after": {"critical": 0, "error": 2, "warning": 8, "info": 0},
            "time_elapsed_ms": 12345,
            "build_status": "pass",
            "test_status": {
                "success": True,
                "passed": 42,
                "failed": 0,
                "skipped": 0,
                "failures": [],
                "time_ms": 3000,
            },
        }
        r = AutoFixResult.model_validate(data)
        assert r.iterations == 3
        assert r.fixes_applied == 5
        assert r.before.critical == 2
        assert r.after.critical == 0
        assert r.build_status == "pass"
        assert r.test_status is not None
        assert r.test_status.success is True
        assert r.test_status.passed == 42


class TestSearchResult:
    def test_defaults(self):
        r = SearchResult()
        assert r.output == ""
        assert r.error is None

    def test_from_dict(self):
        r = SearchResult.model_validate({"output": "42", "error": None})
        assert r.output == "42"


class TestExecuteResult:
    def test_defaults(self):
        r = ExecuteResult()
        assert r.output == ""
        assert r.error is None

    def test_from_dict_with_error(self):
        r = ExecuteResult.model_validate({"output": "", "error": "ReferenceError"})
        assert r.error == "ReferenceError"


class TestQueryResult:
    def test_defaults(self):
        r = QueryResult()
        assert r.output == ""
        assert r.error is None

    def test_from_dict(self):
        r = QueryResult.model_validate(
            {"output": '[{"id": "NIL001-main.go:5"}]', "error": None}
        )
        assert "NIL001" in r.output


# ---------------------------------------------------------------------------
# Client tests for new methods
# ---------------------------------------------------------------------------


class TestGoGuardAutoFix:
    @patch("goguard.client.subprocess.run")
    def test_auto_fix_returns_typed_result(self, mock_run):
        payload = {
            "iterations": 2,
            "fixes_applied": 3,
            "fixes_skipped": 1,
            "skipped_reasons": ["ERR001: build regression"],
            "before": {"critical": 1, "error": 4, "warning": 8, "info": 0},
            "after": {"critical": 0, "error": 2, "warning": 6, "info": 0},
            "time_elapsed_ms": 5000,
            "build_status": "pass",
        }
        mock = MagicMock()
        mock.stdout = json.dumps(payload)
        mock.stderr = ""
        mock.returncode = 0
        mock_run.return_value = mock

        g = GoGuard()
        result = g.auto_fix(severity="error", max_fixes=10, dry_run=True)

        assert isinstance(result, AutoFixResult)
        assert result.fixes_applied == 3
        assert result.before.critical == 1
        assert result.after.critical == 0

        # Verify params were passed correctly
        args = mock_run.call_args[0][0]
        params_idx = args.index("--params")
        params_json = json.loads(args[params_idx + 1])
        assert params_json["severity"] == "error"
        assert params_json["max_fixes"] == 10
        assert params_json["dry_run"] is True

    @patch("goguard.client.subprocess.run")
    def test_auto_fix_timeout_is_600(self, mock_run):
        """auto_fix should use a 600s timeout by default."""
        mock = MagicMock()
        mock.stdout = json.dumps({"iterations": 0, "fixes_applied": 0})
        mock.stderr = ""
        mock.returncode = 0
        mock_run.return_value = mock

        g = GoGuard()
        g.auto_fix()

        # Verify timeout was 600
        kwargs = mock_run.call_args[1]
        assert kwargs["timeout"] == 600

    @patch("goguard.client.subprocess.run")
    def test_auto_fix_restores_default_timeout(self, mock_run):
        """After auto_fix, the default timeout should be restored to 300."""
        mock = MagicMock()
        mock.stdout = json.dumps({"iterations": 0, "fixes_applied": 0})
        mock.stderr = ""
        mock.returncode = 0
        mock_run.return_value = mock

        g = GoGuard()
        g.auto_fix(timeout=900)
        assert g._default_timeout == 300  # restored


class TestGoGuardSearch:
    @patch("goguard.client.subprocess.run")
    def test_search_returns_typed_result(self, mock_run):
        payload = {"output": '["goguard_analyze","goguard_fix"]', "error": None}
        mock = MagicMock()
        mock.stdout = json.dumps(payload)
        mock.stderr = ""
        mock.returncode = 0
        mock_run.return_value = mock

        g = GoGuard()
        result = g.search("Object.keys(spec.api)")

        assert isinstance(result, SearchResult)
        assert "goguard_analyze" in result.output

        # Verify params
        args = mock_run.call_args[0][0]
        assert args[3] == "goguard_search"
        params_idx = args.index("--params")
        params_json = json.loads(args[params_idx + 1])
        assert params_json["code"] == "Object.keys(spec.api)"


class TestGoGuardExecute:
    @patch("goguard.client.subprocess.run")
    def test_execute_returns_typed_result(self, mock_run):
        payload = {"output": "5", "error": None}
        mock = MagicMock()
        mock.stdout = json.dumps(payload)
        mock.stderr = ""
        mock.returncode = 0
        mock_run.return_value = mock

        g = GoGuard()
        result = g.execute("goguard.diagnostics().length")

        assert isinstance(result, ExecuteResult)
        assert result.output == "5"

        # Verify params include timeout_ms
        args = mock_run.call_args[0][0]
        params_idx = args.index("--params")
        params_json = json.loads(args[params_idx + 1])
        assert params_json["code"] == "goguard.diagnostics().length"
        assert params_json["timeout_ms"] == 5000

    @patch("goguard.client.subprocess.run")
    def test_execute_custom_timeout(self, mock_run):
        payload = {"output": "ok", "error": None}
        mock = MagicMock()
        mock.stdout = json.dumps(payload)
        mock.stderr = ""
        mock.returncode = 0
        mock_run.return_value = mock

        g = GoGuard()
        g.execute("slow_code()", timeout_ms=30000)

        args = mock_run.call_args[0][0]
        params_idx = args.index("--params")
        params_json = json.loads(args[params_idx + 1])
        assert params_json["timeout_ms"] == 30000


class TestGoGuardQuery:
    @patch("goguard.client.subprocess.run")
    def test_query_returns_typed_result(self, mock_run):
        payload = {"output": '[{"id":"NIL001-main.go:5"}]', "error": None}
        mock = MagicMock()
        mock.stdout = json.dumps(payload)
        mock.stderr = ""
        mock.returncode = 0
        mock_run.return_value = mock

        g = GoGuard()
        result = g.query('diagnostics where severity == "critical"')

        assert isinstance(result, QueryResult)
        assert "NIL001" in result.output

        # Verify params
        args = mock_run.call_args[0][0]
        assert args[3] == "goguard_query"
        params_idx = args.index("--params")
        params_json = json.loads(args[params_idx + 1])
        assert params_json["expression"] == 'diagnostics where severity == "critical"'


# ---------------------------------------------------------------------------
# Integration-style tests (still mocked, but test full flow)
# ---------------------------------------------------------------------------


class TestEndToEnd:
    """Test typical usage patterns."""

    @patch("goguard.client.subprocess.run")
    def test_analyze_filter_explain_flow(self, mock_run):
        """Simulate: analyze -> filter critical -> explain each."""
        analyze_payload = {
            "diagnostics": [
                {
                    "id": "NIL001-main.go:10",
                    "rule": "NIL001",
                    "severity": "critical",
                    "title": "nil deref",
                    "location": {"file": "main.go", "line": 10, "column": 1},
                },
                {
                    "id": "ERR001-util.go:5",
                    "rule": "ERR001",
                    "severity": "warning",
                    "title": "unchecked error",
                    "location": {"file": "util.go", "line": 5, "column": 1},
                },
            ],
            "summary": {"total": 2},
            "bridge_errors": [],
        }

        explain_payload = {
            "diagnostic_id": "NIL001-main.go:10",
            "explanation": "Variable x can be nil at this point",
        }

        # First call returns analyze result, second returns explain
        mock = MagicMock()
        mock.stderr = ""
        mock.returncode = 0
        mock.stdout = json.dumps(analyze_payload)
        mock_run.return_value = mock

        g = GoGuard()
        result = g.analyze()
        critical = result.filter(severity=Severity.critical)
        assert len(critical) == 1

        # Now mock explain call
        mock.stdout = json.dumps(explain_payload)
        detail = g.explain(critical[0].id)
        assert detail["explanation"] == "Variable x can be nil at this point"
