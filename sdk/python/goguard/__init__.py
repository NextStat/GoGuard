"""GoGuard Python SDK -- CodeAct-native static analysis for Go."""

from .client import GoGuard, GoGuardError
from .models import (
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

__all__ = [
    "GoGuard",
    "GoGuardError",
    "AnalysisResult",
    "AutoFixResult",
    "BatchResult",
    "DiagnosticSkeleton",
    "ExecuteResult",
    "FixResult",
    "Location",
    "QueryResult",
    "Rule",
    "SearchResult",
    "Severity",
    "SeveritySummary",
    "GoTestResult",
    "TextEdit",
    "VerificationResult",
]
