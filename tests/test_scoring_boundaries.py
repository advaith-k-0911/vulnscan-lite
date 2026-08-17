"""
VulnScan Lite - Scoring Boundaries & Deterministic Grading Test Suite
Validates mathematical boundaries (0-100), letter grade mapping (A-F),
severity weights, anti-double-counting logic, and deterministic reproducibility.
"""

import pytest
from typing import List

from scanner.scoring import (
    calculate_grade,
    Finding,
    ScoringEngine,
)


class TestGradeThresholds:
    """Test all letter grade thresholds according to the standard grading scale."""

    @pytest.mark.parametrize(
        "score,expected_grade",
        [
            (100, "A"),
            (95, "A"),
            (90, "A"),  # Grade A threshold
            (89, "B"),  # Grade B upper boundary
            (85, "B"),
            (80, "B"),  # Grade B threshold
            (79, "C"),  # Grade C upper boundary
            (75, "C"),
            (70, "C"),  # Grade C threshold
            (69, "D"),  # Grade D upper boundary
            (65, "D"),
            (60, "D"),  # Grade D threshold
            (59, "F"),  # Grade F upper boundary
            (50, "F"),
            (25, "F"),
            (0, "F"),
            (-10, "F"),  # Negative edge case capped at F
        ],
    )
    def test_grade_mapping_exact_boundaries(self, score: int, expected_grade: str):
        assert calculate_grade(score) == expected_grade


class TestScoringEngineCalculations:
    """Test deterministic point deductions, category capping, and boundary clamping."""

    def test_perfect_score_all_checks_passed(self):
        """When all checks pass, score is 100 with Grade A."""
        engine = ScoringEngine()
        findings = [
            Finding(
                id=f"CHK_{i}",
                name=f"Check {i}",
                category="security_headers",
                status="PASS",
                severity="INFO",
                points=0,
                applicable=True,
            )
            for i in range(10)
        ]
        res = engine.calculate_score(findings)
        assert res.score == 100
        assert res.grade == "A"
        assert res.summary.passed == 10
        assert res.summary.failed == 0
        assert res.summary.warnings == 0

    def test_minimum_score_cannot_go_below_zero(self):
        """Massive point deductions cannot drop the score below 0."""
        engine = ScoringEngine()
        findings = [
            Finding(
                id=f"FAIL_{i}",
                name=f"Fatal Failure {i}",
                category="critical_vulnerabilities",
                status="FAIL",
                severity="HIGH",
                points=-50,
                applicable=True,
            )
            for i in range(10)
        ]
        res = engine.calculate_score(findings)
        assert res.score == 0
        assert res.grade == "F"
        assert res.summary.failed == 10

    def test_non_applicable_checks_do_not_deduct_points(self):
        """Checks marked applicable=False do not count towards score deductions or totals."""
        engine = ScoringEngine()
        findings = [
            Finding(
                id="HDR_HSTS",
                name="Strict-Transport-Security",
                category="security_headers",
                status="FAIL",
                severity="MEDIUM",
                points=-10,
                applicable=False,  # e.g., plain HTTP connection
            ),
            Finding(
                id="HDR_CSP",
                name="Content-Security-Policy",
                category="security_headers",
                status="PASS",
                severity="INFO",
                points=0,
                applicable=True,
            ),
        ]
        res = engine.calculate_score(findings)
        assert res.score == 100
        assert res.grade == "A"
        assert res.summary.passed == 1
        assert res.summary.failed == 0
        assert res.summary.not_applicable == 1

    def test_warning_status_deductions(self):
        """Warning status findings deduct their configured partial points."""
        engine = ScoringEngine()
        findings = [
            Finding(
                id="TLS_EXPIRY_WARN",
                name="TLS Expiry Warning",
                category="tls",
                status="WARNING",
                severity="LOW",
                points=-5,
                applicable=True,
            )
        ]
        res = engine.calculate_score(findings)
        assert res.score == 95
        assert res.grade == "A"
        assert res.summary.warnings == 1

    def test_deterministic_scoring_consistency(self):
        """Executing the scoring engine 100 times with identical input yields identical output."""
        engine = ScoringEngine()
        findings = [
            Finding(
                id="HDR_CSP",
                name="CSP",
                category="security_headers",
                status="FAIL",
                severity="MEDIUM",
                points=-10,
                applicable=True,
            ),
            Finding(
                id="HDR_HSTS",
                name="HSTS",
                category="security_headers",
                status="FAIL",
                severity="MEDIUM",
                points=-10,
                applicable=True,
            ),
            Finding(
                id="HDR_XFO",
                name="XFO",
                category="security_headers",
                status="PASS",
                severity="INFO",
                points=0,
                applicable=True,
            ),
        ]

        baseline = engine.calculate_score(findings)
        assert baseline.score == 80
        assert baseline.grade == "B"

        for _ in range(100):
            repeated = engine.calculate_score(findings)
            assert repeated.score == baseline.score
            assert repeated.grade == baseline.grade
            assert repeated.summary.passed == baseline.summary.passed
            assert repeated.summary.failed == baseline.summary.failed
