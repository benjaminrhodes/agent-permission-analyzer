"""Tests for data models."""

from src.models import PermissionGrant, RiskFinding, AnalysisReport


def test_permission_grant_from_dict():
    data = {"Effect": "Allow", "Action": ["s3:*"], "Resource": ["arn:aws:s3:::bucket/*"]}
    grant = PermissionGrant.from_dict(data)
    assert grant.effect == "Allow"
    assert grant.actions == ["s3:*"]
    assert grant.resources == ["arn:aws:s3:::bucket/*"]


def test_risk_finding_creation():
    finding = RiskFinding(type="wildcard_action", severity="high", detail="Wildcard action found")
    assert finding.type == "wildcard_action"
    assert finding.severity == "high"


def test_analysis_report_creation():
    findings = [RiskFinding(type="wildcard_action", severity="high", detail="test")]
    report = AnalysisReport(
        risk_score=50, findings=findings, recommendations=["Reduce permissions"]
    )
    assert report.risk_score == 50
    assert len(report.findings) == 1
