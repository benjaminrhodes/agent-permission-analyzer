"""Tests for risk analyzer."""

from src.models import PermissionGrant
from src.analyzer import RiskAnalyzer


def test_detect_wildcard_action():
    grants = [
        PermissionGrant(effect="Allow", actions=["s3:*"], resources=["arn:aws:s3:::bucket/*"])
    ]
    analyzer = RiskAnalyzer()
    findings = analyzer.analyze(grants)
    assert any(f.type == "wildcard_action" for f in findings)


def test_detect_wildcard_resource():
    grants = [PermissionGrant(effect="Allow", actions=["s3:GetObject"], resources=["*"])]
    analyzer = RiskAnalyzer()
    findings = analyzer.analyze(grants)
    assert any(f.type == "wildcard_resource" for f in findings)


def test_detect_network_access():
    grants = [PermissionGrant(effect="Allow", actions=["ec2:*"], resources=["*"])]
    analyzer = RiskAnalyzer()
    findings = analyzer.analyze(grants)
    assert any(f.type == "network_access" for f in findings)


def test_detect_file_access():
    grants = [PermissionGrant(effect="Allow", actions=["s3:*"], resources=["*"])]
    analyzer = RiskAnalyzer()
    findings = analyzer.analyze(grants)
    assert any(f.type == "file_access" for f in findings)


def test_detect_shell_access():
    grants = [PermissionGrant(effect="Allow", actions=["exec:*", "run:*"], resources=["*"])]
    analyzer = RiskAnalyzer()
    findings = analyzer.analyze(grants)
    assert any(f.type == "shell_access" for f in findings)


def test_risk_score_calculation():
    grants = [PermissionGrant(effect="Allow", actions=["s3:*"], resources=["*"])]
    analyzer = RiskAnalyzer()
    findings = analyzer.analyze(grants)
    score = analyzer.calculate_score(findings)
    assert score == 65  # 30 (wildcard action) + 20 (wildcard resource) + 15 (file access)


def test_recommendations_generation():
    grants = [PermissionGrant(effect="Allow", actions=["s3:*"], resources=["*"])]
    analyzer = RiskAnalyzer()
    findings = analyzer.analyze(grants)
    recommendations = analyzer.get_recommendations(findings)
    assert len(recommendations) > 0


def test_detect_pattern_with_asterisk_in_middle():
    grants = [PermissionGrant(effect="Allow", actions=["*Network*"], resources=["*"])]
    analyzer = RiskAnalyzer()
    findings = analyzer.analyze(grants)
    assert any(f.type == "network_access" for f in findings)


def test_recommendations_file_access():
    grants = [PermissionGrant(effect="Allow", actions=["s3:*"], resources=["arn:aws:s3:::bucket"])]
    analyzer = RiskAnalyzer()
    findings = analyzer.analyze(grants)
    recommendations = analyzer.get_recommendations(findings)
    assert any("file" in r.lower() for r in recommendations)


def test_recommendations_shell_access():
    grants = [PermissionGrant(effect="Allow", actions=["exec:*"], resources=["arn:aws:lambda:"])]
    analyzer = RiskAnalyzer()
    findings = analyzer.analyze(grants)
    recommendations = analyzer.get_recommendations(findings)
    assert any("shell" in r.lower() or "exec" in r.lower() for r in recommendations)


def test_no_risks():
    grants = [
        PermissionGrant(
            effect="Allow", actions=["s3:GetObject"], resources=["arn:aws:s3:::bucket/key"]
        )
    ]
    analyzer = RiskAnalyzer()
    findings = analyzer.analyze(grants)
    assert len(findings) == 0
    recommendations = analyzer.get_recommendations(findings)
    assert "Permissions appear appropriately scoped" in recommendations
