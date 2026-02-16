"""CLI interface."""

import json
import sys
from src.models import PermissionGrant, AnalysisReport
from src.analyzer import RiskAnalyzer


def analyze_permissions(permissions: list[dict]) -> dict:
    grants = [PermissionGrant.from_dict(p) for p in permissions]
    analyzer = RiskAnalyzer()
    findings = analyzer.analyze(grants)
    score = analyzer.calculate_score(findings)
    recommendations = analyzer.get_recommendations(findings)
    report = AnalysisReport(risk_score=score, findings=findings, recommendations=recommendations)
    return report.to_dict()


def main():
    if len(sys.argv) < 2:
        print("Usage: python -m src.cli <permissions.json>")
        return 1

    try:
        with open(sys.argv[1]) as f:
            permissions = json.load(f)
    except FileNotFoundError:
        print(f"Error: File {sys.argv[1]} not found")
        return 1
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON: {e}")
        return 1

    result = analyze_permissions(permissions)
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
