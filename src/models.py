from dataclasses import dataclass


@dataclass
class PermissionGrant:
    effect: str
    actions: list[str]
    resources: list[str]

    @classmethod
    def from_dict(cls, data: dict) -> "PermissionGrant":
        return cls(
            effect=data.get("Effect", ""),
            actions=data.get("Action", []),
            resources=data.get("Resource", []),
        )


@dataclass
class RiskFinding:
    type: str
    severity: str
    detail: str


@dataclass
class AnalysisReport:
    risk_score: int
    findings: list[RiskFinding]
    recommendations: list[str]

    def to_dict(self) -> dict:
        return {
            "risk_score": self.risk_score,
            "findings": [
                {"type": f.type, "severity": f.severity, "detail": f.detail} for f in self.findings
            ],
            "recommendations": self.recommendations,
        }
