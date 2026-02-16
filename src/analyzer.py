from src.models import PermissionGrant, RiskFinding

RISK_PATTERNS = {
    "wildcard_action": (["*"], 30),
    "wildcard_resource": (["*"], 20),
    "network_access": (["ec2:*", "*Network*", "iam:*", "*Describe*"], 15),
    "file_access": (["s3:*", "fs:*"], 15),
    "shell_access": (["exec:*", "run:*", "shell:*", "bash:*", "command:*"], 20),
}

SEVERITY_MAP = {
    "wildcard_action": "high",
    "wildcard_resource": "high",
    "network_access": "medium",
    "file_access": "medium",
    "shell_access": "critical",
}


class RiskAnalyzer:
    def analyze(self, grants: list[PermissionGrant]) -> list[RiskFinding]:
        findings = []
        for grant in grants:
            if grant.effect != "Allow":
                continue
            for action in grant.actions:
                for risk_type, (patterns, _) in RISK_PATTERNS.items():
                    if any(self._matches(pattern, action) for pattern in patterns):
                        findings.append(
                            RiskFinding(
                                type=risk_type,
                                severity=SEVERITY_MAP[risk_type],
                                detail=f"Permission '{action}' matches {risk_type}",
                            )
                        )
            for resource in grant.resources:
                if resource == "*":
                    findings.append(
                        RiskFinding(
                            type="wildcard_resource",
                            severity="high",
                            detail=f"Resource '{resource}' uses wildcard",
                        )
                    )
        return findings

    def _matches(self, pattern: str, value: str) -> bool:
        if pattern == "*":
            return "*" in value
        if pattern.startswith("*") and pattern.endswith("*"):
            inner = pattern[1:-1]
            return inner.lower() in value.lower()
        if pattern.endswith("*"):
            prefix = pattern[:-1]
            return value == prefix or value.startswith(prefix + ":") or value == pattern
        if pattern.startswith("*"):
            suffix = pattern[1:]
            return value.endswith(suffix)
        return pattern.lower() == value.lower()

    def calculate_score(self, findings: list[RiskFinding]) -> int:
        score = 0
        seen_types = set()
        for finding in findings:
            if finding.type not in seen_types:
                score += RISK_PATTERNS.get(finding.type, (("", 0)))[1]
                seen_types.add(finding.type)
        return min(score, 100)

    def get_recommendations(self, findings: list[RiskFinding]) -> list[str]:
        recs = []
        if any(f.type == "wildcard_action" for f in findings):
            recs.append("Remove wildcard actions - specify explicit permissions")
        if any(f.type == "wildcard_resource" for f in findings):
            recs.append("Restrict resources to specific ARNs")
        if any(f.type == "network_access" for f in findings):
            recs.append("Limit network access permissions")
        if any(f.type == "file_access" for f in findings):
            recs.append("Restrict file/storage access")
        if any(f.type == "shell_access" for f in findings):
            recs.append("Remove shell/exec permissions if not required")
        return recs if recs else ["Permissions appear appropriately scoped"]
