from __future__ import annotations

from .models import PriorityResult, VulnerabilityFinding


def score_finding(finding: VulnerabilityFinding) -> PriorityResult:
    finding.validate()
    rationale: list[str] = []

    score = finding.epss * 45
    rationale.append(f"EPSS contributes {finding.epss * 45:.1f} points")

    score += (finding.cvss / 10) * 15
    rationale.append(f"CVSS contributes {(finding.cvss / 10) * 15:.1f} points")

    score += finding.asset_criticality * 4
    rationale.append(f"Asset criticality contributes {finding.asset_criticality * 4:.1f} points")

    if finding.kev:
        score += 15
        rationale.append("CISA KEV-style exploited status adds 15 points")

    if finding.internet_exposed:
        score += 10
        rationale.append("Internet exposure adds 10 points")

    if finding.age_days >= 90:
        score += 5
        rationale.append("Finding age >=90 days adds 5 points")

    score = round(min(score, 100), 1)
    if score >= 80:
        priority = "P0"
    elif score >= 60:
        priority = "P1"
    elif score >= 40:
        priority = "P2"
    else:
        priority = "P3"

    return PriorityResult(
        finding_id=finding.finding_id,
        cve=finding.cve,
        asset_id=finding.asset_id,
        score=score,
        priority=priority,
        rationale=tuple(rationale),
    )


def prioritize(findings: list[VulnerabilityFinding]) -> list[PriorityResult]:
    results = [score_finding(item) for item in findings]
    return sorted(results, key=lambda item: (-item.score, item.finding_id))
