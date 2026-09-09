from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from .models import VulnerabilityFinding


def load_findings(path: str | Path) -> list[VulnerabilityFinding]:
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(raw, list):
        raise ValueError("input must be a JSON array")

    findings: list[VulnerabilityFinding] = []
    seen_ids: set[str] = set()
    for row in raw:
        finding = VulnerabilityFinding(
            finding_id=str(row["finding_id"]),
            cve=str(row["cve"]),
            asset_id=str(row["asset_id"]),
            cvss=float(row["cvss"]),
            epss=float(row["epss"]),
            kev=bool(row["kev"]),
            internet_exposed=bool(row["internet_exposed"]),
            asset_criticality=int(row["asset_criticality"]),
            first_seen=datetime.fromisoformat(str(row["first_seen"]).replace("Z", "+00:00")),
            owner=str(row["owner"]),
        )
        finding.validate()
        if finding.finding_id in seen_ids:
            raise ValueError(f"duplicate finding_id: {finding.finding_id}")
        seen_ids.add(finding.finding_id)
        findings.append(finding)
    return findings
