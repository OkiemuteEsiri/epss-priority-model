from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone


@dataclass(frozen=True)
class VulnerabilityFinding:
    finding_id: str
    cve: str
    asset_id: str
    cvss: float
    epss: float
    kev: bool
    internet_exposed: bool
    asset_criticality: int
    first_seen: datetime
    owner: str

    def validate(self) -> None:
        if not self.cve.startswith("CVE-"):
            raise ValueError("cve must use CVE-* format")
        if not 0 <= self.cvss <= 10:
            raise ValueError("cvss must be between 0 and 10")
        if not 0 <= self.epss <= 1:
            raise ValueError("epss must be between 0 and 1")
        if not 1 <= self.asset_criticality <= 5:
            raise ValueError("asset_criticality must be between 1 and 5")
        if self.first_seen.tzinfo is None:
            raise ValueError("first_seen must be timezone-aware")

    @property
    def age_days(self) -> int:
        return max(0, (datetime.now(timezone.utc) - self.first_seen.astimezone(timezone.utc)).days)


@dataclass(frozen=True)
class PriorityResult:
    finding_id: str
    cve: str
    asset_id: str
    score: float
    priority: str
    rationale: tuple[str, ...]
