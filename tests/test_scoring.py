import unittest
from datetime import datetime, timezone

from src.models import VulnerabilityFinding
from src.scoring import prioritize, score_finding


class ScoringTests(unittest.TestCase):
    def make(self, **overrides):
        data = dict(
            finding_id="F-1", cve="CVE-2026-0001", asset_id="A-1", cvss=7.5,
            epss=0.5, kev=False, internet_exposed=False, asset_criticality=3,
            first_seen=datetime(2026, 8, 1, tzinfo=timezone.utc), owner="Team A",
        )
        data.update(overrides)
        return VulnerabilityFinding(**data)

    def test_high_context_risk_becomes_p0(self):
        result = score_finding(self.make(cvss=9.8, epss=0.95, kev=True, internet_exposed=True, asset_criticality=5))
        self.assertEqual(result.priority, "P0")
        self.assertGreaterEqual(result.score, 80)

    def test_low_epss_internal_asset_is_lower_priority(self):
        result = score_finding(self.make(cvss=5.0, epss=0.02, asset_criticality=2))
        self.assertIn(result.priority, {"P2", "P3"})

    def test_kev_increases_score(self):
        base = score_finding(self.make(kev=False))
        kev = score_finding(self.make(kev=True))
        self.assertEqual(round(kev.score - base.score, 1), 15.0)

    def test_internet_exposure_increases_score(self):
        base = score_finding(self.make(internet_exposed=False))
        exposed = score_finding(self.make(internet_exposed=True))
        self.assertEqual(round(exposed.score - base.score, 1), 10.0)

    def test_results_are_sorted_by_score(self):
        a = self.make(finding_id="F-A", epss=0.1)
        b = self.make(finding_id="F-B", epss=0.9)
        results = prioritize([a, b])
        self.assertEqual(results[0].finding_id, "F-B")

    def test_invalid_epss_is_rejected(self):
        with self.assertRaises(ValueError):
            score_finding(self.make(epss=1.2))


if __name__ == "__main__":
    unittest.main()
