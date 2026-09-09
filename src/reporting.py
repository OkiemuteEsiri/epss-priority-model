from __future__ import annotations

from collections import Counter
from .models import PriorityResult


def portfolio_metrics(results: list[PriorityResult]) -> dict[str, object]:
    counts = Counter(item.priority for item in results)
    average = round(sum(item.score for item in results) / len(results), 1) if results else 0.0
    return {
        "total_findings": len(results),
        "average_score": average,
        "priority_counts": {key: counts.get(key, 0) for key in ("P0", "P1", "P2", "P3")},
    }


def render_markdown(results: list[PriorityResult]) -> str:
    metrics = portfolio_metrics(results)
    lines = [
        "# EPSS Prioritization Report",
        "",
        f"Total findings: **{metrics['total_findings']}**",
        f"Average contextual risk score: **{metrics['average_score']}**",
        "",
        "| Priority | Finding | CVE | Asset | Score |",
        "|---|---|---|---|---:|",
    ]
    for item in results:
        lines.append(f"| {item.priority} | {item.finding_id} | {item.cve} | {item.asset_id} | {item.score:.1f} |")
    lines.extend(["", "## Decision rationale"])
    for item in results:
        lines.append(f"\n### {item.finding_id} — {item.priority} ({item.score:.1f})")
        lines.extend(f"- {reason}" for reason in item.rationale)
    return "\n".join(lines) + "\n"
