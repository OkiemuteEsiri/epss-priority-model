from __future__ import annotations

import argparse
from pathlib import Path

from .io import load_findings
from .reporting import render_markdown
from .scoring import prioritize


def main() -> None:
    parser = argparse.ArgumentParser(description="Prioritize vulnerability findings using EPSS plus business context.")
    parser.add_argument("input", help="Path to JSON findings")
    parser.add_argument("--output", default="reports/generated-report.md", help="Markdown report path")
    args = parser.parse_args()

    results = prioritize(load_findings(args.input))
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(render_markdown(results), encoding="utf-8")
    print(f"Wrote {len(results)} prioritized findings to {output}")


if __name__ == "__main__":
    main()
