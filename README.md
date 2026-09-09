# EPSS Priority Model

A recruiter-facing vulnerability management project demonstrating how exploit-probability data can be combined with technical severity, known exploitation, exposure, asset criticality, and aging to produce explainable remediation priorities.

> All data in this repository is synthetic. The project performs no live scanning, exploitation, credential use, or production targeting.

## Problem statement

Large vulnerability backlogs cannot be managed effectively by CVSS alone. A critical CVSS score may have low exploitation probability, while a lower-severity vulnerability on an exposed, business-critical system may deserve faster treatment. This project models a transparent risk-based workflow using EPSS-style probability as one input rather than as a standalone decision.

## Architecture

```text
Synthetic findings
      |
      v
Validated loader --> canonical finding model
      |                     |
      v                     v
 data-quality gates --> contextual scoring engine
                              |
                              v
                    P0 / P1 / P2 / P3
                              |
                              v
                    metrics + Markdown report
```

Core modules:

- `src/models.py` — immutable finding/result models and validation.
- `src/io.py` — JSON ingestion, timestamp parsing and duplicate controls.
- `src/scoring.py` — deterministic, explainable contextual-risk engine.
- `src/reporting.py` — portfolio metrics and decision-rationale reporting.
- `src/cli.py` — repeatable batch execution.

See `docs/architecture.md` for design boundaries and production extension points.

## Risk model

The model intentionally keeps each factor visible:

| Signal | Maximum contribution |
|---|---:|
| EPSS probability | 45 |
| CVSS severity | 15 |
| Asset criticality | 20 |
| KEV-style known exploitation | 15 |
| Internet exposure | 10 |
| Age >= 90 days | 5 |

The final score is capped at 100 and translated into:

- **P0:** >= 80 — immediate validation and accelerated remediation.
- **P1:** >= 60 — high-priority remediation.
- **P2:** >= 40 — planned remediation with business context.
- **P3:** < 40 — monitor and remediate through normal lifecycle.

The weighting is deliberately simple enough to audit. It is a portfolio model, not a claim that these exact weights are universally correct.

## Usage

Requires Python 3.11+ and only the standard library.

```bash
python -m unittest discover -s tests -v
python -m src.cli data/synthetic_findings.json --output reports/generated-report.md
```

The generated report contains prioritized findings, score distribution, and the rationale behind each decision.

## Synthetic dataset

`data/synthetic_findings.json` includes five deliberately varied scenarios:

- internet-facing, KEV-correlated critical web exposure;
- high-criticality internal application finding;
- older KEV-correlated laboratory server finding;
- low-EPSS internal development-system finding;
- high-EPSS exposed VPN-gateway finding.

No real organization, scanner export, asset name, or credential is represented.

## Methodology

The workflow follows a practical vulnerability-management sequence:

1. Normalize and validate vulnerability data.
2. Confirm CVE, probability, severity, asset ownership and exposure context.
3. Apply deterministic contextual scoring.
4. Prioritize P0/P1 remediation activity.
5. Patch, upgrade, restrict exposure, remove vulnerable software, or apply documented compensating controls.
6. Re-scan or query the authoritative source after remediation.
7. Capture evidence and reassess residual risk.
8. Re-score periodically as EPSS, KEV status, asset criticality, and exposure change.

Full methodology is in `docs/methodology.md`.

## MITRE ATT&CK context

Where a vulnerable service could form part of an attack path, the project references:

- **T1190 — Exploit Public-Facing Application**
- **T1210 — Exploitation of Remote Services**

These mappings are threat context only. Vulnerability presence and EPSS probability do **not** prove exploitation or compromise.

## Testing and CI

The unit suite validates:

- P0 classification for high-context risk;
- lower prioritization for low-EPSS internal findings;
- explicit KEV score contribution;
- explicit internet-exposure score contribution;
- descending priority ordering;
- input rejection for invalid EPSS values.

GitHub Actions runs the test suite and a synthetic CLI smoke assessment with read-only repository permissions.

## Example output

`reports/example-assessment.md` shows how results can be translated into an executive-friendly remediation sequence, validation criteria, and residual-risk discussion.

## Design decisions

- **Explainability over opaque scoring:** every score contribution is visible.
- **Probability is not compromise evidence:** EPSS affects urgency but is never treated as telemetry.
- **Business context matters:** asset criticality and exposure change remediation priority.
- **Deterministic execution:** identical inputs produce identical priorities, except the explicit age calculation as time advances.
- **Input validation before scoring:** malformed probability, severity, dates, CVEs, or duplicate IDs are rejected rather than silently normalized.

## Limitations

This project does not:

- call the live FIRST EPSS API;
- ingest the live CISA KEV catalog;
- integrate with a vulnerability scanner or CMDB;
- model compensating-control effectiveness quantitatively;
- predict exploitation independently;
- prove that a vulnerable asset has been attacked.

Those integrations are intentionally separated from the scoring core so production adapters can be added without changing the decision model.

## Skills demonstrated

- risk-based vulnerability management
- exposure management
- EPSS/CVSS contextualization
- KEV-informed prioritization
- security data modeling and validation
- Python security automation
- deterministic scoring design
- unit testing and CI/CD
- remediation governance
- technical and executive reporting
- MITRE ATT&CK contextual mapping

## Roadmap

- add pluggable EPSS/KEV ingestion adapters with cached fixtures for offline testing;
- add scanner and CMDB normalization interfaces;
- add configurable scoring policy in YAML;
- track score movement over time;
- model remediation SLA and exception governance;
- add risk-concentration metrics by owner and asset class.

## Responsible-use statement

This repository is defensive and educational. It contains no exploitation code, offensive payloads, credentials, real infrastructure targeting, confidential employer/client data, or fabricated incident claims.
