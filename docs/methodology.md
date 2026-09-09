# Prioritization Methodology

## Objective

Reduce vulnerability backlog using exploit-likelihood and business context rather than CVSS alone.

## Scoring inputs

- EPSS probability: 45% maximum contribution.
- CVSS severity: 15% maximum contribution.
- Asset criticality: up to 20 points.
- KEV-style known exploitation flag: 15 points.
- Internet exposure: 10 points.
- Finding age >=90 days: 5 points.

Scores are capped at 100 and mapped to P0/P1/P2/P3.

## Decision principles

EPSS is a probability signal, not evidence of compromise. KEV-style status raises urgency because exploitation is known in the wild, but validation and asset context are still required. Internet exposure and business criticality amplify remediation priority because they influence reachable attack paths and potential impact.

## Remediation workflow

1. Validate finding and asset identity.
2. Confirm owner and exposure state.
3. Prioritize P0/P1 findings for remediation planning.
4. Patch, upgrade, remove exposure, or apply compensating controls.
5. Re-scan/re-query the authoritative source.
6. Record remediation evidence and residual risk.

## MITRE ATT&CK context

- T1190 — Exploit Public-Facing Application
- T1210 — Exploitation of Remote Services

These mappings provide threat context only; a vulnerable asset is not proof that either technique occurred.
