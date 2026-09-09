# Example EPSS Prioritization Assessment

Synthetic portfolio only. No production or employer data is used.

## Executive summary

The model identifies internet-facing and KEV-correlated findings with high EPSS probability as the fastest remediation candidates. High business criticality can also elevate otherwise moderate technical severity.

## Example outcome

| Finding | Context | Expected priority |
|---|---|---|
| F-1001 | High EPSS, KEV, internet-facing, critical asset | P0 |
| F-1005 | High EPSS, internet-facing VPN gateway, critical asset | P1/P0 boundary |
| F-1003 | KEV, older finding, high-criticality internal server | P1/P2 boundary |
| F-1004 | Low EPSS, internal development asset | P3 |

## Remediation sequence

1. Restrict unnecessary public reachability for F-1001 and F-1005.
2. Apply vendor remediation or validated compensating controls.
3. Re-scan and confirm vulnerable versions are no longer detected.
4. Validate external exposure state independently.
5. Close only after evidence is captured and residual risk is accepted or reduced.

## Residual risk

A lower score does not mean zero risk. EPSS changes over time, asset criticality changes, and new exploitation intelligence can materially change priority; production use therefore requires data freshness and periodic re-scoring.
