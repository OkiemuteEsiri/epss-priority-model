# Architecture

The project separates ingestion, validation, scoring, aggregation, and reporting so each layer can be tested independently.

## Components

1. `src/io.py` loads JSON and enforces schema/duplicate controls.
2. `src/models.py` defines immutable canonical findings and results.
3. `src/scoring.py` applies an explainable contextual risk model.
4. `src/reporting.py` generates portfolio metrics and Markdown output.
5. `src/cli.py` provides a repeatable batch execution path.

## Trust boundaries

Input data is treated as untrusted until validated. EPSS, CVSS, KEV-style status, asset criticality and exposure state are explicit inputs; the engine never infers exploitation from probability alone.

## Production extension points

A production implementation could replace the synthetic JSON loader with scanner, CMDB, KEV and EPSS API adapters, while retaining the canonical model and deterministic scoring layer. Authentication, secrets storage, rate limiting and source freshness controls should live outside the scoring engine.
