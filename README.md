> **Standards notice:** This rule set targets NIST FIPS 204 and FIPS 203 baselines and is maintained independently. NIST publishes errata for these standards. Scan outputs should always state the standard and errata baseline used by the analyzer.

# ScanCrypt

**ScanCrypt** is a static analysis platform for post-quantum cryptographic implementations.

It detects and classifies implementations of **ML-DSA (Dilithium)** and **ML-KEM (Kyber)**, then runs standards-oriented auditing checks and produces security findings and reports.

---

## Important Methodology Statement (Non-AI)

ScanCrypt is **not** based on AI agents, generative AI decisions, or probabilistic LLM reasoning.

The analysis is built on:

- deterministic static code inspection,
- statistical/rule-driven signatures,
- parameter consistency checks,
- conformance checks derived from standards,
- security heuristics grounded in published research,
- patterns learned from known implementation attacks (e.g., side-channel and fault-injection literature).

In short: **results come from explicit rules and research-backed criteria, not from AI-generated judgments.**

---

## What the Project Contains

This repository is organized into web app, analysis engine, reporting, templates, and optional external tooling components.

### 1) Web Application Layer

- `app.py`
  - Flask entry point.
  - Handles routes, upload/scan flow, result rendering, and report generation triggers.

### 2) Detection + Auditing Layer

- `scan_detector.py`
  - Core project scanner.
  - Recursively inspects uploaded source trees.
  - Detects algorithm family, security level, implementation type, language, and evidence.
  - Invokes the auditing engine and returns findings/counters.

- `audit_engine.py`
  - Generic scheme-aware orchestrator.
  - Dispatches rule execution by family (currently ML-DSA and ML-KEM).

- `mldsa_audit_rules.py`
  - Rule set for ML-DSA / FIPS 204 checks.

- `mlkem_audit_rules.py`
  - Rule set for ML-KEM / FIPS 203 checks.

### 3) Reporting Layer

- `report_generator.py`
  - Generates structured PDF reports from scan and auditing output.
  - Includes summaries, findings, and rule statistics.

### 4) Front-End Templates and Assets

- `templates/`
  - HTML pages (`index.html`, `about.html`, `services.html`, `pricing.html`, `contact.html`, etc.).
  - Displays scan form, findings table, and navigation pages.

- `static/`
  - Static web assets and generated report outputs (`static/reports/assembly/`).

- `uploads/`
  - Temporary upload area for scanned projects.

### 5) External/Integrated Research Tooling

- `PoMMES-main/`
  - **TO BE DONE** module for future low-level/assembly-oriented security workflows.
  - Planned to improve insecure assembly implementations into more secure code with stronger resistance against side-channel attacks.

---

## Current Capabilities

ScanCrypt currently provides:

- Algorithm detection:
  - ML-DSA (Dilithium)
  - ML-KEM (Kyber)

- Security-level classification:
  - ML-DSA-44, ML-DSA-65, ML-DSA-87
  - ML-KEM-512, ML-KEM-768, ML-KEM-1024

- Implementation-type classification:
  - Portable C / Reference
  - AVX2 Optimized
  - ARM Cortex-M / Embedded
  - Masked Implementation

- Source/language and project statistics:
  - file counts,
  - code line counts,
  - source/header distribution.

- Rule-based auditing:
  - standards readiness checks,
  - implementation quality and security heuristics,
  - actionable findings with mitigation guidance.

- Professional PDF report output.

---

## Detection and Rule Methodology

### Deterministic Fingerprint Detection

The detector searches for known code fingerprints such as constants, macros, functions, and naming conventions.

Examples:

- ML-DSA fingerprints: `poly_challenge`, `polyvecl`, `polyveck`, `make_hint`, `DILITHIUM2/3/5`, `ML_DSA_44/65/87`
- ML-KEM fingerprints: `KYBER_K`, `KYBER_Q`, `KYBER_N`, `indcpa_keypair`, `poly_compress`, `polyvec_decompress`, `cbd2`, `cbd3`

### Rule Execution

After family detection, the audit engine executes scheme-specific rule sets:

- ML-DSA rules (FIPS 204 oriented)
- ML-KEM rules (FIPS 203 oriented)

Each rule returns structured outputs including status, severity, explanation, impact, and mitigation text.

---

## Supported Source Files

ScanCrypt currently analyzes:

```
.c
.h
.cpp
.cc
.hpp
```

---

## Setup

Create a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Run the app:

```bash
python app.py
```

Open:

```
http://127.0.0.1:5000
```

---

## Typical Usage

1. Start the web app.
2. Upload/select a project directory.
3. ScanCrypt will:
   - detect cryptographic family,
   - infer security level,
   - classify implementation type,
   - execute auditing rules,
   - return findings and counters,
   - generate a report-ready result object.

---

## Report Generation

PDF reporting is provided by `report_generator.py`.

Main API:

- `generate_scan_report(results: dict, filename: str)`

Report sections include:

- Cover Page
- Executive Summary
- Project Inspection
- Findings Summary
- Detailed Findings
- Rule Execution Summary
- Statistics
- Appendix

---

## Roadmap

Planned next steps include:

- deeper vulnerability-oriented checks,
- expanded side-channel and fault-injection coverage,
- broader standards/parameter baselines,
- multi-format report exports (PDF/JSON/SARIF),
- support for additional PQC schemes.

---

## Plans in View (Recommended)

To keep upcoming work transparent, the current implementation roadmap is tracked below as a TODO list, with priority on the two currently locked services in the interface.

### TODO — Service 1: Security Analysis (currently locked)

- [ ] Finalize rule-pack stabilization for ML-DSA and ML-KEM security assessment.
- [ ] Improve finding quality with stronger technical explanation and mitigation mapping.
- [ ] Add confidence/risk calibration for rule outcomes and summary scoring.
- [ ] Complete export consistency across HTML, PDF, JSON, and SARIF outputs.
- [ ] Enable production release and unlock this service in the UI.

### TODO — Service 2: Secure Assembly Generation (currently locked)

- [ ] Complete secure transformation pipeline for supported C routines.
- [ ] Add hardened pattern library focused on side-channel-resilient code generation.
- [ ] Improve architecture coverage and validation workflow for embedded targets.
- [ ] Add deterministic verification checks and clearer transformation trace output.
- [ ] Enable production release and unlock this service in the UI.

### Tracking Notes

- Open issues and implementation tasks are maintained incrementally in this repository.
- This section is intentionally kept visible to document work-in-progress priorities.

---

## Project Compliance Declaration

The project owner confirms that this repository is independently owned and shared with appropriate rights. Based on the current project scope and stated constraints, the following points are confirmed:

- no employer, client, or university ownership claim applies,
- no NDA or confidential third-party material is included,
- no unauthorized company-owned code is included,
- the project is not intended to build, train, fine-tune, evaluate, benchmark, serve, or host AI/ML models,
- the project is not designed as offensive security exploit tooling,
- the project is not intended to process unauthorized personal or regulated data,
- no illegal or harmful use is intended, and only code with redistribution rights is included.

This statement is provided for transparency and submission-readiness documentation.

---

## License

This project is licensed under the **MIT License**. See `LICENSE`.
