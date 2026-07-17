> **Standards notice:** This rule set targets NIST FIPS 204 and is maintained independently. NIST currently publishes an errata list containing potential corrections for a future update of FIPS 204. Scan results should therefore state the standard and errata baseline used by the analyzer.

# ScanCrypt

**ScanCrypt** is a static analysis platform designed to identify and classify post-quantum cryptographic implementations before performing security assessments. The project focuses on helping developers and security engineers understand and evaluate implementations of standardized post-quantum algorithms such as **ML-DSA (Dilithium)** and **ML-KEM (Kyber)**.

The current release provides automatic project inspection by detecting the implemented cryptographic algorithm, its security level, and the implementation type.

For ML-DSA assessments, ScanCrypt is based on an internal FIPS 204 conformance-rule baseline intended for implementation review, migration support, and readiness testing.

---

## Current Features

### Project Inspection

ScanCrypt automatically analyzes a source code project and identifies:

- Cryptographic algorithm
  - ML-DSA (Dilithium)
  - ML-KEM (Kyber)

- Security level
  - ML-DSA-44 (Dilithium2)
  - ML-DSA-65 (Dilithium3)
  - ML-DSA-87 (Dilithium5)
  - ML-KEM-512
  - ML-KEM-768
  - ML-KEM-1024

- Implementation type
  - Portable C / Reference
  - AVX2 Optimized
  - ARM Cortex-M / Embedded
  - Masked Implementation
  - Hardware / FPGA (planned)

- Programming language detection

- Project statistics
  - Number of files
  - Number of source files
  - Number of header files
  - Lines of code

- Detection confidence

- Detection evidence showing why the implementation was classified.

---

## Detection Methodology

ScanCrypt performs deterministic static analysis of the uploaded project.

The detector recursively scans source files and searches for algorithm-specific fingerprints including:

### ML-DSA

Examples include:

- `poly_challenge`
- `polyvecl`
- `polyveck`
- `make_hint`
- `use_hint`
- `decompose`
- `rej_uniform`
- `DILITHIUM2`
- `DILITHIUM3`
- `DILITHIUM5`
- `ML_DSA_44`
- `ML_DSA_65`
- `ML_DSA_87`

Security levels are determined from implementation parameters such as:

- K
- L
- ETA
- GAMMA1
- GAMMA2

---

### ML-KEM

Examples include:

- `KYBER_K`
- `KYBER_Q`
- `KYBER_N`
- `indcpa_keypair`
- `indcpa_enc`
- `indcpa_dec`
- `gen_matrix`
- `poly_compress`
- `poly_decompress`
- `polyvec_compress`
- `polyvec_decompress`
- `cbd2`
- `cbd3`

Security levels are determined from parameters including:

- KYBER_K
- KYBER_ETA1
- KYBER_ETA2
- KYBER_DU
- KYBER_DV

---

### Implementation Classification

ScanCrypt also classifies the implementation based on project characteristics.

Current supported implementation types include:

- Portable C / Reference implementation
- AVX2 optimized implementation
- ARM Cortex-M implementation
- Masked implementation

---

## Supported Source Files

ScanCrypt currently analyzes

```
.c
.h
.cpp
.cc
.hpp
```

Support for additional languages is planned.

---

## Setup

Create a virtual environment

```bash
python3 -m venv venv
source venv/bin/activate
```

Install dependencies

```bash
pip install -r requirements.txt
```

Run ScanCrypt

```bash
python app.py
```

Open

```
http://127.0.0.1:5000
```

---

## Usage

1. Launch ScanCrypt.
2. Select a project folder containing a post-quantum cryptographic implementation.
3. ScanCrypt automatically:
   - identifies the implemented algorithm,
   - determines its security level,
   - classifies the implementation type,
   - computes project statistics,
   - generates a detailed inspection report with supporting evidence.

---

## Professional PDF Report Generation

ScanCrypt includes a ReportLab-based PDF generator for enterprise-style security reports.

File:
- `report_generator.py`

Main API:
- `generate_scan_report(results: dict, filename: str)`

### Example

```python
from report_generator import generate_scan_report

results = {
  "project_name": "m4fstack",
  "algorithm": "ML-KEM / Kyber",
  "security_level": "ML-KEM-768 / Kyber768",
  "implementation_type": "Masked Implementation",
  "language": "C/C++",
  "build_system": "Not detected",
  "files": 3,
  "source_files": 2,
  "header_files": 1,
  "lines_of_code": 906,
  "overall_risk": "High",
  "analysis_confidence": "99%",
  "detection_confidence": "97%",
  "rules_executed": 15,
  "rules_passed": 9,
  "rules_failed": 6,
  "analysis_duration": "00:01:25",
  "detection_evidence": [
    "KYBER_K = 3",
    "poly_compress() detected",
    "ntt() detected"
  ],
  "findings": []
}

generate_scan_report(results, "scancrypt_report.pdf")
```

The report includes:
- Cover Page
- Executive Summary
- Project Inspection
- Findings Summary
- Detailed Findings
- Rule Execution Summary
- Statistics (with progress bars)
- Appendix

---

## Roadmap

The current version focuses on automatic project inspection.

Future releases will introduce:

- Implementation vulnerability detection
- Rule-based security analysis
- Research-based mitigation recommendations
- Professional security reports (PDF, JSON, SARIF)
- Advanced side-channel analysis
- Advanced fault-injection analysis
- Support for additional post-quantum algorithms

---

## Vision

ScanCrypt aims to become a dedicated static analysis platform for post-quantum cryptographic implementations, helping developers identify implementation weaknesses before deployment and supporting the secure adoption of post-quantum cryptography.
