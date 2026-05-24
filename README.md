# SecureScan Pro v6
### Hybrid Multi-Scanner Security Intelligence Platform

[![License: CC BY 4.0](https://img.shields.io/badge/License-CC%20BY%204.0-black.svg)](https://creativecommons.org/licenses/by/4.0/)
[![Python](https://img.shields.io/badge/Python-3.11+-black.svg)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-3.0+-black.svg)](https://flask.palletsprojects.com)
[![DOI](https://img.shields.io/badge/DOI-10.5281%2Fzenodo.20313666-black.svg)](https://zenodo.org/records/20313666)
[![OWASP](https://img.shields.io/badge/OWASP-Top%2010%202021-black.svg)](https://owasp.org/Top10/)

> **Research paper:** Jain, S. (2026). *SecureScan Pro: A Hybrid Web Vulnerability Detection Platform Using OWASP-Based Analysis and Machine Learning.* Zenodo. https://doi.org/10.5281/zenodo.20313666

---

## Overview

SecureScan Pro v6 evolves from a single passive OWASP scanner into a full **hybrid orchestration platform** that:

- Coordinates **OWASP ZAP, Nikto, and Burp Suite** through a unified API layer
- Aggregates and de-duplicates findings across all scanners with consensus scoring
- Enriches vulnerabilities via **NVD, VirusTotal, SecurityHeaders, and Shodan**
- Classifies risk using a **Random Forest / Gradient Boosting ML classifier**
- Outputs a **CVSS-normalised risk score (0–10)** with scanner consensus weighting
- Renders an **enterprise-grade dashboard** with severity heatmaps, OWASP breakdowns, and PDF reports

---

## System Architecture

```
Target Application
      │
      ├── Passive Recon + Baseline Response Engine
      │
      ├── Multi-Scanner Orchestration Layer
      │      ├── OWASP ZAP (REST API)
      │      ├── Nikto (CLI JSON mode)
      │      └── Burp Suite (API/proxy ingestion)
      │
      ├── Unified Vulnerability Aggregation Engine
      │      ├── De-duplication
      │      ├── Name normalisation
      │      ├── OWASP category mapping
      │      └── Scanner consensus scoring
      │
      ├── Threat Intelligence Enrichment
      │      ├── NVD (CVE + CVSS)
      │      ├── VirusTotal (domain reputation)
      │      ├── SecurityHeaders (header grade)
      │      └── Shodan (exposed services)
      │
      ├── ML Vulnerability Classifier
      │      └── Severity + confidence + FP probability
      │
      ├── Advanced Risk Engine
      │      └── CVSS-normalised score (0–10)
      │
      └── Enterprise Dashboard + PDF Reporting + Evaluation Suite
```

---

## Project Structure

```
securescan_pro/
├── app.py                        # Flask application entry point
├── hybrid_orchestrator.py        # Multi-scanner coordination layer
├── scanners/
│   ├── zap_scanner.py            # OWASP ZAP REST API integration
│   ├── nikto_scanner.py          # Nikto CLI JSON mode wrapper
│   └── burp_scanner.py           # Burp Suite API/proxy ingestion
├── intel/
│   ├── nvd_lookup.py             # NVD CVE + CVSS enrichment
│   ├── virustotal_lookup.py      # VirusTotal domain reputation
│   ├── security_headers.py       # SecurityHeaders grade analysis
│   └── shodan_lookup.py          # Shodan exposed services lookup
├── engine/
│   ├── vulnerability_aggregator.py  # De-dup, normalise, consensus score
│   └── risk_model.py             # CVSS-inspired risk formula
├── ml/
│   └── vulnerability_classifier.py  # RF / GB severity classifier
├── evaluation/
│   └── benchmark.py              # DVWA + Juice Shop evaluation suite
├── templates/
│   ├── dashboard.html            # Enterprise dashboard
│   └── result.html               # Per-scan result view
└── static/
    └── charts.js                 # Chart.js visualisations
```

---

## Features

### Multi-Scanner Orchestration
All three scanners emit a unified finding schema:
```json
{
  "vulnerability": "SQL Injection",
  "endpoint": "/login",
  "severity": "High",
  "scanner_sources": ["OWASP ZAP", "Nikto"],
  "consensus_score": 0.82,
  "owasp_category": "Injection"
}
```

| Scanner | Method | Integration |
|---|---|---|
| OWASP ZAP | Spider + active scan | REST API |
| Nikto | CLI execution | subprocess JSON mode |
| Burp Suite | Issue ingestion | API / proxy endpoint |

### Threat Intelligence Enrichment

| Source | Data Provided |
|---|---|
| NVD | CVE IDs, CVSS base scores |
| VirusTotal | Domain / URL reputation across 70+ engines |
| SecurityHeaders | Header score, grade, missing headers |
| Shodan | Exposed ports, services, vulnerability hints |

### ML Vulnerability Classifier

**Models:** `RandomForestClassifier` (default) or `GradientBoostingClassifier`

**Features:**
- Vulnerability type signal
- Scanner count (how many scanners flagged it)
- Response behaviour delta
- Scanner confidence score
- Exploitability rating
- Mitigation presence flag
- Endpoint depth

**Outputs:** `severity`, `model_confidence`, `false_positive_probability`, `priority`

### Risk Scoring Formula

```
Risk = (Exposure × Exploitability × Impact) × ScannerConsensusFactor × (1 − MitigationStrength)
```
Normalised to CVSS scale **0.00 – 10.00**

### Dashboard Visualisations
- Severity distribution chart
- OWASP category breakdown
- Scanner comparison view
- Vulnerability heatmap
- Confidence aggregation
- Unified vulnerability list with TI snapshots

---

## Getting Started

### Local Deployment (Windows)
```bash
setup_and_run.bat
```

### Local Deployment (Linux / macOS)
```bash
chmod +x setup_and_run.sh && ./setup_and_run.sh
```

The script will:
1. Create a Python virtual environment
2. Install all dependencies from `requirements.txt`
3. Initialise the SQLite database
4. Train and serialise the ML model
5. Launch Flask at `http://localhost:5000`

**First run:** ~8 minutes | **Subsequent launches:** ~4 seconds

### Cloud Deployment (Render)
One-click deployment via Render dashboard — no CLI required. Configuration files are included in the repository.

### Environment Variables (Optional)
```env
NVD_API_KEY=
VIRUSTOTAL_API_KEY=
SECURITY_HEADERS_API_KEY=
SHODAN_API_KEY=
```
All integrations degrade gracefully if keys are absent — core scanning continues unaffected.

---

## Evaluation Methodology

`evaluation/benchmark.py` supports repeatable academic experiments on **DVWA** and **OWASP Juice Shop**:

| Metric | Description |
|---|---|
| Detection Coverage | % of known vulnerabilities detected |
| False Positive Rate | FP findings as % of total findings |
| Scanner Agreement Rate | Consensus across ZAP, Nikto, Burp |
| Hybrid vs. Individual | Coverage delta of orchestrated vs. single-scanner |

### Suggested Workflow
1. Run each scanner independently → record baseline metrics
2. Run hybrid orchestrator → record combined metrics
3. Compare coverage, FP rate, and agreement over fixed datasets
4. Report statistical deltas and confidence intervals

---

## Research

This platform was developed as part of undergraduate research at Shah and Anchor Kutchhi Engineering College, Mumbai University.

**Published Paper:**
> Jain, S. (2026). *SecureScan Pro: A Hybrid Web Vulnerability Detection Platform Using OWASP-Based Analysis and Machine Learning.* Zenodo. https://doi.org/10.5281/zenodo.20313666

**Key Results (v3 baseline):**
- Weighted F1-score: **0.89**
- Critical class F1: **0.94**
- User needs survey: n = 53, 90.6% positive adoption intent

---

## Tech Stack

| Layer | Technology |
|---|---|
| Backend | Python 3.11, Flask 3.0+ |
| ORM | SQLAlchemy + SQLite / PostgreSQL |
| ML | scikit-learn 1.5+ |
| PDF Reports | ReportLab 4.2+ |
| Frontend | HTML5, CSS3, Chart.js |
| Deployment | Local script, Docker, Render |

---

## License

[Creative Commons Attribution 4.0 International (CC BY 4.0)](https://creativecommons.org/licenses/by/4.0/)
Copyright © 2026 Sahil Jain

---

## Author

**Sahil Jain**
Department of Information Technology
Shah and Anchor Kutchhi Engineering College, Mumbai University
sahil.jain24@sakec.ac.in
