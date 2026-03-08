# SecureScan Pro v6 — Hybrid Multi-Scanner Vulnerability Assessment Platform

SecureScan Pro v6 redesigns the previous OWASP-only engine into a **hybrid orchestration and analysis layer** that combines scanner telemetry from OWASP ZAP, Nikto, and Burp Suite.

## Updated System Architecture

```text
Target Website
      ↓
SecureScan Recon Engine
      ↓
Multi-Scanner Layer
   • OWASP ZAP API
   • Nikto CLI
   • Burp Suite API/Proxy
      ↓
Unified Vulnerability Aggregation Engine
      ↓
Machine Learning Vulnerability Classifier
      ↓
Risk Scoring Engine
      ↓
Reporting & Visualization Dashboard
```

## Modular Project Structure

```text
securescan_pro/
├── app.py
├── hybrid_orchestrator.py
├── scanners/
│   ├── zap_scanner.py
│   ├── nikto_scanner.py
│   └── burp_scanner.py
├── engine/
│   ├── vulnerability_aggregator.py
│   └── risk_model.py
├── ml/
│   └── vulnerability_classifier.py
├── evaluation/
│   └── benchmark.py
├── templates/
│   ├── dashboard.html
│   └── result.html
└── static/
    └── charts.js
```

## Scanner Integration Modules

- **ZAP** (`scanners/zap_scanner.py`): REST calls for spider, active scan, alert retrieval.
- **Nikto** (`scanners/nikto_scanner.py`): subprocess execution + JSON parsing + normalized findings.
- **Burp Suite** (`scanners/burp_scanner.py`): API/proxy ingestion of scan issues with confidence normalization.

Each scanner emits standardized JSON findings:

```json
{
  "vulnerability": "SQL Injection",
  "scanner": "OWASP ZAP",
  "endpoint": "/login",
  "severity": "High",
  "confidence": 0.82,
  "owasp_category": "Injection"
}
```

## Vulnerability Aggregation Algorithm

`engine/vulnerability_aggregator.py` performs:

1. Name normalization (`xss` → `Cross-Site Scripting`).
2. OWASP category mapping.
3. De-duplication by vulnerability + endpoint.
4. Scanner consensus boost for confidence.

## Machine Learning Vulnerability Classifier

`ml/vulnerability_classifier.py` supports:

- RandomForest classification (when `scikit-learn` is available).
- Feature vector including scanner source count, vulnerability type, endpoint depth, response behavior signals, exploitability, and scanner confidence.
- Rule-based fallback for constrained environments.
- False-positive probability estimate and priority bucket (P1–P4).

## Improved Risk Scoring Framework

`engine/risk_model.py` implements:

`Risk = (Exposure × Exploitability × Impact) × Scanner Consensus Factor × (1 − Mitigation Strength)`

Consensus increases confidence for multi-scanner corroboration.

## Dashboard Enhancements

`templates/result.html` and `static/charts.js` now include:

- vulnerabilities by scanner,
- OWASP category breakdown,
- unified vulnerability list,
- aggregated confidence + ML severity/priority,
- scanner status visibility.

## Research Evaluation Methodology

`evaluation/benchmark.py` provides benchmark metrics for vulnerable targets (DVWA, Juice Shop):

- detection coverage,
- false positive rate,
- scanner agreement rate,
- performance/runtime comparison.

Use these outputs as publication-grade experiment tables.
