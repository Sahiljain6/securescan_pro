# SecureScan Pro v5

SecureScan Pro v5 is an industry-grade, defensive-only OWASP Top 5 assessment platform with modular architecture, confidence-weighted risk modeling, dashboard analytics, and PDF reporting.

## Defensive Scope

- No aggressive attack payloads.
- No exploitation workflows.
- Passive and behavioral validation only.
- Legal/ethical scanning model for authorized targets.

## Modular Engine Architecture

Implemented under `securescan_v5/engines`:

1. **Baseline engine** (`baseline_engine.py`) — baseline capture + safe probes.
2. **Correlation engine** (`correlation_engine.py`) — error normalization, behavioral deltas, correlated evidence scoring.
3. **Mitigation analyzer** (`mitigation_analyzer.py`) — security header/session control coverage.
4. **Confidence engine** (`confidence_engine.py`) — confidence scoring using evidence + stage coverage.
5. **Risk modeling engine** (`risk_modeling_engine.py`) —
   `Risk = Exposure × Exploitability × (1 − Mitigation)` weighted by confidence.

## OWASP Control Domains

Implemented in `securescan_v5/domains/owasp_top5.py`:

- Broken Access Control
- Cryptographic Failures
- Injection
- Security Misconfiguration
- Authentication Failures

## Multi-Stage Validation Pipeline

Each domain contains:

1. Baseline capture
2. Non-destructive probe
3. Error normalization
4. Behavioral delta comparison
5. Correlated evidence scoring

## Dashboard and Reporting

- Control-domain breakdown (bar chart)
- OWASP radar chart
- Confidence meter
- Severity classification
- Evidence summary
- PDF report sections:
  - Executive summary
  - Technical appendix
  - Evidence correlation explanation
  - Risk equation section
  - Limitations

## Deployment

- Python 3.11 runtime (`runtime.txt`)
- Render compatible (`Procfile` + `gunicorn`)
- PostgreSQL via `DATABASE_URL`

## Codebase Structure

```text
securescan_pro/
├── app.py
├── owasp_scanner.py
├── report_generator.py
├── cvss.py
├── securescan_v5/
│   ├── __init__.py
│   ├── models.py
│   ├── orchestrator.py
│   ├── engines/
│   │   ├── baseline_engine.py
│   │   ├── correlation_engine.py
│   │   ├── mitigation_analyzer.py
│   │   ├── confidence_engine.py
│   │   └── risk_modeling_engine.py
│   └── domains/
│       └── owasp_top5.py
├── templates/
│   ├── dashboard.html
│   ├── result.html
│   └── report.html
└── static/
    ├── charts.js
    └── style.css
```
