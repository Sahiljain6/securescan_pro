# SecureScan Pro v4

SecureScan Pro v4 is an academic-grade, defensive-only OWASP Top 5 structured assessment engine.

## Scope and safety

- No exploit tooling.
- No aggressive attack payloads.
- Passive, non-destructive, multi-stage validation only.
- Intended for authorized security posture assessment and research workflows.

## OWASP Top 5 structured modules

Implemented in `owasp_scanner.py` with shared passive collection and domain modules:

1. Broken Access Control
2. Cryptographic Failures
3. Injection
4. Security Misconfiguration
5. Identification & Authentication Failures

Each domain module performs:

- Multi-stage validation
- Evidence collection
- Mitigation-aware scoring
- Structured JSON finding output

## Risk modeling system

`risk_model.py` implements:

```text
Risk = Exposure × Exploitability × (1 − Mitigation Strength)
```

Enhancements:

- Evidence weighting (`weighted_evidence_strength`)
- Confidence scoring (`confidence_score`)
- False-positive suppression (`false_positive_suppression`)

Example domain finding:

```json
{
  "domain": "Injection",
  "risk_equation": "Risk = Exposure × Exploitability × (1 − Mitigation Strength)",
  "risk_inputs": {
    "exposure": 0.9,
    "exploitability": 0.75,
    "mitigation_strength": 0.35,
    "evidence_strength": 0.62
  },
  "risk_output": {
    "risk": 0.29,
    "base_risk": 0.4388,
    "confidence": 58.4,
    "false_positive_factor": 0.79,
    "severity": "Medium"
  },
  "evidence": [],
  "stages": []
}
```

## UI updates

The dashboard/result views now provide:

- Control domain breakdown
- Risk equation visualization
- Confidence meter
- Severity classification
- Evidence summary

## PDF report updates

The PDF generator includes:

- Abstract
- Methodology
- Risk modeling explanation
- Domain-by-domain analysis
- Limitations section

## Folder structure

```text
securescan_pro/
├── app.py
├── cvss.py
├── ml_model.py
├── owasp_scanner.py
├── port_scanner.py
├── report_generator.py
├── risk_model.py
├── scanner.py
├── requirements.txt
├── runtime.txt
├── Procfile
├── static/
│   ├── charts.js
│   └── style.css
└── templates/
    ├── dashboard.html
    ├── login.html
    ├── report.html
    └── result.html
```

## Deployment instructions

### Local (Python 3.11)

1. `python3.11 -m venv .venv`
2. `source .venv/bin/activate`
3. `pip install -r requirements.txt`
4. Set environment variables:
   - `export FLASK_ENV=development`
   - `export SECRET_KEY='change-me'`
   - `export ADMIN_USERNAME='admin'`
   - `export ADMIN_PASSWORD='admin123'`
   - `export DATABASE_URL='postgresql://user:pass@host:5432/dbname'` (optional, for PostgreSQL)
5. Start server: `python app.py`
6. Open `http://127.0.0.1:5000`

### Render + PostgreSQL

1. Create Render Web Service from repo.
2. Use `runtime.txt` and `requirements.txt`.
3. Start command: `gunicorn app:app`.
4. Configure env vars in Render:
   - `SECRET_KEY`
   - `ADMIN_USERNAME`
   - `ADMIN_PASSWORD`
   - `DATABASE_URL` (Render PostgreSQL URI)

