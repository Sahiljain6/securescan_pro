# SecureScan Pro v3

SecureScan Pro is a defensive, educational web security assessment platform.

## Multi-stage OWASP analysis engine

The scanner now executes a modular six-stage pipeline:

1. Passive reconnaissance (headers, TLS, redirects, cookie flags)
2. Reflection detection (parameter reflection + context classification)
3. Encoding validation (HTML encoding and JavaScript escaping)
4. Mitigation awareness (CSP, X-Frame-Options, HSTS)
5. Behavioral validation (length/status drift + error signatures)
6. Confidence engine (exploitability scoring, confidence %, severity, false-positive reduction)

Structured findings output:

```json
{
  "vulnerability": "...",
  "exploitability_score": 0.0,
  "confidence": 0.0,
  "severity": "Informational|Low|Medium|High|Critical",
  "mitigation_present": true,
  "explanation": "..."
}
```

## Folder structure

```text
securescan_pro/
├── app.py
├── cvss.py
├── ml_model.py
├── owasp_scanner.py
├── port_scanner.py
├── report_generator.py
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

## Local deployment (Python 3.11)

1. Create and activate a venv:
   - `python3.11 -m venv .venv`
   - `source .venv/bin/activate`
2. Install dependencies:
   - `pip install -r requirements.txt`
3. Configure environment:
   - `export FLASK_ENV=development`
   - `export SECRET_KEY='change-me'`
   - `export ADMIN_USERNAME='admin'`
   - `export ADMIN_PASSWORD='admin123'`
   - Optional PostgreSQL on Render/production:
     - `export DATABASE_URL='postgresql://user:pass@host:5432/dbname'`
4. Run app:
   - `python app.py`
5. Open:
   - `http://127.0.0.1:5000`

## Render deployment

1. Push repository to Git provider.
2. In Render, create a **Web Service** and point it to the repo.
3. Runtime uses `runtime.txt` and dependencies from `requirements.txt`.
4. Start command from `Procfile`:
   - `gunicorn app:app`
5. Set environment variables in Render dashboard:
   - `SECRET_KEY`, `ADMIN_USERNAME`, `ADMIN_PASSWORD`
   - `DATABASE_URL` (Render PostgreSQL, with `postgresql://` format)

## Safety constraints

- Defensive and educational scanning only.
- No aggressive attack payloads.
- Probes are passive/non-destructive and baseline-compared.
