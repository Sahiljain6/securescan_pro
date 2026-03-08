from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from functools import wraps
from hmac import compare_digest
from urllib.parse import urlparse

from dotenv import load_dotenv
from flask import Flask, Response, abort, flash, jsonify, redirect, render_template, request, session, url_for
from flask_sqlalchemy import SQLAlchemy

from hybrid_orchestrator import HybridVulnerabilityOrchestrator

load_dotenv()

db = SQLAlchemy()


class ScanRecord(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False, index=True)
    url = db.Column(db.String(512), nullable=False)
    phishing_result = db.Column(db.String(32), nullable=False)
    phishing_probability = db.Column(db.Float, nullable=False)
    cvss_score = db.Column(db.Float, nullable=False)
    cvss_severity = db.Column(db.String(32), nullable=False)
    confidence_avg = db.Column(db.Float, nullable=False, default=0.0)


class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "change-this-securescan-secret")
    SQLALCHEMY_DATABASE_URI = "sqlite:///securescan.db"
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = os.getenv("FLASK_ENV", "production") == "production"
    SESSION_COOKIE_NAME = "securescan_sid"
    PERMANENT_SESSION_LIFETIME = timedelta(hours=4)


LAB_TARGETS = {
    "lab-sqli": "http://127.0.0.1:5000/lab/sqli?user=demo",
    "lab-xss": "http://127.0.0.1:5000/lab/xss?q=hello",
    "lab-csrf": "http://127.0.0.1:5000/lab/csrf",
}


def _normalize_url(raw_url: str) -> str:
    value = (raw_url or "").strip()
    if not value:
        return ""
    if not value.startswith(("http://", "https://")):
        value = f"https://{value}"
    return value


def _valid_url(url: str) -> bool:
    parsed = urlparse(url)
    return bool(parsed.scheme in {"http", "https"} and parsed.netloc)


def _localhost_only() -> bool:
    host = (request.host or "").split(":")[0]
    remote = request.remote_addr or ""
    return host in {"127.0.0.1", "localhost"} and remote in {"127.0.0.1", "::1"}


def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("auth"):
            flash("Please login first.", "warning")
            return redirect(url_for("login"))
        return fn(*args, **kwargs)

    return wrapper


def create_app() -> Flask:
    app = Flask(__name__)
    app.config.from_object(Config)

    app.config["OPENAI_API_KEY_CONFIGURED"] = bool(os.getenv("OPENAI_API_KEY"))

    db_url = os.getenv("DATABASE_URL", "").strip()
    if db_url:
        if db_url.startswith("postgres://"):
            db_url = db_url.replace("postgres://", "postgresql://", 1)
        app.config["SQLALCHEMY_DATABASE_URI"] = db_url

    db.init_app(app)
    hybrid_orchestrator = HybridVulnerabilityOrchestrator()

    with app.app_context():
        db.create_all()

    @app.route("/", methods=["GET"])
    def home():
        return redirect(url_for("dashboard" if session.get("auth") else "login"))

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            username = request.form.get("username", "")
            password = request.form.get("password", "")
            env_user = os.getenv("ADMIN_USERNAME", "admin")
            env_pass = os.getenv("ADMIN_PASSWORD", "admin123")

            if compare_digest(username, env_user) and compare_digest(password, env_pass):
                session.clear()
                session["auth"] = True
                session["username"] = username
                session["session_nonce"] = os.urandom(16).hex()
                session.permanent = True
                return redirect(url_for("dashboard"))
            flash("Invalid credentials.", "error")
        return render_template("login.html")

    @app.route("/logout", methods=["GET"])
    @login_required
    def logout():
        session.clear()
        flash("Logged out.", "success")
        return redirect(url_for("login"))

    @app.route("/dashboard", methods=["GET", "POST"])
    @login_required
    def dashboard():
        if request.method == "POST":
            target = request.form.get("url", "")
            lab_mode = request.form.get("lab_mode") == "on"
            if lab_mode:
                if not _localhost_only():
                    flash("Lab mode is restricted to localhost only.", "error")
                    return redirect(url_for("dashboard"))
                target = LAB_TARGETS.get(request.form.get("lab_target", ""), target)

            normalized = _normalize_url(target)
            if not _valid_url(normalized):
                flash("Enter a valid URL.", "error")
                return redirect(url_for("dashboard"))

            hybrid_scan = hybrid_orchestrator.run(normalized)
            report = hybrid_scan.get("json_report", {})
            risk_score = float(report.get("risk_score", 0.0))
            severity = report.get("severity", "Low")

            recommendations = [
                "Deploy a strict Content-Security-Policy and complete all recommended browser security headers.",
                "Close unnecessary exposed services and restrict management ports by IP allow-list.",
                "Enforce modern TLS configuration with valid CA-signed certificates and TLS 1.2+ only.",
                "Reduce redirect chains to a single canonical redirect and avoid untrusted redirect targets.",
            ]

            executive_summary = (
                f"Offline passive scanning completed for {normalized}. "
                f"Calculated risk posture is {severity} with score {risk_score}/10 based on headers, TLS, redirects, and open ports."
            )

            db.session.add(
                ScanRecord(
                    username=session.get("username", "analyst"),
                    url=normalized,
                    phishing_result=severity,
                    phishing_probability=min(1.0, risk_score / 10),
                    cvss_score=risk_score,
                    cvss_severity=severity,
                    confidence_avg=round(hybrid_scan.get("scanner_ml_summary", {}).get("score", risk_score) * 10, 2),
                )
            )
            db.session.commit()

            timestamp = datetime.now(timezone.utc).isoformat()
            result_payload = {
                "url": normalized,
                "timestamp": timestamp,
                "phishing_result": severity,
                "phishing_probability": round(min(100.0, risk_score * 10), 2),
                "owasp_findings": hybrid_scan["findings"],
                "owasp_stages": [],
                "domain_breakdown": [
                    {"domain": "Headers", "risk": max(0.0, (10 - report.get("risk_score", 0)) / 10), "confidence": 90},
                    {"domain": "Transport", "risk": min(1.0, report.get("risk_score", 0) / 10), "confidence": 85},
                ],
                "confidence_average": round(hybrid_scan.get("scanner_ml_summary", {}).get("score", risk_score) * 10, 2),
                "cvss_score": risk_score,
                "cvss_severity": severity,
                "cvss_method": "Offline passive risk normalization",
                "open_ports": report.get("open_ports", []),
                "executive_summary": executive_summary,
                "recommendations": recommendations,
                "framework": "SecureScan Pro Offline Engine",
                "scan_model": "Passive-only local Python scanners without external APIs",
                "risk_model": "(10-header_score)*open_ports*redirect_count*tls_issues normalized to 0-10",
                "limitations": ["Passive scan only; no active exploitation performed."],
                "hybrid_findings": hybrid_scan["findings"],
                "hybrid_metrics": hybrid_scan["metrics"],
                "hybrid_architecture": hybrid_scan["architecture"],
                "scanner_status": hybrid_scan.get("scanner_status", {}),
                "threat_intel": hybrid_scan.get("threat_intel", {}),
                "dashboard_data": hybrid_scan.get("dashboard_data", {}),
                "ai_analysis": hybrid_scan.get("ai_analysis", {}),
                "json_report": report,
                "scanner_ml_summary": hybrid_scan.get("scanner_ml_summary", {}),
            }
            session["last_scan"] = result_payload
            return render_template("result.html", **result_payload)

        history = ScanRecord.query.order_by(ScanRecord.id.desc()).limit(8).all()
        return render_template("dashboard.html", lab_targets=LAB_TARGETS, history=history)


    @app.post("/api/scan")
    @login_required
    def scan_api():
        payload = request.get_json(silent=True) or {}
        normalized = _normalize_url(payload.get("url", ""))
        if not _valid_url(normalized):
            return jsonify({"error": "Invalid URL"}), 400

        hybrid_scan = hybrid_orchestrator.run(normalized)
        report = hybrid_scan.get("json_report", {})
        return jsonify(
            {
                "risk_score": report.get("risk_score", 0),
                "severity": report.get("severity", "Low"),
                "missing_headers": report.get("missing_headers", []),
                "open_ports": report.get("open_ports", []),
                "tls_status": report.get("tls_status", "unknown"),
                "redirects": report.get("redirects", 0),
                "target": normalized,
                "scanner_status": hybrid_scan.get("scanner_status", {}),
                "dashboard_data": hybrid_scan.get("dashboard_data", {}),
                "scanner_ml_summary": hybrid_scan.get("scanner_ml_summary", {}),
            }
        )


    @app.get("/api/ai-health")
    @login_required
    def ai_health_api():
        return jsonify(
            {
                "openai_api_key_configured": bool(os.getenv("OPENAI_API_KEY")),
                "openai_model": os.getenv("OPENAI_MODEL", "gpt-4o-mini"),
            }
        )

    @app.get("/api/dashboard-data")
    @login_required
    def dashboard_data_api():
        payload = session.get("last_scan") or {}
        dashboard_data = payload.get("dashboard_data") or {
            "vulnerabilities": [],
            "severity_distribution": {"Low": 1},
            "missing_headers": {"None Missing": 1},
            "open_ports": {"No Open Ports": 1},
            "scanner_comparison": {"Offline Passive Engine": 1},
            "owasp_categories": {"Security Misconfiguration": 1},
            "heatmap": {"Passive::Low": 1},
            "risk_score": 0,
            "message": "Run a scan to populate analytics.",
        }
        return jsonify(dashboard_data)

    @app.route("/report", methods=["GET"])
    @login_required
    def report_view():
        payload = session.get("last_scan")
        if not payload:
            flash("Run a scan first.", "warning")
            return redirect(url_for("dashboard"))
        return render_template("report.html", **payload)

    @app.route("/download-report", methods=["GET"])
    @login_required
    def download_report():
        payload = session.get("last_scan")
        if not payload:
            flash("Run a scan first.", "warning")
            return redirect(url_for("dashboard"))

        from report_generator import generate_pdf_report

        pdf_bytes = generate_pdf_report(payload)
        return Response(
            pdf_bytes,
            mimetype="application/pdf",
            headers={"Content-Disposition": "attachment; filename=securescan_report.pdf"},
        )

    @app.get("/lab/sqli")
    def lab_sqli():
        if not _localhost_only():
            abort(403)
        user = request.args.get("user", "demo")
        if "OR" in user.upper() or "'" in user:
            return "SQL syntax error near 'OR 1=1'", 200
        return f"Lab user profile: {user}", 200

    @app.get("/lab/xss")
    def lab_xss():
        if not _localhost_only():
            abort(403)
        q = request.args.get("q", "")
        return f"<html><body><div>Echo: {q}</div></body></html>", 200

    @app.route("/lab/csrf", methods=["GET", "POST"])
    def lab_csrf():
        if not _localhost_only():
            abort(403)
        return """
        <html><body>
            <form method='post' action='/lab/csrf'>
                <input type='text' name='email' />
                <button type='submit'>Save</button>
            </form>
        </body></html>
        """

    return app


app = create_app()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
