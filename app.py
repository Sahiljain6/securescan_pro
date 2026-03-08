from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from functools import wraps
from hmac import compare_digest
from urllib.parse import urlparse

from dotenv import load_dotenv
from flask import Flask, Response, abort, flash, jsonify, redirect, render_template, request, session, url_for
from flask_sqlalchemy import SQLAlchemy

from cvss import score_findings
from owasp_scanner import run_owasp_scan
from port_scanner import scan_ports
from scanner import scan_url
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

    db_url = os.getenv("DATABASE_URL", "").strip()
    if db_url:
        if db_url.startswith("postgres://"):
            db_url = db_url.replace("postgres://", "postgresql://", 1)
        app.config["SQLALCHEMY_DATABASE_URI"] = db_url

    db.init_app(app)
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

            phishing_result, phishing_probability = scan_url(normalized)
            owasp_scan = run_owasp_scan(normalized)
            findings = owasp_scan["findings"]
            cvss = score_findings(findings)
            open_ports = scan_ports(normalized)
            hybrid_scan = HybridVulnerabilityOrchestrator().run(normalized)

            recommendations = [
                "Validate and sanitize all input server-side and apply strict contextual output encoding.",
                "Harden browser trust boundaries with CSP, X-Frame-Options, and strict transport security.",
                "Implement anti-CSRF tokens and same-site cookie protections on all state-changing requests.",
                "Continuously patch dependencies and externally exposed services identified in port scans.",
                "Operationalize continuous monitoring with periodic authenticated and passive scanning cycles.",
            ]

            executive_summary = (
                f"The target {normalized} was classified as {phishing_result} with a phishing probability of "
                f"{round(phishing_probability * 100, 2)}%. The SecureScan Pro v5 OWASP Top 5 assessment produced {len(findings)} domain-level "
                f"findings with an average confidence of {owasp_scan['confidence_average']}%. "
                f"Overall weighted risk posture is {cvss['severity']} (CVSS {cvss['score']})."
            )

            db.session.add(
                ScanRecord(
                    username=session.get("username", "analyst"),
                    url=normalized,
                    phishing_result=phishing_result,
                    phishing_probability=phishing_probability,
                    cvss_score=cvss["score"],
                    cvss_severity=cvss["severity"],
                    confidence_avg=owasp_scan["confidence_average"],
                )
            )
            db.session.commit()

            timestamp = datetime.now(timezone.utc).isoformat()
            result_payload = {
                "url": normalized,
                "timestamp": timestamp,
                "phishing_result": phishing_result,
                "phishing_probability": round(phishing_probability * 100, 2),
                "owasp_findings": findings,
                "owasp_stages": owasp_scan["stages"],
                "domain_breakdown": owasp_scan["domain_breakdown"],
                "confidence_average": owasp_scan["confidence_average"],
                "cvss_score": cvss["score"],
                "cvss_severity": cvss["severity"],
                "cvss_method": cvss["method"],
                "open_ports": open_ports,
                "executive_summary": executive_summary,
                "recommendations": recommendations,
                "framework": owasp_scan.get("framework", "SecureScan Pro v5"),
                "scan_model": owasp_scan.get("scan_model", "Defensive-only passive behavioral validation"),
                "risk_model": owasp_scan.get("risk_model"),
                "limitations": owasp_scan.get("limitations", []),
                "hybrid_findings": hybrid_scan["findings"],
                "hybrid_metrics": hybrid_scan["metrics"],
                "hybrid_architecture": hybrid_scan["architecture"],
                "scanner_status": hybrid_scan.get("scanner_status", {}),
                "threat_intel": hybrid_scan.get("threat_intel", {}),
                "dashboard_data": hybrid_scan.get("dashboard_data", {}),
                "ai_analysis": hybrid_scan.get("ai_analysis", {}),
                "json_report": hybrid_scan.get("json_report", {}),
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

        hybrid_scan = HybridVulnerabilityOrchestrator().run(normalized)
        report = hybrid_scan.get("json_report", {})
        return jsonify(
            {
                "vulnerabilities": report.get("vulnerabilities", hybrid_scan.get("findings", [])),
                "severity_distribution": report.get("severity_distribution", {}),
                "owasp_categories": report.get("owasp_categories", {}),
                "risk_score": report.get("risk_score", 0),
                "ai_analysis": report.get("ai_analysis", hybrid_scan.get("ai_analysis", {})),
                "target": normalized,
                "scanner_status": hybrid_scan.get("scanner_status", {}),
                "threat_intel": hybrid_scan.get("threat_intel", {}),
                "dashboard_data": hybrid_scan.get("dashboard_data", {}),
                "scanner_ml_summary": hybrid_scan.get("scanner_ml_summary", {}),
            }
        )

    @app.get("/api/dashboard-data")
    @login_required
    def dashboard_data_api():
        payload = session.get("last_scan") or {}
        dashboard_data = payload.get("dashboard_data") or {
            "vulnerabilities": [],
            "severity_distribution": {"Informational": 1},
            "scanner_comparison": {"No Findings": 1},
            "owasp_categories": {"No OWASP Mapping": 1},
            "heatmap": {"No Data::Informational": 1},
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
