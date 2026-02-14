from __future__ import annotations

import os
from datetime import timedelta
from functools import wraps
from urllib.parse import urlparse

from dotenv import load_dotenv
from flask import Flask, Response, flash, redirect, render_template, request, session, url_for
from flask_sqlalchemy import SQLAlchemy

from cvss import score_findings
from owasp_scanner import run_owasp_scan
from port_scanner import scan_ports
from report_generator import generate_pdf_report
from scanner import scan_url

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


class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "change-this-securescan-secret")
    SQLALCHEMY_DATABASE_URI = "sqlite:///securescan.db"
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = os.getenv("FLASK_ENV", "production") == "production"
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
            if username == env_user and password == env_pass:
                session.clear()
                session["auth"] = True
                session["username"] = username
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
                target = LAB_TARGETS.get(request.form.get("lab_target", ""), target)

            normalized = _normalize_url(target)
            if not _valid_url(normalized):
                flash("Enter a valid URL.", "error")
                return redirect(url_for("dashboard"))

            phishing_result, phishing_probability = scan_url(normalized)
            findings = run_owasp_scan(normalized)
            cvss = score_findings(findings)
            open_ports = scan_ports(normalized)

            recommendations = [
                "Enforce strict input validation and output encoding.",
                "Enable and tune a Web Application Firewall (WAF).",
                "Implement anti-CSRF tokens on state-changing forms.",
                "Harden transport with TLS and modern security headers.",
                "Continuously scan and patch exposed services.",
            ]

            db.session.add(
                ScanRecord(
                    username=session.get("username", "analyst"),
                    url=normalized,
                    phishing_result=phishing_result,
                    phishing_probability=phishing_probability,
                    cvss_score=cvss["score"],
                    cvss_severity=cvss["severity"],
                )
            )
            db.session.commit()

            result_payload = {
                "url": normalized,
                "phishing_result": phishing_result,
                "phishing_probability": round(phishing_probability * 100, 2),
                "owasp_findings": findings,
                "cvss_score": cvss["score"],
                "cvss_severity": cvss["severity"],
                "open_ports": open_ports,
                "recommendations": recommendations,
            }
            session["last_scan"] = result_payload
            return render_template("result.html", **result_payload)

        history = ScanRecord.query.order_by(ScanRecord.id.desc()).limit(8).all()
        return render_template("dashboard.html", lab_targets=LAB_TARGETS, history=history)

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

        pdf_bytes = generate_pdf_report(payload)
        return Response(
            pdf_bytes,
            mimetype="application/pdf",
            headers={"Content-Disposition": "attachment; filename=securescan_report.pdf"},
        )

    @app.get("/lab/sqli")
    def lab_sqli():
        user = request.args.get("user", "demo")
        if "OR" in user.upper():
            return "SQL syntax error near 'OR 1=1'", 200
        return f"Lab user profile: {user}", 200

    @app.get("/lab/xss")
    def lab_xss():
        q = request.args.get("q", "")
        return f"<html><body><div>Echo: {q}</div></body></html>", 200

    @app.route("/lab/csrf", methods=["GET", "POST"])
    def lab_csrf():
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
