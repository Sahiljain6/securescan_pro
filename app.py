import os
from datetime import datetime, timedelta, timezone
from functools import wraps
from urllib.parse import urlparse

from dotenv import load_dotenv
from flask import (
    Flask,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from flask_sqlalchemy import SQLAlchemy

from port_scanner import scan_ports
from scanner import scan_url

load_dotenv()

db = SQLAlchemy()


class ScanRecord(db.Model):
    __tablename__ = "scan_records"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False, index=True)
    url = db.Column(db.String(512), nullable=False)
    result = db.Column(db.String(32), nullable=False)
    probability = db.Column(db.Float, nullable=False)
    open_ports = db.Column(db.String(256), nullable=False, default="")
    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        index=True,
    )


class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "dev-insecure-key-change-me")
    SQLALCHEMY_DATABASE_URI = "sqlite:///securescan_local.db"
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = os.getenv("FLASK_ENV", "production") == "production"
    PERMANENT_SESSION_LIFETIME = timedelta(hours=6)


class ProductionConfig(Config):
    SQLALCHEMY_DATABASE_URI = "sqlite:///securescan_local.db"

    @staticmethod
    def init_app(app: Flask) -> None:
        database_url = os.getenv("DATABASE_URL", "").strip()
        if database_url.startswith("postgres://"):
            database_url = database_url.replace("postgres://", "postgresql://", 1)
        if database_url:
            app.config["SQLALCHEMY_DATABASE_URI"] = database_url

        if app.config["SQLALCHEMY_DATABASE_URI"].startswith("postgresql"):
            app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
                "pool_pre_ping": True,
                "pool_recycle": 300,
                "connect_args": {"sslmode": "require"},
            }


def login_required(route_func):
    @wraps(route_func)
    def wrapped(*args, **kwargs):
        if not session.get("is_authenticated"):
            flash("Please log in to continue.", "warning")
            return redirect(url_for("login"))
        return route_func(*args, **kwargs)

    return wrapped


def _normalize_url(raw_url: str) -> str:
    cleaned = (raw_url or "").strip()
    if not cleaned:
        return ""
    if not cleaned.startswith(("http://", "https://")):
        cleaned = f"https://{cleaned}"
    return cleaned


def _is_valid_url(raw_url: str) -> bool:
    normalized = _normalize_url(raw_url)
    parsed = urlparse(normalized)
    return bool(parsed.scheme in {"http", "https"} and parsed.netloc)


def create_app() -> Flask:
    app = Flask(__name__)
    app.config.from_object(ProductionConfig)
    ProductionConfig.init_app(app)

    db.init_app(app)

    with app.app_context():
        db.create_all()

    @app.get("/")
    def home():
        if session.get("is_authenticated"):
            return redirect(url_for("dashboard"))
        return redirect(url_for("login"))

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if session.get("is_authenticated"):
            return redirect(url_for("dashboard"))

        if request.method == "POST":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            admin_user = os.getenv("ADMIN_USERNAME", "admin")
            admin_pass = os.getenv("ADMIN_PASSWORD", "admin123")

            if username == admin_user and password == admin_pass:
                session.clear()
                session["is_authenticated"] = True
                session["username"] = username
                session.permanent = True
                flash("Login successful.", "success")
                return redirect(url_for("dashboard"))

            flash("Invalid username or password.", "error")

        return render_template("login.html")

    @app.get("/logout")
    @login_required
    def logout():
        session.clear()
        flash("Logged out successfully.", "success")
        return redirect(url_for("login"))

    @app.route("/dashboard", methods=["GET", "POST"])
    @login_required
    def dashboard():
        username = session.get("username", "admin")

        if request.method == "POST":
            raw_url = request.form.get("url", "")
            host = request.form.get("host", "").strip()

            if not _is_valid_url(raw_url):
                flash("Please enter a valid URL (example: https://example.com).", "error")
                return redirect(url_for("dashboard"))

            normalized_url = _normalize_url(raw_url)

            try:
                result, probability = scan_url(normalized_url)
                ports = scan_ports(host or normalized_url)
                ports_text = ", ".join(str(port) for port in ports)

                record = ScanRecord(
                    username=username,
                    url=normalized_url,
                    result=result,
                    probability=probability,
                    open_ports=ports_text,
                )
                db.session.add(record)
                db.session.commit()

                return render_template(
                    "result.html",
                    url=normalized_url,
                    result=result,
                    probability=round(probability * 100, 2),
                    open_ports=ports,
                )
            except Exception:
                db.session.rollback()
                flash("Scan failed due to an internal error. Please try again.", "error")
                return redirect(url_for("dashboard"))

        history = (
            ScanRecord.query.filter_by(username=username)
            .order_by(ScanRecord.created_at.desc())
            .limit(10)
            .all()
        )

        return render_template("dashboard.html", username=username, history=history)

    @app.errorhandler(404)
    def not_found(_error):
        flash("The page you requested does not exist.", "warning")
        return redirect(url_for("dashboard") if session.get("is_authenticated") else url_for("login"))

    @app.errorhandler(500)
    def internal_error(_error):
        db.session.rollback()
        flash("Unexpected server error occurred.", "error")
        return redirect(url_for("dashboard") if session.get("is_authenticated") else url_for("login"))

    return app


app = create_app()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5000")), debug=False)
