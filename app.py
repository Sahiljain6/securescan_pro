import os
from datetime import datetime, timezone

from dotenv import load_dotenv
from flask import Flask, redirect, render_template, request, session, url_for
from flask_sqlalchemy import SQLAlchemy

from port_scanner import scan_ports
from scanner import scan_url

load_dotenv()

db = SQLAlchemy()


class ScanRecord(db.Model):
    __tablename__ = "scan_records"

    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String(512), nullable=False)
    result = db.Column(db.String(32), nullable=False)
    probability = db.Column(db.Float, nullable=False)
    open_ports = db.Column(db.String(256), nullable=False, default="")
    timestamp = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))


def _database_uri() -> str:
    database_url = os.getenv("DATABASE_URL", "").strip()
    if database_url.startswith("postgres://"):
        database_url = database_url.replace("postgres://", "postgresql://", 1)
    if database_url:
        return database_url
    return "sqlite:///securescan_local.db"


def create_app() -> Flask:
    app = Flask(__name__)
    app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "change-me-in-production")
    app.config["SQLALCHEMY_DATABASE_URI"] = _database_uri()
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

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
        error = None
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            admin_user = os.getenv("ADMIN_USERNAME", "admin")
            admin_pass = os.getenv("ADMIN_PASSWORD", "admin123")

            if username == admin_user and password == admin_pass:
                session["is_authenticated"] = True
                session["username"] = username
                return redirect(url_for("dashboard"))

            error = "Invalid username or password."

        return render_template("login.html", error=error)

    @app.get("/logout")
    def logout():
        session.clear()
        return redirect(url_for("login"))

    @app.route("/dashboard", methods=["GET", "POST"])
    def dashboard():
        if not session.get("is_authenticated"):
            return redirect(url_for("login"))

        if request.method == "POST":
            url = request.form.get("url", "").strip()
            host = request.form.get("host", "").strip()

            result, probability = scan_url(url)
            ports = scan_ports(host or url)
            ports_text = ", ".join(str(port) for port in ports)

            record = ScanRecord(
                url=url,
                result=result,
                probability=probability,
                open_ports=ports_text,
            )
            db.session.add(record)
            db.session.commit()

            return render_template(
                "result.html",
                url=url,
                result=result,
                probability=round(probability * 100, 2),
                open_ports=ports,
            )

        return render_template("dashboard.html", username=session.get("username", "admin"))

    return app


app = create_app()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5000")), debug=False)
