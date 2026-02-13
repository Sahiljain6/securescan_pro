import os
from flask import Flask, render_template, request, redirect, session
from flask_sqlalchemy import SQLAlchemy
from scanner import scan_url
from port_scanner import scan_ports
from ml_model import predict_input

app = Flask(__name__)
app.secret_key = "supersecretkey"

# ---------- DATABASE CONFIG ----------
database_url = os.environ.get("DATABASE_URL")

if database_url:
    # Fix for Render PostgreSQL URL
    if database_url.startswith("postgres://"):
        database_url = database_url.replace("postgres://", "postgresql://", 1)
    app.config["SQLALCHEMY_DATABASE_URI"] = database_url
else:
    # Local fallback
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///local.db"

app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

# ---------- DATABASE MODEL ----------
class ScanResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String(300))
    vulnerabilities = db.Column(db.Text)
    ports = db.Column(db.Text)
    ml_prediction = db.Column(db.String(100))

# Auto create tables
with app.app_context():
    db.create_all()

# ---------- ROUTES ----------
@app.route("/")
def home():
    return redirect("/login")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        if request.form["username"] == "admin" and request.form["password"] == "admin123":
            session["admin"] = True
            return redirect("/dashboard")
    return render_template("login.html")

@app.route("/dashboard", methods=["GET", "POST"])
def dashboard():
    if "admin" not in session:
        return redirect("/login")

    if request.method == "POST":
        url = request.form["url"]

        vulnerabilities = scan_url(url)
        ports = scan_ports(url)
        ml_result = predict_input(url)

        new_scan = ScanResult(
            url=url,
            vulnerabilities=str(vulnerabilities),
            ports=str(ports),
            ml_prediction=ml_result
        )

        db.session.add(new_scan)
        db.session.commit()

        return render_template("result.html",
                               url=url,
                               vulnerabilities=vulnerabilities,
                               ports=ports,
                               ml_result=ml_result)

    scans = ScanResult.query.order_by(ScanResult.id.desc()).all()
    return render_template("dashboard.html", scans=scans)

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
