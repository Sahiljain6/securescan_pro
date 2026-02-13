from flask import Flask, render_template, request, redirect, send_file
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user
import sqlite3
import os

from scanner import scan_website
from port_scanner import scan_ports
from ml_model import predict_input

from reportlab.platypus import SimpleDocTemplate, Paragraph
from reportlab.lib.styles import getSampleStyleSheet

app = Flask(__name__)
app.secret_key = "supersecretkey"

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

# ---------------- LOGIN SYSTEM ---------------- #

class User(UserMixin):
    def __init__(self, id):
        self.id = id

users = {"admin": {"password": "admin123"}}

@login_manager.user_loader
def load_user(user_id):
    return User(user_id)

# ---------------- DATABASE ---------------- #

def init_db():
    conn = sqlite3.connect("database.db")
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT,
            sql_result TEXT,
            xss_result TEXT,
            header_result TEXT
        )
    """)
    conn.commit()
    conn.close()

# ---------------- ROUTES ---------------- #

@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        if username in users and users[username]["password"] == password:
            login_user(User(username))
            return redirect("/dashboard")

    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect("/")


@app.route("/dashboard")
@login_required
def dashboard():
    conn = sqlite3.connect("database.db")
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM scans")
    total_scans = c.fetchone()[0]
    conn.close()

    return render_template("dashboard.html", total_scans=total_scans)


@app.route("/scan", methods=["POST"])
@login_required
def scan():
    url = request.form["url"]

    results = scan_website(url)
    ports = scan_ports(url.replace("http://", "").replace("https://", ""))
    ml_check = predict_input(url)

    conn = sqlite3.connect("database.db")
    c = conn.cursor()
    c.execute("INSERT INTO scans (url, sql_result, xss_result, header_result) VALUES (?, ?, ?, ?)",
              (url, results["sql"], results["xss"], results["headers"]))
    conn.commit()
    conn.close()

    return render_template("result.html",
                           results=results,
                           ports=ports,
                           ml=ml_check,
                           url=url)


@app.route("/report/<path:url>")
@login_required
def report(url):
    filename = "report.pdf"
    doc = SimpleDocTemplate(filename)
    styles = getSampleStyleSheet()
    elements = []

    elements.append(Paragraph("SecureScan Report", styles["Title"]))
    elements.append(Paragraph("Target: " + url, styles["Normal"]))

    doc.build(elements)

    return send_file(filename, as_attachment=True)


if __name__ == "__main__":
    init_db()
    app.run(debug=True)
