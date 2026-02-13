import os
from flask import Flask, render_template, request
from flask_sqlalchemy import SQLAlchemy
from scanner import scan_url

app = Flask(__name__)

# Database config (Render + Local safe)
database_url = os.environ.get("DATABASE_URL")

if database_url:
    app.config["SQLALCHEMY_DATABASE_URI"] = database_url
else:
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///local.db"

app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

# Database Model
class ScanResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String(500))
    result = db.Column(db.String(100))

# Create tables automatically
with app.app_context():
    db.create_all()

@app.route("/", methods=["GET", "POST"])
def home():
    result = None

    if request.method == "POST":
        url = request.form.get("url")
        result = scan_url(url)

        new_scan = ScanResult(url=url, result=result)
        db.session.add(new_scan)
        db.session.commit()

    return render_template("index.html", result=result)

if __name__ == "__main__":
    app.run(debug=True)
