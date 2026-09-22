from flask import Flask, render_template, request, redirect, url_for, session
from werkzeug.utils import secure_filename
import os
import csv

app = Flask(__name__)

# =========================================================
# CONFIGURATION
# =========================================================

app.secret_key = "security_log_project_key"

# Temporary administrator credentials
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin123"

# Upload configuration
UPLOAD_FOLDER = "uploads"
ALLOWED_EXTENSIONS = {"log", "txt", "csv"}

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

# Create uploads folder automatically
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


# =========================================================
# HELPER FUNCTIONS
# =========================================================

def allowed_file(filename):

    return (
        "." in filename
        and filename.rsplit(".", 1)[1].lower()
        in ALLOWED_EXTENSIONS
    )


# =========================================================
# LOGIN
# =========================================================

@app.route("/")
def login():

    return render_template("login.html")


@app.route("/login", methods=["POST"])
def login_user():

    username = request.form.get("username", "")
    password = request.form.get("password", "")

    if (
        username == ADMIN_USERNAME
        and password == ADMIN_PASSWORD
    ):

        session["admin_logged_in"] = True

        return redirect(url_for("dashboard"))

    return render_template(
        "login.html",
        error="Invalid username or password"
    )


# =========================================================
# DASHBOARD
# =========================================================

@app.route("/dashboard")
def dashboard():

    if not session.get("admin_logged_in"):

        return redirect(url_for("login"))

    return render_template("dashboard.html")


# =========================================================
# LOG DATA PAGE
# =========================================================

@app.route("/logs")
def logs():

    if not session.get("admin_logged_in"):

        return redirect(url_for("login"))

    return render_template("logs.html")


# =========================================================
# LOG FILE UPLOAD + PROCESSING
# =========================================================

@app.route("/upload", methods=["POST"])
def upload():

    if not session.get("admin_logged_in"):

        return redirect(url_for("login"))

    if "logfile" not in request.files:

        return redirect(url_for("logs"))

    file = request.files["logfile"]

    if file.filename == "":

        return redirect(url_for("logs"))

    if not allowed_file(file.filename):

        return render_template(
            "logs.html",
            error="Unsupported file type. Please upload LOG, TXT or CSV."
        )

    filename = secure_filename(file.filename)

    file_path = os.path.join(
        app.config["UPLOAD_FOLDER"],
        filename
    )

    # Save file
    file.save(file_path)

    records = []

    try:

        # =================================================
        # CSV FILE
        # =================================================

        if filename.lower().endswith(".csv"):

            with open(
                file_path,
                "r",
                encoding="utf-8-sig",
                errors="ignore"
            ) as csv_file:

                reader = csv.DictReader(csv_file)

                for row in reader:

                    records.append(dict(row))


        # =================================================
        # LOG / TXT FILE
        # =================================================

        else:

            with open(
                file_path,
                "r",
                encoding="utf-8",
                errors="ignore"
            ) as log_file:

                for line in log_file:

                    line = line.strip()

                    if line:

                        records.append({
                            "log": line
                        })


    except Exception as e:

        return render_template(
            "logs.html",
            error=f"Unable to process file: {e}"
        )


    return render_template(
        "logs.html",
        records=records,
        filename=filename
    )


# =========================================================
# LOGOUT
# =========================================================

@app.route("/logout")
def logout():

    session.clear()

    return redirect(url_for("login"))


# =========================================================
# RUN APPLICATION
# =========================================================

if __name__ == "__main__":

    app.run(debug=True)