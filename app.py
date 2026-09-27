from flask import Flask, render_template, request, redirect, url_for, session
from werkzeug.utils import secure_filename
from collections import Counter
import os
import csv


app = Flask(__name__)


# =========================================================
# CONFIGURATION
# =========================================================

app.secret_key = "security_log_project_key"

ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin123"

UPLOAD_FOLDER = "uploads"

ALLOWED_EXTENSIONS = {"csv", "txt", "log"}

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

os.makedirs(UPLOAD_FOLDER, exist_ok=True)


# =========================================================
# HELPER FUNCTION
# =========================================================

def allowed_file(filename):

    return (
        "." in filename
        and filename.rsplit(".", 1)[1].lower()
        in ALLOWED_EXTENSIONS
    )


# =========================================================
# ANOMALY DETECTION ENGINE
# =========================================================

def detect_anomalies(records):

    anomalies = []

    # -----------------------------------------------------
    # COUNT FAILED LOGIN ATTEMPTS BY IP
    # -----------------------------------------------------

    failed_by_ip = Counter()

    for record in records:

        event = str(
            record.get("event", "")
        ).strip().lower()

        status = str(
            record.get("status", "")
        ).strip().lower()

        ip = str(
            record.get("ip_address", "")
        ).strip()

        if (
            event == "login"
            and status == "failed"
            and ip
        ):

            failed_by_ip[ip] += 1


    # -----------------------------------------------------
    # FIND SUSPICIOUS IPS
    # 3 OR MORE FAILED LOGIN ATTEMPTS
    # -----------------------------------------------------

    suspicious_ips = {
        ip
        for ip, count in failed_by_ip.items()
        if count >= 3
    }


    # -----------------------------------------------------
    # RULE 1: BRUTE FORCE LOGIN
    # -----------------------------------------------------

    for record in records:

        event = str(
            record.get("event", "")
        ).strip().lower()

        status = str(
            record.get("status", "")
        ).strip().lower()

        ip = str(
            record.get("ip_address", "")
        ).strip()

        if (
            event == "login"
            and status == "failed"
            and ip in suspicious_ips
        ):

            anomalies.append({

                "type": "Brute Force Login",

                "severity": "HIGH",

                "ip_address": ip,

                "username": record.get(
                    "username",
                    "Unknown"
                ),

                "timestamp": record.get(
                    "timestamp",
                    "Unknown"
                ),

                "description":
                    f"Multiple failed login attempts detected "
                    f"from {ip}. Total failed attempts: "
                    f"{failed_by_ip[ip]}"
            })


    # -----------------------------------------------------
    # RULE 2: SUSPICIOUS EXTERNAL LOGIN
    # -----------------------------------------------------

    for record in records:

        event = str(
            record.get("event", "")
        ).strip().lower()

        status = str(
            record.get("status", "")
        ).strip().lower()

        ip = str(
            record.get("ip_address", "")
        ).strip()

        if (
            event == "login"
            and status == "failed"
            and ip.startswith("203.")
        ):

            anomalies.append({

                "type": "Suspicious External Login",

                "severity": "MEDIUM",

                "ip_address": ip,

                "username": record.get(
                    "username",
                    "Unknown"
                ),

                "timestamp": record.get(
                    "timestamp",
                    "Unknown"
                ),

                "description":
                    f"Failed login attempt detected from "
                    f"external IP address {ip}."
            })


    return anomalies


# =========================================================
# LOGIN PAGE
# =========================================================

@app.route("/")
def login():

    return render_template(
        "login.html"
    )


# =========================================================
# LOGIN PROCESS
# =========================================================

@app.route("/login", methods=["POST"])
def login_user():

    username = request.form.get(
        "username",
        ""
    ).strip()

    password = request.form.get(
        "password",
        ""
    )


    if (
        username == ADMIN_USERNAME
        and password == ADMIN_PASSWORD
    ):

        session["admin_logged_in"] = True

        return redirect(
            url_for("dashboard")
        )


    return render_template(
        "login.html",
        error="Invalid username or password"
    )


# =========================================================
# DASHBOARD
# =========================================================

@app.route("/dashboard")
def dashboard():

    if not session.get(
        "admin_logged_in"
    ):

        return redirect(
            url_for("login")
        )


    # Get current analysis data

    records = session.get(
        "records",
        []
    )

    anomalies = session.get(
        "anomalies",
        []
    )

    filename = session.get(
        "uploaded_filename",
        None
    )


    # Basic dashboard statistics

    total_logs = len(records)

    total_anomalies = len(anomalies)


    high_anomalies = sum(
        1
        for anomaly in anomalies
        if anomaly.get("severity") == "HIGH"
    )


    medium_anomalies = sum(
        1
        for anomaly in anomalies
        if anomaly.get("severity") == "MEDIUM"
    )


    return render_template(

        "dashboard.html",

        total_logs=total_logs,

        total_anomalies=total_anomalies,

        high_anomalies=high_anomalies,

        medium_anomalies=medium_anomalies,

        filename=filename

    )


# =========================================================
# LOG DATA PAGE
# =========================================================

@app.route("/logs")
def logs():

    if not session.get(
        "admin_logged_in"
    ):

        return redirect(
            url_for("login")
        )


    # Keep previously uploaded data visible

    records = session.get(
        "records",
        []
    )

    filename = session.get(
        "uploaded_filename",
        None
    )


    return render_template(

        "logs.html",

        records=records,

        filename=filename

    )


# =========================================================
# UPLOAD + PROCESS LOG
# =========================================================

@app.route("/upload", methods=["POST"])
def upload():

    # -----------------------------------------------------
    # CHECK LOGIN
    # -----------------------------------------------------

    if not session.get(
        "admin_logged_in"
    ):

        return redirect(
            url_for("login")
        )


    # -----------------------------------------------------
    # CHECK FILE EXISTS
    # -----------------------------------------------------

    if "logfile" not in request.files:

        return render_template(

            "logs.html",

            error="No file was selected."

        )


    file = request.files["logfile"]


    # -----------------------------------------------------
    # CHECK EMPTY FILE
    # -----------------------------------------------------

    if file.filename == "":

        return render_template(

            "logs.html",

            error="Please select a file."

        )


    # -----------------------------------------------------
    # CHECK FILE EXTENSION
    # -----------------------------------------------------

    if not allowed_file(
        file.filename
    ):

        return render_template(

            "logs.html",

            error=
                "Only CSV, TXT and LOG files are supported."

        )


    # -----------------------------------------------------
    # SECURE FILENAME
    # -----------------------------------------------------

    filename = secure_filename(
        file.filename
    )


    if not filename:

        return render_template(

            "logs.html",

            error="Invalid filename."

        )


    # -----------------------------------------------------
    # FILE PATH
    # -----------------------------------------------------

    file_path = os.path.join(

        app.config["UPLOAD_FOLDER"],

        filename

    )


    # -----------------------------------------------------
    # SAVE FILE
    # -----------------------------------------------------

    try:

        file.save(
            file_path
        )

    except Exception as error:

        return render_template(

            "logs.html",

            error=
                f"Unable to save file: {error}"

        )


    # -----------------------------------------------------
    # PROCESS RECORDS
    # -----------------------------------------------------

    records = []


    try:

        # =================================================
        # CSV PROCESSING
        # =================================================

        if filename.lower().endswith(
            ".csv"
        ):

            with open(

                file_path,

                "r",

                encoding="utf-8-sig",

                errors="ignore"

            ) as csv_file:

                reader = csv.DictReader(
                    csv_file
                )


                # Check CSV header

                if reader.fieldnames:

                    reader.fieldnames = [

                        str(field).strip()

                        if field

                        else ""

                        for field
                        in reader.fieldnames

                    ]


                for row in reader:

                    cleaned_row = {}

                    for key, value in row.items():

                        clean_key = (
                            str(key).strip()
                            if key
                            else ""
                        )

                        clean_value = (
                            str(value).strip()
                            if value is not None
                            else ""
                        )

                        cleaned_row[
                            clean_key
                        ] = clean_value


                    # Ignore completely empty rows

                    if any(
                        value != ""
                        for value
                        in cleaned_row.values()
                    ):

                        records.append(
                            cleaned_row
                        )


        # =================================================
        # TXT / LOG PROCESSING
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


    except Exception as error:

        return render_template(

            "logs.html",

            error=
                f"Error processing log file: {error}"

        )


    # -----------------------------------------------------
    # CHECK IF FILE CONTAINS DATA
    # -----------------------------------------------------

    if not records:

        return render_template(

            "logs.html",

            error=
                "The uploaded file contains no readable records."

        )


    # =====================================================
    # RUN ANOMALY DETECTION
    # =====================================================

    anomalies = detect_anomalies(
        records
    )


    # =====================================================
    # SAVE DATA IN SESSION
    # =====================================================

    session["uploaded_filename"] = filename

    session["records"] = records

    session["anomalies"] = anomalies


    # =====================================================
    # SUCCESS MESSAGE
    # =====================================================

    success_message = (
        f"File processed successfully: {filename}"
    )


    # =====================================================
    # DISPLAY PROCESSED LOGS
    # =====================================================

    return render_template(

        "logs.html",

        records=records,

        filename=filename,

        success=success_message

    )


# =========================================================
# ANOMALIES PAGE
# =========================================================

@app.route("/anomalies")
def anomalies():

    if not session.get(
        "admin_logged_in"
    ):

        return redirect(
            url_for("login")
        )


    anomaly_records = session.get(
        "anomalies",
        []
    )


    filename = session.get(

        "uploaded_filename",

        "No file uploaded"

    )


    # -----------------------------------------------------
    # SEVERITY COUNTS
    # -----------------------------------------------------

    total_anomalies = len(
        anomaly_records
    )


    high_anomalies = sum(

        1

        for anomaly in anomaly_records

        if anomaly.get(
            "severity"
        ) == "HIGH"

    )


    medium_anomalies = sum(

        1

        for anomaly in anomaly_records

        if anomaly.get(
            "severity"
        ) == "MEDIUM"

    )


    return render_template(

        "anomalies.html",

        anomalies=anomaly_records,

        filename=filename,

        total_anomalies=total_anomalies,

        high_anomalies=high_anomalies,

        medium_anomalies=medium_anomalies

    )


# =========================================================
# ANALYTICS PAGE
# =========================================================

@app.route("/analytics")
def analytics():

    if not session.get(
        "admin_logged_in"
    ):

        return redirect(
            url_for("login")
        )


    # -----------------------------------------------------
    # GET SAVED DATA
    # -----------------------------------------------------

    records = session.get(
        "records",
        []
    )

    anomalies = session.get(
        "anomalies",
        []
    )


    filename = session.get(

        "uploaded_filename",

        "No file uploaded"

    )


    # =====================================================
    # BASIC STATISTICS
    # =====================================================

    total_logs = len(
        records
    )


    successful_logins = 0

    failed_logins = 0


    event_counts = Counter()

    ip_counts = Counter()


    # =====================================================
    # ANALYZE RECORDS
    # =====================================================

    for record in records:

        event = str(

            record.get(
                "event",
                ""
            )

        ).strip().lower()


        status = str(

            record.get(
                "status",
                ""
            )

        ).strip().lower()


        ip = str(

            record.get(
                "ip_address",
                ""
            )

        ).strip()


        # -------------------------------------------------
        # EVENT COUNT
        # -------------------------------------------------

        if event:

            event_counts[event] += 1


        # -------------------------------------------------
        # IP COUNT
        # -------------------------------------------------

        if ip:

            ip_counts[ip] += 1


        # -------------------------------------------------
        # LOGIN STATISTICS
        # -------------------------------------------------

        if event == "login":

            if status == "success":

                successful_logins += 1


            elif status == "failed":

                failed_logins += 1


    # =====================================================
    # LOGIN TOTAL
    # =====================================================

    total_login_attempts = (

        successful_logins
        + failed_logins

    )


    # =====================================================
    # LOGIN SUCCESS RATE
    # =====================================================

    if total_login_attempts > 0:

        login_success_rate = round(

            (
                successful_logins
                / total_login_attempts
            ) * 100,

            1

        )

    else:

        login_success_rate = 0


    # =====================================================
    # ANOMALY SEVERITY
    # =====================================================

    high_anomalies = sum(

        1

        for anomaly in anomalies

        if anomaly.get(
            "severity"
        ) == "HIGH"

    )


    medium_anomalies = sum(

        1

        for anomaly in anomalies

        if anomaly.get(
            "severity"
        ) == "MEDIUM"

    )


    # =====================================================
    # TOP IP ADDRESSES
    # =====================================================

    top_ips = ip_counts.most_common(
        5
    )


    # =====================================================
    # EVENT DATA
    # =====================================================

    event_data = event_counts.most_common()


    # =====================================================
    # RENDER ANALYTICS
    # =====================================================

    return render_template(

        "analytics.html",

        filename=filename,

        total_logs=total_logs,

        total_events=total_logs,

        successful_logins=successful_logins,

        failed_logins=failed_logins,

        total_login_attempts=
            total_login_attempts,

        login_success_rate=
            login_success_rate,

        unique_ips=len(
            ip_counts
        ),

        total_anomalies=len(
            anomalies
        ),

        high_anomalies=
            high_anomalies,

        medium_anomalies=
            medium_anomalies,

        top_ips=top_ips,

        event_data=event_data

    )


# =========================================================
# CLEAR CURRENT ANALYSIS
# =========================================================

@app.route("/clear-data")
def clear_data():

    if not session.get(
        "admin_logged_in"
    ):

        return redirect(
            url_for("login")
        )


    # Remove current analysis

    session.pop(
        "records",
        None
    )

    session.pop(
        "anomalies",
        None
    )

    session.pop(
        "uploaded_filename",
        None
    )


    return redirect(
        url_for("logs")
    )


# =========================================================
# REPORTS PAGE
# =========================================================

@app.route("/reports")
def reports():

    if not session.get("admin_logged_in"):
        return redirect(url_for("login"))

    records = session.get("records", [])
    anomalies = session.get("anomalies", [])

    filename = session.get(
        "uploaded_filename",
        "No file uploaded"
    )

    # -----------------------------------------------------
    # REPORT STATISTICS
    # -----------------------------------------------------

    total_logs = len(records)

    total_anomalies = len(anomalies)

    high_anomalies = sum(
        1
        for anomaly in anomalies
        if anomaly.get("severity") == "HIGH"
    )

    medium_anomalies = sum(
        1
        for anomaly in anomalies
        if anomaly.get("severity") == "MEDIUM"
    )

    # -----------------------------------------------------
    # LOGIN STATISTICS
    # -----------------------------------------------------

    successful_logins = 0
    failed_logins = 0

    for record in records:

        event = str(
            record.get("event", "")
        ).strip().lower()

        status = str(
            record.get("status", "")
        ).strip().lower()

        if event == "login":

            if status == "success":
                successful_logins += 1

            elif status == "failed":
                failed_logins += 1

    # -----------------------------------------------------
    # UNIQUE IP ADDRESSES
    # -----------------------------------------------------

    ip_addresses = set()

    for record in records:

        ip = str(
            record.get("ip_address", "")
        ).strip()

        if ip:
            ip_addresses.add(ip)

    unique_ips = len(ip_addresses)

    # -----------------------------------------------------
    # RENDER REPORT
    # -----------------------------------------------------

    return render_template(
        "reports.html",

        filename=filename,

        total_logs=total_logs,

        total_anomalies=total_anomalies,

        high_anomalies=high_anomalies,

        medium_anomalies=medium_anomalies,

        successful_logins=successful_logins,

        failed_logins=failed_logins,

        unique_ips=unique_ips,

        records=records,

        anomalies=anomalies
    )


    # =========================================================
# SETTINGS PAGE
# =========================================================

@app.route("/settings")
def settings():

    if not session.get("admin_logged_in"):

        return redirect(
            url_for("login")
        )

    return render_template(
        "settings.html"
    )

    

# =========================================================
# LOGOUT
# =========================================================

@app.route("/logout")
def logout():

    session.clear()

    return redirect(
        url_for("login")
    )


# =========================================================
# START APPLICATION
# =========================================================

if __name__ == "__main__":

    app.run(
        debug=True
    )