"""
app.py
-------
Flask backend + dashboard supporting 6-digit OTP verification flow.
"""
import base64
import io
import os
import random
from datetime import datetime
from functools import wraps

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from flask import Flask, flash, g, jsonify, redirect, render_template, request, session, url_for

import database as db
from mailer import send_verification_email
from waf_engine import get_engine

# تعديل هنا ليقرأ الـ templates من المجلد الحالي (Root) مباشرة حيث توجد الملفات
app = Flask(__name__, template_folder='.')
app.secret_key = os.environ.get("AIWAF_SECRET_KEY", "dev-secret-change-me")

db.init_db()
waf = get_engine()


# ---------------------------------------------------------------- helpers
def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("admin_id"):
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


@app.before_request
def load_company():
    g.company_id = session.get("company_id")


# ---------------------------------------------------------------- landing
@app.route("/")
def landing():
    return render_template("landing.html")


# ---------------------------------------------------------------- auth (OTP Edition)
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        company_name = request.form["company_name"].strip()
        website_url = request.form["website_url"].strip()
        email = request.form["email"].strip().lower()
        password = request.form["password"]

        if not (company_name and website_url and email and password):
            flash("Please fill in all fields.", "error")
            return render_template("register.html")
        if "@" not in email or "." not in email.split("@")[-1]:
            flash("Please enter a valid email address.", "error")
            return render_template("register.html")
        if not (website_url.startswith("http://") or website_url.startswith("https://")):
            flash("Website URL must start with http:// or https://", "error")
            return render_template("register.html")
        if db.get_admin_by_email(email):
            flash("An account with that email already exists.", "error")
            return render_template("register.html")

        company_id, otp_code = db.create_company_and_admin(company_name, website_url, email, password)
        mail_result = send_verification_email(email, otp_code)
        session["pending_email"] = email
        return render_template("check_email.html", email=email, mail_result=mail_result)

    return render_template("register.html")


@app.route("/verify-otp", methods=["POST"])
def verify_otp():
    email = request.form.get("email", "").strip().lower()
    otp_code = request.form.get("otp_code", "").strip()
    
    admin = db.get_admin_by_email(email)
    if not admin:
        flash("No account found for that email.", "error")
        return redirect(url_for("login"))
    
    if admin["is_verified"]:
        flash("Account is already verified. Please sign in.", "success")
        return redirect(url_for("login"))

    if not admin["otp_code"] or admin["otp_code"] != otp_code:
        flash("Invalid verification code. Please try again.", "error")
        return render_template("check_email.html", email=email)

    if admin["otp_expires"] and admin["otp_expires"] < datetime.utcnow().isoformat():
        flash("That verification code has expired. Please request a new one.", "error")
        return render_template("check_email.html", email=email, expired=True)

    db.mark_admin_verified(admin["id"])
    flash("Email verified successfully! You can now sign in.", "success")
    return redirect(url_for("login"))


@app.route("/resend-verification", methods=["POST"])
def resend_verification():
    email = request.form.get("email", "").strip().lower()
    admin = db.get_admin_by_email(email)
    if not admin:
        flash("No account found for that email.", "error")
        return redirect(url_for("login"))
    if admin["is_verified"]:
        flash("That account is already verified — please sign in.", "success")
        return redirect(url_for("login"))

    otp_code = db.set_new_verification_token(admin["id"])
    mail_result = send_verification_email(email, otp_code)
    return render_template("check_email.html", email=email, mail_result=mail_result)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"].strip().lower()
        password = request.form["password"]
        admin = db.get_admin_by_email(email)
        if admin and db.verify_password(password, admin["password_hash"], admin["password_salt"]):
            if not admin["is_verified"]:
                flash("Please verify your email before signing in.", "error")
                return render_template("login.html", unverified_email=email)
            session["admin_id"] = admin["id"]
            session["company_id"] = admin["company_id"]
            session["email"] = admin["email"]
            return redirect(url_for("dashboard"))
        flash("Invalid email or password.", "error")
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("landing"))


# ---------------------------------------------------------------- dashboard
@app.route("/dashboard")
@login_required
def dashboard():
    stats = db.get_dashboard_stats(g.company_id)
    company = db.get_company(g.company_id)
    recent_alerts = db.get_alerts(g.company_id, limit=5)
    return render_template("dashboard.html", stats=stats, company=company, recent_alerts=recent_alerts)


@app.route("/logs")
@login_required
def logs():
    return render_template("logs.html", logs=db.get_logs(g.company_id, limit=200))


@app.route("/alerts")
@login_required
def alerts():
    return render_template("alerts.html", alerts=db.get_alerts(g.company_id, limit=200))


@app.route("/reports")
@login_required
def reports():
    data = db.get_report_data(g.company_id)
    stats = db.get_dashboard_stats(g.company_id)
    chart_b64 = _render_report_chart(stats["by_type"])
    return render_template("reports.html", data=data, stats=stats, chart_b64=chart_b64)


def _render_report_chart(by_type: dict):
    if not by_type:
        return None
    plt.rcParams.update({
        "figure.facecolor": "#10151d", "axes.facecolor": "#10151d",
        "text.color": "#d8e0eb", "axes.edgecolor": "#232b38",
        "axes.labelcolor": "#d8e0eb", "xtick.color": "#7c8aa0", "ytick.color": "#7c8aa0",
        "font.size": 10,
    })
    labels = list(by_type.keys())
    values = list(by_type.values())
    colors = ["#35e0a1" if l == "Normal" else "#ff5c6c" for l in labels]

    fig, ax = plt.subplots(figsize=(7, 3.4))
    ax.bar(labels, values, color=colors, width=0.55)
    ax.spines[["top", "right"]].set_visible(False)
    ax.set_ylabel("Requests")
    fig.tight_layout()

    buf = io.BytesIO()
    fig.savefig(buf, format="png", dpi=150)
    plt.close(fig)
    buf.seek(0)
    return base64.b64encode(buf.read()).decode("ascii")


# ---------------------------------------------------------------- WAF simulation
SAMPLE_REQUESTS = {
    "normal": lambda ip: {"method": "GET", "url": "/products?category=shoes&sort=price", "source_ip": ip},
    "sqli": lambda ip: {"method": "GET", "url": "/search?q=' OR 1=1 -- UNION SELECT * FROM users", "source_ip": ip},
    "xss": lambda ip: {"method": "POST", "url": "/comment?msg=<script>document.cookie</script>", "source_ip": ip},
    "ddos": lambda ip: {"method": "GET", "url": "/", "source_ip": ip, "packet_size": 60, "flow_duration_ms": 4},
    "bruteforce": lambda ip: {"method": "POST", "url": "/login", "source_ip": ip, "is_failed_login": True},
    "bot": lambda ip: {"method": "GET", "url": "/products", "source_ip": ip, "user_agent": "curl/7.1", "packet_size": 200, "flow_duration_ms": 20},
}
SIM_IP_PREFIX = {
    "normal": "192.168.1.", "sqli": "10.0.0.", "xss": "10.0.0.",
    "ddos": "172.16.0.", "bruteforce": "10.10.0.", "bot": "203.0.113."
}


@app.route("/simulate")
@login_required
def simulate_page():
    return render_template("simulate.html")


@app.route("/api/simulate", methods=["POST"])
@login_required
def api_simulate():
    kind = request.json.get("kind", "normal")
    builder = SAMPLE_REQUESTS.get(kind, SAMPLE_REQUESTS["normal"])
    ip = f"{SIM_IP_PREFIX.get(kind, '198.51.100.')}{random.randint(2, 254)}"

    n = {"ddos": 220, "bruteforce": 28, "bot": 30}.get(kind, 1)
    result = None
    for _ in range(n):
        req = builder(ip)
        result = waf.inspect(req)
        log_id = db.insert_log(
            g.company_id, req.get("source_ip"), req.get("method"), req.get("url"),
            result["layer1_result"], result["layer2_result"], result["status"],
        )
        if result["layer2_result"]:
            db.insert_alert(g.company_id, log_id, result["layer2_result"], result["severity"], result["message"])

    return jsonify(result)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)