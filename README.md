# AI-WAF — Working Implementation

A real, runnable implementation of the system described in Chapters 5–7
of the report: a two-layer ML classifier, a WAF engine, a MySQL-style
database (running on SQLite so it needs zero setup), and the Flask
dashboard (landing, register/login, overview, live traffic, alerts,
reports, and a traffic simulator).

## What's actually implemented

| Report section | Code |
|---|---|
| 6.1 Environment/tools | Python, Flask, Scikit-learn, Pandas/NumPy, SQL — all installed and used |
| 6.2 Dataset prep | `data/generate_dataset.py` |
| 6.3 Two-layer model | `ml/train_model.py` → `ml/layer1_pipeline.joblib`, `ml/layer2_pipeline.joblib` |
| 6.4 WAF engine | `waf_engine.py` |
| 6.5 Database | `database.py` (SQLite) / `schema_mysql.sql` (MySQL DDL, same schema) |
| 6.6 Dashboard | `app.py` + `templates/` |
| 6.7 Integration | `app.py` wires DB + models + WAF engine + dashboard together |
| FR5 Email verification | `mailer.py` + `/verify/<token>` route in `app.py` |

## Email verification (FR5)

Registering now creates the account **unverified**. A verification link
(24h expiry token) is generated and sent via `mailer.py`. Login is
blocked until the account is verified, with a "resend verification
email" option on both the login page and the "check your email" page.

**No SMTP configured (default):** the link is printed to the server
console and shown directly on the "check your email" page, clearly
labeled "Dev mode — no SMTP configured", so you can test the full
signup → verify → login flow immediately without setting anything up.

**Real email sending:** set these environment variables before running
`app.py` (Gmail example — use an [App Password](https://myaccount.google.com/apppasswords),
not your normal password):

```bash
export SMTP_HOST=smtp.gmail.com
export SMTP_PORT=587
export SMTP_USER=you@gmail.com
export SMTP_PASSWORD=your-16-char-app-password
export SMTP_FROM="AI-WAF <you@gmail.com>"
export APP_BASE_URL=http://127.0.0.1:5000   # or your real domain when deployed
python app.py
```

Once these are set, `mailer.py` sends a real email via `smtplib` instead
of printing to the console — no code changes needed.


## One honest limitation, up front

This sandbox has **no internet access**, so it could not download the
real CSIC 2010 / CICIDS2017 datasets or install `mysql`/`bcrypt`. Two
substitutions were made, both drop-in replaceable:

1. **Dataset** — `data/generate_dataset.py` generates a synthetic
   dataset that follows the exact feature schema Section 6.2 describes
   (URL length, special chars, SQL/script keywords, flow rate,
   failed-login rate, packet size, etc.). The pipeline that trains on
   it, serves it, and scores it live is genuinely working code — swap
   in the real CSVs and re-run `train_model.py` and everything else is
   unchanged. Because the synthetic classes are cleanly separated, the
   reported accuracy is unrealistically high (~100%); expect the real
   datasets to land you in the 90–97% range typically reported in the
   related work you reviewed in Chapter 2 — which is the number worth
   quoting in your defense, not this one.
2. **Password hashing** — bcrypt isn't installable offline, so
   `database.py` uses PBKDF2-HMAC-SHA256 (260k iterations, per-user
   salt) from Python's standard library, a NIST-approved equivalent.
   Swap two lines in `database.py` for `import bcrypt` if you want
   bcrypt specifically once you have internet access.
3. **Database** — SQLite instead of MySQL, so the whole thing runs
   with `python app.py` and no server to install/configure.
   `schema_mysql.sql` has the exact same schema in MySQL DDL for when
   you deploy for real.

## Run it

```bash
cd ai_waf
pip install -r requirements.txt
python ml/train_model.py      # trains and saves both model layers (~10s)
python app.py                 # starts the dashboard on http://127.0.0.1:5000
```

Then: **Sign up** a company → **sign in** → open **Simulate Traffic**
and click each attack card. You'll see it get classified, blocked/
flagged, logged, and alerted on live, exactly like the pipeline in
Section 6.4.

## How the "interception" works without a second app to protect

There's no second live web app in this environment to sit in front of,
so `/simulate` plays that role: it builds a request shaped like real
traffic (or a real attack pattern) and sends it through the exact same
`waf_engine.py` code path a live reverse-proxy deployment would use.
To actually protect a Flask/Django app, wrap its request handler (or a
`before_request` hook) with `waf_engine.get_engine().inspect(request_dict)`
the same way `app.py`'s `/api/simulate` route does.

## File map

```
ai_waf/
├── app.py                  # Flask app: routes, auth, simulate endpoint
├── database.py              # SQLite schema + queries (companies/admins/logs/alerts)
├── waf_engine.py             # feature extraction + 2-layer inference + decision
├── schema_mysql.sql          # production MySQL DDL (same schema)
├── requirements.txt
├── data/
│   └── generate_dataset.py   # synthetic CSIC2010/CICIDS2017-style dataset
├── ml/
│   └── train_model.py        # trains Layer 1 (RandomForest) + Layer 2 (SVM)
├── templates/                # landing, register, login, dashboard, logs, alerts, reports, simulate
└── static/css/style.css
```
