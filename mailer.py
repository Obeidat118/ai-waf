"""
mailer.py
----------
Sends the 6-digit OTP verification code required for account activation.
"""
import os
import smtplib
from email.mime.text import MIMEText

SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 587
SMTP_USER = "yazanobeidat76@gmail.com"
SMTP_PASSWORD = "cjqc vlek ehxo wfcp"
SMTP_FROM = "AI-WAF <yazanobeidat76@gmail.com>"

DEV_MODE = False

def send_verification_email(to_email: str, otp_code: str) -> dict:
    """Returns {'dev_mode': bool, 'otp': str, 'sent': bool, 'error': str|None}
    so the calling route can handle the 6-digit OTP display/simulation."""

    if DEV_MODE:
        print(f"\n[AI-WAF][DEV MODE] No SMTP configured — OTP verification code for "
              f"{to_email}:\n  👉 {otp_code} 👈\n")
        return {"dev_mode": True, "otp": otp_code, "sent": False, "error": None}

    subject = "Your AI-WAF Verification Code"
    body = (
        f"Welcome to AI-WAF.\n\n"
        f"Your verification code is: {otp_code}\n\n"
        f"This code expires in 10 minutes. If you didn't request this, ignore this email."
    )
    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = SMTP_FROM
    msg["To"] = to_email

    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASSWORD)
            server.sendmail(SMTP_FROM, [to_email], msg.as_string())
        return {"dev_mode": False, "otp": otp_code, "sent": True, "error": None}
    except Exception as exc:  # noqa: BLE001
        print(f"[AI-WAF] Failed to send OTP email to {to_email}: {exc}")
        return {"dev_mode": False, "otp": otp_code, "sent": False, "error": str(exc)}