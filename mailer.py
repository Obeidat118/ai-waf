"""
mailer.py
----------
Sends the 6-digit OTP verification code required for account activation using Brevo API.
"""
import requests

# Brevo API Configuration
BREVO_API_KEY = "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"
BREVO_URL = "https://api.brevo.com/v3/smtp/email"
SENDER_EMAIL = "yazanobeidat76@gmail.com"
SENDER_NAME = "AI-WAF"

DEV_MODE = False

def send_verification_email(to_email: str, otp_code: str) -> dict:
    """Returns {'dev_mode': bool, 'otp': str, 'sent': bool, 'error': str|None}
    so the calling route can handle the 6-digit OTP display/simulation via Brevo API."""

    if DEV_MODE:
        print(f"\n[AI-WAF][DEV MODE] No API configured — OTP verification code for "
              f"{to_email}:\n  👉 {otp_code} 👈\n")
        return {"dev_mode": True, "otp": otp_code, "sent": False, "error": None}

    subject = "Your AI-WAF Verification Code"
    html_content = (
        f"<h3>Welcome to AI-WAF.</h3>"
        f"<p>Your verification code is: <b>{otp_code}</b></p>"
        f"<p>This code expires in 10 minutes. If you didn't request this, ignore this email.</p>"
    )

    headers = {
        "accept": "application/json",
        "api-key": BREVO_API_KEY,
        "content-type": "application/json"
    }

    payload = {
        "sender": {
            "name": SENDER_NAME,
            "email": SENDER_EMAIL
        },
        "to": [
            {
                "email": to_email
            }
        ],
        "subject": subject,
        "htmlContent": html_content
    }

    try:
        response = requests.post(BREVO_URL, json=payload, headers=headers)
        if response.status_code in [200, 201]:
            print(f"[AI-WAF] OTP email successfully sent to {to_email} via Brevo API.")
            return {"dev_mode": False, "otp": otp_code, "sent": True, "error": None}
        else:
            error_msg = f"API Error {response.status_code}: {response.text}"
            print(f"[AI-WAF] Failed to send OTP email to {to_email}: {error_msg}")
            return {"dev_mode": False, "otp": otp_code, "sent": False, "error": error_msg}
            
    except Exception as exc:  # noqa: BLE001
        print(f"[AI-WAF] Exception while sending OTP email to {to_email}: {exc}")
        return {"dev_mode": False, "otp": otp_code, "sent": False, "error": str(exc)}
