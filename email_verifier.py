import imaplib
import email
import re
import os
from datetime import datetime, timedelta, timezone
import email.utils

IMAP_SERVER = "imap.gmail.com"
EMAIL_ACCOUNT = os.environ.get("NETSENTINEL_MAIL_USERNAME", "")
APP_PASSWORD = os.environ.get("NETSENTINEL_MAIL_PASSWORD", "")

def clean_html(raw_html):
    clean = re.sub('<.*?>', '', raw_html)
    clean = re.sub(r'\s+', ' ', clean)
    return clean.lower()

def verify_payment_auto(expected_amount):
    try:
        mail = imaplib.IMAP4_SSL(IMAP_SERVER)
        mail.login(EMAIL_ACCOUNT, APP_PASSWORD)
        mail.select("inbox")

        status, messages = mail.search(None, '(FROM "no-reply@famapp.in")')
        
        if status != "OK" or not messages[0]:
            return False

        email_ids = messages[0].split()

        # Check the last 10 emails
        for e_id in reversed(email_ids[-10:]):
            status, msg_data = mail.fetch(e_id, "(RFC822)")

            for response_part in msg_data:
                if isinstance(response_part, tuple):
                    msg = email.message_from_bytes(response_part[1])

                    # Safely handle timezones by converting everything to UTC
                    email_date = email.utils.parsedate_to_datetime(msg["Date"])
                    if email_date.tzinfo is None:
                        email_date = email_date.replace(tzinfo=timezone.utc)
                    
                    now_utc = datetime.now(timezone.utc)
                    
                    # If the email is older than 5 minutes, skip it
                    if now_utc - email_date > timedelta(minutes=5):
                        continue

                    # Extract the body
                    body = ""
                    if msg.is_multipart():
                        for part in msg.walk():
                            if part.get_content_type() in ["text/plain", "text/html"]:
                                body += part.get_payload(decode=True).decode(errors='ignore')
                    else:
                        body = msg.get_payload(decode=True).decode(errors='ignore')

                    body = clean_html(body)

                    # FIXED REGEX: Now safely captures decimals like 99.0 or 99.00
                    amounts = re.findall(r'(?:₹|rs\.?|inr)\s?(\d+(?:\.\d+)?)', body)

                    for amt in amounts:
                        try:
                            # Use float() to prevent crashing on decimals
                            if abs(float(amt) - float(expected_amount)) < 0.01:
                                print(f"✅ MATCH FOUND: ₹{amt}")
                                mail.logout()
                                return True
                        except ValueError:
                            continue

        mail.logout()

    except Exception as e:
        print(f"[VERIFY ERROR] {e}")

    return False