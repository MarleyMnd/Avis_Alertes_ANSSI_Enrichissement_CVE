import os
import smtplib
from email.mime.text import MIMEText
from dotenv import load_dotenv

load_dotenv()  

EMAIL_USER = os.getenv("EMAIL_USER")
EMAIL_PASS = os.getenv("EMAIL_PASS")


def send_email(to_email, subject, body):
    msg = MIMEText(body)
    msg["From"] = EMAIL_USER
    msg["To"] = to_email
    msg["Subject"] = subject

    with smtplib.SMTP("smtp.gmail.com", 587) as server:
        server.starttls()
        server.login(EMAIL_USER, EMAIL_PASS)
        server.sendmail(EMAIL_USER, to_email, msg.as_string())


def alert_on_critical_cves(cve_data, target_product, recipient):
    for cve in cve_data:
        if cve["product"].lower() == target_product.lower() and cve["cvss_score"] and cve["cvss_score"] >= 9.0:
            subject = f"[ALERTE CRITIQUE] {cve['product']} - CVE: {cve['cve_id']}"
            body = (
                f"Alerte critique détectée :\n"
                f"CVE: {cve['cve_id']}\n"
                f"Produit: {cve['product']}\n"
                f"Score CVSS: {cve['cvss_score']}\n"
                f"Gravité: {cve['base_severity']}\n"
                f"Description: {cve['description']}\n"
                f"URL: {cve['link']}"
            )
            send_email(recipient, subject, body)
            print(f"[EMAIL SENT] {cve['cve_id']} → {recipient}")
