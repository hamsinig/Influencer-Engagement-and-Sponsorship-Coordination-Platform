import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
import pdfkit
from io import BytesIO
from jinja2 import Template

SMTP_SERVER_HOST = "localhost"
SMTP_SERVER_PORT = 1025
SENDER_ADDRESS = "showcase.com"
SENDER_PASSWORD = ''

def send_email(to_address, subject, message, attachment=None):
    msg = MIMEMultipart()
    msg["From"] = SENDER_ADDRESS
    msg['To'] = to_address
    msg['Subject'] = subject

    msg.attach(MIMEText(message, 'html'))
    
    if attachment:
        part = MIMEBase('application', 'pdf')
        part.set_payload(attachment)
        encoders.encode_base64(part)
        part.add_header('Content-Disposition', f'attachment; filename="Monthly_report.pdf"')
        msg.attach(part)

    with smtplib.SMTP(host=SMTP_SERVER_HOST, port=SMTP_SERVER_PORT) as s:
        s.login(SENDER_ADDRESS, SENDER_PASSWORD)
        s.send_message(msg)

    return "sent email successfully"

def generate_pdf(html_content):
    # Generate PDF from HTML content
    pdf = pdfkit.from_string(html_content, False)
    return pdf
