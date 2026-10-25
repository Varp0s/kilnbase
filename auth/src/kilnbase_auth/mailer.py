import smtplib
import ssl
import sys
from email.message import EmailMessage
from urllib.parse import unquote, urlsplit

LOCAL_HOSTS = {"localhost", "127.0.0.1", "mailpit", "mailhog"}


class Mailer:
    """Sends mail over SMTP; without KILNBASE_SMTP_URL it prints messages for local development.

    smtps:// uses implicit TLS; smtp:// requires STARTTLS except for local test servers.
    """

    def __init__(self, smtp_url: str | None, sender: str):
        self.sender = sender
        self.url = urlsplit(smtp_url) if smtp_url else None
        if self.url and self.url.scheme not in ("smtp", "smtps"):
            raise ValueError("KILNBASE_SMTP_URL must start with smtp:// or smtps://")

    def send(self, to: str, subject: str, body: str) -> None:
        msg = EmailMessage()
        msg["From"], msg["To"], msg["Subject"] = self.sender, to, subject
        msg.set_content(body)
        if self.url is None:
            # shortcut: dev-only fallback; codes land in logs, so production needs SMTP.
            print(f"kilnbase-auth: [no SMTP configured] mail to {to}\n{body}", file=sys.stderr)
            return
        host, user, password = self.url.hostname or "", self.url.username, self.url.password
        context = ssl.create_default_context()
        if self.url.scheme == "smtps":
            server = smtplib.SMTP_SSL(host, self.url.port or 465, context=context, timeout=10)
        else:
            server = smtplib.SMTP(host, self.url.port or 587, timeout=10)
        with server:
            if self.url.scheme == "smtp" and host not in LOCAL_HOSTS:
                server.starttls(context=context)
            if user:
                server.login(unquote(user), unquote(password or ""))
            server.send_message(msg)
