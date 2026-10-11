"""Website transport and header checks."""
from __future__ import annotations

import socket
import ssl
import urllib.error
from datetime import datetime, timezone

from .model import WEB, Finding
from .net import CTX, Response, fetch


def cert_days_left(host: str, timeout: float = 10) -> tuple[int, str]:
    with socket.create_connection((host, 443), timeout=timeout) as sock:
        with CTX.wrap_socket(sock, server_hostname=host) as tls:
            cert = tls.getpeercert()
    expires = datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notAfter"]), timezone.utc)
    issuer = dict(x[0] for x in cert.get("issuer", ())).get("organizationName", "")
    return (expires - datetime.now(timezone.utc)).days, issuer


def check_web(domain: str) -> tuple[list[Finding], Response | None]:
    """Returns findings plus the homepage response for the other checks."""
    out: list[Finding] = []
    page = None
    for host in (domain, f"www.{domain}"):
        try:
            page = fetch(f"https://{host}/")
            break
        except (urllib.error.URLError, OSError, ssl.SSLError) as err:
            last = err
    if page is None:
        out.append(Finding(WEB, "fail", "Website not reachable over HTTPS", str(last),
                           "Serve the site over HTTPS with a valid certificate."))
        return out, None
    host = page.url.split("/")[2].split(":")[0]
    out.append(Finding(WEB, "info", "Homepage", f"{page.url} (HTTP {page.status})"))

    try:
        days, issuer = cert_days_left(host)
        if days < 0:
            out.append(Finding(WEB, "fail", "TLS certificate expired", issuer))
        elif days < 14:
            out.append(Finding(WEB, "warn", f"TLS certificate expires in {days} days",
                               issuer, "Renew it, or check that auto-renewal works."))
        else:
            out.append(Finding(WEB, "pass", "Valid TLS certificate",
                               f"{issuer}, {days} days left"))
    except (OSError, ssl.SSLError) as err:
        out.append(Finding(WEB, "fail", "TLS certificate problem", str(err)))

    try:
        plain = fetch(f"http://{domain}/", follow=False, timeout=10)
        loc = plain.header("location")
        if plain.status in (301, 302, 307, 308) and loc.startswith("https://"):
            out.append(Finding(WEB, "pass", "HTTP redirects to HTTPS"))
        else:
            out.append(Finding(WEB, "warn", "HTTP does not redirect to HTTPS",
                               f"http://{domain}/ answered {plain.status}",
                               "Redirect all plain-HTTP requests to HTTPS."))
    except (urllib.error.URLError, OSError):
        pass  # port 80 closed is fine

    out.extend(_headers(page))
    return out, page


def _headers(page: Response) -> list[Finding]:
    out = []
    hsts = page.header("strict-transport-security")
    if hsts:
        out.append(Finding(WEB, "pass", "HSTS enabled", hsts))
    else:
        gh_pages = page.header("server").lower() == "github.com"
        out.append(Finding(WEB, "warn", "No HSTS header",
                           "Browsers may still try plain HTTP first."
                           + (" GitHub Pages can't set this header." if gh_pages else ""),
                           "Put the site behind a CDN such as Cloudflare and enable HSTS there."
                           if gh_pages else
                           "Add Strict-Transport-Security: max-age=31536000."))
    csp = page.header("content-security-policy")
    xfo = page.header("x-frame-options")
    if csp:
        out.append(Finding(WEB, "pass", "Content-Security-Policy set"))
    else:
        out.append(Finding(WEB, "info", "No Content-Security-Policy",
                           "A CSP limits what an injected script can do. Worth adding "
                           "if the site has logins, forms, or a chat widget.",
                           "Have your web developer add a Content-Security-Policy."))
    if not xfo and "frame-ancestors" not in csp.lower():
        out.append(Finding(WEB, "info", "Page can be framed by other sites",
                           "No X-Frame-Options or frame-ancestors (clickjacking).",
                           "Add X-Frame-Options: SAMEORIGIN."))
    if page.header("x-content-type-options").lower() != "nosniff":
        out.append(Finding(WEB, "info", "No X-Content-Type-Options: nosniff"))
    return out
