"""Software versions and public exposure."""
from __future__ import annotations

import re
import urllib.error

from .model import SOFTWARE, Finding
from .net import Response, fetch, fetch_json

WP_API = "https://api.wordpress.org/core/version-check/1.7/"

# Paths that should never be public. Only requested with --authorized,
# because asking for them is active probing.
SENSITIVE_PATHS = {
    "/.git/HEAD": lambda r: r.body.lstrip().startswith("ref:"),
    "/.env": lambda r: bool(re.search(r"^[A-Z0-9_]{3,}=", r.body, re.M)) and "<html" not in r.body.lower(),
    "/wp-config.php.bak": lambda r: "DB_PASSWORD" in r.body,
    "/phpinfo.php": lambda r: "PHP Version" in r.body and "phpinfo" in r.body.lower(),
    "/server-status": lambda r: "Apache Server Status" in r.body,
}


def check_software(domain: str, page: Response | None, *, authorized: bool) -> list[Finding]:
    out: list[Finding] = []
    if page is not None:
        out.extend(_server_banner(page))
        out.extend(_generator(page))
        out.extend(_jquery(page))
    out.extend(_subdomains(domain))
    if authorized and page is not None:
        base = "/".join(page.url.split("/")[:3])
        out.extend(_sensitive_paths(base))
    elif not authorized:
        out.append(Finding(SOFTWARE, "info", "Exposed-file probes skipped",
                           "Run with --authorized \"<name>\" once the owner has given "
                           "written permission to test for exposed files."))
    return out


def _server_banner(page: Response) -> list[Finding]:
    out = []
    for h in ("server", "x-powered-by", "x-aspnet-version"):
        v = page.header(h)
        if v and re.search(r"\d+\.\d+", v):
            out.append(Finding(SOFTWARE, "warn", f"{h} header reveals a version", v,
                               "Hide version numbers in server headers so attackers "
                               "can't match them to known bugs."))
    return out


def _generator(page: Response) -> list[Finding]:
    m = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', page.body, re.I) \
        or re.search(r'<meta[^>]+content=["\']([^"\']+)["\'][^>]+name=["\']generator', page.body, re.I)
    is_wp = "/wp-content/" in page.body or "/wp-includes/" in page.body
    if not m and not is_wp:
        return []
    gen = m.group(1) if m else "WordPress"
    out = [Finding(SOFTWARE, "info", "Site platform", gen)]
    wm = re.search(r"WordPress\s+(\d+(?:\.\d+)+)", gen)
    if wm:
        out.append(_wp_version(wm.group(1)))
    elif is_wp:
        out.append(Finding(SOFTWARE, "info", "WordPress site, version hidden",
                           "Keep core, themes and plugins on automatic updates."))
    return out


def _wp_version(ver: str) -> Finding:
    try:
        latest = fetch_json(WP_API)["offers"][0]["current"]
    except Exception as err:  # noqa: BLE001
        return Finding(SOFTWARE, "info", f"WordPress {ver}", f"Couldn't fetch latest: {err}")

    def key(v):
        return tuple(int(x) for x in v.split("."))

    if key(ver) >= key(latest):
        return Finding(SOFTWARE, "pass", f"WordPress {ver} is current")
    same_branch = key(ver)[:2] == key(latest)[:2]
    return Finding(SOFTWARE, "warn" if same_branch else "fail",
                   f"WordPress {ver} is out of date (latest {latest})",
                   "Old versions have published security bugs.",
                   "Update WordPress and turn on automatic updates.")


def _jquery(page: Response) -> list[Finding]:
    m = re.search(r"jquery[.-](\d+)\.(\d+)\.(\d+)(?:\.min)?\.js", page.body, re.I) \
        or re.search(r"jquery(?:\.min)?\.js\?ver=(\d+)\.(\d+)\.(\d+)", page.body, re.I)
    if not m:
        return []
    ver = tuple(int(x) for x in m.groups())
    if ver < (3, 5, 0):
        return [Finding(SOFTWARE, "warn", f"Old jQuery {'.'.join(map(str, ver))}",
                        "Versions before 3.5.0 have known cross-site scripting bugs.",
                        "Update jQuery, or the theme or plugin that bundles it.")]
    return []


def _cert_log_names(domain: str) -> set[str]:
    """Hostnames from public certificate logs: crt.sh, then CertSpotter."""
    errors = []
    try:
        rows = fetch_json(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=30)
        return {n for r in rows for n in str(r.get("name_value", "")).splitlines()}
    except Exception as err:  # noqa: BLE001  crt.sh is often slow or down
        errors.append(f"crt.sh: {err}")
    try:
        rows = fetch_json("https://api.certspotter.com/v1/issuances?domain="
                          f"{domain}&include_subdomains=true&expand=dns_names", timeout=30)
        return {n for r in rows for n in r.get("dns_names", [])}
    except Exception as err:  # noqa: BLE001
        errors.append(f"certspotter: {err}")
    raise RuntimeError("; ".join(errors))


def _subdomains(domain: str, limit: int = 40) -> list[Finding]:
    """Public certificate logs list every hostname that got a certificate."""
    try:
        raw = _cert_log_names(domain)
    except RuntimeError as err:
        return [Finding(SOFTWARE, "info", "Certificate log lookup unavailable", str(err)[:200])]
    names = set()
    for n in raw:
        n = n.strip().lower().lstrip("*.")
        if n.endswith("." + domain):
            names.add(n)
    if not names:
        return [Finding(SOFTWARE, "info", "No other hostnames in certificate logs")]
    risky = sorted(n for n in names if re.search(
        r"(^|[.-])(dev|test|staging|stage|old|beta|admin|vpn|remote|portal|backup|db|ftp|mail|webmail|cpanel|jenkins|git)([.-]|$)", n))
    shown = sorted(names)[:limit]
    out = [Finding(SOFTWARE, "info", f"{len(names)} hostnames in public certificate logs",
                   ", ".join(shown) + (" …" if len(names) > limit else ""))]
    if risky:
        out.append(Finding(SOFTWARE, "warn", "Admin, test or remote-access hostnames are public",
                           ", ".join(risky[:20]),
                           "Check each one still needs to be online, is patched, "
                           "and sits behind a login with two-step verification."))
    return out


def _sensitive_paths(base: str) -> list[Finding]:
    out = []
    for path, looks_real in SENSITIVE_PATHS.items():
        try:
            r = fetch(base + path, follow=False, timeout=10, max_bytes=200_000)
        except (urllib.error.URLError, OSError):
            continue
        if r.status == 200 and looks_real(r):
            out.append(Finding(SOFTWARE, "fail", f"Exposed file: {path}",
                               f"{base}{path} is publicly readable.",
                               "Remove it from the web root or block it in the server config, "
                               "then rotate any passwords or keys it contained."))
    if not out:
        out.append(Finding(SOFTWARE, "pass", "No common sensitive files exposed",
                           ", ".join(SENSITIVE_PATHS)))
    return out
