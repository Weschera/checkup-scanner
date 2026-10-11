"""Data breaches: Have I Been Pwned.

Two levels:
- Free, no key: breaches of the business's own website (the site itself leaked its users).
- With HIBP_API_KEY: every breached email address at the domain. HIBP only answers
  this for domains verified in the key owner's HIBP dashboard, so it's for your
  own domain or a client who has verified theirs with you.
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request

from .model import BREACH, Finding
from .net import CTX, USER_AGENT

API = "https://haveibeenpwned.com/api/v3"


def _get(path: str, key: str | None = None):
    headers = {"User-Agent": USER_AGENT}
    if key:
        headers["hibp-api-key"] = key
    req = urllib.request.Request(API + path, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=20, context=CTX) as resp:
            return resp.status, json.load(resp)
    except urllib.error.HTTPError as err:
        return err.code, None


def check_breaches(domain: str, *, api_key: str | None = None) -> list[Finding]:
    out: list[Finding] = []
    api_key = api_key or os.environ.get("HIBP_API_KEY")
    try:
        status, site = _get(f"/breaches?domain={domain}")
    except (urllib.error.URLError, OSError) as err:
        return [Finding(BREACH, "info", "Breach lookup unavailable", str(err)[:120])]
    if status == 200 and site:
        names = ", ".join(f"{b['Title']} ({b['BreachDate'][:4]}, {b['PwnCount']:,} accounts)" for b in site)
        out.append(Finding(BREACH, "fail", "This website has had a data breach", names,
                           "Make sure every affected user was told and passwords were reset, "
                           "and that the hole that caused it is closed."))
    elif status == 200:
        out.append(Finding(BREACH, "pass", "No known breach of this website itself"))

    if not api_key:
        out.append(Finding(BREACH, "info", "Staff email breach check not run",
                           "Checking which @" + domain + " addresses appear in breaches needs a "
                           "Have I Been Pwned key and a verified domain. The owner can check "
                           "for free at haveibeenpwned.com/DomainSearch."))
        return out
    status, emails = _get(f"/breacheddomain/{domain}", api_key)
    if status == 200 and emails:
        n = len(emails)
        top = sorted(emails.items(), key=lambda kv: -len(kv[1]))[:10]
        detail = "; ".join(f"{alias}@{domain}: {', '.join(b)}" for alias, b in top)
        out.append(Finding(BREACH, "fail" if n else "pass",
                           f"{n} staff email address{'es' if n != 1 else ''} found in data breaches",
                           detail,
                           "Change the password on those accounts and anywhere it was reused, "
                           "turn on two-step login, and use a password manager."))
    elif status == 200 or status == 404:
        out.append(Finding(BREACH, "pass", "No staff email addresses found in data breaches"))
    elif status in (401, 403):
        out.append(Finding(BREACH, "info", "Staff email breach check not allowed",
                           "The domain isn't verified for this Have I Been Pwned key."))
    else:
        out.append(Finding(BREACH, "info", "Staff email breach check failed", f"HTTP {status}"))
    return out
