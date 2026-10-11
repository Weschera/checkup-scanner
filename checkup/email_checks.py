"""Email spoofing protection: SPF, DMARC, DKIM, MX."""
from __future__ import annotations

import re

from .model import EMAIL, Finding
from .net import DNSError, dns_query, dns_txt

# Selectors used by the common mail providers. DKIM keys can't be listed,
# so a miss here is "not found", never "missing".
DKIM_SELECTORS = [
    "google", "selector1", "selector2", "k1", "k2", "s1", "s2", "default",
    "dkim", "mail", "smtp", "mxvault", "zoho", "protonmail", "fm1", "mandrill",
]

FIX_SPF = ("Publish one SPF TXT record listing the services that send your mail, "
           "ending in -all or ~all. Your email provider documents the exact value.")
FIX_DMARC = ("Publish a DMARC record at _dmarc.<domain>. Start with p=none and a rua= "
             "address to collect reports, then move to p=quarantine or p=reject.")


def check_email(domain: str) -> list[Finding]:
    out: list[Finding] = []
    try:
        mx = dns_query(domain, "MX")
    except (DNSError, OSError) as err:
        return [Finding(EMAIL, "info", "DNS lookup failed", str(err))]
    try:
        txt = dns_txt(domain)
    except (DNSError, OSError):
        txt = []
    spf = [t for t in txt if t.lower().startswith("v=spf1")]
    out.extend(_spf(spf, bool(mx)))
    out.extend(_dmarc(domain, sends_mail=bool(mx)))
    if mx:
        out.append(_dkim(domain))
        hosts = ", ".join(sorted({m.split()[-1].rstrip('.') for m in mx}))
        out.append(Finding(EMAIL, "info", "Mail servers", hosts))
    else:
        out.append(Finding(EMAIL, "info", "No mail servers (MX) for this domain",
                           "Domains that send no mail should still publish SPF "
                           "'v=spf1 -all' and DMARC 'p=reject' so nobody can send as them."))
    return out


def _spf(records: list[str], has_mx: bool) -> list[Finding]:
    if not records:
        return [Finding(EMAIL, "fail", "No SPF record",
                        "Nothing tells receiving servers which senders are allowed "
                        "to send mail as this domain.", FIX_SPF)]
    if len(records) > 1:
        return [Finding(EMAIL, "fail", "More than one SPF record",
                        "Receivers treat multiple SPF records as an error, so none apply.",
                        "Merge them into a single record.")]
    rec = records[0]
    terms = rec.lower().split()
    if "+all" in terms or "all" in terms:
        return [Finding(EMAIL, "fail", "SPF allows anyone to send",
                        f"Record ends in +all: {rec}", FIX_SPF)]
    if "?all" in terms:
        return [Finding(EMAIL, "warn", "SPF is neutral (?all)", rec, FIX_SPF)]
    if not any(t.endswith("all") for t in terms) and "redirect=" not in rec.lower():
        return [Finding(EMAIL, "warn", "SPF has no 'all' rule", rec, FIX_SPF)]
    lookups = len(re.findall(r"\b(include:|a\b|a:|mx\b|mx:|ptr|exists:|redirect=)", rec.lower()))
    out = [Finding(EMAIL, "pass", "SPF record present", rec)]
    if lookups > 10:
        out.append(Finding(EMAIL, "warn", "SPF may exceed the 10-lookup limit",
                           f"{lookups} lookup terms at the top level.",
                           "Flatten or remove unused includes."))
    return out


def _dmarc(domain: str, sends_mail: bool = True) -> list[Finding]:
    try:
        recs = [t for t in dns_txt(f"_dmarc.{domain}") if t.lower().startswith("v=dmarc1")]
    except (DNSError, OSError) as err:
        return [Finding(EMAIL, "info", "DMARC lookup failed", str(err))]
    if not recs:
        return [Finding(EMAIL, "fail", "No DMARC record",
                        "Receivers get no instruction to reject mail that fakes this "
                        "domain, and you get no reports when someone tries.", FIX_DMARC)]
    rec = recs[0]
    tags = dict(
        (k.strip().lower(), v.strip())
        for k, _, v in (p.partition("=") for p in rec.split(";")) if k.strip()
    )
    policy = tags.get("p", "").lower()
    pct = tags.get("pct", "100")
    if policy == "reject" and pct == "100":
        out = [Finding(EMAIL, "pass", "DMARC set to reject", rec)]
    elif policy in ("reject", "quarantine"):
        out = [Finding(EMAIL, "pass" if pct == "100" else "warn",
                       f"DMARC set to {policy}" + ("" if pct == "100" else f" for {pct}% of mail"),
                       rec)]
    else:
        out = [Finding(EMAIL, "warn", "DMARC is monitor-only (p=none)",
                       "Fake mail is reported but still delivered. " + rec,
                       "Once reports show your real senders pass, move to p=quarantine, then p=reject.")]
    if "rua" not in tags:
        out.append(Finding(EMAIL, "warn" if sends_mail or policy != "reject" else "info",
                           "DMARC sends no reports",
                           "Without rua= you can't see who is sending as your domain.",
                           "Add rua=mailto:<an inbox or a free DMARC report service>."))
    return out


def _dkim(domain: str) -> Finding:
    found = []
    for sel in DKIM_SELECTORS:
        name = f"{sel}._domainkey.{domain}"
        try:
            if any("p=" in t for t in dns_txt(name)) or dns_query(name, "CNAME"):
                found.append(sel)
        except (DNSError, OSError):
            continue
    if found:
        return Finding(EMAIL, "pass", "DKIM key found", "Selectors: " + ", ".join(found))
    return Finding(EMAIL, "info", "No DKIM key at common selectors",
                   "DKIM selectors can't be listed from outside, so this may be a "
                   "false alarm. Check a sent email's headers for 'dkim=pass'.",
                   "Turn on DKIM signing in your email provider's admin console.")
