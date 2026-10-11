"""Command line entry point: checkup example.com"""
from __future__ import annotations

import argparse
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .ai_checks import check_ai
from .breach_checks import check_breaches
from .email_checks import check_email
from .model import AREAS, Finding, area_grade
from .net import set_resolver
from .report import DOT, to_html, to_json, to_markdown
from .software_checks import check_software
from .web_checks import check_web


def normalize(target: str) -> str:
    d = target.strip().lower()
    d = re.sub(r"^[a-z]+://", "", d).split("/")[0].split(":")[0]
    if d.startswith("www."):
        d = d[4:]
    if not re.fullmatch(r"(?:[a-z0-9-]+\.)+[a-z]{2,}", d):
        raise SystemExit(f"Not a domain name: {target!r}")
    return d


def scan(domain: str, *, authorized_by: str | None = None, browser: bool = False,
         log=print) -> tuple[dict, list[Finding]]:
    findings: list[Finding] = []
    log("· email (SPF, DMARC, DKIM)")
    findings += check_email(domain)
    log("· website (HTTPS, certificate, headers)")
    web, page = check_web(domain)
    findings += web
    log("· software and exposure" + (" (active probes on)" if authorized_by else ""))
    findings += check_software(domain, page, authorized=bool(authorized_by))
    log("· data breaches")
    findings += check_breaches(domain)
    log("· AI and chatbots" + (" (browser)" if browser else ""))
    findings += check_ai(page, browser=browser)
    meta = {
        "domain": domain,
        "scanned_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "version": __version__,
        "authorized_by": authorized_by,
    }
    return meta, findings


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="checkup",
        description="Outside-in security checkup for a small business domain.")
    ap.add_argument("domain", help="example.com or https://example.com")
    ap.add_argument("-o", "--out", default="reports",
                    help="folder for the report files (default: ./reports)")
    ap.add_argument("--authorized", metavar="NAME",
                    help="name of the person who gave written permission for active checks "
                         "(exposed-file probes). Without it, only public information is read.")
    ap.add_argument("--format", default="md,html,json",
                    help="comma list of md, html, json (default: all)")
    ap.add_argument("--browser", action="store_true",
                    help="load pages in headless Chromium to find chat widgets added by "
                         "scripts (needs: pip install 'checkup-scanner[browser]' and "
                         "playwright install chromium)")
    ap.add_argument("--dns", choices=["cloudflare", "google"], default="cloudflare",
                    help="DNS-over-HTTPS service. Answers can be cached for up to an "
                         "hour after a DNS change; switch services to re-check sooner.")
    ap.add_argument("-q", "--quiet", action="store_true")
    args = ap.parse_args(argv)

    set_resolver(args.dns)
    domain = normalize(args.domain)
    log = (lambda *_: None) if args.quiet else (lambda m: print(m, file=sys.stderr))
    log(f"Scanning {domain}")
    meta, findings = scan(domain, authorized_by=args.authorized, browser=args.browser, log=log)

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    stem = f"{domain}-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M')}"
    writers = {"md": to_markdown, "html": to_html, "json": to_json}
    written = []
    for fmt in [f.strip() for f in args.format.split(",") if f.strip()]:
        if fmt not in writers:
            raise SystemExit(f"Unknown format {fmt!r}")
        p = out / f"{stem}.{fmt}"
        p.write_text(writers[fmt](meta, findings), encoding="utf-8")
        written.append(str(p))

    print(f"\n{domain}")
    for area in AREAS:
        g = area_grade(findings, area)
        print(f"  {DOT[g]} {area}: {g}")
    for p in written:
        print(f"  → {p}")
    return 1 if any(f.status == "fail" for f in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
