"""Markdown, HTML and JSON reports."""
from __future__ import annotations

import html
import json

from .model import AREAS, Finding, area_grade

DOT = {"red": "🔴", "yellow": "🟡", "green": "🟢", "grey": "⚪"}
MARK = {"fail": "✗", "warn": "!", "pass": "✓", "info": "·"}
COLOR = {"red": "#d64545", "yellow": "#d9a400", "green": "#2f9e5b", "grey": "#8a8f98"}

DISCLAIMER = ("This is an outside-in scan of public information. It is a starting point, "
              "not a full security assessment, a guarantee, or a certification.")


def _sorted(findings: list[Finding], area: str) -> list[Finding]:
    order = {"fail": 0, "warn": 1, "pass": 2, "info": 3}
    return sorted((f for f in findings if f.area == area), key=lambda f: order[f.status])


def to_markdown(meta: dict, findings: list[Finding]) -> str:
    lines = [f"# Security checkup: {meta['domain']}", "",
             f"Scanned {meta['scanned_at']} · checkup-scanner {meta['version']}"
             + (f" · active checks authorized by {meta['authorized_by']}" if meta.get("authorized_by") else ""),
             "", "## Summary", ""]
    for area in AREAS:
        g = area_grade(findings, area)
        lines.append(f"- {DOT[g]} **{area}**: {g}")
    fixes = [f for f in findings if f.status in ("fail", "warn") and f.fix]
    if fixes:
        lines += ["", "## Fix first", ""]
        for i, f in enumerate(sorted(fixes, key=lambda f: f.status != "fail"), 1):
            lines.append(f"{i}. **{f.title}**: {f.fix}")
    for area in AREAS:
        items = _sorted(findings, area)
        if not items:
            continue
        lines += ["", f"## {DOT[area_grade(findings, area)]} {area}", ""]
        for f in items:
            lines.append(f"- `{MARK[f.status]}` **{f.title}**" + (f": {f.detail}" if f.detail else ""))
    lines += ["", "---", "", DISCLAIMER, ""]
    return "\n".join(lines)


def to_html(meta: dict, findings: list[Finding]) -> str:
    e = html.escape
    cards = "".join(
        f'<div class="card"><span class="dot" style="background:{COLOR[g]}"></span>'
        f'<strong>{e(a)}</strong><span class="g">{g}</span></div>'
        for a in AREAS for g in [area_grade(findings, a)]
    )
    fixes = [f for f in findings if f.status in ("fail", "warn") and f.fix]
    fix_html = "".join(f"<li><strong>{e(f.title)}</strong> {e(f.fix)}</li>"
                       for f in sorted(fixes, key=lambda f: f.status != "fail"))
    sections = ""
    for a in AREAS:
        items = _sorted(findings, a)
        if not items:
            continue
        rows = "".join(
            f'<tr class="{f.status}"><td class="m">{MARK[f.status]}</td>'
            f"<td><strong>{e(f.title)}</strong><br><span>{e(f.detail)}</span></td></tr>"
            for f in items)
        sections += f"<h2>{e(a)}</h2><table>{rows}</table>"
    auth = f" · active checks authorized by {e(meta['authorized_by'])}" if meta.get("authorized_by") else ""
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Security checkup: {e(meta['domain'])}</title><style>
body{{font:15px/1.5 -apple-system,system-ui,sans-serif;max-width:860px;margin:40px auto;padding:0 20px;color:#1d2125}}
h1{{font-size:28px;margin:0}} .meta{{color:#6b7178;font-size:13px;margin:4px 0 24px}}
.cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:10px}}
.card{{border:1px solid #e3e5e8;border-radius:10px;padding:14px;display:flex;gap:10px;align-items:center}}
.card .g{{margin-left:auto;color:#6b7178;font-size:13px}} .dot{{width:14px;height:14px;border-radius:50%;flex:none}}
h2{{font-size:18px;margin:32px 0 8px}} table{{width:100%;border-collapse:collapse}}
td{{border-top:1px solid #eceef0;padding:9px 6px;vertical-align:top}} td span{{color:#5b6168;font-size:13px;word-break:break-word}}
td.m{{width:22px;font-weight:700}} tr.fail td.m{{color:#d64545}} tr.warn td.m{{color:#b38600}} tr.pass td.m{{color:#2f9e5b}} tr.info td.m{{color:#8a8f98}}
ol li{{margin:6px 0}} footer{{margin-top:40px;color:#6b7178;font-size:12px;border-top:1px solid #eceef0;padding-top:12px}}
</style></head><body>
<h1>Security checkup: {e(meta['domain'])}</h1>
<div class="meta">Scanned {e(meta['scanned_at'])} · checkup-scanner {e(meta['version'])}{auth}</div>
<div class="cards">{cards}</div>
{"<h2>Fix first</h2><ol>" + fix_html + "</ol>" if fix_html else ""}
{sections}
<footer>{e(DISCLAIMER)}</footer></body></html>"""


def to_json(meta: dict, findings: list[Finding]) -> str:
    return json.dumps({
        **meta,
        "grades": {a: area_grade(findings, a) for a in AREAS},
        "findings": [f.to_dict() for f in findings],
    }, indent=2, ensure_ascii=False)
