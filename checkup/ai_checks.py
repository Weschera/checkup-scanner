"""Chatbot detection and AI crawler policy."""
from __future__ import annotations

import re
import urllib.error

from .model import AI, Finding
from .net import Response, fetch

# Script hosts or globals that identify a chat widget, matched on the homepage HTML.
CHAT_WIDGETS = {
    "Intercom": [r"widget\.intercom\.io", r"js\.intercomcdn\.com", r"Intercom\("],
    "Drift": [r"js\.driftt\.com", r"drift\.load\("],
    "Tidio": [r"code\.tidio\.co"],
    "Zendesk": [r"static\.zdassets\.com", r"zE\("],
    "HubSpot chat": [r"js\.usemessages\.com", r"js\.hs-scripts\.com"],
    "Crisp": [r"client\.crisp\.chat"],
    "tawk.to": [r"embed\.tawk\.to"],
    "LiveChat": [r"cdn\.livechatinc\.com"],
    "Freshchat": [r"wchat\.freshchat\.com", r"fw-cdn\.com"],
    "Olark": [r"static\.olark\.com"],
    "Gorgias": [r"config\.gorgias\.chat"],
    "Ada": [r"static\.ada\.support"],
    "Botpress": [r"cdn\.botpress\.cloud", r"botpress\.cloud/webchat"],
    "Voiceflow": [r"cdn\.voiceflow\.com"],
    "Chatbase": [r"chatbase\.co/embed", r"www\.chatbase\.co"],
    "Landbot": [r"cdn\.landbot\.io"],
    "ManyChat": [r"widget\.manychat\.com"],
    "Podium": [r"connect\.podium\.com"],
    "Birdeye": [r"birdeye\.com/embed"],
    "Weave": [r"getweave\.com"],
    "CustomGPT": [r"customgpt\.ai"],
    "Botsonic": [r"botsonic"],
    "Kommunicate": [r"widget\.kommunicate\.io"],
    "Jotform AI agent": [r"jotfor\.ms/agent", r"jotform\.com/agent"],
}

AI_CRAWLERS = ["GPTBot", "ClaudeBot", "Google-Extended", "PerplexityBot", "CCBot", "Bytespider"]


# Public AI API keys. Prefixes are specific enough to avoid false hits.
AI_KEY_PATTERNS = {
    "OpenAI": r"\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}T3BlbkFJ[A-Za-z0-9_-]{20,}\b|\bsk-(?:proj|svcacct)-[A-Za-z0-9_-]{40,}\b",
    "Anthropic": r"\bsk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_-]{80,}\b",
    "Google AI (Gemini)": r"\bAIza[0-9A-Za-z_-]{35}\b",
    "Groq": r"\bgsk_[A-Za-z0-9]{48,}\b",
    "Hugging Face": r"\bhf_[A-Za-z]{34,}\b",
    "Replicate": r"\br8_[A-Za-z0-9]{37,}\b",
}


def widgets_in(text: str) -> list[str]:
    return [name for name, pats in CHAT_WIDGETS.items()
            if any(re.search(p, text, re.I) for p in pats)]


def check_ai(page: Response | None, *, browser: bool = False) -> list[Finding]:
    out: list[Finding] = []
    if page is None:
        return out
    found = set(widgets_in(page.body))
    scripts_text = page.body
    method = "page HTML"
    pages_seen = [page.url]
    if browser:
        try:
            from . import browser as br

            if not br.available():
                raise RuntimeError("Playwright is not installed (pip install 'checkup-scanner[browser]' "
                                   "&& playwright install chromium)")
            rendered = br.render_pages(page.url)
            found |= set(widgets_in("\n".join(rendered["requests"])))
            found |= set(widgets_in(rendered["html"]))
            found |= set(br.widget_names_from_globals(rendered["globals"]))
            scripts_text += rendered["html"]
            method = "a real browser"
            pages_seen = rendered["pages"] or pages_seen
            for err in rendered["errors"]:
                out.append(Finding(AI, "info", "Browser couldn't load a page", err))
        except Exception as err:  # noqa: BLE001
            out.append(Finding(AI, "info", "Browser check skipped", str(err)[:200]))
    pages_note = ", ".join(pages_seen)
    if found:
        out.append(Finding(AI, "warn", "Chat widget on the website: " + ", ".join(sorted(found)),
                           f"Found using {method} on: {pages_note}. If it answers with AI, it can "
                           "be tested for leaking data, being talked out of its rules, or "
                           "promising refunds or prices. This scan only detects it; it does "
                           "not talk to it.",
                           "Ask the vendor what data the bot can see and whether its AI "
                           "answers can be limited. A chatbot test checks it properly."))
    else:
        out.append(Finding(AI, "info", "No known chat widget found",
                           f"Checked with {method} on: {pages_note}."
                           + ("" if browser else " Widgets added later by a script aren't seen "
                              "without --browser.")))
    out.extend(_ai_keys(scripts_text, page))
    base = "/".join(page.url.split("/")[:3])
    out.extend(_robots(base))
    return out


def _ai_keys(text: str, page: Response) -> list[Finding]:
    """Look for AI API keys in the page and its own (same-site) scripts."""
    srcs = re.findall(r'<script[^>]+src=["\']([^"\']+)', page.body, re.I)
    base = "/".join(page.url.split("/")[:3])
    host = page.url.split("/")[2]
    blobs = [text]
    for src in srcs[:15]:
        url = src if src.startswith("http") else (base + src if src.startswith("/") else None)
        if not url or host not in url.split("/")[2]:
            continue
        try:
            blobs.append(fetch(url, timeout=10, max_bytes=2_000_000).body)
        except (urllib.error.URLError, OSError):
            continue
    hits = []
    for vendor, pat in AI_KEY_PATTERNS.items():
        for blob in blobs:
            m = re.search(pat, blob)
            if m:
                key = m.group(0)
                hits.append(f"{vendor} ({key[:8]}…{key[-4:]})")
                break
    if not hits:
        return [Finding(AI, "pass", "No AI API keys in the website's code",
                        f"Checked the page and {len(blobs) - 1} of its scripts.")]
    return [Finding(AI, "fail", "AI API key exposed in the website's code", ", ".join(hits),
                    "Anyone can copy this key and run up your AI bill or read your data. "
                    "Revoke it in the provider's dashboard now, then move AI calls to a server.")]


def _robots(base: str) -> list[Finding]:
    try:
        r = fetch(base + "/robots.txt", timeout=10, max_bytes=200_000)
    except (urllib.error.URLError, OSError):
        return []
    if r.status != 200 or "<html" in r.body[:500].lower():
        return [Finding(AI, "info", "No robots.txt",
                        "AI companies' crawlers may use the site's text for training.")]
    blocked = []
    for bot in AI_CRAWLERS:
        m = re.search(rf"user-agent:\s*{re.escape(bot)}\s*\n((?:(?!user-agent:).*\n?)*)", r.body, re.I)
        if m and re.search(r"disallow:\s*/\s*$", m.group(1), re.I | re.M):
            blocked.append(bot)
    if blocked:
        return [Finding(AI, "info", "robots.txt blocks some AI crawlers", ", ".join(blocked))]
    return [Finding(AI, "info", "robots.txt does not block AI crawlers",
                    "Fine for most businesses. Block GPTBot, ClaudeBot and others if "
                    "you don't want site content used for AI training.")]
