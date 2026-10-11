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


def check_ai(page: Response | None) -> list[Finding]:
    out: list[Finding] = []
    if page is None:
        return out
    found = [name for name, pats in CHAT_WIDGETS.items()
             if any(re.search(p, page.body, re.I) for p in pats)]
    if found:
        out.append(Finding(AI, "warn", "Chat widget on the website: " + ", ".join(found),
                           "If it answers with AI, it can be tested for leaking data, "
                           "being talked out of its rules, or promising refunds or prices. "
                           "This scan only detects it; it does not talk to it.",
                           "Ask the vendor what data the bot can see and whether its AI "
                           "answers can be limited. A chatbot test checks it properly."))
    else:
        out.append(Finding(AI, "info", "No known chat widget on the homepage",
                           "Widgets loaded later, or only on other pages, aren't seen."))
    base = "/".join(page.url.split("/")[:3])
    out.extend(_robots(base))
    return out


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
