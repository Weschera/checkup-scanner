"""Chat widget detection in a real browser (optional: pip install checkup-scanner[browser]).

Many sites load chat widgets through a tag manager or a script that runs after
the page loads, so they never appear in the HTML. This loads the homepage and a
few likely pages in headless Chromium, waits, and records every script host the
page requested plus the widget globals it defined.
"""
from __future__ import annotations

import re
from urllib.parse import urljoin, urlparse

from .net import USER_AGENT

# Pages a widget is often limited to.
PAGE_HINTS = re.compile(r"/(contact|contact-us|support|help|book|booking|appointments?|schedule|about|faq)/?$", re.I)

# window globals set by widget loaders.
GLOBALS = {
    "Intercom": "Intercom", "drift": "Drift", "tidioChatApi": "Tidio", "zE": "Zendesk",
    "HubSpotConversations": "HubSpot chat", "$crisp": "Crisp", "Tawk_API": "tawk.to",
    "LiveChatWidget": "LiveChat", "fcWidget": "Freshchat", "olark": "Olark",
    "GorgiasChat": "Gorgias", "adaEmbed": "Ada", "botpressWebChat": "Botpress",
    "voiceflow": "Voiceflow", "chatbase": "Chatbase", "embeddedChatbotConfig": "Chatbase",
    "Landbot": "Landbot", "Kommunicate": "Kommunicate",
}


def available() -> bool:
    try:
        import playwright.sync_api  # noqa: F401
        return True
    except ImportError:
        return False


def _same_site(url: str, host: str) -> bool:
    h = urlparse(url).hostname or ""
    return h == host or h.endswith("." + host) or host.endswith("." + h)


def render_pages(start_url: str, *, max_pages: int = 4, wait_ms: int = 6000,
                 timeout_ms: int = 20000) -> dict:
    """Return {"pages": [...], "requests": [urls], "globals": [names], "html": str, "errors": [...]}."""
    from playwright.sync_api import sync_playwright

    host = urlparse(start_url).hostname or ""
    host = host[4:] if host.startswith("www.") else host
    result = {"pages": [], "requests": set(), "globals": set(), "html": "", "errors": []}
    with sync_playwright() as p:
        browser = p.chromium.launch()
        ctx = browser.new_context(user_agent=USER_AGENT.replace("compatible;", "compatible; Chrome;"),
                                  viewport={"width": 1280, "height": 900})
        page = ctx.new_page()
        page.on("request", lambda r: result["requests"].add(r.url))
        queue, seen = [start_url], set()
        while queue and len(result["pages"]) < max_pages:
            url = queue.pop(0)
            if url in seen:
                continue
            seen.add(url)
            try:
                page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)
                page.wait_for_timeout(wait_ms)
                # Some loaders wait for user activity.
                page.mouse.move(400, 400)
                page.mouse.wheel(0, 800)
                page.wait_for_timeout(1500)
            except Exception as err:  # noqa: BLE001
                result["errors"].append(f"{url}: {str(err).splitlines()[0][:120]}")
                continue
            if not _same_site(page.url, host):
                continue  # redirected to another site
            result["pages"].append(page.url)
            names = page.evaluate("names => names.filter(n => typeof window[n] !== 'undefined')",
                                  list(GLOBALS))
            result["globals"].update(names)
            html = page.content()
            result["html"] += html
            if len(result["pages"]) == 1:
                links = page.eval_on_selector_all("a[href]", "as => as.map(a => a.href)")
                for link in links:
                    clean = link.split("#")[0].split("?")[0]
                    if _same_site(clean, host) and PAGE_HINTS.search(urlparse(clean).path or ""):
                        if clean not in seen and clean not in queue:
                            queue.append(clean)
        browser.close()
    result["requests"] = sorted(result["requests"])
    result["globals"] = sorted(result["globals"])
    return result


def widget_names_from_globals(names) -> list[str]:
    return sorted({GLOBALS[n] for n in names if n in GLOBALS})
