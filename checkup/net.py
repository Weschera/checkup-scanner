"""HTTP and DNS helpers. Standard library only."""
from __future__ import annotations

import json
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field

USER_AGENT = (
    "Mozilla/5.0 (compatible; checkup-scanner/0.1; "
    "+https://github.com/Weschera/checkup-scanner)"
)


def ssl_context() -> ssl.SSLContext:
    """Default context, using certifi's CA bundle when it is installed."""
    try:
        import certifi  # type: ignore

        return ssl.create_default_context(cafile=certifi.where())
    except ImportError:
        return ssl.create_default_context()


CTX = ssl_context()


@dataclass
class Response:
    url: str
    status: int
    headers: dict = field(default_factory=dict)
    body: str = ""

    def header(self, name: str) -> str:
        return self.headers.get(name.lower(), "")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):  # noqa: D401
        return None


def fetch(url: str, *, follow: bool = True, timeout: float = 15,
          max_bytes: int = 3_000_000) -> Response:
    """GET a URL. HTTP error statuses come back as a Response, not an exception.

    Network failures (DNS, refused, TLS) raise urllib.error.URLError.
    """
    handlers = [urllib.request.HTTPSHandler(context=CTX)]
    if not follow:
        handlers.append(_NoRedirect())
    opener = urllib.request.build_opener(*handlers)
    req = urllib.request.Request(url, headers={
        "User-Agent": USER_AGENT,
        "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
    })
    try:
        resp = opener.open(req, timeout=timeout)
    except urllib.error.HTTPError as err:
        resp = err
    try:
        raw = resp.read(max_bytes) or b""
    except Exception:  # truncated or reset bodies still give us headers
        raw = b""
    headers = {k.lower(): v for k, v in resp.headers.items()} if resp.headers else {}
    status = getattr(resp, "status", None) or getattr(resp, "code", 0)
    return Response(url=resp.geturl() or url, status=status, headers=headers,
                    body=raw.decode("utf-8", "replace"))


def fetch_json(url: str, timeout: float = 20):
    resp = fetch(url, timeout=timeout)
    if resp.status != 200:
        raise ValueError(f"{url}: HTTP {resp.status}")
    return json.loads(resp.body)


# DNS over HTTPS, so the scanner needs no resolver library.
DOH_URL = "https://cloudflare-dns.com/dns-query"
RTYPES = {"A": 1, "CNAME": 5, "MX": 15, "TXT": 16, "AAAA": 28}


class DNSError(Exception):
    pass


def dns_query(name: str, rtype: str, timeout: float = 10) -> list[str]:
    url = DOH_URL + "?" + urllib.parse.urlencode({"name": name, "type": rtype})
    req = urllib.request.Request(url, headers={"Accept": "application/dns-json"})
    with urllib.request.urlopen(req, timeout=timeout, context=CTX) as resp:
        data = json.load(resp)
    status = data.get("Status")
    if status == 3:  # NXDOMAIN
        return []
    if status != 0:
        raise DNSError(f"{name} {rtype}: DNS status {status}")
    want = RTYPES[rtype]
    return [a["data"] for a in data.get("Answer", []) if a.get("type") == want]


def join_txt(data: str) -> str:
    """Join the quoted segments of a TXT answer (RFC 7208 3.3: no separator)."""
    parts = re.findall(r'"((?:[^"\\]|\\.)*)"', data)
    return "".join(parts) if parts else data


def dns_txt(name: str) -> list[str]:
    return [join_txt(d) for d in dns_query(name, "TXT")]
