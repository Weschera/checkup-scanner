"""Offline tests: DNS and HTTP are stubbed."""
import pytest

from checkup import ai_checks, email_checks, software_checks
from checkup.cli import normalize
from checkup.model import EMAIL, Finding, area_grade
from checkup.net import Response, join_txt
from checkup.report import to_html, to_json, to_markdown


def dns_stub(monkeypatch, records):
    def query(name, rtype):
        return records.get((name, rtype), [])

    monkeypatch.setattr(email_checks, "dns_query", query)
    monkeypatch.setattr(email_checks, "dns_txt", lambda n: query(n, "TXT"))


def titles(findings):
    return {f.title: f.status for f in findings}


def test_join_txt_concatenates_segments():
    assert join_txt('"v=spf1 include:_spf.google.com" " ~all"') == "v=spf1 include:_spf.google.com ~all"


@pytest.mark.parametrize("raw,expected", [
    ("https://www.Example.com/path", "example.com"),
    ("example.co.uk", "example.co.uk"),
])
def test_normalize(raw, expected):
    assert normalize(raw) == expected


def test_normalize_rejects_junk():
    with pytest.raises(SystemExit):
        normalize("not a domain")


def test_good_email_setup_passes(monkeypatch):
    dns_stub(monkeypatch, {
        ("shop.com", "MX"): ["1 smtp.google.com."],
        ("shop.com", "TXT"): ["v=spf1 include:_spf.google.com -all"],
        ("_dmarc.shop.com", "TXT"): ["v=DMARC1; p=reject; rua=mailto:d@shop.com"],
        ("google._domainkey.shop.com", "TXT"): ["v=DKIM1; k=rsa; p=MIIB"],
    })
    t = titles(email_checks.check_email("shop.com"))
    assert t["SPF record present"] == "pass"
    assert t["DMARC set to reject"] == "pass"
    assert t["DKIM key found"] == "pass"
    assert area_grade(email_checks.check_email("shop.com"), EMAIL) == "green"


def test_missing_spf_and_dmarc_fail(monkeypatch):
    dns_stub(monkeypatch, {("shop.com", "MX"): ["10 mx.shop.com."]})
    t = titles(email_checks.check_email("shop.com"))
    assert t["No SPF record"] == "fail"
    assert t["No DMARC record"] == "fail"
    assert t["No DKIM key at common selectors"] == "info"


def test_spf_plus_all_fails(monkeypatch):
    dns_stub(monkeypatch, {("shop.com", "TXT"): ["v=spf1 +all"]})
    assert titles(email_checks.check_email("shop.com"))["SPF allows anyone to send"] == "fail"


def test_two_spf_records_fail(monkeypatch):
    dns_stub(monkeypatch, {("shop.com", "TXT"): ["v=spf1 -all", "v=spf1 ~all"]})
    assert titles(email_checks.check_email("shop.com"))["More than one SPF record"] == "fail"


def test_dmarc_none_warns_and_needs_reports(monkeypatch):
    dns_stub(monkeypatch, {
        ("shop.com", "TXT"): ["v=spf1 -all"],
        ("_dmarc.shop.com", "TXT"): ["v=DMARC1; p=none"],
    })
    t = titles(email_checks.check_email("shop.com"))
    assert t["DMARC is monitor-only (p=none)"] == "warn"
    assert t["DMARC sends no reports"] == "warn"


def test_detects_chat_widget(monkeypatch):
    monkeypatch.setattr(ai_checks, "_robots", lambda base: [])
    page = Response("https://shop.com/", 200, {}, '<script src="https://code.tidio.co/abc.js"></script>')
    t = titles(ai_checks.check_ai(page))
    assert t["Chat widget on the website: Tidio"] == "warn"


def test_no_widget_is_info(monkeypatch):
    monkeypatch.setattr(ai_checks, "_robots", lambda base: [])
    page = Response("https://shop.com/", 200, {}, "<html>hello</html>")
    assert titles(ai_checks.check_ai(page))["No known chat widget found"] == "info"


def test_exposed_ai_key_fails(monkeypatch):
    monkeypatch.setattr(ai_checks, "_robots", lambda base: [])
    key = "sk-proj-" + "A1b2C3d4E5" * 5
    page = Response("https://shop.com/", 200, {}, f'<script>const k="{key}"</script>')
    t = titles(ai_checks.check_ai(page))
    assert t["AI API key exposed in the website's code"] == "fail"


def test_key_check_fetches_only_same_site_scripts(monkeypatch):
    monkeypatch.setattr(ai_checks, "_robots", lambda base: [])
    fetched = []
    monkeypatch.setattr(ai_checks, "fetch", lambda url, **kw: fetched.append(url) or Response(url, 200, {}, ""))
    page = Response("https://shop.com/", 200, {},
                    '<script src="/app.js"></script><script src="https://cdn.other.com/x.js"></script>')
    assert titles(ai_checks.check_ai(page))["No AI API keys in the website's code"] == "pass"
    assert fetched == ["https://shop.com/app.js"]


def test_browser_widgets_found_from_requests(monkeypatch):
    from checkup import browser as br
    monkeypatch.setattr(ai_checks, "_robots", lambda base: [])
    monkeypatch.setattr(br, "available", lambda: True)
    monkeypatch.setattr(br, "render_pages", lambda url: {
        "pages": [url], "requests": ["https://widget.intercom.io/widget/abc"],
        "globals": ["Tawk_API"], "html": "", "errors": []})
    page = Response("https://shop.com/", 200, {}, "<html>gtm only</html>")
    t = titles(ai_checks.check_ai(page, browser=True))
    assert t["Chat widget on the website: Intercom, tawk.to"] == "warn"


def test_breaches_without_key(monkeypatch):
    from checkup import breach_checks
    monkeypatch.setattr(breach_checks, "_get", lambda path, key=None: (200, [
        {"Title": "Shop", "BreachDate": "2020-01-01", "PwnCount": 1234}]))
    t = titles(breach_checks.check_breaches("shop.com", api_key=None))
    assert t["This website has had a data breach"] == "fail"
    assert t["Staff email breach check not run"] == "info"


def test_breached_staff_emails_with_key(monkeypatch):
    from checkup import breach_checks
    def get(path, key=None):
        if path.startswith("/breaches"):
            return 200, []
        return 200, {"owner": ["Adobe", "Canva"], "info": ["LinkedIn"]}
    monkeypatch.setattr(breach_checks, "_get", get)
    t = titles(breach_checks.check_breaches("shop.com", api_key="k"))
    assert t["No known breach of this website itself"] == "pass"
    assert t["2 staff email addresses found in data breaches"] == "fail"


def test_old_jquery_and_version_banner():
    page = Response("https://shop.com/", 200, {"server": "Apache/2.4.29 (Ubuntu)"},
                    '<script src="/js/jquery-1.12.4.min.js"></script>')
    t = titles(software_checks._jquery(page) + software_checks._server_banner(page))
    assert t["Old jQuery 1.12.4"] == "warn"
    assert t["server header reveals a version"] == "warn"


def test_active_probes_need_authorization(monkeypatch):
    called = []
    monkeypatch.setattr(software_checks, "_subdomains", lambda d: [])
    monkeypatch.setattr(software_checks, "_sensitive_paths", lambda b: called.append(b) or [])
    page = Response("https://shop.com/", 200, {}, "")
    t = titles(software_checks.check_software("shop.com", page, authorized=False))
    assert called == []
    assert "Exposed-file probes skipped" in t
    software_checks.check_software("shop.com", page, authorized=True)
    assert called == ["https://shop.com"]


def test_exposed_git_detected(monkeypatch):
    def fake_fetch(url, **kw):
        if url.endswith("/.git/HEAD"):
            return Response(url, 200, {}, "ref: refs/heads/main\n")
        return Response(url, 404, {}, "<html>not found</html>")

    monkeypatch.setattr(software_checks, "fetch", fake_fetch)
    t = titles(software_checks._sensitive_paths("https://shop.com"))
    assert t == {"Exposed file: /.git/HEAD": "fail"}


def test_soft_404_is_not_an_exposed_env(monkeypatch):
    monkeypatch.setattr(software_checks, "fetch",
                        lambda url, **kw: Response(url, 200, {}, "<html><body>Page not found</body></html>"))
    t = titles(software_checks._sensitive_paths("https://shop.com"))
    assert t == {"No common sensitive files exposed": "pass"}


def test_reports_render():
    meta = {"domain": "shop.com", "scanned_at": "2026-10-11 00:00 UTC", "version": "0.1.0",
            "authorized_by": None}
    findings = [Finding(EMAIL, "fail", "No SPF record", "<x>", "Add one.")]
    assert "🔴 **Email spoofing**" in to_markdown(meta, findings)
    html = to_html(meta, findings)
    assert "&lt;x&gt;" in html and "<x>" not in html
    assert '"Email spoofing": "red"' in to_json(meta, findings)


def test_no_mail_domain_locked_down_is_green(monkeypatch):
    dns_stub(monkeypatch, {
        ("shop.com", "TXT"): ["v=spf1 -all"],
        ("_dmarc.shop.com", "TXT"): ["v=DMARC1; p=reject;"],
    })
    findings = email_checks.check_email("shop.com")
    assert titles(findings)["DMARC sends no reports"] == "info"
    assert area_grade(findings, EMAIL) == "green"


def test_sending_domain_without_reports_warns(monkeypatch):
    dns_stub(monkeypatch, {
        ("shop.com", "MX"): ["1 smtp.google.com."],
        ("shop.com", "TXT"): ["v=spf1 include:_spf.google.com -all"],
        ("_dmarc.shop.com", "TXT"): ["v=DMARC1; p=reject;"],
    })
    assert titles(email_checks.check_email("shop.com"))["DMARC sends no reports"] == "warn"
