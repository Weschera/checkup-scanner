# checkup-scanner

An outside-in security checkup for small business domains. Give it a domain and it gives back a red, yellow, or green grade for five areas, plus a plain fix list.

**Try it in your browser, free:** [wesche.com/ai/#checkup](https://wesche.com/ai/#checkup)

```
$ checkup example-dental.com

example-dental.com
  🔴 Email spoofing: red
  🟡 Website security: yellow
  🟢 Software and exposure: green
  🟢 Data breaches: green
  🟡 AI and chatbots: yellow
  → reports/example-dental.com-20261011-1923.md
  → reports/example-dental.com-20261011-1923.html
  → reports/example-dental.com-20261011-1923.json
```

It's built for checkups of businesses with no security team: dental offices, law firms, shops, studios. The report is written for the owner, not for a security engineer.

## What it checks

**Email spoofing**: can someone send mail that looks like it came from you? This is how fake invoices and "wire this today" emails work.
- SPF record: present, a single record, and not `+all`
- DMARC policy: `reject`, `quarantine`, or monitor-only, and whether reports are collected
- DKIM keys at common provider selectors
- Mail servers

**Website security**
- HTTPS works, the certificate is valid, and how long until it expires
- HTTP redirects to HTTPS
- HSTS, Content-Security-Policy, framing protection, `nosniff`

**Software and exposure**
- Server headers that reveal version numbers
- WordPress version compared with the latest release
- jQuery older than 3.5.0
- Hostnames in public certificate logs (crt.sh, with CertSpotter as a fallback), flagging admin, test, and remote-access names
- With `--authorized` only: exposed `.git`, `.env`, config backups, `phpinfo`, `server-status`

**Data breaches** (from [Have I Been Pwned](https://haveibeenpwned.com))
- Whether the website itself has had a known breach (free, no key)
- With `HIBP_API_KEY` set and the domain verified in that HIBP account: which staff email addresses appear in breaches

**AI and chatbots**
- Chat widgets (Intercom, Drift, Tidio, Zendesk, HubSpot, Crisp, tawk.to, Botpress, Voiceflow, Chatbase, and more). With `--browser`, pages are loaded in headless Chromium so widgets added by scripts are found too, on the homepage and up to three likely pages (contact, booking, FAQ). This only detects them; it does not talk to them.
- AI API keys (OpenAI, Anthropic, Gemini, Groq, Hugging Face, Replicate) exposed in the page or its own scripts
- Whether robots.txt blocks AI crawlers (GPTBot, ClaudeBot, Google-Extended, and others)

## Install

Python 3.9+, no dependencies. `--browser` needs Playwright: `pip install -e ".[browser]" && playwright install chromium`.

```
git clone https://github.com/Weschera/checkup-scanner
cd checkup-scanner
pip install -e .
checkup example.com
```

Or without installing: `python -m checkup example.com`.

## Options

```
checkup DOMAIN [-o FOLDER] [--format md,html,json] [--authorized NAME] [--browser] [--dns cloudflare|google] [-q]
```

- `-o`: where reports go (default `./reports`)
- `--format`: any of `md`, `html`, `json` (default: all three)
- `--authorized NAME`: turns on active checks, and records who gave permission. See below.
- `--dns`: which DNS-over-HTTPS service to use (default `cloudflare`). Lookups can be cached for up to an hour after a DNS change, so use the other one to re-check a fix sooner.
- Exit code is `1` if anything is red, so it can run in a script.

## Passive by default

Without `--authorized`, the scanner reads only what anyone can see: public DNS, the homepage, robots.txt, and public certificate logs. That is the same information a browser or an email server sees.

The exposed-file checks request paths a normal visitor wouldn't, so they only run with `--authorized "<name of the person who gave written permission>"`. Get that permission in writing before you use it on a site you don't own. The name is printed on the report.

## Limits

- It's an outside-in scan. It can't see inside the network, the computers, or the accounts.
- DKIM selectors can't be listed from outside, so "not found" can be a false alarm.
- Without `--browser`, chat widgets are found only from the homepage HTML, so widgets loaded later by a script are missed. With it, only the homepage and up to three likely pages are checked.
- A green grade means these checks passed, not that the business is secure.

## Tests

```
pip install -e ".[dev]"
pytest
```

The tests stub DNS and HTTP, so they run offline.


## Use it responsibly

Only scan domains you own or have permission to check. The default checks read public information, the same things a browser or mail server sees. Active checks stay off unless you pass `--authorized "Name of the person who approved it"`, and that name goes in the report.

Built by [Raúl Wesche](https://wesche.com/ai/) · [X](https://x.com/WescheNex1q) · [LinkedIn](https://www.linkedin.com/in/raul-wesche-ab1320443) · MIT license
