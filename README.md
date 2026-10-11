# checkup-scanner

An outside-in security checkup for small business domains. Give it a domain and it gives back a red, yellow, or green grade for four areas, plus a plain fix list.

```
$ checkup example-dental.com

example-dental.com
  🔴 Email spoofing: red
  🟡 Website security: yellow
  🟢 Software and exposure: green
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

**AI and chatbots**
- Chat widgets on the homepage (Intercom, Drift, Tidio, Zendesk, HubSpot, Crisp, tawk.to, Botpress, Voiceflow, Chatbase, and more). This only detects them; it does not talk to them.
- Whether robots.txt blocks AI crawlers (GPTBot, ClaudeBot, Google-Extended, and others)

## Install

Python 3.9+, no dependencies.

```
git clone https://github.com/Weschera/checkup-scanner
cd checkup-scanner
pip install -e .
checkup example.com
```

Or without installing: `python -m checkup example.com`.

## Options

```
checkup DOMAIN [-o FOLDER] [--format md,html,json] [--authorized NAME] [--dns cloudflare|google] [-q]
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
- Chat widgets are found from script tags in the homepage HTML. Widgets loaded later by a tag manager or other script, or only on other pages, are not detected.
- A green grade means these checks passed, not that the business is secure.

## Tests

```
pip install -e ".[dev]"
pytest
```

The tests stub DNS and HTTP, so they run offline.

## License

MIT
