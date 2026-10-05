# Web Security Headers Scanner

![tests](https://github.com/prajwal-sharma-cyber/web-security-headers-scanner/actions/workflows/tests.yml/badge.svg) ![python](https://img.shields.io/badge/python-3.10%2B-blue) ![license](https://img.shields.io/badge/license-MIT-green)

A Python command-line tool that grades a website's **HTTP security headers, cookies and TLS certificate** from A+ to F - the same checks a penetration tester or AppSec engineer makes in the first minutes of a web assessment, and that sites like securityheaders.com and Mozilla Observatory automate.

It sends one ordinary GET request per site (exactly what a browser does), so it is passive and safe.

## What it checks

| Check | Why it matters | Points |
|---|---|---|
| HTTPS redirect | visitors typing `http://` must end up on HTTPS | 15 |
| Strict-Transport-Security | forces HTTPS for future visits (stops SSL-stripping) | 20 |
| Content-Security-Policy | main defence against cross-site scripting; `unsafe-inline` and `*` weaken it | 25 |
| X-Content-Type-Options | stops browsers guessing file types | 5 |
| X-Frame-Options / frame-ancestors | stops clickjacking | 10 |
| Referrer-Policy | stops full URLs (with tokens) leaking to other sites | 5 |
| Permissions-Policy | restricts camera, microphone, location | 5 |
| Cookies | every cookie needs `Secure`, `HttpOnly`, `SameSite` | up to 15 |
| Version disclosure | `Server: Apache/2.4.49` tells attackers which exploit to use | 5 |
| TLS certificate | expiring certificate or TLS 1.0/1.1 | 15 each |

Score starts at 100; failed checks subtract points. 95+ A+, 85+ A, 70+ B, 55+ C, 40+ D, below F.

## Quick start

```bash
git clone https://github.com/prajwal-sharma-cyber/web-security-headers-scanner.git
cd web-security-headers-scanner
pip install -r requirements.txt

python src/header_scanner.py https://your-own-site.example
python src/header_scanner.py --file data/sites.txt --json reports/scan.json
python -m pytest -q          # tests use fake responses - no internet needed
```

## Sample output

```text
========================================================================
https://demo-shop.example  ->  https://demo-shop.example/  [200]
  GRADE D   score 45/100
  TLS: TLSv1.3, issuer Let's Encrypt, expires 2026-12-02 (58 days)
  PASS  HTTPS redirect               http:// redirects to https://
  PASS  Strict-Transport-Security    max-age 31536000s, includeSubDomains
  FAIL  Content-Security-Policy      Missing - no protection against injected scripts (XSS)
  PASS  X-Content-Type-Options       nosniff
  FAIL  Clickjacking protection      No X-Frame-Options or frame-ancestors - page can be framed
  FAIL  Referrer-Policy              Missing - full URLs may leak to other sites
  FAIL  Permissions-Policy           Missing - camera/microphone/geolocation not restricted
  FAIL  Cookies                      PHPSESSID missing httponly/samesite
  FAIL  Version disclosure           Server: Apache/2.4.49 (Unix) - helps attackers pick exploits
```

*(Illustrative output for a fictional site.)*

## A good write-up to add to this repo

Scan your own GitHub Pages site or a small site you build, fix the headers one by one, and document the before/after grade in `docs/case-study.md`. Showing that you can **fix** what you find is worth more to an employer than the scan itself.

## Ethics

Only scan sites you own or have permission to test. This tool makes normal requests, but automated scanning of many third-party sites can breach their terms of service.

## Project structure

```text
web-security-headers-scanner/
├── data/sites.txt          list of URLs (yours)
├── src/header_scanner.py
└── tests/test_scanner.py   offline tests with fake responses
```

## Ideas to extend it

- Check `security.txt` at `/.well-known/security.txt`
- Detect mixed content (HTTP resources on HTTPS pages)
- Produce an HTML report with fix-it snippets for nginx and Apache
- Run it in GitHub Actions on a schedule against your own site
