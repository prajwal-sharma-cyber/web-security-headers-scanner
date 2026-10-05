"""
Web security headers & TLS scanner.

Makes ONE normal GET request per site (the same as opening it in a browser) and grades
how well the response protects visitors:

  HTTPS redirect         does http:// send you to https://?
  Strict-Transport-Security   max-age >= 6 months, includeSubDomains
  Content-Security-Policy     present, and not weakened by 'unsafe-inline' / 'unsafe-eval' / *
  X-Content-Type-Options      nosniff
  Clickjacking                X-Frame-Options or CSP frame-ancestors
  Referrer-Policy             set to a privacy-preserving value
  Permissions-Policy          present
  Cookies                     Secure, HttpOnly, SameSite on every Set-Cookie
  Information disclosure      Server / X-Powered-By version numbers
  TLS certificate             days until expiry, TLS version negotiated

Grade A+ to F, like securityheaders.com and Mozilla Observatory.

Usage:
    python src/header_scanner.py https://example.com
    python src/header_scanner.py --file data/sites.txt --json reports/scan.json

Only scan sites you own or are allowed to test. One request per site is normal browsing,
but scanning many third-party sites automatically may break their terms of use.
"""

from __future__ import annotations

import argparse
import json
import re
import socket
import ssl
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

import requests

TIMEOUT = 10
USER_AGENT = "header-scanner/1.0 (+https://github.com/prajwal-sharma-cyber/web-security-headers-scanner)"


@dataclass
class Check:
    name: str
    passed: bool
    points: int          # points lost when failed
    detail: str


@dataclass
class Result:
    url: str
    final_url: str = ""
    status: int = 0
    checks: list[Check] = field(default_factory=list)
    tls: dict = field(default_factory=dict)
    error: str = ""

    @property
    def score(self) -> int:
        return max(0, 100 - sum(c.points for c in self.checks if not c.passed))

    @property
    def grade(self) -> str:
        if self.error:
            return "ERR"
        s = self.score
        return "A+" if s >= 95 else "A" if s >= 85 else "B" if s >= 70 else "C" if s >= 55 else "D" if s >= 40 else "F"


def _header(headers, name: str) -> str | None:
    for key, value in headers.items():
        if key.lower() == name.lower():
            return value
    return None


def check_hsts(headers) -> Check:
    value = _header(headers, "Strict-Transport-Security")
    if not value:
        return Check("Strict-Transport-Security", False, 20, "Missing - browsers may use plain HTTP")
    age = re.search(r"max-age=(\d+)", value)
    seconds = int(age.group(1)) if age else 0
    if seconds < 15_552_000:
        return Check("Strict-Transport-Security", False, 10, f"max-age {seconds}s is under 6 months")
    sub = "includesubdomains" in value.lower()
    return Check("Strict-Transport-Security", True, 0, f"max-age {seconds}s" + (", includeSubDomains" if sub else ""))


def check_csp(headers) -> Check:
    value = _header(headers, "Content-Security-Policy")
    if not value:
        return Check("Content-Security-Policy", False, 25, "Missing - no protection against injected scripts (XSS)")
    weak = [w for w in ("'unsafe-inline'", "'unsafe-eval'") if w in value]
    if re.search(r"(default|script)-src[^;]*\s\*(\s|;|$)", value):
        weak.append("wildcard *")
    if weak:
        return Check("Content-Security-Policy", False, 10, f"Present but weakened by {', '.join(weak)}")
    return Check("Content-Security-Policy", True, 0, "Present")


def check_simple(headers, name: str, expected: str | None, points: int, why: str) -> Check:
    value = _header(headers, name)
    if value is None:
        return Check(name, False, points, f"Missing - {why}")
    if expected and expected.lower() not in value.lower():
        return Check(name, False, points, f"'{value}' should be '{expected}'")
    return Check(name, True, 0, value)


def check_clickjacking(headers) -> Check:
    xfo = _header(headers, "X-Frame-Options")
    csp = _header(headers, "Content-Security-Policy") or ""
    if (xfo and xfo.upper() in {"DENY", "SAMEORIGIN"}) or "frame-ancestors" in csp:
        return Check("Clickjacking protection", True, 0, xfo or "CSP frame-ancestors")
    return Check("Clickjacking protection", False, 10, "No X-Frame-Options or frame-ancestors - page can be framed")


def check_referrer(headers) -> Check:
    good = {"no-referrer", "same-origin", "strict-origin", "strict-origin-when-cross-origin", "no-referrer-when-downgrade"}
    value = (_header(headers, "Referrer-Policy") or "").lower()
    if not value:
        return Check("Referrer-Policy", False, 5, "Missing - full URLs may leak to other sites")
    if value.split(",")[-1].strip() not in good:
        return Check("Referrer-Policy", False, 5, f"'{value}' leaks full URLs")
    return Check("Referrer-Policy", True, 0, value)


def check_cookies(raw_cookies: list[str]) -> Check:
    if not raw_cookies:
        return Check("Cookies", True, 0, "No cookies set")
    problems = []
    for cookie in raw_cookies:
        name = cookie.split("=", 1)[0].strip()
        lower = cookie.lower()
        missing = [flag for flag in ("secure", "httponly", "samesite") if flag not in lower]
        if missing:
            problems.append(f"{name} missing {'/'.join(missing)}")
    if problems:
        return Check("Cookies", False, min(15, 5 * len(problems)), "; ".join(problems[:3]))
    return Check("Cookies", True, 0, f"{len(raw_cookies)} cookie(s) all Secure, HttpOnly, SameSite")


def check_disclosure(headers) -> Check:
    leaks = []
    for name in ("Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"):
        value = _header(headers, name)
        if value and re.search(r"\d", value):
            leaks.append(f"{name}: {value}")
    if leaks:
        return Check("Version disclosure", False, 5, "; ".join(leaks) + " - helps attackers pick exploits")
    return Check("Version disclosure", True, 0, "No version numbers in headers")


def tls_info(host: str, port: int = 443) -> dict:
    context = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
        with context.wrap_socket(sock, server_hostname=host) as tls:
            cert = tls.getpeercert()
            expires = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            issuer = dict(x[0] for x in cert["issuer"]).get("organizationName", "?")
            return {"version": tls.version(), "issuer": issuer, "expires": expires.date().isoformat(),
                    "days_left": (expires - datetime.now(timezone.utc)).days}


def evaluate(url: str, headers, raw_cookies: list[str], redirected_to_https: bool | None) -> list[Check]:
    checks = [
        check_hsts(headers),
        check_csp(headers),
        check_simple(headers, "X-Content-Type-Options", "nosniff", 5, "browsers may guess file types"),
        check_clickjacking(headers),
        check_referrer(headers),
        check_simple(headers, "Permissions-Policy", None, 5, "camera/microphone/geolocation not restricted"),
        check_cookies(raw_cookies),
        check_disclosure(headers),
    ]
    if redirected_to_https is not None:
        checks.insert(0, Check("HTTPS redirect", redirected_to_https, 15,
                               "http:// redirects to https://" if redirected_to_https else "http:// does not redirect to HTTPS"))
    return checks


def scan(url: str, session: requests.Session | None = None) -> Result:
    session = session or requests.Session()
    session.headers["User-Agent"] = USER_AGENT
    if "://" not in url:
        url = "https://" + url
    result = Result(url=url)
    try:
        response = session.get(url, timeout=TIMEOUT, allow_redirects=True)
        result.final_url, result.status = response.url, response.status_code
        raw_cookies = response.raw.headers.getlist("Set-Cookie") if hasattr(response.raw, "headers") else []

        redirected = None
        host = urlparse(response.url).hostname
        if urlparse(url).scheme == "https":
            try:
                plain = session.get(f"http://{host}", timeout=TIMEOUT, allow_redirects=True)
                redirected = urlparse(plain.url).scheme == "https"
            except requests.RequestException:
                redirected = None  # port 80 closed is fine
        result.checks = evaluate(url, response.headers, raw_cookies, redirected)

        if urlparse(response.url).scheme == "https":
            try:
                result.tls = tls_info(host)
                if result.tls["days_left"] < 14:
                    result.checks.append(Check("TLS certificate", False, 15, f"Expires in {result.tls['days_left']} days"))
                if result.tls["version"] in {"TLSv1", "TLSv1.1"}:
                    result.checks.append(Check("TLS version", False, 15, f"{result.tls['version']} is deprecated"))
            except (OSError, ssl.SSLError) as error:
                result.checks.append(Check("TLS certificate", False, 20, f"TLS problem: {error}"))
    except requests.RequestException as error:
        result.error = str(error)
    return result


def print_result(r: Result) -> None:
    print("=" * 72)
    print(f"{r.url}  ->  {r.final_url or '-'}  [{r.status or '-'}]")
    if r.error:
        print(f"  ERROR: {r.error}")
        return
    print(f"  GRADE {r.grade}   score {r.score}/100")
    if r.status >= 400:
        print(f"  Note: the server returned HTTP {r.status}; an error page may carry different headers.")
    if r.tls:
        print(f"  TLS: {r.tls['version']}, issuer {r.tls['issuer']}, expires {r.tls['expires']} ({r.tls['days_left']} days)")
    for c in r.checks:
        print(f"  {'PASS' if c.passed else 'FAIL'}  {c.name:28} {c.detail}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Grade a website's security headers and TLS.")
    parser.add_argument("urls", nargs="*")
    parser.add_argument("--file", type=Path, help="Text file with one URL per line")
    parser.add_argument("--json", type=Path, help="Write results as JSON")
    args = parser.parse_args()

    urls = list(args.urls)
    if args.file:
        urls += [l.strip() for l in args.file.read_text().splitlines() if l.strip() and not l.startswith("#")]
    if not urls:
        parser.error("give at least one URL or --file")

    results = []
    for url in urls:
        r = scan(url)
        print_result(r)
        results.append(r)

    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps([{**asdict(r), "grade": r.grade, "score": r.score} for r in results],
                                        indent=2, default=str), encoding="utf-8")
        print(f"\nJSON -> {args.json}")


if __name__ == "__main__":
    main()
