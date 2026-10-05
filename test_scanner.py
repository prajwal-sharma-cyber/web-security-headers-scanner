"""Tests use fake responses, so they run offline and never touch a real website."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from header_scanner import Result, evaluate  # noqa: E402

STRONG = {
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
    "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Server": "nginx",
}
GOOD_COOKIE = ["session=abc; Path=/; Secure; HttpOnly; SameSite=Lax"]


def grade(headers, cookies=None, redirect=True):
    r = Result(url="https://test.example")
    r.checks = evaluate(r.url, headers, cookies or [], redirect)
    return r


def test_strong_site_gets_a_plus():
    r = grade(STRONG, GOOD_COOKIE)
    assert r.grade == "A+" and all(c.passed for c in r.checks)


def test_bare_site_fails():
    r = grade({"Server": "Apache/2.4.49 (Unix)", "X-Powered-By": "PHP/7.2.1"},
              ["id=1; Path=/"], redirect=False)
    assert r.grade == "F"
    failed = {c.name for c in r.checks if not c.passed}
    assert {"Content-Security-Policy", "Version disclosure", "Cookies", "HTTPS redirect"} <= failed


def test_weak_csp_flagged():
    r = grade({**STRONG, "Content-Security-Policy": "default-src * 'unsafe-inline'"}, GOOD_COOKIE)
    csp = next(c for c in r.checks if c.name == "Content-Security-Policy")
    assert not csp.passed and "unsafe-inline" in csp.detail


def test_short_hsts_flagged():
    r = grade({**STRONG, "Strict-Transport-Security": "max-age=300"}, GOOD_COOKIE)
    assert not next(c for c in r.checks if c.name == "Strict-Transport-Security").passed


def test_headers_are_case_insensitive():
    lower = {k.lower(): v for k, v in STRONG.items()}
    assert grade(lower, GOOD_COOKIE).grade == "A+"
