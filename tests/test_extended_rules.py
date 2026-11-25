"""
Tests for the SSRF, JNDI and XXE rules, run through the real app and its WAF
middleware (rule loading, decoding, matching and the 403 decision).

These check request-string signatures. They do not prove SSRF is prevented:
the code that makes an outbound request still has to validate the destination
itself (resolve DNS, check the resolved IP, use an allowlist).
"""
import time
import urllib.parse as up

import pytest
from fastapi.testclient import TestClient

from api.waf.rules import SecurityRules

URL = "/api/secure/test"

BLOCKED_URLS = [
    "http://127.0.0.1/admin",
    "http://localhost:8080/admin",
    "HTTP://LOCALHOST/",
    "http://localhost./",
    "http://app.localhost/",
    "http://169.254.169.254/latest/meta-data/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://10.1.2.3/",
    "http://172.16.0.5/",
    "http://192.168.1.10/router",
    "http://100.64.0.1/",
    "http://user@127.0.0.1/",
    "http://[::1]/",
    "http://[::]/",
    "http://[::ffff:127.0.0.1]/",
    "http://[::ffff:7f00:1]/",
    "http://[fd00::1]/",
    "http://[fe80::1]/",
    "http://2130706433/",
    "http://0x7f000001/",
    "http://0177.0.0.1/",
    "http://127.1/",
    "http://0/",
    "http://0.0.0.0/",
    "file:///etc/hosts",
    "gopher://127.0.0.1:6379/_INFO",
]

PUBLIC_URLS = [
    "https://example.com/page",
    "https://8.8.8.8/",
    "http://172.32.0.1/",
    "http://11.0.0.1/",
    "http://10.0.0.1.example.com/",
    "http://127.example.com/",
    "http://localhostess.example.com/",
    "http://100.128.0.1/",
    "http://[2001:4860:4860::8888]/",
    "https://example.com/10.0.0.1",
]


@pytest.mark.parametrize("url", BLOCKED_URLS)
def test_internal_destination_is_blocked_through_middleware(client: TestClient, url):
    assert client.get(URL, params={"payload": url}).status_code == 403


@pytest.mark.parametrize("url", PUBLIC_URLS)
def test_public_destination_passes(client: TestClient, url):
    assert client.get(URL, params={"payload": url}).status_code != 403


def test_private_address_mentioned_in_plain_text_passes(client: TestClient):
    for text in ("my router is at 192.168.1.1", "localhost is the loopback name"):
        assert client.get(URL, params={"payload": text}).status_code != 403


@pytest.mark.parametrize("value", ["http://127.0.0.1/", "file:///etc/passwd", "${jndi:ldap://x/a}"])
def test_repeated_url_encoding_is_decoded(client: TestClient, value):
    once = up.quote(value, safe="")
    for payload in (once, up.quote(once, safe=""), up.quote(up.quote(once, safe=""), safe="")):
        assert client.get(URL + "?payload=" + payload).status_code == 403


def test_json_escaped_body_is_decoded(client: TestClient):
    for body in ('{"url":"http:\\/\\/127.0.0.1\\/"}', '{"url":"http\\u003a//127.0.0.1/"}'):
        response = client.post(URL, content=body, headers={"content-type": "application/json"})
        assert response.status_code == 403


def test_malformed_percent_encoding_does_not_crash(client: TestClient):
    assert client.get(URL + "?payload=%zz%80http://127.0.0.1/").status_code == 403
    assert client.get(URL + "?payload=%").status_code != 500


def test_jndi_blocked_in_header_query_and_body(client: TestClient):
    assert client.get(URL, headers={"X-Api-Version": "${jndi:ldap://e/a}"}).status_code == 403
    assert client.get(URL, params={"payload": "${${lower:j}ndi:ldap://e/a}"}).status_code == 403
    assert client.post(URL, content="x=${jndi:rmi://e/a}").status_code == 403


def test_templating_text_is_not_jndi(client: TestClient):
    assert client.get(URL, params={"payload": "price is ${amount} today"}).status_code != 403


def test_xxe_payload_is_blocked_through_the_middleware(client: TestClient):
    evil = '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>'
    assert client.post(URL, content=evil, headers={"content-type": "application/xml"}).status_code == 403


def test_plain_xml_is_not_flagged_by_the_xxe_rules():
    # Rule level only. Through the middleware, plain XML bodies are still
    # blocked by the existing CMDI-008 rule ("</" counts as input redirection),
    # which is a separate upstream false positive left unchanged here.
    plain = '<?xml version="1.0"?><note><to>A</to></note>'
    flagged = {r.id for r, _ in SecurityRules().check_content(plain)}
    assert not {i for i in flagged if i.startswith("XXE")}


def test_known_limit_dns_names_that_resolve_internally_are_not_seen(client: TestClient):
    assert client.get(URL, params={"payload": "http://localtest.me/"}).status_code != 403


def test_rules_are_registered():
    ids = {r.id for r in SecurityRules().get_all_rules()}
    assert {"SSRF-001", "SSRF-005", "JNDI-001", "XXE-001", "XXE-002"} <= ids


@pytest.mark.parametrize("payload", ["${" * 100_000, "${a:" * 50_000, "http://" * 50_000, "%25" * 300_000])
def test_ssrf_and_jndi_rules_are_bounded_on_hostile_input(payload):
    rules = SecurityRules()
    selected = [r for r in rules.get_all_rules() if r.id.split("-")[0] in {"SSRF", "JNDI", "XXE"}]
    started = time.perf_counter()
    for rule in selected:
        rule.pattern.search(payload)
    assert time.perf_counter() - started < 1.5
