"""A03:2021 - Reflected Cross-Site Scripting на /search."""

from __future__ import annotations

# Канонический безобидный XSS-пробник, используемый в документации OWASP.
PAYLOAD = "<script>alert(1)</script>"


def test_insecure_reflects_raw_markup(insecure_client):
    resp = insecure_client.get("/search", params={"q": PAYLOAD})
    # Сырой тег <script> проникает в тело ответа как есть.
    assert PAYLOAD in resp.text


def test_secure_escapes_markup(secure_client):
    resp = secure_client.get("/search", params={"q": PAYLOAD})
    assert PAYLOAD not in resp.text
    # Угловые скобки закодированы как HTML-сущности, браузер рендерит их
    # как текст, а не как разметку.
    assert "&lt;script&gt;" in resp.text
