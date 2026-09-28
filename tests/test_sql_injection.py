"""A03:2021 - Injection (SQL-инъекция через форму логина)."""

from __future__ import annotations

# Классическая тавтология. `username = '' OR '1'='1' ...` делает условие
# WHERE всегда истинным и возвращает строку без валидных credentials.
INJECTION = {"username": "alice' OR '1'='1", "password": "x' OR '1'='1"}
VALID = {"username": "alice", "password": "s3cret-alice"}


def test_insecure_login_is_vulnerable(insecure_client):
    """Фиксирует уязвимость: инъекция аутентифицирует без пароля."""
    resp = insecure_client.post("/login", json=INJECTION)
    assert resp.status_code == 200
    assert resp.json()["ok"] is True


def test_secure_login_rejects_injection(secure_client):
    """Регрессионная защита: фикс должен по-прежнему отклонять инъекцию."""
    resp = secure_client.post("/login", json=INJECTION)
    assert resp.status_code == 401


def test_secure_login_accepts_valid_credentials(secure_client):
    resp = secure_client.post("/login", json=VALID)
    assert resp.status_code == 200
    assert resp.json()["ok"] is True
