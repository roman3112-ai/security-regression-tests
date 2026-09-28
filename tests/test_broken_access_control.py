"""A01:2021 - Broken Access Control (IDOR на /notes/{id})."""

from __future__ import annotations

# Заметка с id 1 принадлежит alice (см. сид-данные в app/db.py). bob не должен
# иметь возможность её прочитать.


def test_insecure_allows_idor(insecure_client):
    resp = insecure_client.get("/notes/1", headers={"X-User": "bob"})
    assert resp.status_code == 200
    assert resp.json()["owner"] == "alice"


def test_secure_blocks_cross_user_access(secure_client):
    resp = secure_client.get("/notes/1", headers={"X-User": "bob"})
    assert resp.status_code == 403


def test_secure_allows_owner_access(secure_client):
    resp = secure_client.get("/notes/1", headers={"X-User": "alice"})
    assert resp.status_code == 200
    assert resp.json()["owner"] == "alice"


def test_missing_note_returns_404(secure_client):
    resp = secure_client.get("/notes/999", headers={"X-User": "alice"})
    assert resp.status_code == 404
