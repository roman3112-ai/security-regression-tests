"""A02:2021 - Cryptographic Failures (хранение паролей)."""

from __future__ import annotations

from app.db import build_db, hash_password


def test_hash_differs_from_plaintext():
    db = build_db()
    row = db.execute(
        "SELECT password, pw_hash FROM users WHERE username = 'alice'"
    ).fetchone()
    assert row["pw_hash"] != row["password"]
    assert len(row["pw_hash"]) == 64  # длина hex-дайджеста sha256


def test_hash_is_deterministic_and_discriminating():
    assert hash_password("s3cret-alice") == hash_password("s3cret-alice")
    assert hash_password("wrong") != hash_password("s3cret-alice")
