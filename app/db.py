"""In-memory демо-база, общая для insecure- и secure-приложений.

Схема намеренно хранит два столбца с credentials:

* ``password`` — открытый текст, нужен только чтобы показать *insecure*-логин
  и продемонстрировать в тесте, что само хранение plaintext — это находка.
* ``pw_hash``  — PBKDF2-SHA256 хэш, используется *secure*-логином.

Это не production-код. Он существует только чтобы у регрессионных тестов была
детерминированная одноразовая цель для прогона.
"""

from __future__ import annotations

import hashlib
import sqlite3

# Фиксированная соль делает демо детерминированным. В реальных системах
# используется уникальная случайная соль на пользователя (например, через
# argon2/bcrypt). Не копировать это в продакшн.
_DEMO_SALT = b"demo-salt-not-for-production"

_SEED_USERS = [
    ("alice", "s3cret-alice"),
    ("bob", "s3cret-bob"),
]

_SEED_NOTES = [
    ("alice", "alice private note"),
    ("bob", "bob private note"),
]


def hash_password(password: str) -> str:
    """Вернуть hex-дайджест PBKDF2-SHA256 от ``password``."""
    return hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), _DEMO_SALT, 100_000
    ).hex()


def build_db() -> sqlite3.Connection:
    """Создать и заполнить свежую in-memory SQLite базу."""
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.executescript(
        """
        CREATE TABLE users (
            id       INTEGER PRIMARY KEY,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            pw_hash  TEXT NOT NULL
        );
        CREATE TABLE notes (
            id    INTEGER PRIMARY KEY,
            owner TEXT NOT NULL,
            body  TEXT NOT NULL
        );
        """
    )
    for username, password in _SEED_USERS:
        conn.execute(
            "INSERT INTO users (username, password, pw_hash) VALUES (?, ?, ?)",
            (username, password, hash_password(password)),
        )
    for owner, body in _SEED_NOTES:
        conn.execute(
            "INSERT INTO notes (owner, body) VALUES (?, ?)",
            (owner, body),
        )
    conn.commit()
    return conn
