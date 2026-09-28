"""Защищённые версии тех же эндпоинтов.

Каждый роут закрывает уязвимость, показанную в ``insecure.py``:

* параметризованный SQL вместо подстановки строк;
* сравнение хэшей за постоянное время вместо паролей в открытом виде;
* проверка владения объектом вместо доверия к id из запроса;
* HTML-экранирование отражаемого ввода.
"""

from __future__ import annotations

import hmac
from html import escape

from fastapi import FastAPI, Header
from fastapi.responses import HTMLResponse, JSONResponse


def create_app() -> FastAPI:
    from .db import build_db, hash_password

    app = FastAPI(title="secure-demo")
    app.state.db = build_db()

    @app.post("/login")
    def login(payload: dict) -> object:
        db = app.state.db
        username = payload.get("username", "")
        password = payload.get("password", "")
        # ФИКС: биндинг параметров — ввод остаётся данными, а не частью SQL.
        row = db.execute(
            "SELECT id, username, pw_hash FROM users WHERE username = ?",
            (username,),
        ).fetchone()
        # ФИКС: сравнение хэшей за постоянное время; пароль никогда не хранится
        # и не сравнивается в открытом виде.
        if row is not None and hmac.compare_digest(
            row["pw_hash"], hash_password(password)
        ):
            return {"ok": True, "user": row["username"]}
        return JSONResponse({"ok": False}, status_code=401)

    @app.get("/notes/{note_id}")
    def get_note(note_id: int, x_user: str = Header(default="")) -> object:
        db = app.state.db
        row = db.execute(
            "SELECT id, owner, body FROM notes WHERE id = ?", (note_id,)
        ).fetchone()
        if row is None:
            return JSONResponse({"error": "не найдено"}, status_code=404)
        # ФИКС: проверка авторизации на уровне объекта перед выдачей записи.
        if row["owner"] != x_user:
            return JSONResponse({"error": "доступ запрещён"}, status_code=403)
        return {"id": row["id"], "owner": row["owner"], "body": row["body"]}

    @app.get("/search", response_class=HTMLResponse)
    def search(q: str = "") -> str:
        # ФИКС: экранируем ввод, чтобы он рендерился как текст, а не разметка.
        safe = escape(q)
        return f"<html><body>Результаты по запросу: {safe}</body></html>"

    return app


app = create_app()
