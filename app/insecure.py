"""Намеренно уязвимые эндпоинты.

В каждом роуте — известный антипаттерн, явно помеченный комментарием.
Парные регрессионные тесты проверяют, что уязвимость присутствует, — если
кто-то потом "случайно" закроет её здесь, тесты упадут и заставят принять
осознанное решение. В настоящем репозитории оставался бы только ``secure.py``;
этот файл существует лишь для того, чтобы сравнение до/после можно было
протестировать.
"""

from __future__ import annotations

from fastapi import FastAPI, Header
from fastapi.responses import HTMLResponse, JSONResponse


def create_app() -> FastAPI:
    from .db import build_db

    app = FastAPI(title="insecure-demo")
    app.state.db = build_db()

    @app.post("/login")
    def login(payload: dict) -> object:
        db = app.state.db
        username = payload.get("username", "")
        password = payload.get("password", "")
        # АНТИПАТТЕРН (A03 Injection): запрос собирается подстановкой строк,
        # поэтому специально составленный ввод меняет логику запроса.
        query = (
            "SELECT id, username FROM users "
            f"WHERE username = '{username}' AND password = '{password}'"
        )
        row = db.execute(query).fetchone()
        if row:
            return {"ok": True, "user": row["username"]}
        return JSONResponse({"ok": False}, status_code=401)

    @app.get("/notes/{note_id}")
    def get_note(note_id: int, x_user: str = Header(default="")) -> object:
        db = app.state.db
        # АНТИПАТТЕРН (A01 Broken Access Control / IDOR): запись отдаётся
        # без проверки, что она принадлежит вызывающему.
        row = db.execute(
            "SELECT id, owner, body FROM notes WHERE id = ?", (note_id,)
        ).fetchone()
        if row is None:
            return JSONResponse({"error": "не найдено"}, status_code=404)
        return {"id": row["id"], "owner": row["owner"], "body": row["body"]}

    @app.get("/search", response_class=HTMLResponse)
    def search(q: str = "") -> str:
        # АНТИПАТТЕРН (A03 XSS): пользовательский ввод отражается в HTML без
        # экранирования, поэтому разметка в ``q`` интерпретируется браузером.
        return f"<html><body>Результаты по запросу: {q}</body></html>"

    return app


app = create_app()
