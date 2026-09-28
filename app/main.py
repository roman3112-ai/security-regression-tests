"""Точка входа для локального запуска защищённой демо-версии приложения.

    uvicorn app.main:app --reload

Затем открыть http://127.0.0.1:8000/docs
"""

from __future__ import annotations

from .secure import create_app

app = create_app()
