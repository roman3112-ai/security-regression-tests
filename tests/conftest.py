"""Общие фикстуры: TestClient для каждого варианта демо-приложения."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.insecure import create_app as create_insecure_app
from app.secure import create_app as create_secure_app


@pytest.fixture()
def insecure_client() -> TestClient:
    return TestClient(create_insecure_app())


@pytest.fixture()
def secure_client() -> TestClient:
    return TestClient(create_secure_app())
