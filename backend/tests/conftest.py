"""Pytest fixtures for unit, database integration and API tests."""

from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path

import pytest
from dotenv import dotenv_values
from fastapi.testclient import TestClient
from pydantic import SecretStr
from sqlalchemy import text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

import app.models
from app.core.config import Settings
from app.core.security import CSRF_HEADER_NAME, CSRF_HEADER_VALUE
from app.db.base import Base
from app.db.session import build_engine, build_session_factory
from app.domain.enums import UserRole
from app.main import create_app
from app.seeds.seeder import seed_reference_data
from app.services.users import create_user

TEST_SECRET_KEY = "test-only-random-secret-key-at-least-32-chars-long-987654321"
TEST_PASSWORD = "CorrectHorseBatteryStaple!23"
CSRF_HEADERS = {CSRF_HEADER_NAME: CSRF_HEADER_VALUE}


def _resolve_test_db_url() -> str:
    env_url = os.environ.get("TEST_DATABASE_URL")
    if env_url:
        return env_url
    dotenv_path = Path(__file__).resolve().parents[1] / ".env"
    if dotenv_path.exists():
        vals = dotenv_values(dotenv_path)
        if vals.get("TEST_DATABASE_URL"):
            return str(vals["TEST_DATABASE_URL"])
    raise RuntimeError("TEST_DATABASE_URL is not configured in environment or .env")


@pytest.fixture(scope="session")
def test_db_url() -> str:
    return _resolve_test_db_url()


@pytest.fixture(scope="session")
def db_engine(test_db_url: str) -> Iterator[Engine]:
    engine = build_engine(test_db_url)
    Base.metadata.drop_all(bind=engine)
    with engine.begin() as conn:
        conn.execute(text("CREATE SEQUENCE IF NOT EXISTS alert_reference_seq"))
        conn.execute(text("CREATE SEQUENCE IF NOT EXISTS incident_reference_seq"))
    Base.metadata.create_all(bind=engine)

    factory = build_session_factory(engine)
    with factory() as session:
        seed_reference_data(session)

    yield engine
    engine.dispose()


@pytest.fixture
def db_session(db_engine: Engine) -> Iterator[Session]:
    """Clean mutable tables before each DB test while preserving seeded MITRE/rule rows."""
    with db_engine.begin() as conn:
        conn.execute(
            text(
                "TRUNCATE TABLE "
                "alert_events, incident_alerts, incident_timeline, investigation_notes, "
                "alerts, incidents, security_events, ingestion_batches, simulation_runs, "
                "audit_logs, users "
                "RESTART IDENTITY CASCADE"
            )
        )
        conn.execute(text("ALTER SEQUENCE alert_reference_seq RESTART WITH 1"))
        conn.execute(text("ALTER SEQUENCE incident_reference_seq RESTART WITH 1"))
        # Reset any modified rule thresholds/enabled flags back to defaults
    factory: sessionmaker[Session] = build_session_factory(db_engine)
    with factory() as session:
        seed_reference_data(session)
        for rule_row in session.query(app.models.DetectionRule).all():
            from app.detection.rules import RULES_BY_ID

            meta = RULES_BY_ID[rule_row.id].metadata
            rule_row.enabled = True
            rule_row.severity = meta.default_severity.value
            rule_row.threshold = meta.default_threshold
            rule_row.time_window_seconds = meta.default_time_window_seconds
            rule_row.parameters = dict(meta.default_parameters)
        session.commit()

    session = factory()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture
def test_settings(test_db_url: str) -> Settings:
    return Settings(
        environment="test",
        log_level="WARNING",
        database_url=SecretStr(test_db_url),
        secret_key=SecretStr(TEST_SECRET_KEY),
        cors_origins=["http://localhost:5173"],
        rate_limit_enabled=True,
        login_rate_limit_per_minute=10,
    )


@pytest.fixture
def api_client(db_session: Session, test_settings: Settings) -> Iterator[TestClient]:
    create_user(
        db_session,
        username="admin",
        password=TEST_PASSWORD,
        role=UserRole.ADMIN,
        display_name="Alice Admin",
    )
    create_user(
        db_session,
        username="analyst",
        password=TEST_PASSWORD,
        role=UserRole.ANALYST,
        display_name="Bob Analyst",
    )
    create_user(
        db_session,
        username="viewer",
        password=TEST_PASSWORD,
        role=UserRole.VIEWER,
        display_name="Vera Viewer",
    )
    db_session.commit()

    application = create_app(test_settings)
    with TestClient(application) as client:
        yield client


def login_as(client: TestClient, username: str = "analyst", password: str = TEST_PASSWORD) -> None:
    resp = client.post(
        "/api/v1/auth/login",
        json={"username": username, "password": password},
        headers=CSRF_HEADERS,
    )
    assert resp.status_code == 200, resp.text
