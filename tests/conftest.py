"""
@file conftest.py
@brief Shared pytest fixtures for the InClass Platform test suite.
@details Provides mock DB pool, fake user identities, FastAPI dependency
         overrides, and an httpx.AsyncClient bound to the ASGI app.
"""

import os
import uuid
from unittest.mock import AsyncMock, MagicMock

import pytest
import httpx

# ---------------------------------------------------------------------------
# Environment stubs — must be set BEFORE importing app.main / app.services
# ---------------------------------------------------------------------------
os.environ.setdefault("GOOGLE_CLIENT_ID", "test-google-client-id")
os.environ.setdefault("SCHOOL_EMAIL_DOMAIN", "mef.edu.tr")
os.environ.setdefault("DATABASE_URL", "postgresql://test:test@localhost:5432/test_db")
os.environ.setdefault("JWT_SECRET", "test-jwt-secret-key-for-unit-tests")
os.environ.setdefault("JWT_ALGORITHM", "HS256")
os.environ.setdefault("JWT_EXPIRE_MINUTES", "60")

from app.main import app, verify_instructor, verify_student  # noqa: E402
from app import services  # noqa: E402


# ── Static identity dicts ─────────────────────────────────────────────────

INSTRUCTOR_ID = str(uuid.uuid4())
STUDENT_ID = str(uuid.uuid4())
COURSE_ID = str(uuid.uuid4())
ACTIVITY_ID = str(uuid.uuid4())


@pytest.fixture(scope="session")
def fake_instructor() -> dict:
    """Static instructor identity reused across all tests."""
    return {
        "user_id": INSTRUCTOR_ID,
        "email": "instructor@mef.edu.tr",
        "role": "instructor",
    }


@pytest.fixture(scope="session")
def fake_student() -> dict:
    """Static student identity reused across all tests."""
    return {
        "user_id": STUDENT_ID,
        "email": "student@mef.edu.tr",
        "role": "student",
    }


# ── Dependency overrides ──────────────────────────────────────────────────

@pytest.fixture()
def override_instructor_dep(fake_instructor):
    """Override verify_instructor dependency to return fake_instructor."""
    async def _fake_verify_instructor():
        return fake_instructor

    app.dependency_overrides[verify_instructor] = _fake_verify_instructor
    yield
    app.dependency_overrides.pop(verify_instructor, None)


@pytest.fixture()
def override_student_dep(fake_student):
    """Override verify_student dependency to return fake_student."""
    async def _fake_verify_student():
        return fake_student

    app.dependency_overrides[verify_student] = _fake_verify_student
    yield
    app.dependency_overrides.pop(verify_student, None)


# ── Mock DB pool ──────────────────────────────────────────────────────────

@pytest.fixture()
def mock_db_pool():
    """
    @brief Injects an AsyncMock pool into app.state and services.db_pool.
    @details The mock connection supports acquire() as an async context manager
             and exposes fetchrow, fetch, fetchval, execute as AsyncMock.
    """
    mock_conn = AsyncMock()
    mock_conn.fetchrow = AsyncMock(return_value=None)
    mock_conn.fetch = AsyncMock(return_value=[])
    mock_conn.fetchval = AsyncMock(return_value=None)
    mock_conn.execute = AsyncMock(return_value="UPDATE 1")

    # Transaction context manager
    mock_tx = AsyncMock()
    mock_tx.__aenter__ = AsyncMock(return_value=mock_tx)
    mock_tx.__aexit__ = AsyncMock(return_value=False)
    mock_conn.transaction = MagicMock(return_value=mock_tx)

    # Pool.acquire() context manager
    mock_pool = AsyncMock()
    acq_cm = AsyncMock()
    acq_cm.__aenter__ = AsyncMock(return_value=mock_conn)
    acq_cm.__aexit__ = AsyncMock(return_value=False)
    mock_pool.acquire = MagicMock(return_value=acq_cm)

    # Pool-level shortcuts (used by some service helpers)
    mock_pool.fetchrow = AsyncMock(return_value=None)
    mock_pool.fetch = AsyncMock(return_value=[])
    mock_pool.fetchval = AsyncMock(return_value=None)

    # Inject
    app.state.db_pool = mock_pool
    services.db_pool = mock_pool

    yield mock_pool

    # Teardown
    services.db_pool = None
    if hasattr(app.state, "db_pool"):
        del app.state.db_pool


# ── httpx.AsyncClient ─────────────────────────────────────────────────────

@pytest.fixture()
async def async_client():
    """
    @brief Provides an httpx.AsyncClient bound to the FastAPI ASGI app.
    @details Uses ASGITransport to skip network I/O. Startup/shutdown
             lifespan events are intentionally bypassed (mock pool injected
             by mock_db_pool fixture instead).
    """
    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        yield client


# ── Helpers ────────────────────────────────────────────────────────────────

def make_user_record(user_id: str, email: str, role: str) -> dict:
    """
    @brief Builds a dict that mimics an asyncpg.Record for the users table.
    @param user_id UUID string.
    @param email School email.
    @param role One of student, instructor, admin.
    @return Dict with keys matching SELECT id, school_email, role, created_at.
    """
    record = MagicMock()
    record.__getitem__ = lambda self, key: {
        "id": user_id,
        "school_email": email,
        "role": role,
        "created_at": "2026-01-01T00:00:00+00:00",
    }[key]
    return record


def make_activity_record(
    activity_id: str,
    course_id: str,
    activity_no: int,
    objectives: list,
    activity_status: str = "ACTIVE",
    title: str = "Test Activity",
    description: str = "Test description",
    max_score: float = 100,
) -> MagicMock:
    """
    @brief Builds a dict-like MagicMock mimicking an activities asyncpg.Record.
    """
    data = {
        "id": activity_id,
        "course_id": course_id,
        "activity_no": activity_no,
        "title": title,
        "description": description,
        "objectives": objectives,
        "status": activity_status,
        "max_score": max_score,
        "created_by": INSTRUCTOR_ID,
    }
    record = MagicMock()
    record.__getitem__ = lambda self, key: data[key]
    record.__contains__ = lambda self, key: key in data
    record.__bool__ = lambda self: True
    return record
