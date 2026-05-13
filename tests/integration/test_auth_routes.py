"""
@file test_auth_routes.py
@brief Integration tests for authentication routes.
@details Tests POST /instructor/login via httpx.AsyncClient with
         monkeypatched service functions. No real DB required.
"""

import pytest
from unittest.mock import AsyncMock, patch

pytestmark = pytest.mark.integration


class TestInstructorLogin:
    """POST /instructor/login endpoint behavior."""

    async def test_login_returns_200_for_valid_credentials(
        self, async_client, mock_db_pool
    ):
        """Valid email+password must return 200 with access_token."""
        fake_result = {
            "access_token": "jwt-token-abc",
            "token_type": "bearer",
            "user_id": "u-1",
            "role": "instructor",
            "email": "instructor@mef.edu.tr",
        }
        with patch("app.main.instructorLogin", new_callable=AsyncMock) as mock_login:
            mock_login.return_value = fake_result

            resp = await async_client.post(
                "/instructor/login",
                json={"email": "instructor@mef.edu.tr", "password": "pass123"},
            )

        assert resp.status_code == 200
        body = resp.json()
        assert "access_token" in body
        assert body["role"] == "instructor"
        assert body["email"] == "instructor@mef.edu.tr"

    async def test_login_returns_400_when_email_missing(
        self, async_client, mock_db_pool
    ):
        """Missing email must return 400."""
        resp = await async_client.post(
            "/instructor/login",
            json={"password": "pass123"},
        )

        # FastAPI may return 422 (validation) or 400 depending on fallback logic.
        assert resp.status_code in (400, 422)

    async def test_login_returns_401_for_bad_password(
        self, async_client, mock_db_pool
    ):
        """Invalid password must return 401."""
        from fastapi import HTTPException

        with patch("app.main.instructorLogin", new_callable=AsyncMock) as mock_login:
            mock_login.side_effect = HTTPException(
                status_code=401, detail="Invalid credentials"
            )

            resp = await async_client.post(
                "/instructor/login",
                json={"email": "instructor@mef.edu.tr", "password": "wrong"},
            )

        assert resp.status_code == 401

    async def test_login_response_includes_token_type(
        self, async_client, mock_db_pool
    ):
        """Response must include token_type=bearer."""
        fake_result = {
            "access_token": "jwt-xyz",
            "token_type": "bearer",
            "user_id": "u-2",
            "role": "instructor",
            "email": "inst2@mef.edu.tr",
        }
        with patch("app.main.instructorLogin", new_callable=AsyncMock) as mock_login:
            mock_login.return_value = fake_result

            resp = await async_client.post(
                "/instructor/login",
                json={"email": "inst2@mef.edu.tr", "password": "pass"},
            )

        assert resp.json()["token_type"] == "bearer"
