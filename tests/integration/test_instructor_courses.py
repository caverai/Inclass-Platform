"""
@file test_instructor_courses.py
@brief Integration tests for GET /instructor/courses.
@details Verifies that only assigned courses are returned and that
         unauthorized instructors receive 403.
"""

import pytest
from unittest.mock import AsyncMock, patch

pytestmark = pytest.mark.integration


class TestGetInstructorCourses:
    """GET /instructor/courses endpoint behavior."""

    async def test_returns_assigned_courses(
        self, async_client, mock_db_pool, override_instructor_dep
    ):
        """Authorized instructor receives their assigned courses list."""
        fake_courses = {
            "courses": [
                {
                    "id": "c-1",
                    "course_code": "CS101",
                    "course_name": "Intro to CS",
                    "term": "2026-Spring",
                },
            ]
        }
        with patch("app.main.listMyCourses", new_callable=AsyncMock) as mock_list:
            mock_list.return_value = fake_courses

            resp = await async_client.get("/instructor/courses")

        assert resp.status_code == 200
        body = resp.json()
        assert "courses" in body
        assert len(body["courses"]) == 1
        assert body["courses"][0]["course_code"] == "CS101"

    async def test_returns_empty_list_when_no_courses(
        self, async_client, mock_db_pool, override_instructor_dep
    ):
        """Instructor with no course assignments receives an empty list."""
        with patch("app.main.listMyCourses", new_callable=AsyncMock) as mock_list:
            mock_list.return_value = {"courses": []}

            resp = await async_client.get("/instructor/courses")

        assert resp.status_code == 200
        assert resp.json()["courses"] == []

    async def test_403_for_unauthorized_instructor(
        self, async_client, mock_db_pool, override_instructor_dep
    ):
        """Service-level 403 must propagate to the HTTP response."""
        from fastapi import HTTPException

        with patch("app.main.listMyCourses", new_callable=AsyncMock) as mock_list:
            mock_list.side_effect = HTTPException(
                status_code=403,
                detail="Instructor is not authorized for the target course.",
            )

            resp = await async_client.get("/instructor/courses")

        assert resp.status_code == 403

    async def test_401_without_auth_header(self, async_client, mock_db_pool):
        """Request without auth header must be rejected."""
        resp = await async_client.get("/instructor/courses")

        # Without override and without bearer token => 401
        assert resp.status_code == 401
