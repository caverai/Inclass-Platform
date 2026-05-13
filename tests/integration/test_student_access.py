"""
@file test_student_access.py
@brief Integration tests for GET /student/activity.
@details Verifies that only ACTIVE activities are accessible to students
         and that NOT_STARTED/ENDED activities return appropriate errors.
"""

import pytest
from unittest.mock import AsyncMock, patch

from tests.conftest import COURSE_ID

pytestmark = pytest.mark.integration


class TestGetStudentActivity:
    """GET /student/activity endpoint status enforcement."""

    async def test_active_activity_returns_200(
        self, async_client, mock_db_pool, override_student_dep
    ):
        """Student can access an ACTIVE activity and receives content."""
        fake_result = {
            "title": "Photosynthesis",
            "activity_text": "Describe the process of photosynthesis.",
            "status": "ACTIVE",
            "score": 0,
            "completed": False,
            "next_question": "What is one precise academic detail?",
        }
        with patch(
            "app.main.getStudentActivity", new_callable=AsyncMock
        ) as mock_get:
            mock_get.return_value = fake_result

            resp = await async_client.get(
                "/student/activity",
                params={"course_id": COURSE_ID, "activity_no": 1},
            )

        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "ACTIVE"
        assert body["title"] == "Photosynthesis"
        assert body["next_question"] is not None

    async def test_draft_activity_returns_403(
        self, async_client, mock_db_pool, override_student_dep
    ):
        """NOT_STARTED (DRAFT) activity must return 403."""
        from fastapi import HTTPException

        with patch(
            "app.main.getStudentActivity", new_callable=AsyncMock
        ) as mock_get:
            mock_get.side_effect = HTTPException(
                status_code=403,
                detail="Only ACTIVE activities can be opened.",
            )

            resp = await async_client.get(
                "/student/activity",
                params={"course_id": COURSE_ID, "activity_no": 1},
            )

        assert resp.status_code == 403

    async def test_ended_activity_returns_403(
        self, async_client, mock_db_pool, override_student_dep
    ):
        """ENDED activity must return 403 with descriptive message."""
        from fastapi import HTTPException

        with patch(
            "app.main.getStudentActivity", new_callable=AsyncMock
        ) as mock_get:
            mock_get.side_effect = HTTPException(
                status_code=403,
                detail="This activity is ENDED, so the tutoring flow cannot continue.",
            )

            resp = await async_client.get(
                "/student/activity",
                params={"course_id": COURSE_ID, "activity_no": 1},
            )

        assert resp.status_code == 403
        assert "ENDED" in resp.json()["detail"]

    async def test_nonexistent_activity_returns_404(
        self, async_client, mock_db_pool, override_student_dep
    ):
        """Activity that does not exist returns 404."""
        from fastapi import HTTPException

        with patch(
            "app.main.getStudentActivity", new_callable=AsyncMock
        ) as mock_get:
            mock_get.side_effect = HTTPException(
                status_code=404,
                detail="Activity not found.",
            )

            resp = await async_client.get(
                "/student/activity",
                params={"course_id": COURSE_ID, "activity_no": 999},
            )

        assert resp.status_code == 404

    async def test_unauthenticated_request_returns_401(
        self, async_client, mock_db_pool
    ):
        """Request without any authentication is rejected with 401."""
        resp = await async_client.get(
            "/student/activity",
            params={"course_id": COURSE_ID, "activity_no": 1},
        )

        assert resp.status_code == 401
