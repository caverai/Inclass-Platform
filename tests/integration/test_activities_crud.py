"""
@file test_activities_crud.py
@brief Integration tests for activity CRUD endpoints.
@details Tests create, update, start, end, and reset activity routes
         via httpx.AsyncClient with monkeypatched service functions.
"""

import pytest
from unittest.mock import AsyncMock, patch

from tests.conftest import COURSE_ID, ACTIVITY_ID

pytestmark = pytest.mark.integration


# ── POST /instructor/activity/create ──────────────────────────────────────

class TestCreateActivity:
    """POST /instructor/activity/create endpoint behavior."""

    async def test_create_returns_success(
        self, async_client, mock_db_pool, override_instructor_dep
    ):
        """Valid payload returns 200 with activity metadata."""
        fake_result = {
            "status": "success",
            "activity_id": ACTIVITY_ID,
            "course_id": COURSE_ID,
            "activity_no": 1,
            "title": "Test Activity",
            "activity_text": "Describe photosynthesis.",
            "objectives": ["Light reactions", "Calvin cycle"],
            "activity_status": "DRAFT",
        }
        with patch("app.main.createActivity", new_callable=AsyncMock) as mock_create:
            mock_create.return_value = fake_result

            resp = await async_client.post(
                "/instructor/activity/create",
                json={
                    "course_id": COURSE_ID,
                    "activity_no": 1,
                    "activity_text": "Describe photosynthesis.",
                    "objectives": ["Light reactions", "Calvin cycle"],
                },
            )

        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "success"
        assert body["activity_status"] == "DRAFT"
        assert len(body["objectives"]) == 2

    async def test_create_409_duplicate(
        self, async_client, mock_db_pool, override_instructor_dep
    ):
        """Duplicate activity_no in the same course returns 409."""
        from fastapi import HTTPException

        with patch("app.main.createActivity", new_callable=AsyncMock) as mock_create:
            mock_create.side_effect = HTTPException(
                status_code=409,
                detail="An activity with this activity_no already exists in the selected course.",
            )

            resp = await async_client.post(
                "/instructor/activity/create",
                json={
                    "course_id": COURSE_ID,
                    "activity_no": 1,
                    "activity_text": "Duplicate test.",
                    "objectives": ["Obj A"],
                },
            )

        assert resp.status_code == 409

    async def test_create_422_missing_objectives(
        self, async_client, mock_db_pool, override_instructor_dep
    ):
        """Missing required field objectives triggers 422 validation error."""
        resp = await async_client.post(
            "/instructor/activity/create",
            json={
                "course_id": COURSE_ID,
                "activity_no": 1,
                "activity_text": "Text here",
                # objectives intentionally omitted
            },
        )

        assert resp.status_code == 422


# ── PATCH /instructor/activity/{course_id}/{activity_no} ──────────────────

class TestUpdateActivity:
    """PATCH activity endpoint behavior."""

    async def test_update_returns_success(
        self, async_client, mock_db_pool, override_instructor_dep
    ):
        """Valid partial update returns 200 with success message."""
        fake_result = {
            "status": "success",
            "message": "Activity 1 updated successfully.",
        }
        with patch("app.main.updateActivity", new_callable=AsyncMock) as mock_update:
            mock_update.return_value = fake_result

            resp = await async_client.patch(
                f"/instructor/activity/{COURSE_ID}/1",
                json={"activity_text": "Updated description."},
            )

        assert resp.status_code == 200
        assert resp.json()["status"] == "success"

    async def test_update_400_empty_patch(
        self, async_client, mock_db_pool, override_instructor_dep
    ):
        """Empty patch body (no fields) returns 400."""
        from fastapi import HTTPException

        with patch("app.main.updateActivity", new_callable=AsyncMock) as mock_update:
            mock_update.side_effect = HTTPException(
                status_code=400,
                detail="Empty patch: At least one allowed field must be provided.",
            )

            resp = await async_client.patch(
                f"/instructor/activity/{COURSE_ID}/1",
                json={},
            )

        assert resp.status_code == 400

    async def test_update_404_nonexistent(
        self, async_client, mock_db_pool, override_instructor_dep
    ):
        """Update on a nonexistent activity returns 404."""
        from fastapi import HTTPException

        with patch("app.main.updateActivity", new_callable=AsyncMock) as mock_update:
            mock_update.side_effect = HTTPException(
                status_code=404, detail="Activity not found."
            )

            resp = await async_client.patch(
                f"/instructor/activity/{COURSE_ID}/999",
                json={"title": "New Title"},
            )

        assert resp.status_code == 404


# ── POST /instructor/activity/start ───────────────────────────────────────

class TestStartActivity:
    """POST /instructor/activity/start endpoint behavior."""

    async def test_start_draft_activity_returns_active(
        self, async_client, mock_db_pool, override_instructor_dep
    ):
        """Starting a DRAFT activity returns status ACTIVE."""
        fake_result = {
            "status": "success",
            "course_id": COURSE_ID,
            "activity_no": 1,
            "activity_status": "ACTIVE",
        }
        with patch("app.main.startActivity", new_callable=AsyncMock) as mock_start:
            mock_start.return_value = fake_result

            resp = await async_client.post(
                "/instructor/activity/start",
                params={"course_id": COURSE_ID, "activity_no": 1},
            )

        assert resp.status_code == 200
        assert resp.json()["activity_status"] == "ACTIVE"

    async def test_start_non_draft_returns_409(
        self, async_client, mock_db_pool, override_instructor_dep
    ):
        """Starting an already ACTIVE activity returns 409."""
        from fastapi import HTTPException

        with patch("app.main.startActivity", new_callable=AsyncMock) as mock_start:
            mock_start.side_effect = HTTPException(
                status_code=409,
                detail="Only DRAFT activities can be started.",
            )

            resp = await async_client.post(
                "/instructor/activity/start",
                params={"course_id": COURSE_ID, "activity_no": 1},
            )

        assert resp.status_code == 409


# ── POST /instructor/activity/end ─────────────────────────────────────────

class TestEndActivity:
    """POST /instructor/activity/end endpoint behavior."""

    async def test_end_active_activity_returns_ended(
        self, async_client, mock_db_pool, override_instructor_dep
    ):
        """Ending an ACTIVE activity returns status ENDED."""
        fake_result = {
            "status": "success",
            "course_id": COURSE_ID,
            "activity_no": 1,
            "activity_status": "ENDED",
        }
        with patch("app.main.endActivity", new_callable=AsyncMock) as mock_end:
            mock_end.return_value = fake_result

            resp = await async_client.post(
                "/instructor/activity/end",
                params={"course_id": COURSE_ID, "activity_no": 1},
            )

        assert resp.status_code == 200
        assert resp.json()["activity_status"] == "ENDED"

    async def test_end_draft_returns_409(
        self, async_client, mock_db_pool, override_instructor_dep
    ):
        """Ending a DRAFT activity returns 409."""
        from fastapi import HTTPException

        with patch("app.main.endActivity", new_callable=AsyncMock) as mock_end:
            mock_end.side_effect = HTTPException(
                status_code=409,
                detail="Only ACTIVE activities can be ended.",
            )

            resp = await async_client.post(
                "/instructor/activity/end",
                params={"course_id": COURSE_ID, "activity_no": 1},
            )

        assert resp.status_code == 409


# ── POST /instructor/activity/reset ───────────────────────────────────────

class TestResetActivity:
    """POST /instructor/activity/reset endpoint behavior."""

    async def test_reset_returns_success(
        self, async_client, mock_db_pool, override_instructor_dep
    ):
        """Reset deletes related rows and returns success."""
        fake_result = {"status": "success", "message": "Activity reset."}

        with patch("app.main.resetActivity", new_callable=AsyncMock) as mock_reset:
            mock_reset.return_value = fake_result

            resp = await async_client.post(
                "/instructor/activity/reset",
                params={"course_id": COURSE_ID, "activity_no": 1},
            )

        assert resp.status_code == 200
        assert resp.json()["status"] == "success"

    async def test_reset_404_nonexistent(
        self, async_client, mock_db_pool, override_instructor_dep
    ):
        """Resetting a nonexistent activity returns 404."""
        from fastapi import HTTPException

        with patch("app.main.resetActivity", new_callable=AsyncMock) as mock_reset:
            mock_reset.side_effect = HTTPException(
                status_code=404, detail="Not found."
            )

            resp = await async_client.post(
                "/instructor/activity/reset",
                params={"course_id": COURSE_ID, "activity_no": 999},
            )

        assert resp.status_code == 404
