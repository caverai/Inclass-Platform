"""
@file test_reset_activity_cascade.py
@brief Acceptance tests for activity reset cascade behavior (US-M).
@details Validates that resetActivity deletes objective_score_logs,
         activity_scores, student_activity_progress rows for the target
         activity, and sets activity status to ENDED.
"""

import json
import uuid
import pytest
from unittest.mock import AsyncMock, MagicMock, patch, call

from app import services
from app.services import resetActivity
from tests.conftest import INSTRUCTOR_ID, COURSE_ID, ACTIVITY_ID

pytestmark = pytest.mark.acceptance


def _make_instructor_record():
    """Build a mock asyncpg.Record for an instructor user row."""
    record = MagicMock()
    data = {
        "id": INSTRUCTOR_ID,
        "school_email": "instructor@mef.edu.tr",
        "role": "instructor",
        "created_at": "2026-01-01T00:00:00+00:00",
    }
    record.__getitem__ = lambda self, key: data[key]
    return record


def _make_activity_id_record():
    """Build a mock asyncpg.Record returning just the activity id."""
    record = MagicMock()
    record.__getitem__ = lambda self, key: ACTIVITY_ID if key == "id" else None
    record.__bool__ = lambda self: True
    return record


class TestResetActivityCascade:
    """
    After reset, ensure objective_score_logs, activity_scores,
    student_activity_progress rows for that activity are deleted
    and activity status == ENDED.
    """

    async def test_reset_deletes_all_related_rows(self, mock_db_pool):
        """
        resetActivity must execute DELETE on objective_score_logs,
        activity_scores, and student_activity_progress, then UPDATE
        activity status to ENDED.
        """
        mock_conn = AsyncMock()
        mock_tx = AsyncMock()
        mock_tx.__aenter__ = AsyncMock(return_value=mock_tx)
        mock_tx.__aexit__ = AsyncMock(return_value=False)
        mock_conn.transaction = MagicMock(return_value=mock_tx)

        # fetchrow: SELECT id FROM activities ... FOR UPDATE
        mock_conn.fetchrow = AsyncMock(return_value=_make_activity_id_record())
        mock_conn.execute = AsyncMock(return_value="DELETE 3")

        acq_cm = AsyncMock()
        acq_cm.__aenter__ = AsyncMock(return_value=mock_conn)
        acq_cm.__aexit__ = AsyncMock(return_value=False)
        mock_db_pool.acquire = MagicMock(return_value=acq_cm)

        instructor_record = _make_instructor_record()

        with (
            patch.object(
                services, "fetch_registered_instructor_by_email",
                new_callable=AsyncMock,
            ) as mock_fetch_inst,
            patch.object(
                services, "_ensure_instructor_assigned_to_course",
                new_callable=AsyncMock,
            ) as mock_assigned,
        ):
            mock_fetch_inst.return_value = instructor_record
            mock_assigned.return_value = None

            result = await resetActivity(
                email="instructor@mef.edu.tr",
                password="",
                course_id=COURSE_ID,
                activity_no=1,
            )

        assert result["status"] == "success"

        # Verify the cascade: 4 DELETEs + 1 UPDATE = 5 execute calls
        execute_calls = mock_conn.execute.call_args_list
        assert len(execute_calls) == 5

        # Extract SQL from each call
        sql_statements = [c.args[0] for c in execute_calls]

        # Assert each table was cleaned
        assert any("objective_score_logs" in sql for sql in sql_statements), \
            "Must DELETE FROM objective_score_logs"
        assert any("activity_scores" in sql for sql in sql_statements), \
            "Must DELETE FROM activity_scores"
        assert any("activity_action_logs" in sql for sql in sql_statements), \
            "Must DELETE FROM activity_action_logs"
        assert any("student_activity_progress" in sql for sql in sql_statements), \
            "Must DELETE FROM student_activity_progress"

        # Assert status update to ENDED
        assert any(
            "ENDED" in sql and "UPDATE" in sql.upper()
            for sql in sql_statements
        ), "Must UPDATE activity status to ENDED"

    async def test_reset_all_deletes_use_correct_activity_id(self, mock_db_pool):
        """
        All DELETE and UPDATE statements must reference the correct
        activity_id from the SELECT ... FOR UPDATE result.
        """
        mock_conn = AsyncMock()
        mock_tx = AsyncMock()
        mock_tx.__aenter__ = AsyncMock(return_value=mock_tx)
        mock_tx.__aexit__ = AsyncMock(return_value=False)
        mock_conn.transaction = MagicMock(return_value=mock_tx)

        mock_conn.fetchrow = AsyncMock(return_value=_make_activity_id_record())
        mock_conn.execute = AsyncMock(return_value="DELETE 1")

        acq_cm = AsyncMock()
        acq_cm.__aenter__ = AsyncMock(return_value=mock_conn)
        acq_cm.__aexit__ = AsyncMock(return_value=False)
        mock_db_pool.acquire = MagicMock(return_value=acq_cm)

        instructor_record = _make_instructor_record()

        with (
            patch.object(
                services, "fetch_registered_instructor_by_email",
                new_callable=AsyncMock,
            ) as mock_fetch_inst,
            patch.object(
                services, "_ensure_instructor_assigned_to_course",
                new_callable=AsyncMock,
            ) as mock_assigned,
        ):
            mock_fetch_inst.return_value = instructor_record
            mock_assigned.return_value = None

            await resetActivity(
                email="instructor@mef.edu.tr",
                password="",
                course_id=COURSE_ID,
                activity_no=1,
            )

        # Every execute call after fetchrow uses ACTIVITY_ID as parameter
        for c in mock_conn.execute.call_args_list:
            assert ACTIVITY_ID in c.args, \
                f"Execute call must use activity_id={ACTIVITY_ID}: {c}"

    async def test_reset_nonexistent_activity_raises_404(self, mock_db_pool):
        """Resetting a nonexistent activity must raise HTTPException 404."""
        from fastapi import HTTPException

        mock_conn = AsyncMock()
        mock_tx = AsyncMock()
        mock_tx.__aenter__ = AsyncMock(return_value=mock_tx)
        mock_tx.__aexit__ = AsyncMock(return_value=False)
        mock_conn.transaction = MagicMock(return_value=mock_tx)

        # No activity found
        no_record = MagicMock()
        no_record.__bool__ = lambda self: False
        mock_conn.fetchrow = AsyncMock(return_value=no_record)

        acq_cm = AsyncMock()
        acq_cm.__aenter__ = AsyncMock(return_value=mock_conn)
        acq_cm.__aexit__ = AsyncMock(return_value=False)
        mock_db_pool.acquire = MagicMock(return_value=acq_cm)

        instructor_record = _make_instructor_record()

        with (
            patch.object(
                services, "fetch_registered_instructor_by_email",
                new_callable=AsyncMock,
            ) as mock_fetch_inst,
            patch.object(
                services, "_ensure_instructor_assigned_to_course",
                new_callable=AsyncMock,
            ) as mock_assigned,
        ):
            mock_fetch_inst.return_value = instructor_record
            mock_assigned.return_value = None

            with pytest.raises(HTTPException) as exc_info:
                await resetActivity(
                    email="instructor@mef.edu.tr",
                    password="",
                    course_id=COURSE_ID,
                    activity_no=999,
                )

            assert exc_info.value.status_code == 404

    async def test_reset_returns_success_message(self, mock_db_pool):
        """Successful reset returns {status: success, message: Activity reset.}."""
        mock_conn = AsyncMock()
        mock_tx = AsyncMock()
        mock_tx.__aenter__ = AsyncMock(return_value=mock_tx)
        mock_tx.__aexit__ = AsyncMock(return_value=False)
        mock_conn.transaction = MagicMock(return_value=mock_tx)

        mock_conn.fetchrow = AsyncMock(return_value=_make_activity_id_record())
        mock_conn.execute = AsyncMock(return_value="DELETE 0")

        acq_cm = AsyncMock()
        acq_cm.__aenter__ = AsyncMock(return_value=mock_conn)
        acq_cm.__aexit__ = AsyncMock(return_value=False)
        mock_db_pool.acquire = MagicMock(return_value=acq_cm)

        instructor_record = _make_instructor_record()

        with (
            patch.object(
                services, "fetch_registered_instructor_by_email",
                new_callable=AsyncMock,
            ) as mock_fetch_inst,
            patch.object(
                services, "_ensure_instructor_assigned_to_course",
                new_callable=AsyncMock,
            ) as mock_assigned,
        ):
            mock_fetch_inst.return_value = instructor_record
            mock_assigned.return_value = None

            result = await resetActivity(
                email="instructor@mef.edu.tr",
                password="",
                course_id=COURSE_ID,
                activity_no=1,
            )

        assert result == {"status": "success", "message": "Activity reset."}
