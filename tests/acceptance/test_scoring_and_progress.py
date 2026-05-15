"""
@file test_scoring_and_progress.py
@brief Acceptance tests for the full tutoring scoring flow.
@details Simulates a student fetching an activity, submitting answers that
         achieve objectives one by one, and asserts score persistence,
         objective_score_logs entries, and completion state.

         Strategy: monkeypatch service-level DB calls so the scoring logic
         in submitAnswer executes fully (text matching, achievement detection,
         progress upsert) while all SQL is intercepted by mock objects.
         call_deepseek_api is also patched to return None so the keyword
         matching fallback runs deterministically without network I/O.
"""

import json
import uuid
import pytest
from unittest.mock import AsyncMock, MagicMock, patch, call

from app import services
from app.services import (
    submitAnswer,
    getStudentActivity,
    _meaningful_words,
    _find_new_objective_achievement,
)
from tests.conftest import STUDENT_ID, COURSE_ID, ACTIVITY_ID

pytestmark = pytest.mark.acceptance


# -- Helpers ------------------------------------------------------------------

def _make_student_record():
    """Build a mock asyncpg.Record for a student user row."""
    record = MagicMock()
    data = {
        "id": STUDENT_ID,
        "school_email": "student@mef.edu.tr",
        "role": "student",
        "created_at": "2026-01-01T00:00:00+00:00",
    }
    record.__getitem__ = lambda self, key: data[key]
    return record


def _make_activity_record(objectives_list, activity_status="ACTIVE"):
    """Build a mock asyncpg.Record for an activity row."""
    record = MagicMock()
    data = {
        "id": ACTIVITY_ID,
        "course_id": COURSE_ID,
        "activity_no": 1,
        "title": "Test Activity",
        "description": "Describe cellular respiration and photosynthesis.",
        "objectives": json.dumps(objectives_list),
        "status": activity_status,
        "max_score": 100,
    }
    record.__getitem__ = lambda self, key: data[key]
    record.__bool__ = lambda self: True
    return record


def _make_objective_index_row(index: int):
    """Build a mock row for SELECT objective_index FROM objective_score_logs."""
    row = MagicMock()
    row.__getitem__ = lambda self, key: index if key == "objective_index" else None
    return row


def _make_inserted_score_row(total_score: int):
    """Build a mock RETURNING row from INSERT INTO objective_score_logs."""
    row = MagicMock()
    row.__getitem__ = lambda self, key: total_score if key == "total_score" else None
    return row


# -- Full Scoring Flow --------------------------------------------------------

class TestScoringAndProgressFlow:
    """
    Acceptance scenario: seed an activity with 2 objectives, simulate
    student answers, and assert score increments and completion state.

    call_deepseek_api is patched to None so the keyword-matching fallback
    runs without any network calls.
    """

    OBJECTIVES = [
        "cellular respiration produces energy in mitochondria",
        "photosynthesis converts light energy into glucose",
    ]

    async def test_first_answer_achieves_objective_0(self, mock_db_pool):
        """
        First answer matching objective 0 must yield score_delta=1,
        score=1, completed=False.
        """
        mock_conn = AsyncMock()
        mock_tx = AsyncMock()
        mock_tx.__aenter__ = AsyncMock(return_value=mock_tx)
        mock_tx.__aexit__ = AsyncMock(return_value=False)
        mock_conn.transaction = MagicMock(return_value=mock_tx)

        activity_record = _make_activity_record(self.OBJECTIVES)
        mock_conn.fetchrow = AsyncMock(side_effect=[
            activity_record,
            _make_inserted_score_row(1),
        ])
        mock_conn.fetch = AsyncMock(return_value=[])
        mock_conn.execute = AsyncMock(return_value="INSERT 0 1")

        acq_cm = AsyncMock()
        acq_cm.__aenter__ = AsyncMock(return_value=mock_conn)
        acq_cm.__aexit__ = AsyncMock(return_value=False)
        mock_db_pool.acquire = MagicMock(return_value=acq_cm)

        student_record = _make_student_record()

        with (
            patch.object(services, "fetch_registered_student_by_email", new_callable=AsyncMock) as mock_fetch_student,
            patch.object(services, "_ensure_student_enrolled_in_course", new_callable=AsyncMock) as mock_enroll,
            patch.object(services, "call_deepseek_api", new_callable=AsyncMock, return_value=None),
            patch.object(services, "_next_objective_question", new_callable=AsyncMock, return_value="What is cellular respiration?"),
        ):
            mock_fetch_student.return_value = student_record
            mock_enroll.return_value = None

            result = await submitAnswer(
                email="student@mef.edu.tr",
                password="",
                course_id=COURSE_ID,
                activity_no=1,
                answer="Cellular respiration produces energy in the mitochondria of cells",
            )

        assert result["score_delta"] == 1
        assert result["score"] == 1
        assert result["completed"] is False
        assert result["next_question"] is not None

    async def test_repeated_objective_no_score_increase(self, mock_db_pool):
        """
        Submitting an answer that matches an already-earned objective
        must yield score_delta=0 and no new log entry.
        """
        mock_conn = AsyncMock()
        mock_tx = AsyncMock()
        mock_tx.__aenter__ = AsyncMock(return_value=mock_tx)
        mock_tx.__aexit__ = AsyncMock(return_value=False)
        mock_conn.transaction = MagicMock(return_value=mock_tx)

        activity_record = _make_activity_record(self.OBJECTIVES)
        earned_row_0 = _make_objective_index_row(0)

        mock_conn.fetchrow = AsyncMock(side_effect=[activity_record])
        mock_conn.fetch = AsyncMock(return_value=[earned_row_0])
        mock_conn.execute = AsyncMock(return_value="INSERT 0 1")

        acq_cm = AsyncMock()
        acq_cm.__aenter__ = AsyncMock(return_value=mock_conn)
        acq_cm.__aexit__ = AsyncMock(return_value=False)
        mock_db_pool.acquire = MagicMock(return_value=acq_cm)

        student_record = _make_student_record()

        with (
            patch.object(services, "fetch_registered_student_by_email", new_callable=AsyncMock) as mock_fetch_student,
            patch.object(services, "_ensure_student_enrolled_in_course", new_callable=AsyncMock) as mock_enroll,
            patch.object(services, "call_deepseek_api", new_callable=AsyncMock, return_value=None),
            patch.object(services, "_next_objective_question", new_callable=AsyncMock, return_value="What is photosynthesis?"),
        ):
            mock_fetch_student.return_value = student_record
            mock_enroll.return_value = None

            result = await submitAnswer(
                email="student@mef.edu.tr",
                password="",
                course_id=COURSE_ID,
                activity_no=1,
                answer="Cellular respiration produces energy in the mitochondria",
            )

        assert result["score_delta"] == 0
        assert result["score"] == 1
        assert result["completed"] is False

    async def test_second_objective_completes_activity(self, mock_db_pool):
        """
        Achieving the last remaining objective must yield score_delta=1,
        completed=True, and next_question=None.
        """
        mock_conn = AsyncMock()
        mock_tx = AsyncMock()
        mock_tx.__aenter__ = AsyncMock(return_value=mock_tx)
        mock_tx.__aexit__ = AsyncMock(return_value=False)
        mock_conn.transaction = MagicMock(return_value=mock_tx)

        activity_record = _make_activity_record(self.OBJECTIVES)
        earned_row_0 = _make_objective_index_row(0)

        mock_conn.fetchrow = AsyncMock(side_effect=[
            activity_record,
            _make_inserted_score_row(2),
        ])
        mock_conn.fetch = AsyncMock(return_value=[earned_row_0])
        mock_conn.execute = AsyncMock(return_value="INSERT 0 1")

        acq_cm = AsyncMock()
        acq_cm.__aenter__ = AsyncMock(return_value=mock_conn)
        acq_cm.__aexit__ = AsyncMock(return_value=False)
        mock_db_pool.acquire = MagicMock(return_value=acq_cm)

        student_record = _make_student_record()

        with (
            patch.object(services, "fetch_registered_student_by_email", new_callable=AsyncMock) as mock_fetch_student,
            patch.object(services, "_ensure_student_enrolled_in_course", new_callable=AsyncMock) as mock_enroll,
            patch.object(services, "call_deepseek_api", new_callable=AsyncMock, return_value=None),
        ):
            mock_fetch_student.return_value = student_record
            mock_enroll.return_value = None

            result = await submitAnswer(
                email="student@mef.edu.tr",
                password="",
                course_id=COURSE_ID,
                activity_no=1,
                answer="Photosynthesis converts light energy into glucose in chloroplasts",
            )

        assert result["score_delta"] == 1
        assert result["score"] == 2
        assert result["completed"] is True
        assert result["next_question"] is None

    async def test_answer_after_all_completed_returns_celebrate(self, mock_db_pool):
        """
        Submitting after all objectives are earned must return
        score_delta=0, completed=True, celebrate message.
        """
        mock_conn = AsyncMock()
        mock_tx = AsyncMock()
        mock_tx.__aenter__ = AsyncMock(return_value=mock_tx)
        mock_tx.__aexit__ = AsyncMock(return_value=False)
        mock_conn.transaction = MagicMock(return_value=mock_tx)

        activity_record = _make_activity_record(self.OBJECTIVES)
        earned_rows = [
            _make_objective_index_row(0),
            _make_objective_index_row(1),
        ]

        mock_conn.fetchrow = AsyncMock(return_value=activity_record)
        mock_conn.fetch = AsyncMock(return_value=earned_rows)
        mock_conn.execute = AsyncMock(return_value="INSERT 0 1")

        acq_cm = AsyncMock()
        acq_cm.__aenter__ = AsyncMock(return_value=mock_conn)
        acq_cm.__aexit__ = AsyncMock(return_value=False)
        mock_db_pool.acquire = MagicMock(return_value=acq_cm)

        student_record = _make_student_record()

        with (
            patch.object(services, "fetch_registered_student_by_email", new_callable=AsyncMock) as mock_fetch_student,
            patch.object(services, "_ensure_student_enrolled_in_course", new_callable=AsyncMock) as mock_enroll,
            patch.object(services, "call_deepseek_api", new_callable=AsyncMock, return_value=None),
        ):
            mock_fetch_student.return_value = student_record
            mock_enroll.return_value = None

            result = await submitAnswer(
                email="student@mef.edu.tr",
                password="",
                course_id=COURSE_ID,
                activity_no=1,
                answer="Any answer text after completion",
            )

        assert result["score_delta"] == 0
        assert result["completed"] is True
        assert "all objectives" in result["message"].lower()

    async def test_submit_to_ended_activity_returns_403(self, mock_db_pool):
        """Submitting to an ENDED activity must raise 403."""
        from fastapi import HTTPException

        mock_conn = AsyncMock()
        mock_tx = AsyncMock()
        mock_tx.__aenter__ = AsyncMock(return_value=mock_tx)
        mock_tx.__aexit__ = AsyncMock(return_value=False)
        mock_conn.transaction = MagicMock(return_value=mock_tx)

        ended_activity = _make_activity_record(self.OBJECTIVES, activity_status="ENDED")
        mock_conn.fetchrow = AsyncMock(return_value=ended_activity)
        mock_conn.fetch = AsyncMock(return_value=[])

        acq_cm = AsyncMock()
        acq_cm.__aenter__ = AsyncMock(return_value=mock_conn)
        acq_cm.__aexit__ = AsyncMock(return_value=False)
        mock_db_pool.acquire = MagicMock(return_value=acq_cm)

        student_record = _make_student_record()

        with (
            patch.object(services, "fetch_registered_student_by_email", new_callable=AsyncMock) as mock_fetch_student,
            patch.object(services, "_ensure_student_enrolled_in_course", new_callable=AsyncMock) as mock_enroll,
        ):
            mock_fetch_student.return_value = student_record
            mock_enroll.return_value = None

            with pytest.raises(HTTPException) as exc_info:
                await submitAnswer(
                    email="student@mef.edu.tr",
                    password="",
                    course_id=COURSE_ID,
                    activity_no=1,
                    answer="Any answer",
                )

            assert exc_info.value.status_code == 403
            assert "ENDED" in exc_info.value.detail


# -- getStudentActivity flow --------------------------------------------------

class TestGetStudentActivityFlow:
    """Acceptance tests for activity fetch with progress state."""

    OBJECTIVES = [
        "cellular respiration produces energy in mitochondria",
        "photosynthesis converts light energy into glucose",
    ]

    async def test_fresh_student_gets_first_question(self, mock_db_pool):
        """Student with no progress sees score=0 and a guidance question."""
        activity_record = _make_activity_record(self.OBJECTIVES)
        student_record = _make_student_record()

        # pool.fetchrow is called 3 times:
        #   1) activity SELECT
        #   2) manual_score SELECT (None => no override)
        #   3) existing_progress SELECT (None => no prior answer)
        mock_db_pool.fetchrow = AsyncMock(side_effect=[
            activity_record,
            None,
            None,
        ])
        mock_db_pool.fetch = AsyncMock(return_value=[])

        mock_conn = AsyncMock()
        mock_conn.execute = AsyncMock(return_value="INSERT 0 1")
        acq_cm = AsyncMock()
        acq_cm.__aenter__ = AsyncMock(return_value=mock_conn)
        acq_cm.__aexit__ = AsyncMock(return_value=False)
        mock_db_pool.acquire = MagicMock(return_value=acq_cm)

        with (
            patch.object(services, "fetch_registered_student_by_email", new_callable=AsyncMock) as mock_fetch,
            patch.object(services, "_ensure_student_enrolled_in_course", new_callable=AsyncMock) as mock_enroll,
            patch.object(services, "_next_objective_question", new_callable=AsyncMock, return_value="What is cellular respiration?"),
        ):
            mock_fetch.return_value = student_record
            mock_enroll.return_value = None

            result = await getStudentActivity(
                email="student@mef.edu.tr",
                password="",
                course_id=COURSE_ID,
                activity_no=1,
            )

        assert result["score"] == 0
        assert result["completed"] is False
        assert result["next_question"] is not None
        assert result["status"] == "ACTIVE"
