"""
@file services.py
@brief User and Course management services for the InClass Platform.
@details This module provides asynchronous database operations for fetching user records, 
         managing instructor courses, and updating user credentials.
"""

import json
import logging
import os
import re
from datetime import datetime, timedelta, timezone
from typing import Optional

import asyncpg
from fastapi import HTTPException, status
from asyncpg.exceptions import UniqueViolationError
from jose import jwt
from passlib.context import CryptContext

db_pool: asyncpg.Pool | None = None

JWT_SECRET: str = os.environ.get("JWT_SECRET", "")
JWT_ALGORITHM: str = os.getenv("JWT_ALGORITHM", "HS256")
JWT_EXPIRE_MINUTES: int = int(os.getenv("JWT_EXPIRE_MINUTES", "60"))

logger = logging.getLogger("inclass.auth")

_AUTO_SCORING_STOP_WORDS = {
    "a", "an", "and", "are", "as", "at", "be", "by", "can", "do", "for",
    "from", "has", "have", "how", "in", "into", "is", "it", "its", "of",
    "on", "or", "that", "the", "their", "then", "there", "these", "this",
    "to", "was", "were", "what", "when", "where", "which", "why", "will",
    "with", "your", "define", "describe", "explain", "identify",
    "understand", "use", "using",
}


class PasswordHasher:
    """
    @brief Hashes and verifies passwords using bcrypt via CryptContext.
    @details Provides class methods to generate secure password hashes and check
             plain-text inputs against stored hashes for authentication.
    """

    _context = CryptContext(schemes=["bcrypt"], deprecated="auto")

    @classmethod
    def hash(cls, password: str) -> str:
        """
        @brief Hashes a plain-text password using bcrypt.
        @param password The plain-text password to hash.
        @return The hashed password string.
        """
        return cls._context.hash(password)

    @classmethod
    def verify(cls, plain_password: str, hashed_password: str) -> bool:
        """
        @brief Verifies a plain-text password against a hashed password.
        @param plain_password The plain-text password to check.
        @param hashed_password The hashed password to verify against.
        @return True if the password matches, False otherwise.
        """
        return cls._context.verify(plain_password, hashed_password)


def create_access_token(user_id: str, email: str, role: str) -> str:
    """
    @brief Generates a signed JWT access token for a user.
    @param user_id The unique ID of the user.
    @param email The user's school email.
    @param role The role assigned to the user.
    @return A string representing the encoded JWT.
    """
    now = datetime.now(tz=timezone.utc)
    payload = {
        "sub": user_id,
        "email": email,
        "role": role,
        "iat": now,
        "exp": now + timedelta(minutes=JWT_EXPIRE_MINUTES),
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    logger.info("JWT issued for user_id=%s role=%s", user_id, role)
    return token


async def fetch_user_by_email(pool: asyncpg.Pool, email: str) -> asyncpg.Record:
    """
    @brief Query the users table for a record matching the verified school email.
    @param pool The asyncpg connection pool instance used for database operations.
    @param email The school email address to search for (case-insensitive).
    @return asyncpg.Record containing user 'id', 'school_email', 'role', and 'created_at'.
    @throws HTTPException 404 If no user record is found for the specified email.
    """
    query = """
        SELECT id, school_email, role, created_at
        FROM   users
        WHERE  school_email = $1
        LIMIT  1
    """
    async with pool.acquire() as conn:
        row = await conn.fetchrow(query, email.lower())

    if row is None:
        logger.warning("No user record found for email=%s", email)
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=(
                "Your school account is not yet registered on the InClass Platform. "
                "Please contact your instructor or platform administrator."
            ),
        )

    logger.info("User found: id=%s role=%s", row["id"], row["role"])
    return row


async def fetch_user_by_id(pool: asyncpg.Pool, user_id: str) -> asyncpg.Record:
    """
    @brief Query the users table for the user id stored in a signed JWT subject.
    @param pool The asyncpg connection pool instance.
    @param user_id The unique identifier of the user as a string.
    @return asyncpg.Record containing user 'id', 'school_email', 'role', and 'created_at'.
    @throws HTTPException 404 If no user record matches the provided user_id.
    """
    query = """
        SELECT id, school_email, role, created_at
        FROM   users
        WHERE  id::text = $1
        LIMIT  1
    """
    async with pool.acquire() as conn:
        row = await conn.fetchrow(query, str(user_id))

    if row is None:
        logger.warning("No user record found for id=%s", user_id)
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=(
                "Your user account is not yet registered on the InClass Platform. "
                "Please contact your instructor or platform administrator."
            ),
        )

    logger.info("User found: id=%s role=%s", row["id"], row["role"])
    return row


async def fetch_registered_student_by_email(
    pool: asyncpg.Pool,
    email: str,
) -> asyncpg.Record:
    """
    @brief Ensure there is an active student record for the verified school email.
    @param pool The asyncpg connection pool instance.
    @param email The school email address of the student.
    @return asyncpg.Record containing student data if found.
    @throws HTTPException 404 If no record with 'student' role matches the email.
    """
    query = """
        SELECT id, school_email, role, created_at
        FROM   users
        WHERE  school_email = $1
          AND  role = 'student'
        LIMIT  1
    """
    async with pool.acquire() as conn:
        row = await conn.fetchrow(query, email.lower())

    if row is None:
        logger.warning("Student auth rejected; no student record for email=%s", email)
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=(
                "No registered student account was found for this school email. "
                "Please contact your instructor or platform administrator."
            ),
        )

    logger.info("Student verified: id=%s email=%s", row["id"], row["school_email"])
    return row


async def fetch_registered_instructor_by_email(
    pool: asyncpg.Pool,
    email: str,
) -> asyncpg.Record:
    """
    @brief Ensure there is an instructor record for the provided school email.
    @param pool The asyncpg connection pool instance.
    @param email The school email address of the instructor.
    @return asyncpg.Record containing instructor data if found.
    @throws HTTPException 404 If no record with 'instructor' role matches the email.
    """
    query = """
        SELECT id, school_email, role, created_at
        FROM   users
        WHERE  school_email = $1
          AND  role = 'instructor'
        LIMIT  1
    """
    async with pool.acquire() as conn:
        row = await conn.fetchrow(query, email.lower())

    if row is None:
        logger.warning("Instructor auth rejected; no user record for email=%s", email)
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=(
                "No registered instructor account was found for this school email. "
                "Please contact your platform administrator."
            ),
        )

    logger.info("Instructor verified: id=%s email=%s", row["id"], row["school_email"])
    return row


async def fetch_instructor_courses(pool: asyncpg.Pool, instructor_id: str) -> list[asyncpg.Record]:
    """
    @brief Query the database for all courses assigned to a specific instructor.
    @details This join ensures we only return courses mapped to the instructor's ID.
    @param pool The asyncpg connection pool instance.
    @param instructor_id The unique identifier of the instructor.
    @return A list of asyncpg.Record objects representing the assigned courses.
    """
    query = """
        SELECT c.id, c.course_code, c.course_name, c.term, c.created_at
        FROM   courses c
        JOIN   instructor_course_mapping icm ON c.id = icm.course_id
        WHERE  icm.instructor_id::text = $1
    """
    async with pool.acquire() as conn:
        rows = await conn.fetch(query, str(instructor_id))

    logger.info(
        "Instructor courses fetched: instructor_id=%s count=%d", instructor_id, len(rows)
    )
    return rows


async def update_user_password(
    pool: asyncpg.Pool, user_id: str, hashed_password: str
) -> bool:
    """
    @brief Update the password_hash for the user with the specified ID.
    @param pool The asyncpg connection pool instance.
    @param user_id The unique identifier of the user to update.
    @param hashed_password The new bcrypt-hashed password string.
    @return True if the update was successful (one row affected), False otherwise.
    """
    query = """
        UPDATE users
        SET    password_hash = $1,
               updated_at = NOW()
        WHERE  id::text = $2
    """
    async with pool.acquire() as conn:
        status_msg = await conn.execute(query, hashed_password, str(user_id))

    success = status_msg == "UPDATE 1"
    if success:
        logger.info("Password updated for user_id=%s", user_id)
    else:
        logger.warning("Password update failed or user not found: user_id=%s", user_id)

    return success


async def fetch_password_hash_by_email(pool: asyncpg.Pool, email: str) -> str | None:
    """!
    @brief Retrieve the stored bcrypt hash for a user by their school email.
    @param pool The asyncpg connection pool instance.
    @param email The school email address of the user.
    @return The password hash string if found, otherwise None.
    """
    query = """
        SELECT password_hash
        FROM   users
        WHERE  school_email = $1
        LIMIT  1
    """
    async with pool.acquire() as conn:
        row = await conn.fetchrow(query, email.lower())

    if row is None:
        logger.warning("Password hash lookup failed: email=%s", email)
        return None

    return row["password_hash"]


async def instructorLogin(email: str, password: str) -> dict:
    """
    @brief Authenticates an instructor using their email and password.
    @details Verifies the credentials against the stored password hash and issues a JWT.
             The return dictionary matches the expected authentication script structure.
    @param email The school email address of the instructor.
    @param password The plain-text password to verify.
    @return A dictionary containing the authentication status and token details.
    @throws HTTPException 401 If credentials are invalid or password is not set.
    """
    pool = db_pool

    instructor = await fetch_registered_instructor_by_email(pool, email)

    stored_hash = await fetch_password_hash_by_email(pool, email)
    if not stored_hash or not PasswordHasher.verify(password, stored_hash):
        logger.warning("Login failed: Incorrect password or no password for instructor=%s", email)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    access_token = create_access_token(
        user_id=str(instructor["id"]),
        email=instructor["school_email"],
        role=instructor["role"],
    )

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user_id": str(instructor["id"]),
        "role": instructor["role"],
        "email": instructor["school_email"],
    }


async def studentLogin(email: str, password: str) -> dict:
    """
    @brief Authenticates a student using email and password.
    @param email School email address of the student.
    @param password Plain-text password to verify against the stored bcrypt hash.
    @return Dictionary with keys: access_token, token_type, user_id, role, email.
    @throws HTTPException 401 If credentials are invalid or no password is set.
    @throws HTTPException 404 If no student account exists for the given email.
    """
    pool = db_pool
    student = await fetch_registered_student_by_email(pool, email)

    stored_hash = await fetch_password_hash_by_email(pool, email)
    if not stored_hash or not PasswordHasher.verify(password, stored_hash):
        logger.warning("Login failed: Incorrect password for student=%s", email)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    access_token = create_access_token(
        user_id=str(student["id"]),
        email=student["school_email"],
        role=student["role"],
    )

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user_id": str(student["id"]),
        "role": student["role"],
        "email": student["school_email"],
    }


async def registerStudent(email: str, password: str, full_name: str) -> dict:
    """
    @brief Creates a new student account and issues a JWT.
    @param email School email address; stored lowercase; must be unique.
    @param password Plain-text password; hashed with bcrypt before storage.
    @param full_name Display name stored in users.full_name.
    @return Dictionary with keys: access_token, token_type, user_id, role, email, name.
    @throws HTTPException 400 If a user with the same email already exists.
    """
    pool = db_pool
    hashed_password = PasswordHasher.hash(password)

    query = """
        INSERT INTO users (school_email, full_name, role, password_hash)
        VALUES ($1, $2, 'student', $3)
        RETURNING id, school_email, role, full_name
    """
    try:
        async with pool.acquire() as conn:
            row = await conn.fetchrow(query, email.lower(), full_name, hashed_password)
    except UniqueViolationError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="A user with this email already exists."
        )

    access_token = create_access_token(
        user_id=str(row["id"]),
        email=row["school_email"],
        role=row["role"],
    )

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user_id": str(row["id"]),
        "role": row["role"],
        "email": row["school_email"],
        "name": row["full_name"]
    }


async def listMyCourses(email: str, password: str) -> dict:
    """
    @brief Retrieves the courses assigned to an instructor after optional credential validation.
    @details Ensures the instructor is registered before fetching assigned courses.
    @param email The school email address of the instructor.
    @param password The plain-text password (used for grading script fallback).
    @return A dictionary containing a list of assigned courses.
    """
    pool = db_pool

    if password:
        await instructorLogin(email, password)

    instructor = await fetch_registered_instructor_by_email(pool, email)

    courses = await fetch_instructor_courses(pool, str(instructor["id"]))
    return {"courses": [dict(c) for c in courses]}


async def setInstructorPassword(email: str, password: str | None = None) -> dict:
    """
    @brief Allows an instructor to set their initial password.
    @details Hashes the provided plain-text password and stores it in the database.
    @param email The school email address of the instructor.
    @param password The new plain-text password to set, or None to ignore.
    @return A dictionary indicating the status of the password setup.
    @throws HTTPException 500 If the database update fails.
    """
    pool = db_pool

    instructor = await fetch_registered_instructor_by_email(pool, email)

    if not password:
        logger.info("setInstructorPassword: No password provided for user_id=%s", instructor["id"])
        return {"status": "ignored", "message": "No password provided; no changes made."}

    hashed = PasswordHasher.hash(password)
    success = await update_user_password(pool, str(instructor["id"]), hashed)

    if not success:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update password.",
        )

    return {"status": "success", "message": "Password set successfully."}


async def changeInstructorPassword(
    email: str, password: str, old_password: str, new_password: str
) -> dict:
    """
    @brief Changes the instructor's password after verifying the existing one.
    @details Ensures the old password matches the stored hash before updating.
    @param email The school email address of the instructor.
    @param password The current password (for grading script compatibility).
    @param old_password The old password to verify.
    @param new_password The new password to set.
    @return A dictionary indicating the result of the password change.
    @throws HTTPException 400 If no existing password is found.
    @throws HTTPException 401 If the old password verification fails.
    @throws HTTPException 500 If the database update fails.
    """
    pool = db_pool

    instructor = await fetch_registered_instructor_by_email(pool, email)
    stored_hash = await fetch_password_hash_by_email(pool, email)

    if not stored_hash:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No existing password found. Use 'set' instead.",
        )

    if not PasswordHasher.verify(old_password, stored_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect existing password.",
        )

    new_hashed = PasswordHasher.hash(new_password)
    success = await update_user_password(pool, str(instructor["id"]), new_hashed)

    if not success:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update password.",
        )

    return {"status": "success", "message": "Password changed successfully."}


async def _ensure_instructor_assigned_to_course(
    pool: asyncpg.Pool,
    instructor_id: str,
    course_id: str,
) -> None:
    """
    @brief Validates instructor-course authorization for activity state operations.
    @param pool The asyncpg connection pool instance.
    @param instructor_id The authenticated instructor identifier.
    @param course_id The target course identifier.
    @return None.
    @throws HTTPException 403 If instructor is not assigned to the provided course.
    """
    query = """
        SELECT 1
        FROM   instructor_course_mapping
        WHERE  instructor_id::text = $1
          AND  course_id::text = $2
        LIMIT 1
    """
    async with pool.acquire() as conn:
        row = await conn.fetchrow(query, str(instructor_id), str(course_id))

    if row is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Instructor is not authorized for the target course.",
        )


async def _ensure_student_enrolled_in_course(
    pool: asyncpg.Pool,
    student_id: str,
    course_id: str,
) -> None:
    """
    @brief Validates that a student is enrolled in the target course.
    @param pool The asyncpg connection pool instance.
    @param student_id The student user identifier as a string.
    @param course_id The target course identifier as a string.
    @return None.
    @throws HTTPException 403 If no matching row exists in student_course_mapping.
    """
    query = """
        SELECT 1
        FROM   student_course_mapping
        WHERE  student_id::text = $1
          AND  course_id::text = $2
        LIMIT 1
    """
    async with pool.acquire() as conn:
        row = await conn.fetchrow(query, str(student_id), str(course_id))

    if row is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Student is not enrolled in this course.",
        )


def _coerce_objectives_payload(objectives: object) -> list[str]:
    """
    @brief Normalizes the objectives field from a database row into a list of strings.
    @details Handles both raw JSON strings (from asyncpg text columns) and already-parsed
             lists. Blank entries are filtered out.
    @param objectives Raw value from activities.objectives; may be a JSON string or list.
    @return List of non-empty objective strings; empty list if input is invalid.
    """
    raw_objectives = objectives
    if isinstance(raw_objectives, str):
        try:
            raw_objectives = json.loads(raw_objectives)
        except json.JSONDecodeError:
            raw_objectives = [raw_objectives]

    if not isinstance(raw_objectives, list):
        return []

    return [
        objective.strip()
        for objective in raw_objectives
        if isinstance(objective, str) and objective.strip()
    ]


def _meaningful_words(text: str) -> set[str]:
    """
    @brief Extracts meaningful words from text for objective matching.
    @details Lowercases, strips punctuation, splits on whitespace, and removes
             stop words and tokens shorter than 3 characters.
    @param text Raw answer or objective string.
    @return Set of normalized content words; empty set if text is blank.
    """
    normalized = re.sub(r"[^a-z0-9\s]", " ", (text or "").lower())
    return {
        word
        for word in normalized.split()
        if len(word) > 2 and word not in _AUTO_SCORING_STOP_WORDS
    }


def _objective_is_achieved(objective_words: set[str], matched_words: list[str]) -> bool:
    """
    @brief Determines whether enough objective words appear in a student answer.
    @details For objectives with 1-2 words all must match. For longer objectives
             at least 60% of words must match, with a floor of 2.
    @param objective_words Set of meaningful words extracted from the objective text.
    @param matched_words List of words present in both the objective and the answer.
    @return True if the required match threshold is met; False otherwise.
    """
    if not objective_words:
        return False

    if len(objective_words) <= 2:
        required_matches = len(objective_words)
    else:
        required_matches = max(2, (len(objective_words) * 3 + 4) // 5)

    return len(matched_words) >= required_matches


def _find_new_objective_achievement(
    objectives: list[str],
    answer: str,
    earned_indexes: set[int],
) -> tuple[int, str, list[str]] | None:
    """
    @brief Scans objectives for the first one newly satisfied by the student answer.
    @param objectives Full list of objective strings for the activity.
    @param answer The student's submitted answer text.
    @param earned_indexes Set of objective indexes already awarded a point.
    @return Tuple of (objective_index, objective_text, matched_words) for the first
            newly achieved objective, or None if no new objective is satisfied.
    """
    answer_words = _meaningful_words(answer)

    for objective_index, objective_text in enumerate(objectives):
        objective_words = _meaningful_words(objective_text)
        matched_words = sorted(objective_words & answer_words)
        if (
            objective_index not in earned_indexes
            and _objective_is_achieved(objective_words, matched_words)
        ):
            return objective_index, objective_text, matched_words

    return None


def _build_objective_mini_lesson(objective_text: str, matched_words: list[str]) -> str:
    """
    @brief Builds a brief academic reinforcement note for a newly scored objective.
    @param objective_text The full text of the achieved objective.
    @param matched_words Words from the objective that appeared in the student answer.
    @return A plain-text mini-lesson string surfacing up to three matched key terms.
    """
    if matched_words:
        focus = ", ".join(matched_words[:3])
        return (
            f"Mini-lesson: {objective_text} depends on using key ideas like "
            f"{focus} in a clear explanation, example, or cause-and-effect link."
        )

    return (
        f"Mini-lesson: {objective_text} is strongest when the answer states the "
        "main idea clearly and supports it with one precise academic detail."
    )


def _next_objective_question(objective_text: str) -> str:
    """
    @brief Returns a generic guidance question to steer the student toward the next objective.
    @details The objective text is accepted as a parameter for future customization but is
             intentionally not embedded in the question to avoid revealing answer keywords.
    @param objective_text Text of the next unearned objective (reserved for future use).
    @return A fixed prompt asking the student for a more specific academic detail.
    """
    _ = objective_text
    return (
        "What is one precise academic detail you can add next to strengthen your answer "
        "for this activity objective?"
    )


async def _fetch_activity_status(
    pool: asyncpg.Pool,
    course_id: str,
    activity_no: int,
) -> str:
    """
    @brief Retrieves the current status of a course activity by course_id and activity_no.
    @param pool The asyncpg connection pool instance.
    @param course_id The target course identifier.
    @param activity_no The activity number unique within the course.
    @return The current activity status value.
    @throws HTTPException 404 If no matching activity exists.
    """
    query = """
        SELECT status
        FROM   activities
        WHERE  course_id::text = $1
          AND  activity_no = $2
        LIMIT 1
    """
    async with pool.acquire() as conn:
        row = await conn.fetchrow(query, str(course_id), int(activity_no))

    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Activity not found for the specified course and activity number.",
        )

    return str(row["status"])


def _normalize_objectives(objectives: list[str]) -> list[str]:
    """
    @brief Validates and normalizes objective text values.
    @param objectives Raw objective list from API payload.
    @return A trimmed list of objectives.
    @throws HTTPException 400 If list is empty or contains blank values.
    """
    normalized = [o.strip() for o in objectives if isinstance(o, str)]
    if not normalized or any(not o for o in normalized):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="At least one non-empty objective is required.",
        )

    return normalized


def _build_activity_title(activity_text: str, optional_title: Optional[str]) -> str:
    """
    @brief Produces a non-empty title for activities table compatibility.
    @param activity_text Main activity text.
    @param optional_title Optional explicit title from API payload.
    @return A non-empty title string with max 120 chars.
    """
    if optional_title and optional_title.strip():
        return optional_title.strip()[:120]

    compact_text = " ".join(activity_text.strip().split())
    return compact_text[:120] if compact_text else "Untitled Activity"


async def create_activity(
    pool: asyncpg.Pool,
    instructor_id: str,
    course_id: str,
    activity_no: int,
    activity_text: str,
    objectives: list[str],
    title: Optional[str] = None,
) -> dict:
    """
    @brief Creates a new activity for an authorized instructor (US-F).
    @param pool The asyncpg connection pool instance.
    @param instructor_id Authenticated instructor ID.
    @param course_id Target course ID.
    @param activity_no Activity number unique within the course.
    @param activity_text Core activity text shown to students.
    @param objectives Objective list stored for tutoring/scoring flows.
    @param title Optional activity title.
    @return A dictionary containing created activity metadata.
    @throws HTTPException 400 For invalid required fields.
    @throws HTTPException 403 If instructor is not assigned to the course.
    @throws HTTPException 409 For duplicate activity number in same course.
    """
    await _ensure_instructor_assigned_to_course(pool, instructor_id, course_id)

    if activity_no < 1:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="activity_no must be greater than or equal to 1.",
        )

    clean_text = activity_text.strip()
    if not clean_text:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="activity_text is required.",
        )

    clean_objectives = _normalize_objectives(objectives)
    final_title = _build_activity_title(clean_text, title)

    query = """
        INSERT INTO activities (
            course_id,
            activity_no,
            title,
            description,
            objectives,
            created_by,
            status
        )
        VALUES ($1, $2, $3, $4, $5::jsonb, $6, 'DRAFT')
        RETURNING id, course_id, activity_no, title, description, objectives, status
    """

    try:
        async with pool.acquire() as conn:
            row = await conn.fetchrow(
                query,
                str(course_id),
                int(activity_no),
                final_title,
                clean_text,
                clean_objectives,
                str(instructor_id),
            )
    except UniqueViolationError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An activity with this activity_no already exists in the selected course.",
        ) from exc

    return {
        "status": "success",
        "activity_id": str(row["id"]),
        "course_id": str(row["course_id"]),
        "activity_no": int(row["activity_no"]),
        "title": row["title"],
        "activity_text": row["description"],
        "objectives": row["objectives"],
        "activity_status": row["status"],
    }


async def start_activity(
    pool: asyncpg.Pool,
    instructor_id: str,
    course_id: str,
    activity_no: int,
) -> dict:
    """
    @brief Transitions an activity from DRAFT to ACTIVE for an authorized instructor.
    @param pool The asyncpg connection pool instance.
    @param instructor_id The authenticated instructor identifier.
    @param course_id The target course identifier.
    @param activity_no The activity number unique within the course.
    @return A dictionary containing operation status and resulting activity state.
    @throws HTTPException 403 If instructor is not assigned to the target course.
    @throws HTTPException 404 If activity does not exist.
    @throws HTTPException 409 If the current activity state is not DRAFT.
    """
    await _ensure_instructor_assigned_to_course(pool, instructor_id, course_id)
    current_status = await _fetch_activity_status(pool, course_id, activity_no)

    if current_status != "DRAFT":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                "Invalid activity transition. "
                "Only DRAFT activities can be started."
            ),
        )

    query = """
        UPDATE activities
        SET    status = 'ACTIVE',
               starts_at = NOW()
        WHERE  course_id::text = $1
          AND  activity_no = $2
    """
    async with pool.acquire() as conn:
        status_msg = await conn.execute(query, str(course_id), int(activity_no))

    if status_msg != "UPDATE 1":
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Activity not found for the specified course and activity number.",
        )

    return {
        "status": "success",
        "course_id": str(course_id),
        "activity_no": int(activity_no),
        "activity_status": "ACTIVE",
    }


async def end_activity(
    pool: asyncpg.Pool,
    instructor_id: str,
    course_id: str,
    activity_no: int,
) -> dict:
    """
    @brief Transitions an activity from ACTIVE to ENDED for an authorized instructor.
    @param pool The asyncpg connection pool instance.
    @param instructor_id The authenticated instructor identifier.
    @param course_id The target course identifier.
    @param activity_no The activity number unique within the course.
    @return A dictionary containing operation status and resulting activity state.
    @throws HTTPException 403 If instructor is not assigned to the target course.
    @throws HTTPException 404 If activity does not exist.
    @throws HTTPException 409 If the current activity state is not ACTIVE.
    """
    await _ensure_instructor_assigned_to_course(pool, instructor_id, course_id)
    current_status = await _fetch_activity_status(pool, course_id, activity_no)

    if current_status != "ACTIVE":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                "Invalid activity transition. "
                "Only ACTIVE activities can be ended."
            ),
        )

    query = """
        UPDATE activities
        SET    status = 'ENDED'
        WHERE  course_id::text = $1
          AND  activity_no = $2
    """
    async with pool.acquire() as conn:
        status_msg = await conn.execute(query, str(course_id), int(activity_no))

    if status_msg != "UPDATE 1":
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Activity not found for the specified course and activity number.",
        )

    return {
        "status": "success",
        "course_id": str(course_id),
        "activity_no": int(activity_no),
        "activity_status": "ENDED",
    }


async def startActivity(
    email: str,
    password: str,
    course_id: str,
    activity_no: int,
) -> dict:
    """
    @brief Starts an activity by transitioning state from DRAFT to ACTIVE.
    @details Exact signature required by Phase 1 API Contract.
    """
    pool = db_pool

    if password:
        await instructorLogin(email, password)

    instructor = await fetch_registered_instructor_by_email(pool, email)
    instructor_id = str(instructor["id"])

    return await start_activity(
        pool=pool,
        instructor_id=instructor_id,
        course_id=course_id,
        activity_no=activity_no,
    )


async def createActivity(
    email: str,
    password: str,
    course_id: str,
    activity_no: int,
    activity_text: str,
    objectives: list[str],
    title: Optional[str] = None,
) -> dict:
    """
    @brief Creates an activity with US-F contract-compatible signature.
    @details Validates instructor credentials (fallback mode) and authorization.
    """
    pool = db_pool

    if password:
        await instructorLogin(email, password)

    instructor = await fetch_registered_instructor_by_email(pool, email)
    instructor_id = str(instructor["id"])

    return await create_activity(
        pool=pool,
        instructor_id=instructor_id,
        course_id=course_id,
        activity_no=activity_no,
        activity_text=activity_text,
        objectives=objectives,
        title=title,
    )


async def endActivity(
    email: str,
    password: str,
    course_id: str,
    activity_no: int,
) -> dict:
    """
    @brief Ends an activity by transitioning state from ACTIVE to ENDED.
    @details Exact signature required by Phase 1 API Contract.
    """
    pool = db_pool

    if password:
        await instructorLogin(email, password)

    instructor = await fetch_registered_instructor_by_email(pool, email)
    instructor_id = str(instructor["id"])

    return await end_activity(
        pool=pool,
        instructor_id=instructor_id,
        course_id=course_id,
        activity_no=activity_no,
    )


async def submitAnswer(
    email: str,
    password: str,
    course_id: str,
    activity_no: int,
    answer: str,
) -> dict:
    """
    @brief Scores a student answer by awarding +1 for a newly achieved objective.
    @details Signature is grading-script-compatible; password is accepted but the
             endpoint authenticates the student before this service is called.
    """
    pool = db_pool
    if pool is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Database pool is not initialized.",
        )

    student = await fetch_registered_student_by_email(pool, email)
    student_id = str(student["id"])
    await _ensure_student_enrolled_in_course(pool, student_id, course_id)

    clean_answer = (answer or "").strip()
    async with pool.acquire() as conn:
        async with conn.transaction():
            activity = await conn.fetchrow(
                """
                SELECT id, course_id, activity_no, objectives, status
                FROM   activities
                WHERE  course_id::text = $1
                  AND  activity_no = $2
                LIMIT 1
                FOR UPDATE
                """,
                str(course_id),
                int(activity_no),
            )

            if activity is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Activity not found.",
                )

            activity_status = str(activity["status"])
            if activity_status != "ACTIVE":
                detail = "Only ACTIVE activities accept student answers."
                if activity_status == "ENDED":
                    detail = "This activity is ENDED, so the tutoring flow cannot continue."
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=detail,
                )

            objectives = _coerce_objectives_payload(activity["objectives"])
            earned_rows = await conn.fetch(
                """
                SELECT objective_index
                FROM   objective_score_logs
                WHERE  student_id = $1
                  AND  activity_id = $2
                ORDER BY objective_index
                """,
                student["id"],
                activity["id"],
            )
            earned_indexes = {int(row["objective_index"]) for row in earned_rows}
            current_score = len(earned_indexes)

            if not objectives or current_score >= len(objectives):
                await _upsert_student_activity_progress(
                    conn=conn,
                    student_id=str(student["id"]),
                    course_id=str(activity["course_id"]),
                    activity_id=str(activity["id"]),
                    current_score=current_score,
                    completed=True,
                    last_question=None,
                    last_answer=clean_answer,
                )
                await _log_activity_action(
                    conn=conn,
                    student_id=str(student["id"]),
                    course_id=str(activity["course_id"]),
                    activity_id=str(activity["id"]),
                    action_type="COMPLETED",
                )
                return {
                    "score_delta": 0,
                    "score": current_score,
                    "message": (
                        "Excellent work, all objectives are covered. "
                        f"Your score is {current_score}."
                    ),
                    "completed": True,
                    "next_question": None,
                }

            achievement = _find_new_objective_achievement(
                objectives=objectives,
                answer=clean_answer,
                earned_indexes=earned_indexes,
            )

            if achievement is None:
                next_unearned_index = next(
                    (index for index in range(len(objectives)) if index not in earned_indexes),
                    None,
                )
                next_question = (
                    _next_objective_question(objectives[next_unearned_index])
                    if next_unearned_index is not None
                    else None
                )
                await _upsert_student_activity_progress(
                    conn=conn,
                    student_id=str(student["id"]),
                    course_id=str(activity["course_id"]),
                    activity_id=str(activity["id"]),
                    current_score=current_score,
                    completed=False,
                    last_question=next_question,
                    last_answer=clean_answer,
                )
                return {
                    "score_delta": 0,
                    "score": current_score,
                    "message": (
                        "No new objective was scored yet. Keep trying with a "
                        "more specific academic detail."
                    ),
                    "completed": False,
                    "next_question": next_question,
                }

            objective_index, objective_text, matched_words = achievement
            total_score = current_score + 1
            metadata = {
                "answer": clean_answer,
                "matched_words": matched_words,
                "grading_type": "auto",
            }
            inserted = await conn.fetchrow(
                """
                INSERT INTO objective_score_logs (
                    student_id,
                    course_id,
                    activity_id,
                    objective_index,
                    objective_text,
                    score_delta,
                    total_score,
                    metadata
                )
                VALUES ($1, $2, $3, $4, $5, 1, $6, $7::jsonb)
                ON CONFLICT (student_id, activity_id, objective_index)
                DO NOTHING
                RETURNING total_score
                """,
                student["id"],
                activity["course_id"],
                activity["id"],
                int(objective_index),
                objective_text,
                int(total_score),
                json.dumps(metadata),
            )

            if inserted is None:
                latest_earned_rows = await conn.fetch(
                    """
                    SELECT objective_index
                    FROM   objective_score_logs
                    WHERE  student_id = $1
                      AND  activity_id = $2
                    ORDER BY objective_index
                    """,
                    student["id"],
                    activity["id"],
                )
                latest_earned_indexes = {
                    int(row["objective_index"]) for row in latest_earned_rows
                }
                latest_score = len(latest_earned_indexes)
                next_unearned_index = next(
                    (
                        index
                        for index in range(len(objectives))
                        if index not in latest_earned_indexes
                    ),
                    None,
                )
                next_question = (
                    _next_objective_question(objectives[next_unearned_index])
                    if next_unearned_index is not None
                    else None
                )
                completed = latest_score >= len(objectives)
                await _upsert_student_activity_progress(
                    conn=conn,
                    student_id=str(student["id"]),
                    course_id=str(activity["course_id"]),
                    activity_id=str(activity["id"]),
                    current_score=latest_score,
                    completed=completed,
                    last_question=None if completed else next_question,
                    last_answer=clean_answer,
                )
                if completed:
                    await _log_activity_action(
                        conn=conn,
                        student_id=str(student["id"]),
                        course_id=str(activity["course_id"]),
                        activity_id=str(activity["id"]),
                        action_type="COMPLETED",
                    )
                return {
                    "score_delta": 0,
                    "score": latest_score,
                    "message": (
                        "Excellent work, all objectives are covered. Your score did not change."
                        if completed
                        else (
                            "That objective was already counted, so your score did "
                            "not change. Keep going with another specific idea."
                        )
                    ),
                    "completed": completed,
                    "next_question": None if completed else next_question,
                }

            total_score = int(inserted["total_score"])
            await conn.execute(
                """
                INSERT INTO activity_scores (
                    activity_id,
                    student_id,
                    score,
                    grading_type,
                    note
                )
                VALUES ($1, $2, $3, 'auto', 'Objective-based automatic score')
                ON CONFLICT (activity_id, student_id)
                DO UPDATE SET
                    score = EXCLUDED.score,
                    grading_type = 'auto',
                    note = EXCLUDED.note,
                    updated_at = NOW()
                WHERE activity_scores.grading_type = 'auto'
                """,
                activity["id"],
                student["id"],
                total_score,
            )

            updated_earned_indexes = set(earned_indexes)
            updated_earned_indexes.add(int(objective_index))
            next_unearned_index = next(
                (
                    index
                    for index in range(len(objectives))
                    if index not in updated_earned_indexes
                ),
                None,
            )
            next_question = (
                _next_objective_question(objectives[next_unearned_index])
                if next_unearned_index is not None
                else None
            )
            completed = total_score >= len(objectives)
            response = {
                "score_delta": 1,
                "score": total_score,
                "achieved_objective": objective_text,
                "mini_lesson": _build_objective_mini_lesson(
                    objective_text,
                    matched_words,
                ),
                "message": (
                    "Great work, you earned +1 point. "
                    f"Your score is now {total_score}."
                ),
                "completed": completed,
                "next_question": None if completed else next_question,
            }

            if completed:
                response["message"] = (
                    "Excellent work, you covered all objectives. "
                    f"Your final objective score is {total_score}."
                )

            await _upsert_student_activity_progress(
                conn=conn,
                student_id=str(student["id"]),
                course_id=str(activity["course_id"]),
                activity_id=str(activity["id"]),
                current_score=total_score,
                completed=completed,
                last_question=None if completed else next_question,
                last_answer=clean_answer,
            )

            if completed:
                await _log_activity_action(
                    conn=conn,
                    student_id=str(student["id"]),
                    course_id=str(activity["course_id"]),
                    activity_id=str(activity["id"]),
                    action_type="COMPLETED",
                )

            return response


def _json_safe(value: object) -> object:
    """
    @brief Converts a database value to a JSON-serializable form.
    @param value Any value returned from an asyncpg row field.
    @return ISO-format string for datetime values; the original value otherwise.
    """
    if isinstance(value, datetime):
        return value.isoformat()

    return value


def _coerce_json_object(value: object) -> dict:
    """
    @brief Normalizes a JSONB field value to a Python dict.
    @details asyncpg may return JSONB columns as a dict or as a raw JSON string
             depending on driver version and column type. Both cases are handled.
    @param value Raw field value from an asyncpg row.
    @return Parsed dict; empty dict if value is missing, unparseable, or not an object.
    """
    if isinstance(value, dict):
        return value

    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError:
            return {}
        return parsed if isinstance(parsed, dict) else {}

    return {}


def _timestamp_or_none(value: object) -> datetime | None:
    """
    @brief Coerces a value to a timezone-aware datetime or returns None.
    @param value A datetime object, an ISO-format string, or any other type.
    @return Timezone-aware datetime if conversion succeeds; None otherwise.
    """
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)

    if isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value)
        except ValueError:
            return None
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)

    return None


def _latest_timestamp(*values: object) -> datetime | None:
    """
    @brief Returns the most recent timezone-aware datetime from a variable argument list.
    @param values Any mix of datetime objects, ISO strings, or other types.
    @return The maximum datetime among parseable values; None if no valid timestamps found.
    """
    timestamps = [value for value in (_timestamp_or_none(item) for item in values) if value]
    return max(timestamps) if timestamps else None


async def getActivityLogs(
    email: str,
    password: str,
    activity_id: str,
) -> list[dict]:
    """
    @brief Returns per-student completion logs for an instructor activity.
    @details Uses student_activity_progress as the primary source of truth.
             LEFT JOINs from student_course_mapping so every enrolled student
             appears even if they have not yet interacted with the activity.
    """
    pool = db_pool
    if pool is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Database pool is not initialized.",
        )

    if password:
        await instructorLogin(email, password)

    instructor = await fetch_registered_instructor_by_email(pool, email)

    activity = await pool.fetchrow(
        """
        SELECT id, course_id, title, objectives
        FROM   activities
        WHERE  id::text = $1
        LIMIT  1
        """,
        str(activity_id),
    )

    if activity is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Activity not found.",
        )

    await _ensure_instructor_assigned_to_course(
        pool,
        str(instructor["id"]),
        str(activity["course_id"]),
    )

    objectives = _coerce_objectives_payload(activity["objectives"])
    max_score = len(objectives)

    rows = await pool.fetch(
        """
        SELECT
            u.id::text                          AS student_id,
            u.full_name                         AS student_name,
            u.school_email                      AS student_email,
            sap.current_score                   AS current_score,
            sap.completed                       AS completed,
            sap.last_question                   AS last_question,
            sap.last_answer                     AS last_answer,
            sap.last_interaction_at             AS last_interaction_at
        FROM   student_course_mapping scm
        JOIN   users u
               ON  u.id = scm.student_id
               AND u.role = 'student'
        LEFT   JOIN student_activity_progress sap
               ON  sap.student_id = u.id
               AND sap.activity_id = $1
        WHERE  scm.course_id = $2
        ORDER  BY u.full_name ASC
        """,
        activity["id"],
        activity["course_id"],
    )

    logs: list[dict] = []
    for row in rows:
        has_progress = row["current_score"] is not None
        current_score = int(row["current_score"]) if has_progress else 0
        completed = bool(row["completed"]) if has_progress else False

        if completed:
            completion_status = "Completed"
        elif has_progress:
            completion_status = "In Progress"
        else:
            completion_status = "Not Started"

        last_interaction_at = row["last_interaction_at"]
        last_interaction_str = (
            last_interaction_at.isoformat()
            if isinstance(last_interaction_at, datetime)
            else None
        )

        logs.append(
            {
                "student_id": row["student_id"],
                "student_name": row["student_name"] or row["student_email"],
                "student_email": row["student_email"],
                "activity_id": str(activity["id"]),
                "activity_title": activity["title"],
                "course_id": str(activity["course_id"]),
                "current_score": current_score,
                "max_score": max_score,
                "completed": completed,
                "completion_status": completion_status,
                "last_question": row["last_question"],
                "last_answer": row["last_answer"],
                "last_interaction_at": last_interaction_str,
            }
        )

    _STATUS_ORDER = {"Completed": 0, "In Progress": 1, "Not Started": 2}
    logs.sort(key=lambda item: (_STATUS_ORDER.get(item["completion_status"], 9), item["student_name"]))
    return logs


async def getActivityCompletionLogs(
    email: str,
    password: str,
    activity_id: str,
) -> list[dict]:
    """
    @brief Returns completion log events for a specific activity.
    @details Includes only completed actions and is ordered by most recent first.
    """
    pool = db_pool
    if pool is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Database pool is not initialized.",
        )

    if password:
        await instructorLogin(email, password)

    instructor = await fetch_registered_instructor_by_email(pool, email)

    activity = await pool.fetchrow(
        """
        SELECT id, course_id, title
        FROM   activities
        WHERE  id::text = $1
        LIMIT  1
        """,
        str(activity_id),
    )

    if activity is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Activity not found.",
        )

    await _ensure_instructor_assigned_to_course(
        pool,
        str(instructor["id"]),
        str(activity["course_id"]),
    )

    rows = await pool.fetch(
        """
        SELECT
            aal.student_id::text AS student_id,
            u.full_name          AS student_name,
            u.school_email       AS student_email,
            aal.action_type      AS action_type,
            aal.created_at       AS created_at
        FROM activity_action_logs aal
        JOIN users u ON u.id = aal.student_id
        WHERE aal.activity_id = $1
          AND aal.action_type = 'COMPLETED'
        ORDER BY aal.created_at DESC
        """,
        activity["id"],
    )

    return [
        {
            "student_id": row["student_id"],
            "student_name": row["student_name"] or row["student_email"],
            "student_email": row["student_email"],
            "activity_id": str(activity["id"]),
            "activity_title": activity["title"],
            "course_id": str(activity["course_id"]),
            "action_type": row["action_type"],
            "created_at": row["created_at"].isoformat() if isinstance(row["created_at"], datetime) else None,
        }
        for row in rows
    ]


async def updateActivity(
    email: str, 
    password: str, 
    course_id: str, 
    activity_no: int, 
    activity_text: str | None = None, 
    objectives: list[str] | None = None, 
    title: str | None = None
) -> dict:
    """
    @brief Updates one or more editable fields of an existing activity.
    @details At least one of activity_text, objectives, or title must be provided.
             Only fields that are not None are written; others are left unchanged.
             Instructor must be assigned to the course.
    @param email School email of the authenticated instructor.
    @param password Optional plain-text password for grading-script fallback auth.
    @param course_id The course that owns the activity.
    @param activity_no Activity number within the course.
    @param activity_text Replacement activity description; None to leave unchanged.
    @param objectives Replacement objectives list; None to leave unchanged.
    @param title Replacement title (max 120 chars); None to leave unchanged.
    @return Dictionary with keys: status, message.
    @throws HTTPException 400 If all three fields are None.
    @throws HTTPException 403 If instructor is not assigned to the course.
    @throws HTTPException 404 If the activity does not exist.
    """
    pool = db_pool

    if password:
        await instructorLogin(email, password)

    instructor = await fetch_registered_instructor_by_email(pool, email)
    instructor_id = str(instructor["id"])

    await _ensure_instructor_assigned_to_course(pool, instructor_id, course_id)

    if activity_text is None and objectives is None and title is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, 
            detail="Empty patch: At least one allowed field must be provided."
        )

    updates = []
    values = [course_id, activity_no]
    idx = 3

    if activity_text is not None:
        updates.append(f"description = ${idx}")
        values.append(activity_text.strip())
        idx += 1

    if objectives is not None:
        clean_objectives = _normalize_objectives(objectives)
        updates.append(f"objectives = ${idx}::jsonb")
        values.append(json.dumps(clean_objectives))
        idx += 1

    if title is not None:
        updates.append(f"title = ${idx}")
        clean_title = title.strip()[:120] if title.strip() else "Untitled Activity"
        values.append(clean_title)
        idx += 1

    set_clause = ", ".join(updates)
    query = f"""
        UPDATE activities
        SET {set_clause}, updated_at = NOW()
        WHERE course_id::text = $1 AND activity_no = $2
        RETURNING id
    """

    async with pool.acquire() as conn:
        row = await conn.fetchrow(query, *values)

    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Activity not found.")

    return {
        "status": "success",
        "message": f"Activity {activity_no} updated successfully."
    }


async def submitManualGrade(
    email: str, 
    password: str, 
    course_id: str, 
    activity_no: int, 
    student_email: str, 
    score: float, 
    note: str = ""
) -> dict:
    """
    @brief Records a manual score override for a student on a specific activity.
    @details Verifies instructor course authorization, activity existence and non-ENDED
             status, student enrollment, and score range before upserting into
             activity_scores with grading_type='manual'.
    @param email School email of the authenticated instructor.
    @param password Optional plain-text password for grading-script fallback auth.
    @param course_id The course that owns the activity.
    @param activity_no Activity number within the course.
    @param student_email School email of the student receiving the grade.
    @param score Numeric score to record; must be between 0 and activities.max_score.
    @param note Optional free-text note stored alongside the grade.
    @return Dictionary with keys: status, message.
    @throws HTTPException 400 If score is outside the valid range.
    @throws HTTPException 403 If instructor is not assigned to the course, activity is
                             ENDED, or student is not enrolled in the course.
    @throws HTTPException 404 If the activity or student does not exist.
    """
    pool = db_pool

    if password:
        await instructorLogin(email, password)

    instructor = await fetch_registered_instructor_by_email(pool, email)
    instructor_id = str(instructor["id"])

    await _ensure_instructor_assigned_to_course(pool, instructor_id, course_id)

    activity_query = "SELECT id, max_score, status FROM activities WHERE course_id::text = $1 AND activity_no = $2"
    async with pool.acquire() as conn:
        activity = await conn.fetchrow(activity_query, course_id, activity_no)

    if not activity:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Activity not found.")

    if activity["status"] == "ENDED":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, 
            detail="Cannot submit manual grades for an ended or reset activity."
        )

    student = await fetch_registered_student_by_email(pool, student_email)

    enrolled_query = "SELECT 1 FROM student_course_mapping WHERE student_id = $1 AND course_id::text = $2"
    async with pool.acquire() as conn:
        is_enrolled = await conn.fetchrow(enrolled_query, student["id"], course_id)
        if not is_enrolled:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Student is not enrolled in this course.")

    if score < 0 or score > activity["max_score"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, 
            detail=f"Score must be between 0 and the activity maximum ({activity['max_score']})."
        )

    upsert_query = """
        INSERT INTO activity_scores (activity_id, student_id, score, grading_type, note)
        VALUES ($1, $2, $3, 'manual', $4)
        ON CONFLICT (activity_id, student_id)
        DO UPDATE SET 
            score = EXCLUDED.score, 
            grading_type = 'manual', 
            note = EXCLUDED.note, 
            updated_at = NOW()
    """
    async with pool.acquire() as conn:
        await conn.execute(upsert_query, activity["id"], student["id"], score, note)

    return {
        "status": "success",
        "message": f"Manual grade of {score} successfully logged for {student_email}."
    }


async def _upsert_student_activity_progress(
    conn: asyncpg.Connection,
    student_id: str,
    course_id: str,
    activity_id: str,
    current_score: int,
    completed: bool,
    last_question: str | None,
    last_answer: str | None,
) -> None:
    """
    @brief Inserts or updates a student_activity_progress row for the given student and activity.
    @details Uses ON CONFLICT (student_id, activity_id) DO UPDATE to ensure exactly one row
             per student per activity. Sets last_interaction_at and updated_at to NOW().
    @param conn An active asyncpg connection; must be called inside an open transaction.
    @param student_id Student user ID as a string.
    @param course_id Course ID as a string; denormalized into the progress row.
    @param activity_id Activity UUID as a string.
    @param current_score Number of objectives the student has earned so far.
    @param completed True when current_score equals the total number of objectives.
    @param last_question The guidance question last shown to the student, or None.
    @param last_answer The student's most recent submitted answer text, or None.
    @return None.
    """
    await conn.execute(
        """
        INSERT INTO student_activity_progress (
            student_id,
            course_id,
            activity_id,
            current_score,
            completed,
            last_question,
            last_answer,
            last_interaction_at,
            updated_at
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, NOW(), NOW())
        ON CONFLICT (student_id, activity_id)
        DO UPDATE SET
            course_id = EXCLUDED.course_id,
            current_score = EXCLUDED.current_score,
            completed = EXCLUDED.completed,
            last_question = EXCLUDED.last_question,
            last_answer = EXCLUDED.last_answer,
            last_interaction_at = NOW(),
            updated_at = NOW()
        """,
        student_id,
        course_id,
        activity_id,
        int(current_score),
        bool(completed),
        last_question,
        last_answer,
    )


async def _log_activity_action(
    conn: asyncpg.Connection,
    student_id: str,
    course_id: str,
    activity_id: str,
    action_type: str,
) -> None:
    """
    @brief Records a student activity action event (e.g., COMPLETED).
    @details Uses ON CONFLICT to ensure the same action is logged once per activity.
    """
    await conn.execute(
        """
        INSERT INTO activity_action_logs (
            student_id,
            course_id,
            activity_id,
            action_type
        )
        VALUES ($1, $2, $3, $4)
        ON CONFLICT (student_id, activity_id, action_type)
        DO NOTHING
        """,
        student_id,
        course_id,
        activity_id,
        action_type,
    )


async def getStudentActivity(
    email: str, password: str, course_id: str, activity_no: int
) -> dict:
    """
    @brief Returns the activity content and first guidance question for students.
    """
    pool = db_pool
    student = await fetch_registered_student_by_email(pool, email)
    await _ensure_student_enrolled_in_course(pool, str(student["id"]), course_id)
    activity = await pool.fetchrow(
        """
        SELECT id, title, description, objectives, status
        FROM activities
        WHERE course_id::text = $1
          AND activity_no = $2
        LIMIT 1
        """,
        course_id,
        activity_no,
    )
    if not activity:
        raise HTTPException(status_code=404, detail="Activity not found.")

    activity_status = str(activity["status"])
    if activity_status != "ACTIVE":
        detail = "Only ACTIVE activities can be opened."
        if activity_status == "ENDED":
            detail = "This activity is ENDED, so the tutoring flow cannot continue."
        raise HTTPException(status_code=403, detail=detail)

    objectives = _coerce_objectives_payload(activity["objectives"])
    earned_rows = await pool.fetch(
        """
        SELECT objective_index
        FROM objective_score_logs
        WHERE student_id = $1
          AND activity_id = $2
        ORDER BY objective_index
        """,
        student["id"],
        activity["id"],
    )
    earned_indexes = {int(row["objective_index"]) for row in earned_rows}
    current_score = len(earned_indexes)

    next_unearned_index = next(
        (index for index in range(len(objectives)) if index not in earned_indexes),
        None,
    )
    completed = bool(objectives) and current_score >= len(objectives)
    next_question = (
        _next_objective_question(objectives[next_unearned_index])
        if next_unearned_index is not None
        else None
    )

    if not objectives:
        next_question = (
            "What is one clear, objective-focused explanation you can provide for this activity?"
        )

    async with pool.acquire() as conn:
        await _upsert_student_activity_progress(
            conn=conn,
            student_id=str(student["id"]),
            course_id=str(course_id),
            activity_id=str(activity["id"]),
            current_score=current_score,
            completed=completed,
            last_question=next_question,
            last_answer=None,
        )

    return {
        "title": activity["title"],
        "activity_text": activity["description"],
        "status": activity_status,
        "score": current_score,
        "completed": completed,
        "next_question": next_question if not completed else None,
    }


async def _fetch_activity_reference_by_id(
    pool: asyncpg.Pool,
    activity_id: str,
) -> tuple[str, int]:
    """
    @brief Resolves an activity UUID to its course_id and activity_no.
    @throws HTTPException 404 if activity does not exist.
    """
    row = await pool.fetchrow(
        """
        SELECT course_id::text AS course_id, activity_no
        FROM activities
        WHERE id::text = $1
        LIMIT 1
        """,
        str(activity_id),
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Activity not found.")
    return str(row["course_id"]), int(row["activity_no"])


async def getStudentActivityById(
    email: str,
    password: str,
    activity_id: str,
) -> dict:
    """
    @brief Wrapper for getStudentActivity using activity UUIDs.
    """
    pool = db_pool
    if pool is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Database pool is not initialized.",
        )
    course_id, activity_no = await _fetch_activity_reference_by_id(pool, activity_id)
    return await getStudentActivity(
        email=email,
        password=password,
        course_id=course_id,
        activity_no=activity_no,
    )


async def submitAnswerByActivityId(
    email: str,
    password: str,
    activity_id: str,
    answer: str,
) -> dict:
    """
    @brief Wrapper for submitAnswer using activity UUIDs.
    """
    pool = db_pool
    if pool is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Database pool is not initialized.",
        )
    course_id, activity_no = await _fetch_activity_reference_by_id(pool, activity_id)
    return await submitAnswer(
        email=email,
        password=password,
        course_id=course_id,
        activity_no=activity_no,
        answer=answer,
    )
async def resetActivity(
    email: str, password: str, course_id: str, activity_no: int
) -> dict:
    """
    @brief Deletes all student scores for an activity and sets its status to ENDED.
    @details Removes rows from objective_score_logs, activity_scores, and
             student_activity_progress in a single transaction. The activity
             status becomes ENDED, not DRAFT; it cannot be restarted after reset.
    @param email School email of the authenticated instructor.
    @param password Optional plain-text password for grading-script fallback auth.
    @param course_id The course that owns the activity.
    @param activity_no Activity number within the course.
    @return Dictionary with keys: status, message.
    @throws HTTPException 403 If instructor is not assigned to the course.
    @throws HTTPException 404 If the activity does not exist.
    """
    pool = db_pool
    if password: await instructorLogin(email, password)
    instructor = await fetch_registered_instructor_by_email(pool, email)
    await _ensure_instructor_assigned_to_course(pool, str(instructor["id"]), course_id)
    async with pool.acquire() as conn:
        async with conn.transaction():
            activity = await conn.fetchrow("SELECT id FROM activities WHERE course_id::text = $1 AND activity_no = $2 FOR UPDATE", course_id, activity_no)
            if not activity: raise HTTPException(404, detail="Not found.")
            await conn.execute("DELETE FROM objective_score_logs WHERE activity_id = $1", activity["id"])
            await conn.execute("DELETE FROM activity_scores WHERE activity_id = $1", activity["id"])
            await conn.execute("DELETE FROM activity_action_logs WHERE activity_id = $1", activity["id"])
            await conn.execute("DELETE FROM student_activity_progress WHERE activity_id = $1", activity["id"])
            await conn.execute("UPDATE activities SET status = 'ENDED' WHERE id = $1", activity["id"])
    return {"status": "success", "message": "Activity reset."}
async def listActivities(
    email: str, password: str, course_id: str
) -> dict:
    """
    @brief Returns all activities for a course the instructor is assigned to.
    @param email School email of the authenticated instructor.
    @param password Optional plain-text password for grading-script fallback auth.
    @param course_id The course to query.
    @return Dictionary with key "activities"; value is a list of objects each containing
            activity_id, activity_no, title, and status. Ordered by activity_no ascending.
    @throws HTTPException 403 If instructor is not assigned to the course.
    """
    pool = db_pool
    if password: await instructorLogin(email, password)
    instructor = await fetch_registered_instructor_by_email(pool, email)
    await _ensure_instructor_assigned_to_course(pool, str(instructor["id"]), course_id)
    rows = await pool.fetch("SELECT id, activity_no, title, description, status FROM activities WHERE course_id::text = $1 ORDER BY activity_no ASC", course_id)
    activities = [{"activity_id": str(r["id"]), "activity_no": r["activity_no"], "title": r["title"], "status": r["status"]} for r in rows]
    return {"activities": activities}


async def getStudentCourses(email: str) -> list[dict]:
    """
    @brief Returns all courses a student is enrolled in, with per-activity progress.
    @details Queries student_course_mapping for enrolled courses, then for each course
             LEFT JOINs activities against student_activity_progress to include
             current_score and completed even when no progress row exists yet.
    @param email School email of the authenticated student.
    @return List of course dicts each containing: course_id, course_code, course_name,
            and activities (list of activity_id, activity_no, title, description,
            status, current_score, completed).
    @throws HTTPException 404 If no student account exists for the given email.
    """
    pool = db_pool
    student = await fetch_registered_student_by_email(pool, email)
    student_id = student["id"]

    course_rows = await pool.fetch(
        """
        SELECT c.id, c.course_code, c.course_name
        FROM   courses c
        JOIN   student_course_mapping scm ON scm.course_id = c.id
        WHERE  scm.student_id = $1
        ORDER  BY c.course_name ASC
        """,
        student_id,
    )

    courses: list[dict] = []
    for course in course_rows:
        course_id = str(course["id"])

        activity_rows = await pool.fetch(
            """
            SELECT
                a.id,
                a.activity_no,
                a.title,
                a.description,
                a.status,
                sap.current_score,
                sap.completed
            FROM   activities a
            LEFT   JOIN student_activity_progress sap
                   ON  sap.activity_id = a.id
                   AND sap.student_id  = $1
            WHERE  a.course_id::text = $2
            ORDER  BY a.activity_no ASC
            """,
            student_id,
            course_id,
        )

        activities = [
            {
                "activity_id":   str(r["id"]),
                "activity_no":   r["activity_no"],
                "title":         r["title"],
                "description":   r["description"],
                "status":        r["status"],
                "current_score": int(r["current_score"]) if r["current_score"] is not None else 0,
                "completed":     bool(r["completed"]) if r["completed"] is not None else False,
            }
            for r in activity_rows
        ]

        courses.append(
            {
                "course_id":   course_id,
                "course_code": course["course_code"],
                "course_name": course["course_name"],
                "activities":  activities,
            }
        )

    return courses
