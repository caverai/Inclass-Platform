"""
@file services.py
@brief User and Course management services for the InClass Platform.
@details This module provides asynchronous database operations for fetching user records, 
         managing instructor courses, and updating user credentials.
"""

import logging

import asyncpg
from fastapi import HTTPException, status

logger = logging.getLogger("inclass.auth")


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

    # 'UPDATE 1' indicates exactly one row was modified.
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
