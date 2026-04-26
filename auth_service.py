"""
InClass Platform — Google Federated Sign-In Service
----------------------------------------------------
#TASK-101 | Auth Service Bootstrap
Implements Google ID Token verification, school email enforcement,
PostgreSQL role mapping, and JWT session issuance.

Linked work items:
  ClickUp : TASK-101 (Auth Service)
  GitHub  : feature/task-101-google-auth
"""

# Dependencies
#   pip install fastapi uvicorn google-auth asyncpg python-jose[cryptography]
#               python-dotenv pydantic

import os
import logging
from datetime import datetime, timedelta, timezone

import asyncpg
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.responses import HTMLResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from google.auth.transport import requests as google_requests
from google.oauth2 import id_token as google_id_token
from jose import JWTError, jwt
from pydantic import BaseModel

# #TASK-101 | Configuration & environment loading

load_dotenv()

GOOGLE_CLIENT_ID: str = os.environ["GOOGLE_CLIENT_ID"]
SCHOOL_EMAIL_DOMAIN: str = os.environ["SCHOOL_EMAIL_DOMAIN"]
DATABASE_URL: str = os.environ["DATABASE_URL"]
JWT_SECRET: str = os.environ["JWT_SECRET"]
JWT_ALGORITHM: str = os.getenv("JWT_ALGORITHM", "HS256")
JWT_EXPIRE_MINUTES: int = int(os.getenv("JWT_EXPIRE_MINUTES", "60"))

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("inclass.auth")

# FastAPI app & DB connection pool

app = FastAPI(
    title="InClass Auth Service",
    description="Google Federated Sign-In with role-based access",
    version="1.0.0",
)

# #TASK-101 | DB pool lifecycle — created on startup, closed on shutdown
@app.on_event("startup")
async def startup():
    app.state.db_pool = await asyncpg.create_pool(DATABASE_URL, min_size=2, max_size=10)
    logger.info("Database connection pool created.")

@app.on_event("shutdown")
async def shutdown():
    await app.state.db_pool.close()
    logger.info("Database connection pool closed.")


# Pydantic models

class GoogleTokenRequest(BaseModel):
    """#TASK-101 | Request body — client sends the raw Google ID token."""
    id_token: str

class AuthResponse(BaseModel):
    """#TASK-101 | Successful auth response — returns a signed JWT."""
    access_token: str
    token_type: str = "bearer"
    user_id: str
    role: str
    email: str

# #TASK-101 | Step 1: Verify Google ID Token

def verify_google_id_token(raw_token: str) -> dict:
    """
    Validate the Google ID token against Google's public keys.
    Raises HTTPException 401 if the token is invalid or expired.

    #TASK-101 | Google token verification
    Docs: https://developers.google.com/identity/gsi/web/guides/verify-google-id-token
    """
    try:
        claims = google_id_token.verify_oauth2_token(
            raw_token,
            google_requests.Request(),
            audience=GOOGLE_CLIENT_ID,
        )
        logger.info("Google token verified for sub=%s", claims.get("sub"))
        return claims

    except ValueError as exc:
        # Token is malformed, expired, or issued for a different client_id
        logger.warning("Google token verification failed: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired Google ID token.",
        ) from exc

# #TASK-101 | Step 2: Enforce school email domain

def enforce_school_email(email: str) -> None:
    """
    Ensure the authenticated user's email belongs to the institution domain.
    Raises HTTPException 403 for personal / non-school addresses.

    #TASK-101 | School email domain enforcement
    """
    if not email.lower().endswith(f"@{SCHOOL_EMAIL_DOMAIN.lower()}"):
        logger.warning("Non-school email rejected: %s", email)
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                f"Access is restricted to @{SCHOOL_EMAIL_DOMAIN} addresses. "
                f"Please sign in with your school account."
            ),
        )

# #TASK-101 | Step 3: Map email → user record & role in PostgreSQL

async def fetch_user_by_email(pool: asyncpg.Pool, email: str) -> asyncpg.Record:
    """
    Query the `users` table for a record matching the verified school email.

    Returns the full row on success.
    Raises HTTPException 404 if no record exists (covers the student
    identity-not-found requirement — #TASK-101).
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
        # #TASK-101 | Clear error for unmapped identities (students or instructors)
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


async def fetch_registered_student_by_email(
    pool: asyncpg.Pool,
    email: str,
) -> asyncpg.Record:
    """
    Student-only counterpart for auth verification.
    Uses the already-verified Google school email and ensures there is an
    active student record in `users`.
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

# #TASK-101 | Step 4: Issue a signed JWT session token

def create_access_token(user_id: str, email: str, role: str) -> str:
    """
    Mint a short-lived JWT containing the user's identity and role.
    Downstream services validate this token independently — no DB hit required.

    #TASK-101 | JWT issuance
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

# #TASK-101 | Main auth endpoint

@app.post(
    "/auth/google",
    response_model=AuthResponse,
    summary="Google Federated Sign-In",
    tags=["Authentication"],
)
async def google_sign_in(body: GoogleTokenRequest) -> AuthResponse:
    """
    Full sign-in flow:
      1. Verify Google ID token         (#TASK-101)
      2. Enforce school email domain     (#TASK-101)
      3. Map identity to DB user record  (#TASK-101)
      4. Return signed JWT               (#TASK-101)

    Error codes:
      401 — invalid / expired Google token
      403 — non-school email address
      404 — email not mapped to any user record
    """
    # --- 1. Verify token with Google ---
    claims = verify_google_id_token(body.id_token)
    email: str = claims.get("email", "")

    # --- 2. Enforce school email ---
    enforce_school_email(email)

    # --- 3. Fetch user & role from DB ---
    user = await fetch_user_by_email(app.state.db_pool, email)

    # --- 4. Issue JWT ---
    access_token = create_access_token(
        user_id=str(user["id"]),
        email=user["school_email"],
        role=user["role"],
    )

    return AuthResponse(
        access_token=access_token,
        user_id=str(user["id"]),
        role=user["role"],
        email=user["school_email"],
    )


@app.post(
    "/auth/google/student",
    response_model=AuthResponse,
    summary="Google Sign-In (Student)",
    tags=["Authentication"],
)
async def google_student_sign_in(body: GoogleTokenRequest) -> AuthResponse:
    """
    Student auth flow for US-B / US-C support.
    1) Verify Google ID token
    2) Enforce school domain
    3) Ensure email maps to a registered student in `users`
    4) Return JWT
    """
    claims = verify_google_id_token(body.id_token)
    email: str = claims.get("email", "")

    enforce_school_email(email)
    student = await fetch_registered_student_by_email(app.state.db_pool, email)

    access_token = create_access_token(
        user_id=str(student["id"]),
        email=student["school_email"],
        role=student["role"],
    )

    return AuthResponse(
        access_token=access_token,
        user_id=str(student["id"]),
        role=student["role"],
        email=student["school_email"],
    )

# #TASK-101 | Optional: token introspection helper for other services

bearer_scheme = HTTPBearer()

def decode_access_token(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
) -> dict:
    """
    Dependency — verifies an InClass JWT and returns its payload.
    Use this in any route that requires an authenticated user.

    #TASK-101 | JWT verification dependency
    """
    try:
        payload = jwt.decode(
            credentials.credentials,
            JWT_SECRET,
            algorithms=[JWT_ALGORITHM],
        )
        return payload
    except JWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session token is invalid or has expired. Please sign in again.",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc

@app.get(
    "/auth/me",
    summary="Current user identity",
    tags=["Authentication"],
)
async def get_current_user(payload: dict = Depends(decode_access_token)) -> dict:
    """
    Returns the identity embedded in a valid JWT.
    Useful for frontend session restoration.

    #TASK-101 | /me endpoint — session check
    """
    return {
        "user_id": payload["sub"],
        "email":   payload["email"],
        "role":    payload["role"],
    }


@app.get(
    "/health/db",
    summary="Database health check",
    tags=["Health"],
)
async def db_health() -> dict:
    """Lightweight connectivity check for DATABASE_URL / Supabase readiness."""
    async with app.state.db_pool.acquire() as conn:
        ok = await conn.fetchval("SELECT 1")
    return {"database": "ok" if ok == 1 else "unexpected"}


@app.get(
        "/auth/google/student/test",
        response_class=HTMLResponse,
        summary="Google student sign-in test page",
        tags=["Authentication"],
)
def google_student_sign_in_test_page() -> HTMLResponse:
        """Simple browser test page to get a Google ID token and call student auth."""
        html = f"""
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>InClass Student Google Sign-In Test</title>
    <script src="https://accounts.google.com/gsi/client" async defer></script>
    <style>
        body {{
            font-family: Segoe UI, Arial, sans-serif;
            max-width: 760px;
            margin: 40px auto;
            padding: 0 16px;
            line-height: 1.45;
        }}
        .panel {{
            border: 1px solid #d9d9d9;
            border-radius: 10px;
            padding: 16px;
            margin-top: 16px;
            background: #fafafa;
        }}
        pre {{
            white-space: pre-wrap;
            word-break: break-word;
            background: #0f172a;
            color: #e2e8f0;
            border-radius: 8px;
            padding: 12px;
            min-height: 84px;
        }}
    </style>
</head>
<body>
    <h1>Student Google Sign-In Test</h1>
    <p>Use your school Google account. This page sends the Google ID token to <strong>/auth/google/student</strong>.</p>

    <div class="panel">
        <div id="g_id_onload"
                 data-client_id="{GOOGLE_CLIENT_ID}"
                 data-callback="handleCredentialResponse"
                 data-auto_prompt="false">
        </div>
        <div class="g_id_signin"
                 data-type="standard"
                 data-size="large"
                 data-theme="outline"
                 data-text="signin_with"
                 data-shape="pill"
                 data-logo_alignment="left">
        </div>
    </div>

    <div class="panel">
        <h3>Backend Response</h3>
        <pre id="result">Waiting for sign-in...</pre>
    </div>

    <script>
        async function handleCredentialResponse(response) {{
            const resultEl = document.getElementById('result');
            resultEl.textContent = 'Google token received. Calling backend...';

            try {{
                const apiResponse = await fetch('/auth/google/student', {{
                    method: 'POST',
                    headers: {{ 'Content-Type': 'application/json' }},
                    body: JSON.stringify({{ id_token: response.credential }})
                }});

                const data = await apiResponse.json();
                resultEl.textContent = JSON.stringify({{
                    status: apiResponse.status,
                    ok: apiResponse.ok,
                    data: data
                }}, null, 2);
            }} catch (error) {{
                resultEl.textContent = 'Request failed: ' + String(error);
            }}
        }}
        window.handleCredentialResponse = handleCredentialResponse;
    </script>
</body>
</html>
"""
        return HTMLResponse(content=html)

# Entry point (local dev only — use `uvicorn auth_service:app` in production)

if __name__ == "__main__":
    import uvicorn
    # #TASK-101 | Local dev server
    uvicorn.run("auth_service:app", host="0.0.0.0", port=8000, reload=True)
