# InClass Platform

A classroom activity platform with instructor-led scoring and student participation. Instructors create and manage activities with learning objectives. Students enroll in courses, answer questions, and earn scores automatically or via manual grading.

## Stack

- **Backend**: Python 3.11, FastAPI, asyncpg, PostgreSQL (Supabase)
- **Frontend**: React 18, TypeScript, Vite, Tailwind CSS
- **Auth**: JWT (HS256), Google OAuth 2.0, bcrypt password hashing
- **Docs**: Doxygen

## Project Structure

```
app/
  main.py         # FastAPI app, route handlers, auth dependencies
  services.py     # All database logic and business rules
db/
  supabase_schema.sql
  migrations/
frontend/
  src/
    api/          # Axios API clients (authApi, instructorApi, studentApi)
    pages/        # Route-level React components
    components/   # Shared UI components
    types/        # TypeScript interfaces
```

## Setup

### 1. Database

Open Supabase SQL Editor and run:

```
db/supabase_schema.sql
```

If your database already existed before this version, also run:

```
db/migrations/2026-04-26_us_b_schema_patch.sql
db/migrations/2026-05-11_us_k_objective_scoring.sql
```

The second migration creates `objective_score_logs`, which is required for `POST /student/answer`. Without it, that endpoint fails.

Tables: `users`, `courses`, `instructor_course_mapping`, `student_course_mapping`, `activities`, `student_activity_progress`, `objective_score_logs`, `activity_scores`.

### 2. Environment

Copy `.env.example` to `.env` and set:

```
GOOGLE_CLIENT_ID=<your Google OAuth client ID>
SCHOOL_EMAIL_DOMAIN=<e.g. mef.edu.tr>
DATABASE_URL=<Supabase Postgres connection string>
JWT_SECRET=<random secret>
```

### 3. Run

```bash
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Default: `http://127.0.0.1:8000/` — redirects to `/frontend/`.

### 4. Frontend (dev mode)

```bash
cd frontend
npm install
npm run dev
```

Proxies API calls to `http://127.0.0.1:8000` by default (see `vite.config.ts`).

## Authentication

Two token types are stored separately in `localStorage`:

| Key                | Written by           | Used for                  |
|--------------------|----------------------|---------------------------|
| `instructor_token` | `POST /instructor/login` | All `/instructor/*` calls |
| `student_token`    | `POST /student/login` or `POST /student/register` | All `/student/*` calls |

Tokens are HS256 JWTs signed with `JWT_SECRET`. Payload: `sub` (user UUID), `email`, `role`, `exp` (24 h).

**Grading script fallback**: `verify_student` and `verify_instructor` also accept a raw `email` value in the request body or query string with no `Authorization` header. This is intentional for automated grading script compatibility. It is a known security risk (ghost login) and should be removed in production.

## API Endpoints

All protected endpoints require `Authorization: Bearer <token>` unless noted.

### Health

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/health/db` | None | Returns `{"database": "ok"}` if the connection pool is healthy. |

### Authentication

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/auth/google` | None | Google federated sign-in for any role. Body: `{"id_token": "..."}`. Returns `AuthResponse`. Email must match `SCHOOL_EMAIL_DOMAIN`. |
| POST | `/auth/google/student` | None | Same as above but enforces `role=student`. |
| GET | `/auth/google/student/test` | None | Serves an HTML test page for Google sign-in. |
| GET | `/auth/me` | Bearer | Returns `{user_id, email, role}` for the token owner. |
| POST | `/instructor/login` | None | Password-based instructor login. Body: `{"email": "...", "password": "..."}`. Returns `AuthResponse`. |
| POST | `/student/login` | None | Password-based student login. Body: `{"email": "...", "password": "..."}`. Returns `AuthResponse`. |
| POST | `/student/register` | None | Student self-registration. Body: `{"full_name", "email", "password", "confirm_password"}`. Email must match `SCHOOL_EMAIL_DOMAIN`. Returns `AuthResponse`. |
| POST | `/instructor/password/set` | Instructor | Sets the initial password for an instructor account. Body: `{"password": "..."}`. |
| POST | `/instructor/password/change` | Instructor | Changes the instructor password. Body: `{"old_password": "...", "new_password": "..."}`. |

`AuthResponse` shape:

```json
{
  "access_token": "...",
  "token_type": "bearer",
  "user_id": "uuid",
  "role": "instructor | student",
  "email": "user@school.edu",
  "name": "Full Name"
}
```

### Authorization Tests

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/instructor/test` | Instructor | Returns `{access, email, role}` for valid instructor tokens. |
| GET | `/student/test` | Student | Returns `{access, email, role}` for valid student tokens. |

### Instructor

All instructor endpoints require an `instructor` role token.

| Method | Path | Description |
|--------|------|-------------|
| GET | `/instructor/courses` | Lists all courses assigned to the authenticated instructor via `instructor_course_mapping`. |
| GET | `/instructor/activities?course_id=<id>` | Lists all activities in the specified course. Each item includes `activity_id`, `activity_no`, `status` (`DRAFT`/`ACTIVE`/`ENDED`), `title`, `description`, and `objectives`. |
| POST | `/instructor/activity/create` | Creates an activity. Body: `{course_id, activity_no, activity_text, objectives: [...], title?}`. Returns the created activity record. Fails `409` on duplicate `(course_id, activity_no)`. |
| PATCH | `/instructor/activity/{course_id}/{activity_no}` | Updates activity text, objectives, or title. Body fields are all optional: `{activity_text?, objectives?, title?}`. |
| POST | `/instructor/activity/start?course_id=<id>&activity_no=<n>` | Transitions activity from `DRAFT` → `ACTIVE`. Fails `409` if not in `DRAFT`. |
| POST | `/instructor/activity/end?course_id=<id>&activity_no=<n>` | Transitions activity from `ACTIVE` → `ENDED`. Fails `409` if not in `ACTIVE`. |
| POST | `/instructor/activity/reset?course_id=<id>&activity_no=<n>` | Deletes all student scores for the activity and sets status to `ENDED`. |
| POST | `/instructor/activity/{course_id}/{activity_no}/grade/manual` | Submits a manual score for a specific student. Body: `{student_email, score, note?}`. Overwrites any existing manual grade. |
| GET | `/instructor/activities/{activity_id}/logs` | Returns completion logs for all enrolled students. Includes students with no progress (status `Not Started`). See response shape below. |

**Activity log response item**:

```json
{
  "student_id": "uuid",
  "student_name": "Full Name",
  "student_email": "student@school.edu",
  "activity_id": "uuid",
  "activity_title": "Activity 1",
  "course_id": "uuid",
  "current_score": 2,
  "max_score": 3,
  "completed": true,
  "completion_status": "Completed | In Progress | Not Started",
  "last_question": "...",
  "last_answer": "...",
  "last_interaction_at": "2026-05-14T10:00:00Z"
}
```

Results are sorted: Completed first, then In Progress, then Not Started.

### Student

All student endpoints require a `student` role token.

| Method | Path | Description |
|--------|------|-------------|
| GET | `/student/courses` | Lists all courses the student is enrolled in, with activities and current progress (score, completed) per activity. |
| GET | `/student/activity?course_id=<id>&activity_no=<n>` | Returns content of an ACTIVE activity. Fails `403` if the activity is `DRAFT` or `ENDED`. |
| POST | `/student/answer` | Submits an answer for objective-based automatic scoring. Body: `{course_id, activity_no, answer, email?, password?}`. Returns score delta, total score, mini-lesson (on new objective hit), completion status, and the next question. |

**Scoring rules** (`POST /student/answer`): each learning objective earns at most +1 point. The service uses keyword matching against the objective text. Repeated matching of an already-scored objective adds no points. When all objectives are achieved, `completed=true` is returned and no further question is issued. Score events are logged to `objective_score_logs`.

## Documentation Generation

This project uses Doxygen. All Python functions have `@brief`, `@param`, `@return`, and `@throws` tags.

Generate HTML docs:

```bash
# Windows
./doxy.ps1

# Linux / macOS
./doxy.sh
```

Output: `docs/gen/html/index.html`

## Enrolling Students

Students are not auto-enrolled. A row must exist in `student_course_mapping` for a student to see a course. Insert via Supabase SQL Editor:

```sql
INSERT INTO student_course_mapping (student_id, course_id)
SELECT u.id, '<course-uuid>'
FROM users u
WHERE u.school_email = 'student@school.edu';
```

## Known Limitations

- `/student/activities/:id` and `/student/activities/:id/chat` are called by the frontend React app but are not implemented in the backend. The backend uses composite key routes (`course_id` + `activity_no`). These frontend paths will 404 unless a migration to UUID-based routes is done.
- The grading script fallback in `verify_student` / `verify_instructor` must be removed before any production deployment.
