# InClass Platform

A classroom activity platform built for the MEF Software Engineering Term Project. Instructors create and manage activities with learning objectives. Students enroll in courses, participate in an LLM-guided tutoring flow, and earn scores automatically based on objective achievement — or via instructor manual grading.

## Stack

- **Backend**: Python 3.11, FastAPI, asyncpg, PostgreSQL (Supabase)
- **Frontend**: React 18, TypeScript, Vite, Tailwind CSS
- **Auth**: Google OAuth 2.0 (federated sign-in) + password-based fallback, JWT (HS256), bcrypt
- **LLM**: DeepSeek API (objective scoring + guiding question generation), keyword fallback
- **Docs**: Doxygen (HTML output at `docs/gen/html/index.html`)

## Project Structure

```
app/
  main.py              # FastAPI app, all route handlers, auth dependencies
  services.py          # All business logic, DB queries, LLM calls
db/
  supabase_schema.sql  # Full schema — run this on a fresh database
  migrations/          # Incremental patches (run in date order if upgrading)
    2026-04-26_us_b_schema_patch.sql
    2026-04-29_us_d_auth_schema.sql
    2026-05-01_us_h_activity_no_and_state.sql
    2026-05-10_us_f_create_activity_objectives.sql
    2026-05-11_us_g_l_schema.sql
    2026-05-11_us_k_objective_scoring.sql
    2026-05-12_us_j_student_activity_progress.sql
    2026-05-14_us_m_activity_action_logs.sql
frontend/
  src/
    api/
      authApi.ts        # Google sign-in, password login, /auth/me
      instructorApi.ts  # Courses, activities, logs, enrollment, manual grade
      studentApi.ts     # Student courses, activity access, tutoring chat
      client.ts         # Axios instance with auth header injection
    pages/
      LoginPage.tsx              # Instructor login (password + Google)
      StudentLoginPage.tsx       # Student login (password + Google)
      StudentRegisterPage.tsx    # Student self-registration
      InstructorDashboard.tsx    # Instructor course list + course creation
      InstructorCoursePage.tsx   # Activity list with start / end / reset controls
      ActivityFormPage.tsx       # Create / edit activity (text + objectives)
      ActivityLogsPage.tsx       # Per-student progress table + manual grade modal
      CourseStudentsPage.tsx     # Enrolled students list + enroll/unenroll
      StudentDashboard.tsx       # Student course + activity list
      StudentActivityPage.tsx    # Tutoring chat with live score and mini-lessons
    components/
      GoogleSignInButton.tsx   # Google Identity Services button wrapper
      ManualGradeModal.tsx     # Manual grading dialog (US-L)
      EnrollStudentsModal.tsx  # Bulk student enrollment by email (US-C)
      CreateCourseModal.tsx    # New course creation dialog
      ConfirmModal.tsx         # Generic confirmation dialog
      ChatMessage.tsx          # Tutor/student chat bubbles + mini-lesson display
      Layout.tsx               # App shell with nav
      ProtectedRoute.tsx       # Role-aware route guards
      StatusBadge.tsx          # DRAFT / ACTIVE / ENDED badge
    types/
      index.ts          # All shared TypeScript interfaces
    utils/
      demoAuth.ts       # Demo/grading script auth helpers
tests/
  unit/
    test_auth.py           # JWT creation, password hashing
    test_scoring_logic.py  # Objective achievement, mini-lesson, keyword matching
  integration/
    test_auth_routes.py        # /auth/google, /instructor/login, /student/login
    test_activities_crud.py    # Create, update, list activities
    test_instructor_courses.py # Course listing, authorization
    test_manual_grading.py     # Manual grade submission (all states including ENDED)
    test_student_access.py     # Activity access control (ACTIVE-only gate)
  acceptance/
    test_scoring_and_progress.py    # Full tutoring + scoring flow (US-J, US-K)
    test_reset_activity_cascade.py  # Reset deletes scores, sets ENDED (US-M)
Sprint_Data/
  S1_SPRINT_GOAL.md / S2_SPRINT_GOAL.md
  S1_SPRINT_BACKLOG.csv / S2_SPRINT_BACKLOG.csv
  S1_SCOPE_CHANGE_LOG.csv / S2_SCOPE_CHANGE_LOG.csv
  S1_REVIEW.md / S2_REVIEW.md
  S1_RETRO.md / S2_RETRO.md
  S1_TEST_EVIDENCE.md / S2_TEST_EVIDENCE.md
  sprint1_burndown.png / sprint2_burndown.png
```

## Setup

### 1. Database

On a fresh Supabase project, open the SQL Editor and run:

```
db/supabase_schema.sql
```

If upgrading an existing database, run the migration files in date order instead.

Database tables: `users`, `courses`, `instructor_course_mapping`, `student_course_mapping`, `activities`, `student_activity_progress`, `objective_score_logs`, `activity_scores`, `activity_action_logs`.

### 2. Environment

Copy `.env.example` to `.env` and fill in all values:

```
GOOGLE_CLIENT_ID=<your Google OAuth client ID>
SCHOOL_EMAIL_DOMAIN=mef.edu.tr
DATABASE_URL=postgresql://user:password@host:5432/postgres
JWT_SECRET=<random secret string>
JWT_ALGORITHM=HS256
JWT_EXPIRE_MINUTES=60
DEEPSEEK_API_KEY=<your DeepSeek API key>
```

Frontend also needs its own env file at `frontend/.env`:

```
VITE_API_BASE_URL=http://127.0.0.1:8000
VITE_GOOGLE_CLIENT_ID=<same Google OAuth client ID>
```

### 3. Backend

```bash
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Default: `http://127.0.0.1:8000` — root redirects to `/frontend/`.

### 4. Frontend (dev mode)

```bash
cd frontend
npm install
npm run dev
```

Proxies API calls to `http://127.0.0.1:8000` via `vite.config.ts`.

### 5. Tests

```bash
pytest                        # all tests
pytest tests/unit             # unit only
pytest tests/integration      # integration only
pytest tests/acceptance       # acceptance only
```

## Authentication

The platform supports two authentication methods for both roles:

**Google Sign-In (primary)**: The frontend renders a `GoogleSignInButton` using the Google Identity Services library. The returned credential is posted to `/auth/google` (instructor) or `/auth/google/student` (student). The backend verifies the token via `google.oauth2.id_token.verify_oauth2_token` against `GOOGLE_CLIENT_ID` and enforces `SCHOOL_EMAIL_DOMAIN`.

**Password-based (secondary)**: Instructors use `POST /instructor/login`, students use `POST /student/login` or `POST /student/register`. Passwords are hashed with bcrypt.

Both paths return the same `AuthResponse` and issue identical JWTs.

Tokens are stored in `localStorage` and injected into all API calls by the Axios client:

| Key | Written by | Used for |
|---|---|---|
| `instructor_token` | `/instructor/login` or Google sign-in | All `/instructor/*` calls |
| `student_token` | `/student/login`, `/student/register`, or Google sign-in | All `/student/*` calls |

JWTs are HS256, signed with `JWT_SECRET`. Payload: `sub` (user UUID), `email`, `role`, `exp` (configurable via `JWT_EXPIRE_MINUTES`).

**Grading script fallback**: `verify_student` and `verify_instructor` also accept a raw `email` (and optional `password`) in the request body or query string with no `Authorization` header. This is required for automated grading script compatibility. It is a known ghost-login risk and must be removed before any production deployment.

## API Reference

All protected endpoints require `Authorization: Bearer <token>` unless stated otherwise.

### Health

| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/health/db` | None | Returns `{"database": "ok"}` if pool is healthy. |

### Authentication

| Method | Path | Auth | Description |
|---|---|---|---|
| POST | `/auth/google` | None | Google federated sign-in (any role). Body: `{"id_token": "..."}`. Email must match `SCHOOL_EMAIL_DOMAIN`. |
| POST | `/auth/google/student` | None | Same as above, enforces `role=student`. |
| GET | `/auth/google/student/test` | None | HTML test page for Google student sign-in. |
| GET | `/auth/me` | Bearer | Returns `{user_id, email, role}` for the token owner. |
| POST | `/instructor/login` | None | Password login. Body: `{"email", "password"}`. |
| POST | `/student/login` | None | Password login. Body: `{"email", "password"}`. |
| POST | `/student/register` | None | Self-registration. Body: `{"full_name", "email", "password", "confirm_password"}`. |
| POST | `/instructor/password/set` | Instructor | Sets initial password. Body: `{"password": "..."}`. |
| POST | `/instructor/password/change` | Instructor | Changes password. Body: `{"old_password", "new_password"}`. |

`AuthResponse` shape:

```json
{
  "access_token": "...",
  "token_type": "bearer",
  "user_id": "uuid",
  "role": "instructor | student",
  "email": "user@mef.edu.tr",
  "name": "Full Name"
}
```

### Authorization Tests

| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/instructor/test` | Instructor | Returns `{access, email, role}` for valid instructor tokens. |
| GET | `/student/test` | Student | Returns `{access, email, role}` for valid student tokens. |

### Instructor Endpoints

All require an `instructor` role token.

| Method | Path | Description |
|---|---|---|
| GET | `/instructor/courses` | Lists courses assigned to the authenticated instructor only (via `instructor_course_mapping`). |
| POST | `/instructor/courses` | Creates a new course and assigns the instructor to it. Body: `{course_code, course_name, term?}`. Returns `201` with the created record. |
| DELETE | `/instructor/courses/{course_id}` | Deletes a course and all associated data (cascade). Instructor must own the course. |
| GET | `/instructor/courses/{course_id}/students` | Lists all students enrolled in the course. |
| POST | `/instructor/courses/{course_id}/enroll` | Enrolls students by email. Body: `{"student_emails": [...]}`. Returns `{enrolled, already_enrolled, not_found}`. |
| DELETE | `/instructor/courses/{course_id}/students` | Removes a student from the course. Body: `{"student_email": "..."}`. |
| GET | `/instructor/activities?course_id=<id>` | Lists all activities in the course, ordered by `activity_no` ascending. Each item includes `activity_id`, `activity_no`, `status`, `title`, `description`, `objectives`. |
| POST | `/instructor/activity/create` | Creates an activity in `DRAFT` state. Body: `{course_id, activity_no, activity_text, objectives: [...], title?, max_score?}`. Returns `409` on duplicate `(course_id, activity_no)`. |
| PATCH | `/instructor/activity/{course_id}/{activity_no}` | Updates activity fields. All body fields optional: `{activity_text?, objectives?, title?, max_score?}`. Requires at least one field. |
| DELETE | `/instructor/activity/{course_id}/{activity_no}` | Deletes an activity and all associated student data. |
| POST | `/instructor/activity/start?course_id=<id>&activity_no=<n>` | Transitions `DRAFT` → `ACTIVE`. Returns `409` if not in `DRAFT`. |
| POST | `/instructor/activity/end?course_id=<id>&activity_no=<n>` | Transitions `ACTIVE` → `ENDED`. Returns `409` if not in `ACTIVE`. |
| POST | `/instructor/activity/reset?course_id=<id>&activity_no=<n>` | Deletes all student scores and progress for the activity, then sets status to `ENDED`. Cannot be undone. |
| POST | `/instructor/activity/{course_id}/{activity_no}/grade/manual` | Submits a manual score for a student. Body: `{student_email, score, note?}`. Works for activities in any state including `ENDED`. Overwrites any existing score with `grading_type='manual'`. |
| GET | `/instructor/activities/{activity_id}/logs` | Returns per-student progress for all enrolled students. Includes students with no activity (status `Not Started`). Sorted: Completed → In Progress → Not Started. |
| GET | `/instructor/activities/{activity_id}/completion-logs` | Returns completion events (students who finished the activity) with timestamps. |

**Activity log response item:**

```json
{
  "student_id": "uuid",
  "student_name": "Full Name",
  "student_email": "student@mef.edu.tr",
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

### Student Endpoints

All require a `student` role token.

| Method | Path | Description |
|---|---|---|
| GET | `/student/courses` | Lists all courses the student is enrolled in, with activities and current progress (score, completed) per activity. |
| GET | `/student/activity?course_id=<id>&activity_no=<n>` | Returns content of an `ACTIVE` activity. Objectives are not exposed. Returns `403` if `DRAFT` or `ENDED`. Generates and returns the first guiding question. |
| GET | `/student/activities/{activity_id}` | Same as above, addressed by UUID instead of composite key. |
| POST | `/student/answer` | Submits an answer (by composite key). Body: `{course_id, activity_no, answer}`. See scoring rules below. |
| POST | `/student/activities/{activity_id}/chat` | Submits an answer (by UUID). Body: `{"answer": "..."}`. Returns the same response shape. |

**Scoring rules**: Each learning objective earns at most +1 point. On each submission, the DeepSeek API evaluates whether the answer satisfies an unearned objective. A keyword-matching fallback runs if the API call fails. Achieving an objective immediately returns the updated score, a mini-lesson for that objective, and the next guiding question. When all objectives are achieved, `completed: true` is returned and the tutoring flow stops. Score events are logged to `objective_score_logs` with a UNIQUE constraint on `(student_id, activity_id, objective_index)`, preventing double-scoring.

**Answer response shape:**

```json
{
  "score": 2,
  "score_delta": 1,
  "completed": false,
  "next_question": "Can you explain how the scheduler decides which process runs next?",
  "message": "Great, you've earned a point for objective 2!",
  "mini_lesson": "A short academic note on the objective just achieved.",
  "matched_objective": "Describe the role of the CPU scheduler"
}
```

## Activity State Machine

```
DRAFT ──start──▶ ACTIVE ──end──▶ ENDED
                    │                │
                    └──reset────────▶ ENDED (scores deleted)
```

- Students can only access and submit answers for `ACTIVE` activities.
- `ENDED` activities block new submissions but allow instructor manual grading.
- Reset is irreversible — there is no path back to `DRAFT` or `ACTIVE` after reset.

## Student Enrollment

Students are enrolled via the instructor UI (`CourseStudentsPage`) or directly via the API:

```bash
POST /instructor/courses/{course_id}/enroll
{"student_emails": ["student1@mef.edu.tr", "student2@mef.edu.tr"]}
```

Or manually via Supabase SQL Editor:

```sql
INSERT INTO student_course_mapping (student_id, course_id)
SELECT u.id, '<course-uuid>'
FROM users u
WHERE u.school_email = 'student@mef.edu.tr';
```

## Manual Grading Flow (US-L)

1. Instructor navigates to `/instructor/activities/:activityId/logs`.
2. Each student row shows a **Grade** button.
3. Clicking **Grade** opens `ManualGradeModal` with the student pre-filled.
4. Instructor enters a numeric score (0 – max_score) and an optional note.
5. The frontend calls `POST /instructor/activity/{courseId}/{activityNo}/grade/manual`.
6. On success, the modal closes and the log table refreshes. Manual grades can be submitted regardless of activity state, including after `ENDED` or reset.

## Frontend Pages

| Page | Route | Role |
|---|---|---|
| Student login | `/student/login` | Student |
| Student registration | `/student/register` | Student |
| Instructor login | `/instructor/login` | Instructor |
| Instructor dashboard | `/instructor/dashboard` | Instructor |
| Course activity list | `/instructor/courses/:courseId` | Instructor |
| Enrolled students | `/instructor/courses/:courseId/students` | Instructor |
| Create activity | `/instructor/courses/:courseId/activities/new` | Instructor |
| Edit activity | `/instructor/activities/:activityId/edit` | Instructor |
| Activity logs + manual grade | `/instructor/activities/:activityId/logs` | Instructor |
| Student dashboard | `/student/dashboard` | Student |
| Tutoring chat | `/student/activities/:activityId` | Student |

## Documentation

This project uses Doxygen. All Python functions carry `@brief`, `@param`, `@return`, and `@throws` tags.

Generate HTML docs:

```bash
# Windows
./doxy.ps1

# Linux / macOS
./doxy.sh
```

Output: `docs/gen/html/index.html`

## Known Limitations

- The grading script fallback in `verify_student` / `verify_instructor` (raw email without `Authorization` header) must be removed before any production deployment.
- `ActivityLogsPage` resolves `activityNo` via a secondary `getCourseActivities` call because the logs endpoint does not return the integer `activity_no` directly. This can be eliminated by adding `activity_no` to the log response.
- The DeepSeek keyword fallback is intentionally simple. It matches meaningful words from the student answer against the objective text. For production use, prompt tuning or a stronger model is recommended.
