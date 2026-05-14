Sprint 1 — Acceptance Criteria & Test Evidence

Test run summary (pytest JUnit XML):
- Date: 2026-05-13
- Total tests executed: 65
- Passed: 65
- Failures: 0

Key Sprint 1 Acceptance Criteria (mapped to tests)

- US-A / US-B — Instructor & Student Sign-In
  - tests/unit/test_auth.py::TestCreateAccessToken::test_token_contains_sub_email_role — PASS
  - tests/unit/test_auth.py::TestCreateAccessToken::test_token_has_expiry — PASS
  - tests/unit/test_auth.py::TestCreateAccessToken::test_token_has_issued_at — PASS
  - tests/integration/test_auth_routes.py::TestInstructorLogin::test_login_returns_200_for_valid_credentials — PASS
  - tests/integration/test_auth_routes.py::TestInstructorLogin::test_login_returns_400_when_email_missing — PASS
  - tests/integration/test_auth_routes.py::TestInstructorLogin::test_login_returns_401_for_bad_password — PASS

- US-C — Role and Course Mapping (Instructor course list)
  - tests/integration/test_instructor_courses.py::TestGetInstructorCourses::test_returns_assigned_courses — PASS
  - tests/integration/test_instructor_courses.py::TestGetInstructorCourses::test_returns_empty_list_when_no_courses — PASS
  - tests/integration/test_instructor_courses.py::TestGetInstructorCourses::test_403_for_unauthorized_instructor — PASS

- US-H — Start/End Activity (API state transitions)
  - tests/integration/test_activities_crud.py::TestStartActivity::test_start_draft_activity_returns_active — PASS
  - tests/integration/test_activities_crud.py::TestEndActivity::test_end_active_activity_returns_ended — PASS

Notes
- All Sprint 1 acceptance tests and supporting unit/integration tests passed in the latest run (see above). The JUnit XML report was written to `pytest_report.xml` at test run time for audit evidence.
- If you want this in CSV/Excel format for submission, I can export the mapping into CSV files next.
