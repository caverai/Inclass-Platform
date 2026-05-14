# Sprint 2 Retrospective

**Date:** 2026-05-12
**Duration:** 60 Minutes
**Attendees:** Aksel Uğur, Başar Metin, Ceyda Akgün, Mustafa Garip, Necati Onur Yaman

---

## 1. What Went Well?
- **End-to-end functionality:** The backend and new frontend were integrated so the core demo flows (instructor activity management, student tutoring flow, and objective scoring) could be demonstrated end-to-end.
- **Feature delivery:** US-E through US-M (activity list/create/update/start/end/reset, tutoring flow, objective scoring, manual grading) were implemented and demoed.
- **Testing investment:** A runnable test suite (unit, integration, acceptance) was added, validating scoring logic and critical API behaviors.

## 2. What Could Be Improved?
- **CI and dependency stability:** Tests revealed environment gaps (missing bcrypt backend) and we need a CI workflow to ensure dependencies (e.g., `bcrypt`) are installed and tests run reproducibly.
- **Auth/test parity:** Several integration tests returned `422` due to request/validation mismatches; refine request signatures and dependency overrides so tests assert service behavior rather than validation surface errors.
- **Process evidence capture:** ClickUp screenshots, burndown charts, and scope-change exports must be collected and attached for submission.

## 3. Action List (for follow-up tasks)
| Action Item | Responsible Owner | Target Date |
| :--- | :--- | :--- |
| Add CI workflow (run tests, lint, and build) and ensure `bcrypt` is installed in CI image. | DevOps / Necati | 2026-05-13 |
| Fix integration request signatures and update test fixtures so endpoints return expected status codes. | Backend Team | 2026-05-13 |
| Produce ClickUp exports, board screenshots (baseline + post-daily + final) and burndown charts for both sprints. | Scrum Facilitator | 2026-05-14 |
| Harden demo data seeding script to prepare required instructor/student/course/activity fixtures prior to demo. | QA / Dev | 2026-05-14 |
| Create `REPO_INFO.txt` and tag `sprint-1` / `sprint-2` in Git, verify instructor repository access. | Release Manager | 2026-05-14 |

---
**Decision Owner:** Başar Metin
