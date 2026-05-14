# Sprint 1 Planning Record

**Date:** 2026-04-12
**Duration:** 90 Minutes
**Facilitator (S1):** Necati Onur Yaman
**Attendees:** Necati Onur Yaman, [Teammate Name 1], [Teammate Name 2]

---

## 1. Sprint Goal Selection
The team reviewed the Product Backlog and selected the following stories for Sprint 1 to build the "Auth & Authorization Foundation":
* **US-A:** Instructor Sign-In
* **US-B:** Student Sign-In
* **US-C:** Role and Course Mapping
* **US-D:** List Assigned Courses
* **US-H:** Start and End Activity

## 2. Planning Poker (Re-estimation) - [Evidence E03]
We re-evaluated the initial SP estimates from the Product Backlog.

| Story ID | Initial SP | Final SP | Rationale for Change |
| :--- | :--- | :--- | :--- |
| **US-A** | 3 | 3 | Standard Google OAuth implementation; kept as is. |
| **US-B** | 3 | 3 | Mirror of US-A; logic is already understood. |
| **US-C** | 5 | 8 | **Increased:** Backend middleware for course-level authorization is more complex than initially thought. |
| **US-D** | 3 | 2 | **Decreased:** Once US-C is done, this is a simple filtered database query. |
| **US-H** | 5 | 5 | Requires state management in PostgreSQL; estimate remains solid. |

**Total Committed SP for Sprint 1:** 21 SP
**Team Velocity:** 35 SP (Left buffer for environment setup and CI/CD configuration).

## 3. Task Breakdown Strategy
The team agreed that each story must follow the **Definition of Done (DoD)**:
1. Database schema updated (PostgreSQL).
2. Backend API endpoints implemented (Python).
3. Frontend components built.
4. Unit tests passed.
5. Evidence (screenshots/logs) captured.

## 4. Resource Allocation
* **Backend/DB Lead:** Necati Onur Yaman
* **Frontend/Auth Lead:** [Teammate Name 1]
* **QA/Documentation:** [Teammate Name 2]

---
**Decision Owner:** Necati Onur Yaman
