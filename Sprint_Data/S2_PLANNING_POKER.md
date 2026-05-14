# G17 - Sprint 2 Planning Record & Planning Poker (E03)

**Date:** 2026-05-03
**Duration:** 90 Minutes
**Facilitator (S2):** Başar Metin
**Attendees:** Necati Onur Yaman, Başar Metin, Ceyda Akgün, Mustafa Garip, Aksel Uğur

---

## 1. Sprint Goal Selection
With the authentication and authorization foundation completed in Sprint 1, the team selected the remaining 8 User Stories from the Product Backlog for Sprint 2. The core goal of Sprint 2 is to build the **"Activity Management, Tutoring Flow, and Scoring Engine."**

Selected Stories:
* **US-E:** List Activities
* **US-F:** Create Activity
* **US-G:** Update Activity
* **US-I:** Student Access Control
* **US-J:** Tutoring Flow
* **US-K:** Objective Scoring
* **US-L:** Manual Grading
* **US-M:** Reset Activity
* **TECH-2:** Automated Test Coverage (Code Quality Task)

## 2. Planning Poker (Re-estimation) - [Evidence E03]
We re-evaluated the initial SP estimates from the Product Backlog. To accommodate the mandatory testing evidence while maintaining our strict 35 SP velocity, we adjusted the complexity weights of the backend tasks, leveraging the reusable architecture we built in Sprint 1.

| Story ID | Initial SP | Final SP | Rationale for Change |
| :--- | :--- | :--- | :--- |
| **US-E** | 3 | **2** | Reuses `verify_instructor` and existing DB indexes; this is a filtered SELECT with deterministic ordering, so effort is primarily query plumbing rather than new logic. |
| **US-F** | 5 | **3** | Create is a standard `INSERT` into the existing `activities` schema (`activity_no`, `objectives`, `activity_text` already present), reducing complexity to service validation and constraint checks. |
| **US-G** | 5 | **3** | Update is a limited PATCH on existing columns (text/objectives/title); no new schema required and existing service validation logic can be reused. |
| **US-I** | 5 | **3** | Student access checks reuse `verify_student` and activity status guards (`getStudentActivity`); most authorization work is already implemented. |
| **US-J** | 8 | **7** | Tutoring flow reuses routing and state patterns from existing endpoints; remaining work is prompt tuning and follow-up question sequencing (allow a small buffer for prompt iterations). |
| **US-K** | 8 | **7** | Scoring reuses objective-detection helpers and integrates with the tutoring flow; main effort is ensuring idempotent +1 scoring and logging. |
| **US-L** | 5 | **4** | Manual grading is an `UPSERT` into `activity_scores` plus an audit log entry; no new tables are required, testing/authorization are primary work. |
| **US-M** | 5 | **3** | Reset is a controlled cascade: DELETE related score/progress rows and set activity status to ENDED; focus on safe transactions and tests. |
| **TECH-2**| - | **3** | New: write unit, integration, and acceptance tests and add CI automation so behavior is reproducible; accounts for test design and automation work. |

**Total Committed SP for Sprint 2:** 35 SP
**Team Velocity Target:** 35 SP

## 3. Task Breakdown Strategy
The team agreed that each story must follow the **Definition of Done (DoD)**:
1. Database schema updated/migrated safely (PostgreSQL).
2. Backend API endpoints implemented matching the exact Phase 1 signatures.
3. Automated Tests (TECH-2) written and passing.
4. Code documented with Doxygen-style docstrings.
5. Evidence (GitHub PRs, ClickUp logs) captured and recorded in the Scope Change Log.
