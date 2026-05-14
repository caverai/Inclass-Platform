# G17 - Sprint 2 Planning Record (E07)

**Date:** 2026-05-03
**Duration:** 90 Minutes
**Facilitator (S2):** Başar Metin
**Attendees:** Necati Onur Yaman, Başar Metin, Ceyda Akgün, Mustafa Garip, Aksel Uğur

---

## 1. Capacity & Velocity Planning
* **Target Velocity:** 35 Story Points (Mandatory constraint for Phase 1).
* **Team Capacity:** 5 members available for the full sprint duration.
* **Commitment:** The team has committed to exactly 35 SP, leveraging the foundational architecture built in Sprint 1 to take on a heavier feature load while maintaining high code quality.

## 2. Sprint Goal Selection
The team reviewed the Product Backlog and selected the core application logic stories. 
**Sprint Goal:** Deliver the "Activity Management, Tutoring Flow, and Scoring Engine," providing full classroom control for instructors and a secure, objective-driven LLM tutoring experience for students.

## 3. Selected Backlog Items & Estimates (Planning Poker Results)
We evaluated the initial SP estimates and adjusted them via Planning Poker to reflect our Sprint 1 learnings and the reusable codebase (like the `db_pool` and authentication middleware).

| Story / Task ID | Title | Final SP | Notes / Rationale |
| :--- | :--- | :--- | :--- |
| **US-E** | List Activities | **2** | Reuses `verify_instructor` and existing DB indexes; effort is a deterministic SELECT and result shaping for the UI. |
| **US-F** | Create Activity | **3** | Insert into existing `activities` schema (`activity_no`, `objectives`, `activity_text`) with service-layer validation and conflict handling. |
| **US-G** | Update Activity | **3** | PATCH on existing fields (text/objectives/title); no schema changes required and existing validation applies. |
| **US-I** | Student Access Control | **3** | Leverages `verify_student` and `getStudentActivity` guards; mainly wiring and small access checks. |
| **US-J** | Tutoring Flow | **7** | Reuses routing/state patterns; remaining complexity is prompt tuning and stepwise question sequencing (allow buffer for prompt iterations). |
| **US-K** | Objective Scoring | **7** | Integrates objective-detection helpers with the tutoring flow; focus on idempotent +1 scoring and logging. |
| **US-L** | Manual Grading | **4** | `UPSERT` into `activity_scores` plus audit logging; primary work is authorization and tests. |
| **US-M** | Reset Activity | **3** | Controlled cascade: DELETE related score/progress rows and UPDATE activity status to ENDED inside a transaction. |
| **TECH-2** | Automated Test Coverage | **3** | Write unit/integration/acceptance tests and add CI automation to ensure reproducible behavior across environments. |

**Total Committed SP for Sprint 2:** 35 SP

## 4. Task Breakdown & Execution Strategy
To complete the committed stories, the team defined the following technical task breakdown strategy:
1. **Database / Migrations:** Create the `activity_scores` table (for US-L/US-M/US-K) and ensure the `objectives` JSONB column is ready (US-F/US-G).
2. **LLM Engine & State Control:** Develop the system prompts and state tracking required for the US-J tutoring loop and US-K objective detection.
3. **API Implementation:** Implement the remaining FastAPI endpoints strictly adhering to the exact Phase 1 signatures and fallback credential extraction.
4. **Quality Assurance:** Write and execute automated tests (TECH-2) covering both instructor management and the student LLM flows.

*(Note: In accordance with Agile principles, specific sub-tasks are not rigidly pre-assigned to individuals during this meeting. Team members will "pull" tasks from the To-Do column in ClickUp as they gain capacity throughout the sprint.)*

## 5. Confidence Vote
At the conclusion of the meeting, the facilitator (Başar Metin) asked for a confidence vote (1-5 fingers). All team members voted 4 or 5, indicating high confidence in achieving the Sprint 2 Goal and delivering the committed 35 SP.
