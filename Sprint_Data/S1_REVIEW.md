# Sprint 1 Review Record

**Date:** 2026-05-04
**Time:** 20:00
**Location:** Google Meet
**Attendees:** Aksel Uğur, Başar Metin, Ceyda Akgün, Mustafa Garip, Necati Onur Yaman

---

## 1. Sprint Goal Assessment
**Goal Statement:** The primary objective of Sprint 1 is to establish a secure and functional foundation for the InClass platform. This includes implementing federated authentication for both roles, establishing the backend authorization layer to strictly map users to their specific courses, providing instructors with the ability to manage course visibility, and ensuring robust activity state control (Start/End) integrated with comprehensive code documentation.

**Status:** SUCCESSFUL
**Summary:** The team successfully met all the defined success criteria for Sprint 1. Both instructor and student authentication were implemented and demonstrated, with secure JWT handling. The backend authorization layer effectively restricted access based on user roles, and instructors could manage their assigned courses without issues. Activity state control was fully functional, allowing instructors to toggle between DRAFT, ACTIVE, and ENDED states while enforcing the correct transition rules. Additionally, all backend code was documented using Doxygen-compliant docstrings, ensuring a high standard of code quality and maintainability.

## 2. Completed User Stories
The following stories met the **Definition of Done (DoD)** and were demonstrated:

| Story ID | Title | Re-estimated SP | Status |
| :--- | :--- | :--- | :--- |
| US-A | Instructor Sign-In | 5 | Done |
| US-B | Student Sign-In | 5 | Done |
| US-C | Role and Course Mapping | 13 | Done |
| US-D | List Assigned Courses | 4 | Done |
| US-H | Start and End Activity | 8 | Done |

**Total Points Completed:** 35 / 35 SP Velocity

## 3. Demo Evidence
* **Authentication:** Showed successful login redirect via Google.
* **Authorization:** Demonstrated that a student cannot access instructor-only routes via Postman/Backend logs.
* **Course List:** Displayed the course cards for a specific instructor identity.
* **Activity Control:** Toggled an activity from "Not Started" to "Active" and verified the change in the PostgreSQL database.

---
**Decision Owner:** Necati Onur Yaman
