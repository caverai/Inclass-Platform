# G17 - Sprint 1 Goal (E02)

## Goal Statement
The primary objective of Sprint 1 is to establish a secure and functional foundation for the InClass platform. This includes implementing federated authentication for both roles, establishing the backend authorization layer to strictly map users to their specific courses, providing instructors with the ability to manage course visibility, and ensuring robust activity state control (Start/End) integrated with comprehensive code documentation.

## Included User Stories & Tasks
Based on the Sprint 1 Planning Poker session, the following items are committed to achieve this goal:
- **US-A:** Instructor Sign-In (5 SP)
- **US-B:** Student Sign-In (5 SP)
- **US-C:** Role and Course Mapping (11 SP)
- **US-D:** List Assigned Courses (4 SP)
- **US-H:** Start and End Activity (7 SP)
- **TECH-1:** Add Doxygen to the project (3 SP)

## Velocity & Capacity
- **Planned Velocity Target:** 35 SP
- **Total Committed Points:** 35 SP
*(Note: The team has committed to the exact capacity required by the project constraints, balancing feature work with critical architectural and documentation tasks.)*

## Success Criteria (Definition of Ready for Demo)
1. **Authentication:** Instructors and Students can securely log in via Google/Federated auth and receive valid JWTs.
2. **Authorization:** The backend correctly identifies the user's role and explicitly prevents unauthorized access to course data using middleware.
3. **Data Isolation:** Instructors can retrieve a list containing *only* their assigned courses.
4. **State Management:** Instructors can successfully toggle an activity state between DRAFT, ACTIVE, and ENDED, with strict transition rules enforced in PostgreSQL.
5. **Code Quality:** All backend endpoints and services are documented using Doxygen-compliant docstrings.
