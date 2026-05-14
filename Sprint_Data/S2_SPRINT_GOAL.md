# G17 - Sprint 2 Goal (E02)

## Goal Statement
The primary objective of Sprint 2 is to deliver the core educational value of the InClass platform: **"Activity Management, Tutoring Flow, and Scoring Engine."** Building upon Sprint 1's authorization foundation, this sprint empowers instructors with full control over activity content and grading exceptions, while providing students with a structured, step-by-step LLM tutoring experience that strictly enforces access rules and automatically awards objective-based scores. 

## Included User Stories & Tasks
Based on the Sprint 2 Planning Poker session, the following items are committed to achieve this goal:
- **US-E:** List Activities (2 SP)
- **US-F:** Create Activity (3 SP)
- **US-G:** Update Activity (3 SP)
- **US-I:** Student Access Control (3 SP)
- **US-J:** Tutoring Flow (7 SP)
- **US-K:** Objective Scoring (7 SP)
- **US-L:** Manual Grading (4 SP)
- **US-M:** Reset Activity (3 SP)
- **TECH-2:** Automated Test Coverage (Code Quality Task) (3 SP)

## Velocity & Capacity
- **Planned Velocity Target:** 35 SP
- **Total Committed Points:** 35 SP
*(Note: The team has committed to the exact capacity required by the project constraints, successfully balancing a heavy feature load with the mandatory automated testing quality standards.)*

## Success Criteria (Definition of Ready for Demo)
1. **Instructor Control:** Instructors can seamlessly list, create, update, reset, and manually grade activities.
2. **Access Enforcement:** The backend strictly prevents students from accessing DRAFT or ENDED activities, ensuring class rules are maintained.
3. **Tutoring Experience:** Students receive a guided, step-by-step LLM tutoring flow that asks steering questions without revealing direct answers.
4. **Automated Scoring:** The system accurately detects when a student achieves a learning objective, awards exactly +1 score (ignoring repeats), logs the achievement, and returns a short academic mini-lesson.
5. **Quality Assurance:** Comprehensive automated tests (TECH-2) validate that all API endpoints strictly adhere to the Phase 1 non-negotiable contract signatures.
