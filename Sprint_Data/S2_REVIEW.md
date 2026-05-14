# Sprint 1 Review Record

**Date:** 2026-05-12
**Time:** 20:00
**Location:** Google Meet
**Attendees:** Aksel Uğur, Başar Metin, Ceyda Akgün, Mustafa Garip, Necati Onur Yaman

---

## 1. Sprint Goal Assessment
**Goal Statement:** The primary objective of Sprint 2 is to deliver the core educational value of the InClass platform: **"Activity Management, Tutoring Flow, and Scoring Engine."** Building upon Sprint 1's authorization foundation, this sprint empowers instructors with full control over activity content and grading exceptions, while providing students with a structured, step-by-step LLM tutoring experience that strictly enforces access rules and automatically awards objective-based scores. 

**Status:** SUCCESSFUL
**Summary:** The team successfully achieved all the defined success criteria for Sprint 2. Instructors were able to manage activities effectively, including listing, creating, updating, resetting, and manually grading activities. The backend enforced strict access control, preventing students from accessing DRAFT or ENDED activities while allowing access to ACTIVE ones. The tutoring flow provided a guided experience for students, with progress persistence and proper handling of activity completion. The objective scoring system functioned as intended, awarding points accurately and providing mini-lessons upon achievement. Finally, comprehensive automated tests were implemented to ensure code quality and adherence to API contracts.

## 2. Completed User Stories
The following stories met the **Definition of Done (DoD)** and were demonstrated:

| Story ID | Title | Re-estimated SP | Status |
| :--- | :--- | :--- | :--- |
| US-F | Create Activity | 3 | Done |
| US-G | Update Activity | 3 | Done |
| US-L | Enter Manual Grade | 5 | Done |
| US-K | Increase Score | 8 | Done |
| US-E | List Activities | 2 | Done |
| US-M | Reset Activity | 3 | Done |
| US-I | Activity Access | 3 | Done |
| US-J | Submit Answers | 8 | Done |

**Total Points Completed:** 35 / 35 SP Velocity

## 3. Demo Evidence
* **Instructor flow:** Signed in successfully and showed that the instructor could manage only assigned course activities.
* **Activity management:** Demonstrated activity listing, creation, update, start, end, and reset for a selected course.
* **Student access control:** Showed that a student could not open a NOT_STARTED or ENDED activity, while an ACTIVE activity returned the activity text without exposing learning objectives.
* **Tutoring flow:** Submitted student answers one step at a time and showed the next guiding question, progress persistence, and the activity stopping after completion.
* **Objective scoring:** Verified that the first achievement of an objective added +1, repeated achievement did not add score again, score logs stored metadata, and the mini-lesson appeared after a point was earned.
* **Manual grading and cleanup:** Showed manual grading for an exception case and confirmed reset removed student score/progress data and set the activity to ENDED.

---
**Decision Owner:** Başar Metin
