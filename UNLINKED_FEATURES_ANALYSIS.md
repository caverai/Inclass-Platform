# Unlinked Features Analysis
## Backend Endpoints vs Frontend UI Coverage

Generated: 2026-05-14

---

## Summary

The InClass Platform has **several backend endpoints that lack corresponding frontend UI implementations**. This document identifies which backend capabilities are missing from the instructor and student interfaces.

---

## 🔴 CRITICAL: No Frontend UI

### 1. **Student Enrollment Management**
- **Backend**: `student_course_mapping` table exists, manual SQL enrollment required
- **Frontend**: ❌ NO UI to enroll students
- **Impact**: HIGH - Instructors cannot enroll students through the app; must use SQL directly
- **Workaround**: Manual SQL in Supabase console
- **Suggested UI**: 
  - "Enroll Students" page in instructor dashboard
  - Search/filter students by email
  - Bulk upload (CSV) support

---

### 2. **Course Deletion**
- **Backend API**: ❌ No DELETE endpoint exists for courses
- **Frontend**: ❌ No delete button in course list
- **Impact**: MEDIUM - Courses cannot be deleted once created
- **Note**: The `POST /instructor/courses` endpoint creates courses, but there's no corresponding delete functionality
- **Current workaround**: Manual database deletion in Supabase

---

### 3. **Activity Deletion**
- **Backend API**: ❌ No DELETE endpoint exists for activities
- **Frontend**: ❌ No delete button in activity list
- **Impact**: MEDIUM - Activities cannot be deleted once created
- **Current workaround**: Manual database deletion in Supabase
- **Related**: Activities can be reset (`/instructor/activity/reset`) but not deleted

---

## 🟡 PARTIALLY IMPLEMENTED: Backend Exists, Frontend Incomplete

### 4. **Activity Update/Edit**
- **Backend API**: ✅ `PATCH /instructor/activity/{course_id}/{activity_no}` exists
- **Frontend**: ✅ **PARTIALLY IMPLEMENTED**
  - Edit button exists in `InstructorCoursePage`
  - Routes to `/instructor/activities/{activityId}/edit`
  - Need to verify `ActivityFormPage` handles PATCH (update) vs POST (create)
- **Status**: Check if `ActivityFormPage.tsx` properly handles both create and update modes

### 5. **Bulk Student Enrollment**
- **Backend API**: ❌ No batch enrollment endpoint
- **Frontend**: ❌ No bulk upload UI
- **Impact**: MEDIUM - Only manual SQL or single-student enrollment possible
- **Suggestion**: Create `POST /instructor/courses/{course_id}/enroll-bulk` endpoint + CSV upload UI

---

## ✅ FULLY IMPLEMENTED: Backend + Frontend

### Working Features
- ✅ Student registration (`/student/register`)
- ✅ Student/instructor login (password + Google OAuth)
- ✅ Create courses (`POST /instructor/courses`)
- ✅ Create activities (`POST /instructor/activity/create`)
- ✅ Start activity (`POST /instructor/activity/start`)
- ✅ End activity (`POST /instructor/activity/end`)
- ✅ Reset activity (`POST /instructor/activity/reset`)
- ✅ Manual grading (`POST /instructor/activity/{course_id}/{activity_no}/grade/manual`)
- ✅ View activity logs (`GET /instructor/activities/{activity_id}/logs`)
- ✅ View completion logs (`GET /instructor/activities/{activity_id}/completion-logs`)
- ✅ Student answer submission (`POST /student/answer`)
- ✅ View enrolled courses (student) (`GET /student/courses`)
- ✅ Get activity content (student) (`GET /student/activity`)

---

## 📋 Complete Backend Endpoint Inventory

### Authentication Endpoints
| Method | Path | Frontend UI | Status |
|--------|------|-------------|--------|
| POST | `/auth/google` | LoginPage.tsx | ✅ Implemented |
| POST | `/auth/google/student` | StudentLoginPage.tsx | ✅ Implemented |
| GET | `/auth/me` | Internal use | ✅ Implemented |
| POST | `/instructor/login` | LoginPage.tsx | ✅ Implemented |
| POST | `/student/login` | StudentLoginPage.tsx | ✅ Implemented |
| POST | `/student/register` | StudentRegisterPage.tsx | ✅ Implemented |
| POST | `/instructor/password/set` | ⚠️ Not found | ⚠️ Partial |
| POST | `/instructor/password/change` | ⚠️ Not found | ⚠️ Partial |

### Instructor Endpoints
| Method | Path | Frontend UI | Status |
|--------|------|-------------|--------|
| POST | `/instructor/courses` | InstructorDashboard (button) | ✅ Implemented |
| GET | `/instructor/courses` | InstructorDashboard | ✅ Implemented |
| DELETE | `/instructor/courses/{id}` | ❌ MISSING | 🔴 **NOT IMPLEMENTED** |
| GET | `/instructor/activities` | InstructorCoursePage | ✅ Implemented |
| POST | `/instructor/activity/create` | ActivityFormPage | ✅ Implemented |
| PATCH | `/instructor/activity/{course_id}/{activity_no}` | ActivityFormPage (edit) | ⚠️ Partial |
| DELETE | `/instructor/activity/{course_id}/{activity_no}` | ❌ MISSING | 🔴 **NOT IMPLEMENTED** |
| POST | `/instructor/activity/start` | InstructorCoursePage (button) | ✅ Implemented |
| POST | `/instructor/activity/end` | InstructorCoursePage (button) | ✅ Implemented |
| POST | `/instructor/activity/reset` | InstructorCoursePage (button) | ✅ Implemented |
| GET | `/instructor/activities/{activity_id}/logs` | ActivityLogsPage | ✅ Implemented |
| GET | `/instructor/activities/{activity_id}/completion-logs` | ActivityLogsPage | ✅ Implemented |
| POST | `/instructor/activity/{course_id}/{activity_no}/grade/manual` | ActivityLogsPage (ManualGradeModal) | ✅ Implemented |
| POST | `/instructor/enroll-students` | ❌ MISSING | 🔴 **NOT IMPLEMENTED** |

### Student Endpoints
| Method | Path | Frontend UI | Status |
|--------|------|-------------|--------|
| GET | `/student/courses` | StudentDashboard | ✅ Implemented |
| GET | `/student/activity` | StudentActivityPage | ✅ Implemented |
| GET | `/student/activities/{activity_id}` | StudentActivityPage | ✅ Implemented |
| POST | `/student/answer` | StudentActivityPage (chat) | ✅ Implemented |
| POST | `/student/activities/{activity_id}/chat` | StudentActivityPage (chat) | ✅ Implemented |

### Authorization Test Endpoints
| Method | Path | Frontend UI | Status |
|--------|------|-------------|--------|
| GET | `/instructor/test` | None (test only) | ✅ Implemented |
| GET | `/student/test` | None (test only) | ✅ Implemented |

### Health Endpoints
| Method | Path | Frontend UI | Status |
|--------|------|-------------|--------|
| GET | `/health/db` | None (monitoring) | ✅ Implemented |
| GET | `/auth/google/student/test` | Standalone test page | ✅ Implemented |

---

## 🎯 Recommendations (Priority Order)

### Priority 1 (Critical)
1. **Add Student Enrollment UI**
   - Create `/instructor/courses/{courseId}/students` page
   - Implement student search and enrollment
   - Add bulk upload (CSV) support
   - Backend: Create `POST /instructor/courses/{course_id}/enroll` endpoint

2. **Add Course Delete Functionality**
   - Create `DELETE /instructor/courses/{course_id}` endpoint
   - Add delete button with confirmation modal to course cards
   - Add authorization check (instructor must own course)

3. **Add Activity Delete Functionality**
   - Create `DELETE /instructor/activity/{course_id}/{activity_no}` endpoint
   - Add delete button with confirmation modal to activity list
   - Cascade rules: Delete related `student_activity_progress` records

### Priority 2 (High)
4. **Verify Activity Edit Implementation**
   - Check if `ActivityFormPage.tsx` properly distinguishes create vs. update mode
   - Ensure PATCH request is being called on update (not POST)

5. **Add Password Management UI**
   - Add UI for `/instructor/password/set` and `/instructor/password/change`
   - Create a "Settings" page in instructor dashboard

### Priority 3 (Nice-to-Have)
6. **Add Batch Enrollment API**
   - Create `POST /instructor/courses/{course_id}/enroll-batch` endpoint
   - Accept list of student emails

---

## Database Tables Affected by Missing Features

### Student Enrollment
- `student_course_mapping` - Manual inserts only, no frontend CRUD

### Course Management
- `courses` - Can create, cannot delete
- `instructor_course_mapping` - Auto-created, no delete UI

### Activity Management
- `activities` - Can create/update, cannot delete
- `student_activity_progress` - Auto-managed by student answers

### Grading
- `activity_scores` - Auto-managed or manual via UI ✅
- `objective_score_logs` - Auto-managed ✅

---

## Code Files to Modify

### Backend (Python/FastAPI)
- `app/main.py` - Add DELETE endpoints
- `app/services.py` - Add delete and enroll service functions

### Frontend (React/TypeScript)
- `frontend/src/pages/InstructorDashboard.tsx` - Add enroll button
- `frontend/src/pages/InstructorCoursePage.tsx` - Add delete buttons
- `frontend/src/pages/` - Create new `EnrollStudentsPage.tsx` or `CourseSettingsPage.tsx`
- `frontend/src/api/instructorApi.ts` - Add delete and enroll API calls
- `frontend/src/components/` - Create `EnrollmentModal.tsx` or `BulkUploadModal.tsx`

---

## Known Workarounds

1. **Enroll students**: Use Supabase SQL Editor
   ```sql
   INSERT INTO student_course_mapping (student_id, course_id)
   SELECT u.id, '<course-uuid>'
   FROM users u WHERE u.school_email = 'student@school.edu';
   ```

2. **Delete course**: Direct SQL deletion in Supabase (cascade required)

3. **Delete activity**: Direct SQL deletion (manual cascade to related records)

