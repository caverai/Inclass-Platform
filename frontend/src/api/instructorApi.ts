import { apiClient } from './client';
import type { Course, Activity, ActivityLog, ActivityCompletionLog, ManualGradeRequest, ManualGradeResult, EnrolledStudent, EnrollmentResult } from '../types';

// ---------------------------------------------------------------------------
// Response normalizers
// ---------------------------------------------------------------------------

const normalizeCourse = (raw: Record<string, unknown>): Course => ({
  id: String(raw.id),
  title: String(raw.course_name ?? raw.title ?? ''),
  description: String(raw.course_code ?? raw.description ?? ''),
});

const normalizeActivity = (raw: Record<string, unknown>): Activity => {
  const objectives = Array.isArray(raw.objectives)
    ? (raw.objectives as unknown[]).map(String)
    : [];

  // Backend status values: DRAFT | ACTIVE | ENDED  →  frontend: NOT_STARTED | ACTIVE | ENDED
  const rawStatus = String(raw.status ?? raw.activity_status ?? 'DRAFT');
  const status: Activity['status'] =
    rawStatus === 'ACTIVE' ? 'ACTIVE' :
    rawStatus === 'ENDED'  ? 'ENDED'  : 'NOT_STARTED';

  return {
    id: String(raw.activity_id ?? raw.id),
    courseId: String(raw.course_id ?? ''),
    activityNumber: Number(raw.activity_no ?? raw.activityNumber ?? 0),
    text: String(raw.description ?? raw.activity_text ?? raw.text ?? ''),
    status,
    learningObjectives: objectives,
  };
};

const normalizeActivityLog = (raw: Record<string, unknown>): ActivityLog => ({
  studentId:        String(raw.student_id),
  studentName:      String(raw.student_name ?? raw.student_email ?? 'Unknown'),
  studentEmail:     String(raw.student_email ?? ''),
  activityId:       String(raw.activity_id),
  activityTitle:    String(raw.activity_title ?? ''),
  courseId:         String(raw.course_id),
  currentScore:     Number(raw.current_score ?? 0),
  maxScore:         Number(raw.max_score ?? 0),
  completed:        Boolean(raw.completed),
  completionStatus: (raw.completion_status as ActivityLog['completionStatus']) ?? 'Not Started',
  lastQuestion:     raw.last_question != null ? String(raw.last_question) : null,
  lastAnswer:       raw.last_answer   != null ? String(raw.last_answer)   : null,
  lastInteractionAt: raw.last_interaction_at != null ? String(raw.last_interaction_at) : null,
});

const normalizeActivityCompletionLog = (raw: Record<string, unknown>): ActivityCompletionLog => ({
  studentId: String(raw.student_id),
  studentName: String(raw.student_name ?? raw.student_email ?? 'Unknown'),
  studentEmail: String(raw.student_email ?? ''),
  activityId: String(raw.activity_id),
  activityTitle: String(raw.activity_title ?? ''),
  courseId: String(raw.course_id),
  action: 'COMPLETED',
  createdAt: raw.created_at != null ? String(raw.created_at) : null,
});

// ---------------------------------------------------------------------------
// API surface
// ---------------------------------------------------------------------------

export const instructorApi = {
  getCourses: async (): Promise<Course[]> => {
    const res = await apiClient.get('/instructor/courses');
    const raw: unknown[] = res.data?.courses ?? res.data ?? [];
    return raw.map(r => normalizeCourse(r as Record<string, unknown>));
  },

  /**
   * @brief Creates a new course and auto-assigns the authenticated instructor (US extension).
   *
   * Calls `POST /instructor/courses`. The backend wraps the course INSERT and the
   * instructor_course_mapping INSERT in a single transaction, so the course
   * immediately appears in the instructor's dashboard on success.
   *
   * @param courseCode  Short unique code (e.g. "CS101"). Must be unique across all courses.
   * @param courseName  Full human-readable name (e.g. "Introduction to Software Engineering").
   * @param term        Optional academic term label (e.g. "2026 Spring").
   * @returns           The normalised {@link Course} that was created.
   * @throws            Axios error with HTTP 409 if the course_code is already taken.
   */
  createCourse: async (courseCode: string, courseName: string, term?: string): Promise<Course> => {
    const res = await apiClient.post('/instructor/courses', {
      course_code: courseCode,
      course_name: courseName,
      term: term ?? null,
    });
    return normalizeCourse(res.data as Record<string, unknown>);
  },

  getCourseActivities: async (courseId: string): Promise<Activity[]> => {
    const res = await apiClient.get('/instructor/activities', { params: { course_id: courseId } });
    const raw: unknown[] = res.data?.activities ?? res.data ?? [];
    return raw.map(r => normalizeActivity(r as Record<string, unknown>));
  },

  createActivity: async (courseId: string, data: Omit<Activity, 'id' | 'courseId' | 'status'>): Promise<Activity> => {
    const res = await apiClient.post('/instructor/activity/create', {
      course_id: courseId,
      activity_no: data.activityNumber,
      activity_text: data.text,
      objectives: data.learningObjectives,
    });
    return normalizeActivity(res.data as Record<string, unknown>);
  },

  updateActivityContent: async (
    courseId: string,
    activityNo: number,
    data: { text?: string; objectives?: string[]; title?: string },
  ): Promise<void> => {
    await apiClient.patch(`/instructor/activity/${courseId}/${activityNo}`, {
      activity_text: data.text,
      objectives: data.objectives,
      title: data.title,
    });
  },

  startActivity: async (activityId: string, courseId: string, activityNo: number): Promise<void> => {
    await apiClient.post('/instructor/activity/start', null, {
      params: { course_id: courseId, activity_no: activityNo },
    });
  },

  endActivity: async (activityId: string, courseId: string, activityNo: number): Promise<void> => {
    await apiClient.post('/instructor/activity/end', null, {
      params: { course_id: courseId, activity_no: activityNo },
    });
  },

  resetActivity: async (activityId: string, courseId: string, activityNo: number): Promise<void> => {
    await apiClient.post('/instructor/activity/reset', null, {
      params: { course_id: courseId, activity_no: activityNo },
    });
  },

  getActivityLogs: async (activityId: string): Promise<ActivityLog[]> => {
    const res = await apiClient.get(`/instructor/activities/${activityId}/logs`);
    const raw: unknown[] = Array.isArray(res.data) ? res.data : res.data?.logs ?? [];
    return raw.map(r => normalizeActivityLog(r as Record<string, unknown>));
  },

  getActivityCompletionLogs: async (activityId: string): Promise<ActivityCompletionLog[]> => {
    const res = await apiClient.get(`/instructor/activities/${activityId}/completion-logs`);
    const raw: unknown[] = Array.isArray(res.data) ? res.data : res.data?.logs ?? [];
    return raw.map(r => normalizeActivityCompletionLog(r as Record<string, unknown>));
  },

  /**
   * @brief Submits a manual grade for a student in a specific activity (US-L).
   *
   * Calls `POST /instructor/activity/{courseId}/{activityNo}/grade/manual`.
   * The backend verifies that the caller is an authorized instructor for the
   * given course before persisting the grade event.
   *
   * @param courseId    Identifier of the course that owns the activity.
   * @param activityNo  Sequential activity number within the course.
   * @param payload     Grade data: student e-mail, score value, and optional note.
   * @returns           Confirmation message from the backend.
   * @throws            Axios error propagated to the caller for UI-level handling.
   */
  submitManualGrade: async (
    courseId: string,
    activityNo: number,
    payload: ManualGradeRequest,
  ): Promise<ManualGradeResult> => {
    const res = await apiClient.post(
      `/instructor/activity/${courseId}/${activityNo}/grade/manual`,
      {
        student_email: payload.studentEmail,
        score: payload.score,
        note: payload.note,
      },
    );
    return {
      message: String((res.data as Record<string, unknown>)?.message ?? 'Grade submitted successfully.'),
    };
  },

  /**
   * @brief Enrolls a list of students into a course by email.
   * @param courseId  UUID of the target course.
   * @param emails    List of student school emails to enroll.
   * @returns         EnrollmentResult with enrolled / already_enrolled / not_found lists.
   */
  enrollStudents: async (courseId: string, emails: string[]): Promise<EnrollmentResult> => {
    const res = await apiClient.post(`/instructor/courses/${courseId}/enroll`, {
      student_emails: emails,
    });
    const data = res.data as Record<string, unknown>;
    return {
      enrolled: (data.enrolled as string[]) ?? [],
      alreadyEnrolled: (data.already_enrolled as string[]) ?? [],
      notFound: (data.not_found as string[]) ?? [],
    };
  },

  /**
   * @brief Returns students enrolled in a course.
   * @param courseId  UUID of the target course.
   */
  getEnrolledStudents: async (courseId: string): Promise<EnrolledStudent[]> => {
    const res = await apiClient.get(`/instructor/courses/${courseId}/students`);
    const raw: unknown[] = Array.isArray(res.data) ? res.data : [];
    return raw.map((r) => {
      const row = r as Record<string, unknown>;
      return {
        studentId: String(row.student_id),
        email: String(row.email),
        fullName: String(row.full_name ?? ''),
        enrolledAt: row.enrolled_at != null ? String(row.enrolled_at) : null,
      };
    });
  },

  /**
   * @brief Removes a student from a course.
   * @param courseId      UUID of the target course.
   * @param studentEmail  Email of the student to remove.
   */
  unenrollStudent: async (courseId: string, studentEmail: string): Promise<void> => {
    await apiClient.delete(`/instructor/courses/${courseId}/students`, {
      data: { student_email: studentEmail },
    });
  },

  /**
   * @brief Deletes a course and all its associated data.
   * @param courseId  UUID of the course to delete.
   */
  deleteCourse: async (courseId: string): Promise<void> => {
    await apiClient.delete(`/instructor/courses/${courseId}`);
  },

  /**
   * @brief Deletes an activity from a course.
   * @param courseId    UUID of the course.
   * @param activityNo  Activity number within the course.
   */
  deleteActivity: async (courseId: string, activityNo: number): Promise<void> => {
    await apiClient.delete(`/instructor/activity/${courseId}/${activityNo}`);
  },
};
