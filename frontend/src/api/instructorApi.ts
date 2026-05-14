import { apiClient } from './client';
import type { Course, Activity, ActivityLog } from '../types';

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

// ---------------------------------------------------------------------------
// API surface
// ---------------------------------------------------------------------------

export const instructorApi = {
  getCourses: async (): Promise<Course[]> => {
    const res = await apiClient.get('/instructor/courses');
    const raw: unknown[] = res.data?.courses ?? res.data ?? [];
    return raw.map(r => normalizeCourse(r as Record<string, unknown>));
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

  updateActivity: async (activityId: string, data: Partial<Activity>): Promise<Activity> => {
    // We need courseId + activity_no for the PATCH endpoint.
    // The frontend passes activityId (UUID). We resolve courseId/activity_no via
    // a full scan only in the edit form path; for status transitions we use the
    // dedicated start/end/reset endpoints below instead of this generic stub.
    // This stub is kept for the ActivityFormPage edit path which provides courseId.
    throw new Error(`updateActivity stub called for ${activityId} — use specific action methods`);
    return data as Activity; // unreachable; satisfies TS return type
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
};
