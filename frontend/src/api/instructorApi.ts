
import { apiClient } from './client';
import type { Course, Activity, ActivityLog } from '../types';

// Mock data
let mockActivities: Activity[] = [
  {
    id: 'act-1',
    courseId: 'course-1',
    activityNumber: 1,
    text: 'Explain how active retrieval and targeted feedback help students correct mistakes during learning.',
    status: 'NOT_STARTED',
    learningObjectives: ['Explain active retrieval as recall from memory', 'Explain how feedback helps students correct mistakes'],
  },
  {
    id: 'act-2',
    courseId: 'course-1',
    activityNumber: 2,
    text: 'Design a system architecture for a real-time chat application.',
    status: 'ACTIVE',
    learningObjectives: ['System design principles', 'Real-time communication protocols'],
  },
];

const mockCourses: Course[] = [
  { id: 'course-1', title: 'Introduction to Computer Science', description: 'Basic concepts of programming.' },
  { id: 'course-2', title: 'Advanced Software Engineering', description: 'Design patterns and scalable architectures.' },
];

const normalizeActivityLog = (raw: Record<string, unknown>): ActivityLog => {
  const studentId = raw.studentId ?? raw.student_id;
  const studentEmail = raw.studentEmail ?? raw.student_email;
  const objectivesCompleted = raw.objectivesCompleted ?? raw.objectives_completed;
  const totalObjectives = raw.totalObjectives ?? raw.total_objectives;

  return {
    id: String(raw.id),
    activityId: String(raw.activityId ?? raw.activity_id),
    studentId: studentId === undefined || studentId === null ? undefined : String(studentId),
    studentName: String(raw.studentName ?? raw.student_name ?? studentEmail ?? 'Unknown Student'),
    studentEmail: studentEmail === undefined || studentEmail === null ? undefined : String(studentEmail),
    score: raw.score === null || raw.score === undefined ? null : Number(raw.score),
    objectiveMetadata: raw.objectiveMetadata ?? raw.objective_metadata ?? {},
    objectivesCompleted: objectivesCompleted === undefined || objectivesCompleted === null
      ? undefined
      : Number(objectivesCompleted),
    totalObjectives: totalObjectives === undefined || totalObjectives === null
      ? undefined
      : Number(totalObjectives),
    completed: Boolean(raw.completed),
    timestamp: String(raw.timestamp),
    eventType: String(raw.eventType ?? raw.event_type ?? 'PARTIAL_PROGRESS'),
  };
};

export const instructorApi = {
  getCourses: async () => {
    // return apiClient.get<Course[]>('/instructor/courses').then(res => res.data);
    return new Promise<Course[]>((resolve) => setTimeout(() => resolve(mockCourses), 300));
  },

  getCourseActivities: async (courseId: string) => {
    // return apiClient.get<Activity[]>(`/instructor/courses/${courseId}/activities`).then(res => res.data);
    return new Promise<Activity[]>((resolve) => 
      setTimeout(() => resolve(mockActivities.filter(a => a.courseId === courseId)), 300)
    );
  },

  createActivity: async (courseId: string, data: Omit<Activity, 'id' | 'courseId' | 'status'>) => {
    // return apiClient.post<Activity>(`/instructor/courses/${courseId}/activities`, data).then(res => res.data);
    return new Promise<Activity>((resolve) => {
      setTimeout(() => {
        const newActivity: Activity = {
          ...data,
          id: `act-${Date.now()}`,
          courseId,
          status: 'NOT_STARTED',
        };
        mockActivities.push(newActivity);
        resolve(newActivity);
      }, 300);
    });
  },

  updateActivity: async (activityId: string, data: Partial<Activity>) => {
    // return apiClient.patch<Activity>(`/instructor/activities/${activityId}`, data).then(res => res.data);
    return new Promise<Activity>((resolve, reject) => {
      setTimeout(() => {
        const index = mockActivities.findIndex(a => a.id === activityId);
        if (index > -1) {
          mockActivities[index] = { ...mockActivities[index], ...data };
          resolve(mockActivities[index]);
        } else {
          reject(new Error('Activity not found'));
        }
      }, 300);
    });
  },

  startActivity: async (activityId: string) => {
    // return apiClient.post<Activity>(`/instructor/activities/${activityId}/start`).then(res => res.data);
    return instructorApi.updateActivity(activityId, { status: 'ACTIVE' });
  },

  endActivity: async (activityId: string) => {
    // return apiClient.post<Activity>(`/instructor/activities/${activityId}/end`).then(res => res.data);
    return instructorApi.updateActivity(activityId, { status: 'ENDED' });
  },

  resetActivity: async (activityId: string) => {
    // return apiClient.post<Activity>(`/instructor/activities/${activityId}/reset`).then(res => res.data);
    return instructorApi.updateActivity(activityId, { status: 'ENDED' });
  },

  getActivityLogs: async (activityId: string) => {
    const response = await apiClient.get(`/instructor/activities/${activityId}/logs`);
    const rawLogs = Array.isArray(response.data) ? response.data : response.data?.logs ?? [];
    return rawLogs.map((raw: Record<string, unknown>) => normalizeActivityLog(raw));
  },
};
