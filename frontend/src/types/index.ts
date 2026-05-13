export type Role = 'INSTRUCTOR' | 'STUDENT' | 'ADMIN';

export interface User {
  id: string;
  email: string;
  name: string;
  role: Role;
}

export interface Course {
  id: string;
  title: string;
  description: string;
}

export type ActivityStatus = 'NOT_STARTED' | 'ACTIVE' | 'ENDED';

export interface Activity {
  id: string;
  courseId: string;
  activityNumber: number;
  text: string;
  status: ActivityStatus;
  learningObjectives: string[];
}

export interface ActivityLog {
  id: string;
  activityId: string;
  studentId?: string;
  studentName: string;
  studentEmail?: string;
  score: number | null;
  objectiveMetadata: unknown;
  objectivesCompleted?: number;
  totalObjectives?: number;
  completed?: boolean;
  timestamp: string;
  eventType: string;
}
