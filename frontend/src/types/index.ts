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
  studentId: string;
  studentName: string;
  studentEmail: string;
  activityId: string;
  activityTitle: string;
  courseId: string;
  currentScore: number;
  maxScore: number;
  completed: boolean;
  completionStatus: 'Completed' | 'In Progress' | 'Not Started';
  lastQuestion: string | null;
  lastAnswer: string | null;
  lastInteractionAt: string | null;
}
