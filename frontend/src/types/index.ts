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

export interface ActivityCompletionLog {
  studentId: string;
  studentName: string;
  studentEmail: string;
  activityId: string;
  activityTitle: string;
  courseId: string;
  action: 'COMPLETED';
  createdAt: string | null;
}

/**
 * @interface ManualGradeRequest
 * @brief Payload sent by an instructor to manually override a student score (US-L).
 *
 * Maps directly to the backend `ManualGradeRequest` Pydantic model.
 *
 * @property studentEmail  E-mail address of the student being graded.
 * @property score         Explicit score value to assign.
 * @property note          Optional justification note logged alongside the grade event.
 */
export interface ManualGradeRequest {
  studentEmail: string;
  score: number;
  note: string;
}

/**
 * @interface ManualGradeResult
 * @brief Shape of the successful response returned after a manual grade submission.
 *
 * @property message  Human-readable confirmation message from the backend.
 */
export interface ManualGradeResult {
  message: string;
}

/**
 * @interface EnrolledStudent
 * @brief A student enrolled in a course.
 */
export interface EnrolledStudent {
  studentId: string;
  email: string;
  fullName: string;
  enrolledAt: string | null;
}

/**
 * @interface EnrollmentResult
 * @brief Result returned after a bulk enrollment request.
 */
export interface EnrollmentResult {
  enrolled: string[];
  alreadyEnrolled: string[];
  notFound: string[];
}
