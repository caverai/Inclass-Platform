import { isAxiosError } from 'axios';
import { apiClient } from './client';
import { instructorApi } from './instructorApi';
import type { ActivityStatus, Course } from '../types';

export type StudentDataSource = 'backend' | 'mock';
export type StudentAccessReason = 'NOT_STARTED' | 'ENDED' | 'UNAUTHORIZED';

export interface StudentActivitySummary {
  id: string;
  courseId: string;
  activityNumber: number;
  text: string;
  status?: ActivityStatus;
  score?: number;
  completed?: boolean;
}

export interface StudentCourse extends Course {
  activities: StudentActivitySummary[];
  source: StudentDataSource;
}

export interface StudentChatMessage {
  id: string;
  sender: 'student' | 'tutor';
  content: string;
  miniLesson?: string;
  isCelebration?: boolean;
  timestamp: string;
}

export interface StudentActivityDetail {
  id: string;
  courseId: string;
  activityNumber: number;
  title?: string;
  text: string;
  status: ActivityStatus;
  score: number;
  totalObjectives?: number;
  completed: boolean;
  nextQuestion?: string | null;
  chatHistory: StudentChatMessage[];
  source: StudentDataSource;
}

export interface StudentChatResponse {
  tutorMessage: string;
  score: number;
  scoreDelta: number;
  completed: boolean;
  status: ActivityStatus;
  nextQuestion?: string | null;
  miniLesson?: string;
  isMock: boolean;
}

export class StudentActivityAccessError extends Error {
  reason: StudentAccessReason;

  constructor(reason: StudentAccessReason, message: string) {
    super(message);
    this.name = 'StudentActivityAccessError';
    this.reason = reason;
  }
}

interface MockProgress {
  score: number;
  completed: boolean;
  awardedActiveRetrieval: boolean;
  awardedFeedback: boolean;
  chatHistory: StudentChatMessage[];
}

const mockProgressByActivityId: Record<string, MockProgress> = {};
const MOCK_TOTAL_OBJECTIVES = 2;

const createMessageId = () => `${Date.now()}-${Math.random().toString(36).slice(2)}`;

const buildTutorMessage = (
  content: string,
  options: Pick<StudentChatMessage, 'miniLesson' | 'isCelebration'> = {},
): StudentChatMessage => ({
  id: createMessageId(),
  sender: 'tutor',
  content,
  timestamp: new Date().toISOString(),
  ...options,
});

const buildStudentMessage = (content: string): StudentChatMessage => ({
  id: createMessageId(),
  sender: 'student',
  content,
  timestamp: new Date().toISOString(),
});

const firstMockQuestion =
  'Question: How does active retrieval help a student learn from this activity?';

const feedbackMockQuestion =
  'Question: How can feedback help a student correct mistakes after trying an answer?';

const getAccessMessage = (reason: StudentAccessReason) => {
  if (reason === 'NOT_STARTED') return 'This activity has not started yet.';
  if (reason === 'ENDED') return 'This activity has ended.';
  return 'You are not authorized to access this activity.';
};

const mapAccessReason = (detail: unknown, statusCode?: number): StudentAccessReason => {
  const text = typeof detail === 'object'
    ? JSON.stringify(detail).toLowerCase()
    : String(detail ?? '').toLowerCase();
  if (text.includes('ended')) return 'ENDED';
  if (text.includes('not_started') || text.includes('not started') || text.includes('draft') || text.includes('only active')) {
    return 'NOT_STARTED';
  }
  if (statusCode === 404) return 'UNAUTHORIZED';
  return 'UNAUTHORIZED';
};

const shouldUseMockFallback = (error: unknown) => {
  if (!isAxiosError(error)) return true;
  if (!error.response) return true;

  const statusCode = error.response.status;
  const hasDemoToken = localStorage.getItem('demo_token') === 'mock-jwt-token';
  return statusCode === 404 || statusCode === 501 || (statusCode === 401 && hasDemoToken);
};

const throwAccessError = (error: unknown): never => {
  if (isAxiosError(error)) {
    const responseData =
      typeof error.response?.data === 'object' && error.response.data !== null
        ? (error.response.data as Record<string, unknown>)
        : undefined;
    const reason = mapAccessReason(
      responseData?.detail ?? responseData?.code ?? responseData?.status ?? error.response?.data,
      error.response?.status,
    );
    throw new StudentActivityAccessError(reason, getAccessMessage(reason));
  }

  throw new StudentActivityAccessError('UNAUTHORIZED', getAccessMessage('UNAUTHORIZED'));
};

const normalizeStatus = (value: unknown): ActivityStatus | undefined => {
  const status = String(value ?? '').toUpperCase();
  if (status === 'NOT_STARTED' || status === 'ACTIVE' || status === 'ENDED') {
    return status;
  }
  return undefined;
};

const normalizeCourse = (raw: Record<string, unknown>): Course => ({
  id: String(raw.id ?? raw.course_id ?? ''),
  title: String(raw.title ?? raw.course_name ?? raw.name ?? raw.course_code ?? 'Untitled Course'),
  description: String(raw.description ?? raw.term ?? ''),
});

const normalizeActivitySummary = (
  raw: Record<string, unknown>,
  courseId: string,
): StudentActivitySummary => ({
  id: String(raw.id ?? raw.activity_id ?? ''),
  courseId: String(raw.courseId ?? raw.course_id ?? courseId),
  activityNumber: Number(raw.activityNumber ?? raw.activity_no ?? raw.activity_number ?? 1),
  text: String(raw.text ?? raw.activity_text ?? raw.description ?? raw.prompt ?? ''),
  status: normalizeStatus(raw.status),
  score: typeof raw.score === 'number' ? raw.score : undefined,
  completed: typeof raw.completed === 'boolean' ? raw.completed : undefined,
});

const normalizeMessage = (raw: Record<string, unknown>, index: number): StudentChatMessage => {
  const senderValue = String(raw.sender ?? raw.role ?? '').toLowerCase();
  const sender = senderValue === 'student' || senderValue === 'user' ? 'student' : 'tutor';

  return {
    id: String(raw.id ?? `history-${index}`),
    sender,
    content: String(raw.content ?? raw.message ?? raw.text ?? ''),
    miniLesson: raw.miniLesson
      ? String(raw.miniLesson)
      : raw.mini_lesson
        ? String(raw.mini_lesson)
        : undefined,
    isCelebration: Boolean(raw.completed ?? raw.isCelebration ?? raw.is_celebration),
    timestamp: String(raw.timestamp ?? new Date().toISOString()),
  };
};

const normalizeActivityDetail = (
  raw: Record<string, unknown>,
  activityId: string,
): StudentActivityDetail => {
  const courseId = String(raw.courseId ?? raw.course_id ?? '');
  const chatRaw = Array.isArray(raw.chatHistory)
    ? raw.chatHistory
    : Array.isArray(raw.chat_history)
      ? raw.chat_history
      : [];
  const chatHistory = chatRaw.map((message, index) =>
    normalizeMessage(message as Record<string, unknown>, index),
  );
  const nextQuestion = raw.nextQuestion ?? raw.next_question ?? null;

  if (nextQuestion && chatHistory.length === 0) {
    chatHistory.push(buildTutorMessage(String(nextQuestion)));
  }

  return {
    id: String(raw.id ?? raw.activity_id ?? activityId),
    courseId,
    activityNumber: Number(raw.activityNumber ?? raw.activity_no ?? raw.activity_number ?? 1),
    title: raw.title ? String(raw.title) : undefined,
    text: String(raw.text ?? raw.activity_text ?? raw.description ?? raw.prompt ?? ''),
    status: normalizeStatus(raw.status) ?? 'ACTIVE',
    score: Number(raw.score ?? raw.current_score ?? 0),
    totalObjectives: raw.totalObjectives
      ? Number(raw.totalObjectives)
      : raw.total_objectives
        ? Number(raw.total_objectives)
        : undefined,
    completed: Boolean(raw.completed ?? raw.is_completed),
    nextQuestion: nextQuestion ? String(nextQuestion) : null,
    chatHistory,
    source: 'backend',
  };
};

const findMockActivity = async (activityId: string) => {
  const courses = await instructorApi.getCourses();

  for (const course of courses) {
    const activities = await instructorApi.getCourseActivities(course.id);
    const activity = activities.find((item) => item.id === activityId);
    if (activity) return { course, activity };
  }

  throw new StudentActivityAccessError('UNAUTHORIZED', getAccessMessage('UNAUTHORIZED'));
};

const getMockProgress = (activityId: string, activityText: string): MockProgress => {
  const existing = mockProgressByActivityId[activityId];
  if (existing) return existing;

  const progress: MockProgress = {
    score: 0,
    completed: false,
    awardedActiveRetrieval: false,
    awardedFeedback: false,
    chatHistory: [
      buildTutorMessage(`Activity text: ${activityText}\n\n${firstMockQuestion}`),
    ],
  };
  mockProgressByActivityId[activityId] = progress;
  return progress;
};

const getNextMockQuestion = (progress: MockProgress) => {
  if (!progress.awardedActiveRetrieval) return firstMockQuestion;
  if (!progress.awardedFeedback) return feedbackMockQuestion;
  return null;
};

const getMockStudentCourses = async (): Promise<StudentCourse[]> => {
  const courses = await instructorApi.getCourses();
  const coursesWithActivities = await Promise.all(
    courses.map(async (course) => {
      const activities = await instructorApi.getCourseActivities(course.id);
      return {
        ...course,
        activities: activities
          .sort((left, right) => left.activityNumber - right.activityNumber)
          .map((activity) => {
            const progress = mockProgressByActivityId[activity.id];
            return {
              id: activity.id,
              courseId: activity.courseId,
              activityNumber: activity.activityNumber,
              text: activity.text,
              status: activity.status,
              score: progress?.score,
              completed: progress?.completed,
            };
          }),
        source: 'mock' as const,
      };
    }),
  );

  return coursesWithActivities;
};

const getMockStudentActivity = async (activityId: string): Promise<StudentActivityDetail> => {
  const { course, activity } = await findMockActivity(activityId);

  if (activity.status === 'NOT_STARTED') {
    throw new StudentActivityAccessError('NOT_STARTED', getAccessMessage('NOT_STARTED'));
  }

  if (activity.status === 'ENDED') {
    throw new StudentActivityAccessError('ENDED', getAccessMessage('ENDED'));
  }

  const progress = getMockProgress(activity.id, activity.text);

  return {
    id: activity.id,
    courseId: course.id,
    activityNumber: activity.activityNumber,
    title: `Activity ${activity.activityNumber}`,
    text: activity.text,
    status: activity.status,
    score: progress.score,
    totalObjectives: MOCK_TOTAL_OBJECTIVES,
    completed: progress.completed,
    nextQuestion: getNextMockQuestion(progress),
    chatHistory: progress.chatHistory,
    source: 'mock',
  };
};

const runMockChat = async (activityId: string, answer: string): Promise<StudentChatResponse> => {
  const { activity } = await findMockActivity(activityId);

  if (activity.status === 'NOT_STARTED') {
    throw new StudentActivityAccessError('NOT_STARTED', getAccessMessage('NOT_STARTED'));
  }

  if (activity.status === 'ENDED') {
    throw new StudentActivityAccessError('ENDED', getAccessMessage('ENDED'));
  }

  const progress = getMockProgress(activity.id, activity.text);
  progress.chatHistory.push(buildStudentMessage(answer));

  const normalizedAnswer = answer.toLowerCase();
  const mentionsActiveRetrieval =
    normalizedAnswer.includes('active retrieval') ||
    normalizedAnswer.includes('retrieval practice') ||
    normalizedAnswer.includes('recall') ||
    normalizedAnswer.includes('remember without');
  const mentionsFeedback =
    normalizedAnswer.includes('feedback') ||
    normalizedAnswer.includes('correcting mistakes') ||
    normalizedAnswer.includes('correct mistakes') ||
    normalizedAnswer.includes('fix mistakes') ||
    normalizedAnswer.includes('errors');

  let scoreDelta = 0;
  let miniLesson: string | undefined;
  let tutorMessage = 'No new point yet. Add a more specific idea and try again.';

  if (mentionsActiveRetrieval && !progress.awardedActiveRetrieval) {
    progress.awardedActiveRetrieval = true;
    progress.score += 1;
    scoreDelta = 1;
    miniLesson = 'Active retrieval means pulling an idea from memory before seeing the answer. That effort makes the learning stickier than rereading alone.';
    tutorMessage = `Nice, you earned +1 for active retrieval. Your score is now ${progress.score}.`;
  } else if (mentionsFeedback && !progress.awardedFeedback) {
    progress.awardedFeedback = true;
    progress.score += 1;
    scoreDelta = 1;
    miniLesson = 'Feedback works best when it points to the mistake and gives the learner a chance to revise, so the correction becomes part of the next attempt.';
    tutorMessage = `Strong connection, you earned +1 for feedback and correcting mistakes. Your score is now ${progress.score}.`;
  } else if (
    (mentionsActiveRetrieval && progress.awardedActiveRetrieval) ||
    (mentionsFeedback && progress.awardedFeedback)
  ) {
    tutorMessage = `That idea was already counted, so your score stays ${progress.score}.`;
  }

  progress.completed = progress.score >= MOCK_TOTAL_OBJECTIVES;
  const nextQuestion = getNextMockQuestion(progress);

  if (progress.completed) {
    tutorMessage = `Excellent work, you completed the activity. Your final score is ${progress.score}.`;
  } else if (nextQuestion) {
    tutorMessage = `${tutorMessage}\n\n${nextQuestion}`;
  }

  const tutorChatMessage = buildTutorMessage(tutorMessage, {
    miniLesson,
    isCelebration: progress.completed,
  });
  progress.chatHistory.push(tutorChatMessage);

  return {
    tutorMessage,
    score: progress.score,
    scoreDelta,
    completed: progress.completed,
    status: activity.status,
    nextQuestion,
    miniLesson,
    isMock: true,
  };
};

const normalizeChatResponse = (raw: Record<string, unknown>): StudentChatResponse => {
  const completed = Boolean(raw.completed ?? raw.is_completed);
  const score = Number(raw.score ?? raw.updated_score ?? raw.current_score ?? 0);
  const message = String(raw.tutorMessage ?? raw.tutor_message ?? raw.message ?? raw.response ?? '');
  const nextQuestion = raw.nextQuestion ?? raw.next_question ?? null;
  const status = normalizeStatus(raw.status) ?? 'ACTIVE';

  return {
    tutorMessage: nextQuestion && !completed ? `${message}\n\nQuestion: ${String(nextQuestion)}` : message,
    score,
    scoreDelta: Number(raw.scoreDelta ?? raw.score_delta ?? 0),
    completed,
    status,
    nextQuestion: nextQuestion ? String(nextQuestion) : null,
    miniLesson: raw.miniLesson ? String(raw.miniLesson) : raw.mini_lesson ? String(raw.mini_lesson) : undefined,
    isMock: false,
  };
};

export const studentApi = {
  getCourses: async (): Promise<StudentCourse[]> => {
    try {
      const response = await apiClient.get('/student/courses');
      const rawCourses = Array.isArray(response.data) ? response.data : response.data?.courses ?? [];
      return rawCourses.map((raw: Record<string, unknown>) => {
        const course = normalizeCourse(raw);
        const rawActivities = Array.isArray(raw.activities)
          ? raw.activities
          : Array.isArray(raw.available_activities)
            ? raw.available_activities
            : [];

        return {
          ...course,
          activities: rawActivities.map((activity) =>
            normalizeActivitySummary(activity as Record<string, unknown>, course.id),
          ),
          source: 'backend' as const,
        };
      });
    } catch (error) {
      if (shouldUseMockFallback(error)) {
        return getMockStudentCourses();
      }
      throwAccessError(error);
    }
  },

  getActivity: async (activityId: string): Promise<StudentActivityDetail> => {
    try {
      const response = await apiClient.get(`/student/activities/${activityId}`);
      return normalizeActivityDetail(response.data, activityId);
    } catch (error) {
      if (shouldUseMockFallback(error)) {
        return getMockStudentActivity(activityId);
      }
      throwAccessError(error);
    }
  },

  sendChatMessage: async (activityId: string, answer: string): Promise<StudentChatResponse> => {
    try {
      const response = await apiClient.post(`/student/activities/${activityId}/chat`, { answer });
      return normalizeChatResponse(response.data);
    } catch (error) {
      if (shouldUseMockFallback(error)) {
        return runMockChat(activityId, answer);
      }
      throwAccessError(error);
    }
  },
};
