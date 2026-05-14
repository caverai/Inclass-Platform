import React, { useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { AlertCircle, ArrowRight, BookOpen, Lock, Mail, UserRound } from 'lucide-react';
import { authApi } from '../api/authApi';
import { studentApi } from '../api/studentApi';
import type { StudentCourse, StudentActivitySummary } from '../api/studentApi';
import type { User } from '../types';
import { StatusBadge } from '../components/StatusBadge';

const getActivityMessage = (activity: StudentActivitySummary) => {
  if (activity.status === 'ACTIVE') {
    return activity.completed ? 'Completed' : 'Available now';
  }

  if (activity.status === 'NOT_STARTED') {
    return 'This activity has not started yet.';
  }

  if (activity.status === 'ENDED') {
    return 'This activity has ended.';
  }

  return 'This activity is unavailable.';
};

export const StudentDashboard: React.FC = () => {
  const navigate = useNavigate();
  const [user, setUser] = useState<User | null>(null);
  const [courses, setCourses] = useState<StudentCourse[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    const fetchData = async () => {
      try {
        setIsLoading(true);
        setError('');
        const [currentUser, courseData] = await Promise.all([
          authApi.getMe(),
          studentApi.getCourses(),
        ]);
        setUser(currentUser);
        setCourses(courseData);
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Unable to load the student dashboard.');
      } finally {
        setIsLoading(false);
      }
    };

    fetchData();
  }, []);

  const usingMockData = useMemo(
    () => courses.some((course) => course.source === 'mock'),
    [courses],
  );

  const activityCount = courses.reduce((count, course) => count + course.activities.length, 0);

  if (isLoading) {
    return <div className="py-10 text-center text-gray-600">Loading student dashboard...</div>;
  }

  if (error) {
    return (
      <div className="rounded-lg border border-red-200 bg-red-50 p-5 text-red-800">
        <div className="flex items-center gap-2 font-semibold">
          <AlertCircle className="h-5 w-5" />
          Dashboard unavailable
        </div>
        <p className="mt-2 text-sm">{error}</p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-4 rounded-lg border border-gray-200 bg-white p-5 shadow-sm sm:flex-row sm:items-center sm:justify-between">
        <div>
          <p className="text-sm font-semibold uppercase tracking-wide text-indigo-600">Student Dashboard</p>
          <h1 className="mt-1 text-2xl font-bold text-gray-900">{user?.name}</h1>
          <div className="mt-3 flex flex-col gap-2 text-sm text-gray-600 sm:flex-row sm:items-center sm:gap-5">
            <span className="inline-flex items-center gap-2">
              <Mail className="h-4 w-4 text-gray-400" />
              {user?.email}
            </span>
            <span className="inline-flex items-center gap-2">
              <BookOpen className="h-4 w-4 text-gray-400" />
              {courses.length} enrolled course{courses.length === 1 ? '' : 's'}
            </span>
          </div>
        </div>
        <div className="rounded-lg border border-indigo-100 bg-indigo-50 px-4 py-3 text-sm font-semibold text-indigo-700">
          {activityCount} available activit{activityCount === 1 ? 'y' : 'ies'}
        </div>
      </div>

      {usingMockData && (
        <div className="rounded-lg border border-amber-200 bg-amber-50 p-4 text-sm text-amber-900">
          Mock tutoring mode is active because the student backend endpoints are unavailable.
        </div>
      )}

      {courses.length === 0 ? (
        <div className="rounded-lg border border-gray-200 bg-white p-8 text-center text-gray-500">
          No enrolled courses are available.
        </div>
      ) : (
        <div className="space-y-6">
          {courses.map((course) => (
            <section key={course.id} className="space-y-3">
              <div>
                <h2 className="text-xl font-bold text-gray-900">{course.title}</h2>
                {course.description && <p className="mt-1 text-sm text-gray-500">{course.description}</p>}
              </div>

              {course.activities.length === 0 ? (
                <div className="rounded-lg border border-gray-200 bg-white p-5 text-sm text-gray-500">
                  No activities have been shared for this course yet.
                </div>
              ) : (
                <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-3">
                  {course.activities.map((activity) => {
                    const isActive = activity.status === 'ACTIVE';

                    return (
                      <article
                        key={activity.id}
                        className="flex min-h-[220px] flex-col rounded-lg border border-gray-200 bg-white p-5 shadow-sm transition-shadow hover:shadow-md"
                      >
                        <div className="mb-3 flex items-start justify-between gap-3">
                          <div>
                            <h3 className="font-semibold text-gray-900">Activity {activity.activityNumber}</h3>
                            {typeof activity.score === 'number' && (
                              <p className="mt-1 text-xs font-medium text-gray-500">Current score: {activity.score}</p>
                            )}
                          </div>
                          {activity.status && <StatusBadge status={activity.status} />}
                        </div>

                        <p className="line-clamp-3 flex-1 text-sm leading-6 text-gray-600">{activity.text}</p>

                        <div
                          className={`mt-4 flex items-start gap-2 rounded-lg p-3 text-sm ${
                            isActive
                              ? 'bg-emerald-50 text-emerald-800'
                              : 'border border-gray-200 bg-gray-50 text-gray-600'
                          }`}
                        >
                          {isActive ? (
                            <UserRound className="mt-0.5 h-4 w-4 flex-shrink-0" />
                          ) : (
                            <Lock className="mt-0.5 h-4 w-4 flex-shrink-0" />
                          )}
                          <span>{getActivityMessage(activity)}</span>
                        </div>

                        <button
                          type="button"
                          onClick={() => navigate(`/student/activities/${activity.id}`)}
                          className="mt-4 inline-flex items-center justify-center rounded-md border border-transparent bg-indigo-600 px-4 py-2 text-sm font-semibold text-white shadow-sm transition-colors hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:ring-offset-2"
                        >
                          <ArrowRight className="mr-2 h-4 w-4" />
                          {isActive ? 'Open Activity' : 'View Status'}
                        </button>
                      </article>
                    );
                  })}
                </div>
              )}
            </section>
          ))}
        </div>
      )}
    </div>
  );
};
