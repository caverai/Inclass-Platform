import React, { useEffect, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { instructorApi } from '../api/instructorApi';
import type { ActivityCompletionLog, ActivityLog } from '../types';
import { AlertCircle, ArrowLeft, User, Clock, CheckCircle2, Circle, Loader2 } from 'lucide-react';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const formatDateTime = (iso: string | null): string => {
  if (!iso) return '—';
  try {
    return new Date(iso).toLocaleString();
  } catch {
    return iso;
  }
};

const truncate = (text: string | null, max = 80): string => {
  if (!text) return '—';
  return text.length > max ? text.slice(0, max) + '…' : text;
};

const StatusBadge: React.FC<{ status: ActivityLog['completionStatus'] }> = ({ status }) => {
  if (status === 'Completed') {
    return (
      <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-semibold bg-green-100 text-green-800">
        <CheckCircle2 className="w-3 h-3 mr-1" />
        Completed
      </span>
    );
  }
  if (status === 'In Progress') {
    return (
      <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-semibold bg-yellow-100 text-yellow-800">
        <Loader2 className="w-3 h-3 mr-1" />
        In Progress
      </span>
    );
  }
  return (
    <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-semibold bg-gray-100 text-gray-600">
      <Circle className="w-3 h-3 mr-1" />
      Not Started
    </span>
  );
};

// ---------------------------------------------------------------------------
// Page component
// ---------------------------------------------------------------------------

export const ActivityLogsPage: React.FC = () => {
  const { activityId } = useParams<{ activityId: string }>();
  const navigate = useNavigate();
  const [logs, setLogs] = useState<ActivityLog[]>([]);
  const [completionLogs, setCompletionLogs] = useState<ActivityCompletionLog[]>([]);
  const [activityTitle, setActivityTitle] = useState('');
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState('');
  const [completionError, setCompletionError] = useState('');

  useEffect(() => {
    const fetchLogs = async () => {
      if (!activityId) return;
      setIsLoading(true);
      setError('');
      setCompletionError('');

      const [activityResult, completionResult] = await Promise.allSettled([
        instructorApi.getActivityLogs(activityId),
        instructorApi.getActivityCompletionLogs(activityId),
      ]);

      if (activityResult.status === 'fulfilled') {
        setLogs(activityResult.value);
        if (activityResult.value.length > 0) {
          setActivityTitle(activityResult.value[0].activityTitle);
        }
      } else {
        setError(
          activityResult.reason instanceof Error
            ? activityResult.reason.message
            : 'Failed to fetch activity logs.',
        );
        setLogs([]);
      }

      if (completionResult.status === 'fulfilled') {
        setCompletionLogs(completionResult.value);
      } else {
        setCompletionError(
          completionResult.reason instanceof Error
            ? completionResult.reason.message
            : 'Failed to fetch completion logs.',
        );
        setCompletionLogs([]);
      }

      setIsLoading(false);
    };
    fetchLogs();
  }, [activityId]);

  // Summary counts
  const completedCount  = logs.filter(l => l.completionStatus === 'Completed').length;
  const inProgressCount = logs.filter(l => l.completionStatus === 'In Progress').length;
  const notStartedCount = logs.filter(l => l.completionStatus === 'Not Started').length;

  if (isLoading) {
    return <div className="text-center py-10 text-gray-500">Loading logs…</div>;
  }

  return (
    <div>
      {/* Header */}
      <div className="flex items-center mb-6">
        <button
          onClick={() => navigate(-1)}
          className="mr-4 p-2 text-gray-500 hover:text-gray-700 hover:bg-gray-100 rounded-full transition-colors"
        >
          <ArrowLeft className="w-5 h-5" />
        </button>
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Activity Logs</h1>
          {activityTitle && (
            <p className="text-gray-500 text-sm mt-0.5">{activityTitle}</p>
          )}
        </div>
      </div>

      {error ? (
        <div className="rounded-lg border border-red-200 bg-red-50 p-4 text-red-800">
          <div className="flex items-center font-semibold">
            <AlertCircle className="h-5 w-5 mr-2" />
            Unable to load activity logs
          </div>
          <p className="mt-2 text-sm">{error}</p>
        </div>
      ) : (
        <>
          <div className="bg-white shadow-sm rounded-lg border border-gray-200 p-5 mb-6">
            <h2 className="text-lg font-semibold text-gray-900 mb-3">Completion Events</h2>
            {completionError ? (
              <p className="text-sm text-red-600">{completionError}</p>
            ) : completionLogs.length === 0 ? (
              <p className="text-sm text-gray-500">No completion events yet.</p>
            ) : (
              <ul className="space-y-2">
                {completionLogs.map((log) => (
                  <li
                    key={`${log.activityId}-${log.studentId}-${log.createdAt ?? 'unknown'}`}
                    className="flex items-center justify-between gap-4 text-sm text-gray-700"
                  >
                    <span>
                      <span className="font-semibold">{log.studentName}</span> completed{' '}
                      <span className="font-semibold">{log.activityTitle}</span>.
                    </span>
                    <span className="flex items-center text-xs text-gray-500">
                      <Clock className="h-3 w-3 mr-1" />
                      {formatDateTime(log.createdAt)}
                    </span>
                  </li>
                ))}
              </ul>
            )}
          </div>

          {/* Summary bar */}
          {logs.length > 0 && (
            <div className="grid grid-cols-3 gap-4 mb-6">
              <div className="bg-green-50 border border-green-200 rounded-lg p-4 text-center">
                <p className="text-2xl font-bold text-green-700">{completedCount}</p>
                <p className="text-sm text-green-600 mt-1">Completed</p>
              </div>
              <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-4 text-center">
                <p className="text-2xl font-bold text-yellow-700">{inProgressCount}</p>
                <p className="text-sm text-yellow-600 mt-1">In Progress</p>
              </div>
              <div className="bg-gray-50 border border-gray-200 rounded-lg p-4 text-center">
                <p className="text-2xl font-bold text-gray-600">{notStartedCount}</p>
                <p className="text-sm text-gray-500 mt-1">Not Started</p>
              </div>
            </div>
          )}

          <div className="bg-white shadow overflow-hidden sm:rounded-lg">
            {logs.length === 0 ? (
              <div className="text-center py-12 text-gray-500">
                No students enrolled in this course yet.
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="min-w-full divide-y divide-gray-200">
                  <thead className="bg-gray-50">
                    <tr>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                        Student
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                        Score
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                        Status
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                        Last Interaction
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                        Last Answer
                      </th>
                    </tr>
                  </thead>
                  <tbody className="bg-white divide-y divide-gray-200">
                    {logs.map((log) => (
                      <tr
                        key={`${log.activityId}-${log.studentId}`}
                        className="hover:bg-gray-50 transition-colors"
                      >
                        {/* Student */}
                        <td className="px-6 py-4 whitespace-nowrap">
                          <div className="flex items-center">
                            <div className="flex-shrink-0 h-8 w-8 bg-indigo-100 rounded-full flex items-center justify-center">
                              <User className="h-4 w-4 text-indigo-600" />
                            </div>
                            <div className="ml-3">
                              <div className="text-sm font-medium text-gray-900">{log.studentName}</div>
                              <div className="text-xs text-gray-400">{log.studentEmail}</div>
                            </div>
                          </div>
                        </td>

                        {/* Score */}
                        <td className="px-6 py-4 whitespace-nowrap">
                          <span className={`text-sm font-semibold ${
                            log.completionStatus === 'Completed'
                              ? 'text-green-700'
                              : log.completionStatus === 'In Progress'
                              ? 'text-yellow-700'
                              : 'text-gray-400'
                          }`}>
                            {log.completionStatus === 'Not Started'
                              ? '—'
                              : `${log.currentScore} / ${log.maxScore}`}
                          </span>
                        </td>

                        {/* Status badge */}
                        <td className="px-6 py-4 whitespace-nowrap">
                          <StatusBadge status={log.completionStatus} />
                        </td>

                        {/* Last interaction */}
                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                          {log.lastInteractionAt ? (
                            <div className="flex items-center">
                              <Clock className="h-4 w-4 mr-1 text-gray-400 flex-shrink-0" />
                              {formatDateTime(log.lastInteractionAt)}
                            </div>
                          ) : (
                            <span className="text-gray-300">—</span>
                          )}
                        </td>

                        {/* Last answer preview */}
                        <td className="px-6 py-4 text-sm text-gray-600 max-w-xs">
                          <span className="italic text-gray-400 text-xs">
                            {truncate(log.lastAnswer)}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </>
      )}
    </div>
  );
};
