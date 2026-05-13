import React, { useEffect, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { instructorApi } from '../api/instructorApi';
import type { ActivityLog } from '../types';
import { AlertCircle, ArrowLeft, User, Calendar, Award, CheckCircle } from 'lucide-react';

interface MetadataDisplayEntry {
  label: string;
  text: string;
  detail?: string;
}

const stringifyMetadataValue = (value: unknown): string => {
  if (value === null || value === undefined) return '';
  if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') {
    return String(value);
  }
  if (Array.isArray(value)) return value.map(String).join(', ');
  return JSON.stringify(value);
};

const getMetadataEntries = (metadata: unknown): MetadataDisplayEntry[] => {
  if (!metadata || typeof metadata !== 'object' || Array.isArray(metadata)) return [];

  return Object.entries(metadata as Record<string, unknown>).map(([label, value]) => {
    if (!value || typeof value !== 'object' || Array.isArray(value)) {
      return { label, text: stringifyMetadataValue(value) };
    }

    const record = value as Record<string, unknown>;
    const matchedWords = Array.isArray(record.matchedWords)
      ? record.matchedWords.map(String).join(', ')
      : '';
    const detailParts = [
      matchedWords ? `Matched: ${matchedWords}` : '',
      record.achievedAt ? `Achieved: ${new Date(String(record.achievedAt)).toLocaleString()}` : '',
      record.gradingType ? `Type: ${record.gradingType}` : '',
    ].filter(Boolean);

    return {
      label,
      text: String(record.objectiveText ?? record.note ?? record.score ?? ''),
      detail: detailParts.join('; '),
    };
  });
};

export const ActivityLogsPage: React.FC = () => {
  const { activityId } = useParams<{ activityId: string }>();
  const navigate = useNavigate();
  const [logs, setLogs] = useState<ActivityLog[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    const fetchLogs = async () => {
      if (!activityId) return;
      try {
        setError('');
        const data = await instructorApi.getActivityLogs(activityId);
        // Sort by timestamp descending
        setLogs(data.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()));
      } catch (error) {
        setError(error instanceof Error ? error.message : 'Failed to fetch activity logs.');
        setLogs([]);
      } finally {
        setIsLoading(false);
      }
    };
    fetchLogs();
  }, [activityId]);

  if (isLoading) return <div className="text-center py-10">Loading logs...</div>;

  return (
    <div>
      <div className="flex items-center mb-6">
        <button 
          onClick={() => navigate(-1)}
          className="mr-4 p-2 text-gray-500 hover:text-gray-700 hover:bg-gray-100 rounded-full transition-colors"
        >
          <ArrowLeft className="w-5 h-5" />
        </button>
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Activity Logs</h1>
          <p className="text-gray-500 text-sm mt-1">Student submissions and analytics</p>
        </div>
      </div>

      <div className="bg-white shadow overflow-hidden sm:rounded-lg">
        {error ? (
          <div className="m-6 rounded-lg border border-red-200 bg-red-50 p-4 text-red-800">
            <div className="flex items-center font-semibold">
              <AlertCircle className="h-5 w-5 mr-2" />
              Unable to load activity logs
            </div>
            <p className="mt-2 text-sm">{error}</p>
          </div>
        ) : logs.length === 0 ? (
          <div className="text-center py-12 text-gray-500">
            No logs available for this activity yet.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-gray-200">
              <thead className="bg-gray-50">
                <tr>
                  <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Student
                  </th>
                  <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Score
                  </th>
                  <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Objectives Met
                  </th>
                  <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Event Type
                  </th>
                  <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Timestamp
                  </th>
                  <th scope="col" className="px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Completion
                  </th>
                </tr>
              </thead>
              <tbody className="bg-white divide-y divide-gray-200">
                {logs.map((log) => {
                  const metadataEntries = getMetadataEntries(log.objectiveMetadata);
                  const scoreText = log.eventType !== 'MANUAL_GRADE' && log.objectivesCompleted !== undefined && log.totalObjectives !== undefined
                    ? `${log.objectivesCompleted}/${log.totalObjectives}`
                    : log.score !== null
                      ? String(log.score)
                      : 'N/A';

                  return (
                    <tr key={log.id} className="hover:bg-gray-50 transition-colors">
                      <td className="px-6 py-4 whitespace-nowrap">
                        <div className="flex items-center">
                          <div className="flex-shrink-0 h-8 w-8 bg-indigo-100 rounded-full flex items-center justify-center">
                            <User className="h-4 w-4 text-indigo-600" />
                          </div>
                          <div className="ml-4">
                            <div className="text-sm font-medium text-gray-900">{log.studentName}</div>
                            {log.studentEmail && (
                              <div className="text-xs text-gray-500">{log.studentEmail}</div>
                            )}
                          </div>
                        </div>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <div className="flex items-center">
                          <Award className={`h-4 w-4 mr-1 ${log.completed ? 'text-green-500' : 'text-yellow-500'}`} />
                          <span className="text-sm text-gray-900 font-semibold">{scoreText}</span>
                        </div>
                      </td>
                      <td className="px-6 py-4">
                        <div className="text-sm text-gray-900 max-w-md">
                          {metadataEntries.length === 0 ? (
                            <span className="text-xs text-gray-500">No objective details available.</span>
                          ) : metadataEntries.map((entry, i) => (
                            <div key={`${entry.label}-${i}`} className="flex items-start text-xs mb-2">
                              <CheckCircle className="h-3 w-3 text-green-500 mr-1 mt-0.5 flex-shrink-0" />
                              <span className="min-w-0">
                                <span className="font-medium">{entry.label}</span>
                                {entry.text && <span>: {entry.text}</span>}
                                {entry.detail && <span className="block text-gray-500">{entry.detail}</span>}
                              </span>
                            </div>
                          ))}
                        </div>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <span className="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-blue-100 text-blue-800">
                          {log.eventType}
                        </span>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                        <div className="flex items-center">
                          <Calendar className="h-4 w-4 mr-1 text-gray-400" />
                          {new Date(log.timestamp).toLocaleString()}
                        </div>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                        <span className={`px-2 inline-flex text-xs leading-5 font-semibold rounded-full ${
                          log.completed ? 'bg-green-100 text-green-800' : 'bg-yellow-100 text-yellow-800'
                        }`}>
                          {log.completed ? 'Completed' : 'In progress'}
                        </span>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};
