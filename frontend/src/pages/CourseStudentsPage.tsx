/**
 * @file CourseStudentsPage.tsx
 * @brief Page for instructors to view and manage enrolled students in a course.
 *
 * ## Responsibilities
 * - Fetch and display the list of enrolled students.
 * - Open {@link EnrollStudentsModal} to enroll new students.
 * - Allow unenrolling individual students via a confirm modal.
 *
 * ## SOLID notes
 * - **SRP** – page owns data fetching and layout only; enrollment logic lives in
 *   {@link EnrollStudentsModal}.
 * - **DIP** – depends on `instructorApi` abstraction, not axios directly.
 */

import React, { useCallback, useEffect, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { instructorApi } from '../api/instructorApi';
import type { EnrolledStudent } from '../types';
import { ArrowLeft, UserPlus, UserMinus, Users } from 'lucide-react';
import { EnrollStudentsModal } from '../components/EnrollStudentsModal';
import { ConfirmModal } from '../components/ConfirmModal';

export const CourseStudentsPage: React.FC = () => {
  const { courseId } = useParams<{ courseId: string }>();
  const navigate = useNavigate();

  const [students, setStudents] = useState<EnrolledStudent[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [isEnrollModalOpen, setIsEnrollModalOpen] = useState(false);
  const [unenrollTarget, setUnenrollTarget] = useState<EnrolledStudent | null>(null);
  const [isUnenrolling, setIsUnenrolling] = useState(false);
  const [error, setError] = useState('');

  const fetchStudents = useCallback(async () => {
    if (!courseId) return;
    try {
      setIsLoading(true);
      const data = await instructorApi.getEnrolledStudents(courseId);
      setStudents(data);
    } catch (err) {
      console.error('Failed to fetch enrolled students', err);
      setError('Failed to load students.');
    } finally {
      setIsLoading(false);
    }
  }, [courseId]);

  useEffect(() => {
    void fetchStudents();
  }, [fetchStudents]);

  const handleEnrollSuccess = () => {
    setIsEnrollModalOpen(false);
    void fetchStudents();
  };

  const handleUnenrollConfirm = async () => {
    if (!unenrollTarget || !courseId) return;
    try {
      setIsUnenrolling(true);
      await instructorApi.unenrollStudent(courseId, unenrollTarget.email);
      setUnenrollTarget(null);
      void fetchStudents();
    } catch (err) {
      console.error('Failed to unenroll student', err);
    } finally {
      setIsUnenrolling(false);
    }
  };

  const formatDate = (iso: string | null): string => {
    if (!iso) return '—';
    try {
      return new Date(iso).toLocaleDateString(undefined, {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
      });
    } catch {
      return iso;
    }
  };

  return (
    <div>
      {/* Page header */}
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-3">
          <button
            onClick={() => navigate(-1)}
            className="p-2 rounded-lg text-gray-500 hover:bg-gray-100 hover:text-gray-700 transition-colors"
            title="Back"
          >
            <ArrowLeft className="h-5 w-5" />
          </button>
          <div>
            <h1 className="text-2xl font-bold text-gray-900">Enrolled Students</h1>
            <p className="text-sm text-gray-500 mt-0.5">
              {isLoading ? '…' : `${students.length} student(s) enrolled`}
            </p>
          </div>
        </div>
        <button
          onClick={() => setIsEnrollModalOpen(true)}
          className="inline-flex items-center gap-2 rounded-md border border-transparent bg-indigo-600 px-4 py-2 text-sm font-semibold text-white shadow-sm hover:bg-indigo-700 transition-colors focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:ring-offset-2"
        >
          <UserPlus className="h-4 w-4" />
          Enroll Students
        </button>
      </div>

      {/* Error banner */}
      {error && (
        <div className="mb-4 rounded-lg border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-800">
          {error}
        </div>
      )}

      {/* Student list */}
      {isLoading ? (
        <div className="text-center py-10 text-gray-500">Loading students…</div>
      ) : students.length === 0 ? (
        <div className="bg-white rounded-lg border border-gray-200 p-10 text-center">
          <Users className="mx-auto h-10 w-10 text-gray-300 mb-3" />
          <p className="text-gray-500 font-medium">No students enrolled yet.</p>
          <p className="text-gray-400 text-sm mt-1">
            Click <span className="font-semibold text-gray-600">Enroll Students</span> to add students by email.
          </p>
        </div>
      ) : (
        <div className="bg-white shadow overflow-hidden sm:rounded-lg border border-gray-200">
          <table className="min-w-full divide-y divide-gray-200">
            <thead className="bg-gray-50">
              <tr>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Student
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Email
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Enrolled On
                </th>
                <th className="px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Actions
                </th>
              </tr>
            </thead>
            <tbody className="bg-white divide-y divide-gray-100">
              {students.map((student) => (
                <tr key={student.studentId} className="hover:bg-gray-50 transition-colors">
                  <td className="px-6 py-4 whitespace-nowrap">
                    <div className="flex items-center gap-3">
                      <div className="h-8 w-8 rounded-full bg-indigo-100 flex items-center justify-center text-indigo-600 text-sm font-semibold flex-shrink-0">
                        {(student.fullName || student.email).charAt(0).toUpperCase()}
                      </div>
                      <span className="text-sm font-medium text-gray-900">
                        {student.fullName || '(no name)'}
                      </span>
                    </div>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                    {student.email}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-400">
                    {formatDate(student.enrolledAt)}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-right">
                    <button
                      onClick={() => setUnenrollTarget(student)}
                      className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md text-red-600 bg-red-50 hover:bg-red-100 transition-colors focus:outline-none focus:ring-2 focus:ring-red-400"
                      title="Remove student"
                    >
                      <UserMinus className="h-3.5 w-3.5" />
                      Remove
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Enroll modal */}
      {courseId && (
        <EnrollStudentsModal
          isOpen={isEnrollModalOpen}
          courseId={courseId}
          onSuccess={handleEnrollSuccess}
          onCancel={() => setIsEnrollModalOpen(false)}
        />
      )}

      {/* Unenroll confirmation modal */}
      <ConfirmModal
        isOpen={unenrollTarget !== null}
        title="Remove Student"
        message={
          unenrollTarget
            ? `Are you sure you want to remove "${unenrollTarget.fullName || unenrollTarget.email}" from this course? Their progress data will be retained.`
            : ''
        }
        confirmText={isUnenrolling ? 'Removing…' : 'Remove'}
        confirmStyle="danger"
        onConfirm={handleUnenrollConfirm}
        onCancel={() => setUnenrollTarget(null)}
      />
    </div>
  );
};
