/**
 * @file InstructorDashboard.tsx
 * @brief Instructor dashboard showing all assigned courses with options to
 *        create or delete courses.
 *
 * ## Responsibilities
 * - Fetch and display the instructor's course list.
 * - Open {@link CreateCourseModal} when the "+ Add Course" button is clicked.
 * - Allow deleting a course via a trash icon + confirmation modal.
 * - Refresh the course list after a successful creation or deletion.
 *
 * ## SOLID notes
 * - **SRP** – page owns data fetching and layout only; creation logic lives in
 *   {@link CreateCourseModal}.
 * - **DIP** – depends on `instructorApi` abstraction, not on axios directly.
 */

import React, { useCallback, useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { instructorApi } from '../api/instructorApi';
import type { Course } from '../types';
import { BookOpen, Plus, Trash2 } from 'lucide-react';
import { CreateCourseModal } from '../components/CreateCourseModal';
import { ConfirmModal } from '../components/ConfirmModal';

/**
 * @component InstructorDashboard
 * @brief Root page for authenticated instructors.
 *
 * Displays a card grid of assigned courses.  Each card navigates to the
 * course activity list on click.  The "+ Add Course" button opens a modal
 * for creating new courses.  The trash icon on each card deletes it after
 * confirmation.
 */
export const InstructorDashboard: React.FC = () => {
  const [courses, setCourses] = useState<Course[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [deleteTarget, setDeleteTarget] = useState<Course | null>(null);
  const [isDeleting, setIsDeleting] = useState(false);
  const navigate = useNavigate();

  /**
   * @brief Fetches all courses assigned to the authenticated instructor.
   */
  const fetchCourses = useCallback(async () => {
    try {
      setIsLoading(true);
      const data = await instructorApi.getCourses();
      setCourses(data);
    } catch (error) {
      console.error('Failed to fetch courses', error);
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    void fetchCourses();
  }, [fetchCourses]);

  const handleCourseCreated = () => {
    setIsModalOpen(false);
    void fetchCourses();
  };

  const handleDeleteCourse = async () => {
    if (!deleteTarget) return;
    try {
      setIsDeleting(true);
      await instructorApi.deleteCourse(deleteTarget.id);
      setDeleteTarget(null);
      void fetchCourses();
    } catch (error) {
      console.error('Failed to delete course', error);
    } finally {
      setIsDeleting(false);
    }
  };

  if (isLoading) {
    return <div className="text-center py-10">Loading courses...</div>;
  }

  return (
    <div>
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <h1 className="text-2xl font-bold text-gray-900">My Courses</h1>
        <button
          type="button"
          onClick={() => setIsModalOpen(true)}
          className="inline-flex items-center gap-2 rounded-md border border-transparent bg-indigo-600 px-4 py-2 text-sm font-semibold text-white shadow-sm hover:bg-indigo-700 transition-colors focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:ring-offset-2"
        >
          <Plus className="h-4 w-4" />
          Add Course
        </button>
      </div>

      {/* Course grid */}
      {courses.length === 0 ? (
        <div className="bg-white rounded-lg border border-gray-200 p-8 text-center text-gray-500">
          No courses assigned yet. Click <span className="font-semibold">Add Course</span> to create one.
        </div>
      ) : (
        <div className="grid grid-cols-1 gap-6 sm:grid-cols-2 lg:grid-cols-3">
          {courses.map((course) => (
            <div
              key={course.id}
              className="relative bg-white overflow-hidden shadow-sm rounded-lg border border-gray-200 cursor-pointer hover:shadow-md transition-shadow"
              onClick={() => navigate(`/instructor/courses/${course.id}`)}
            >
              {/* Delete button — stops propagation so the card click doesn't fire */}
              <button
                type="button"
                onClick={(e) => {
                  e.stopPropagation();
                  setDeleteTarget(course);
                }}
                className="absolute top-3 right-3 p-1.5 rounded-md text-gray-400 hover:bg-red-50 hover:text-red-500 transition-colors focus:outline-none focus:ring-2 focus:ring-red-400"
                title="Delete course"
              >
                <Trash2 className="h-4 w-4" />
              </button>

              <div className="p-6">
                <div className="flex items-center">
                  <div className="flex-shrink-0 bg-indigo-100 rounded-md p-3">
                    <BookOpen className="h-6 w-6 text-indigo-600" />
                  </div>
                  <div className="ml-4 pr-6">
                    <h3 className="text-lg font-medium text-gray-900">{course.title}</h3>
                  </div>
                </div>
                <div className="mt-4 text-sm text-gray-500 line-clamp-2">
                  {course.description}
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Create course modal */}
      <CreateCourseModal
        isOpen={isModalOpen}
        onSuccess={handleCourseCreated}
        onCancel={() => setIsModalOpen(false)}
      />

      {/* Delete course confirm modal */}
      <ConfirmModal
        isOpen={deleteTarget !== null}
        title="Delete Course"
        message={
          deleteTarget
            ? `Are you sure you want to permanently delete "${deleteTarget.title}"? All activities and student data for this course will also be deleted.`
            : ''
        }
        confirmText={isDeleting ? 'Deleting…' : 'Delete'}
        confirmStyle="danger"
        onConfirm={handleDeleteCourse}
        onCancel={() => setDeleteTarget(null)}
      />
    </div>
  );
};
