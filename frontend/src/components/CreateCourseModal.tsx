/**
 * @file CreateCourseModal.tsx
 * @brief Self-contained modal component for instructor course creation.
 *
 * ## Responsibilities (SRP)
 * This component owns exactly one concern: collecting and submitting the data
 * needed to create a new course.  It does not manage the course list, routing,
 * or any other page-level state — those belong to {@link InstructorDashboard}.
 *
 * ## SOLID notes
 * - **SRP**  – one reason to change: the create-course form UX.
 * - **OCP**  – closed for modification; open for extension via props (e.g. adding
 *              a `defaultTerm` prop without touching existing callers).
 * - **ISP**  – `CreateCourseModalProps` exposes only what this component needs.
 * - **DIP**  – depends on the `instructorApi` abstraction, not on axios directly.
 */

import React, { useEffect, useRef, useState } from 'react';
import { AlertCircle, BookPlus, Loader2, X } from 'lucide-react';
import { instructorApi } from '../api/instructorApi';

// ---------------------------------------------------------------------------
// Props
// ---------------------------------------------------------------------------

/**
 * @interface CreateCourseModalProps
 * @brief Public contract for the CreateCourseModal component.
 *
 * @property isOpen     Controls modal visibility.
 * @property onSuccess  Callback invoked after a successful course creation so the
 *                      parent can refresh its course list.
 * @property onCancel   Callback invoked when the user dismisses the modal without
 *                      submitting.
 */
export interface CreateCourseModalProps {
  isOpen: boolean;
  onSuccess: () => void;
  onCancel: () => void;
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

/**
 * @component CreateCourseModal
 * @brief Modal dialog for creating a new course.
 *
 * Renders a focused overlay with three fields:
 * - Course Code (required, unique key)
 * - Course Name (required, human-readable title)
 * - Term        (optional, e.g. "2026 Spring")
 *
 * Submission is disabled while a request is in flight.  All API errors
 * (including 409 duplicate-code conflicts) are surfaced inline.  Focus is
 * trapped to the first input when the modal opens.
 *
 * @param props  See {@link CreateCourseModalProps}.
 */
export const CreateCourseModal: React.FC<CreateCourseModalProps> = ({
  isOpen,
  onSuccess,
  onCancel,
}) => {
  const [courseCode, setCourseCode] = useState('');
  const [courseName, setCourseName] = useState('');
  const [term, setTerm] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState('');

  const codeInputRef = useRef<HTMLInputElement>(null);

  /** Reset form state and focus the first field each time the modal opens. */
  useEffect(() => {
    if (isOpen) {
      setCourseCode('');
      setCourseName('');
      setTerm('');
      setError('');
      const frame = requestAnimationFrame(() => codeInputRef.current?.focus());
      return () => cancelAnimationFrame(frame);
    }
  }, [isOpen]);

  if (!isOpen) return null;

  /**
   * @brief Validates and submits the new course to the backend.
   *
   * Guards against double-submission via the `isSubmitting` flag.
   * Trims all string fields before sending.
   */
  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (isSubmitting) return;

    const trimmedCode = courseCode.trim();
    const trimmedName = courseName.trim();

    if (!trimmedCode) {
      setError('Course code is required.');
      return;
    }
    if (!trimmedName) {
      setError('Course name is required.');
      return;
    }

    try {
      setIsSubmitting(true);
      setError('');
      await instructorApi.createCourse(trimmedCode, trimmedName, term.trim() || undefined);
      onSuccess();
    } catch (err: unknown) {
      const axiosDetail =
        err &&
        typeof err === 'object' &&
        'response' in err &&
        err.response &&
        typeof err.response === 'object' &&
        'data' in err.response &&
        err.response.data &&
        typeof err.response.data === 'object' &&
        'detail' in err.response.data
          ? String((err.response.data as Record<string, unknown>).detail)
          : null;

      setError(axiosDetail ?? (err instanceof Error ? err.message : 'Failed to create course.'));
    } finally {
      setIsSubmitting(false);
    }
  };

  /** @brief Closes the modal on backdrop click unless a submission is in flight. */
  const handleBackdropClick = () => {
    if (!isSubmitting) onCancel();
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 backdrop-blur-sm"
      onClick={handleBackdropClick}
      role="dialog"
      aria-modal="true"
      aria-labelledby="create-course-title"
    >
      <div
        className="relative w-full max-w-md rounded-2xl bg-white shadow-2xl mx-4"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className="flex items-center justify-between px-6 pt-5 pb-4 border-b border-gray-100">
          <div className="flex items-center gap-2">
            <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-indigo-50 text-indigo-600">
              <BookPlus className="h-4 w-4" />
            </div>
            <h2 id="create-course-title" className="text-base font-semibold text-gray-900">
              Add Course
            </h2>
          </div>
          <button
            type="button"
            onClick={onCancel}
            disabled={isSubmitting}
            className="rounded-lg p-1.5 text-gray-400 hover:bg-gray-100 hover:text-gray-600 transition-colors disabled:cursor-not-allowed"
            aria-label="Close"
          >
            <X className="h-5 w-5" />
          </button>
        </div>

        {/* Body */}
        <form onSubmit={handleSubmit} className="px-6 py-5 space-y-4">
          {/* Error banner */}
          {error && (
            <div className="flex items-start gap-2 rounded-lg border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-800">
              <AlertCircle className="h-4 w-4 mt-0.5 flex-shrink-0" />
              <span>{error}</span>
            </div>
          )}

          {/* Course code */}
          <div>
            <label
              htmlFor="create-course-code"
              className="block text-sm font-medium text-gray-700 mb-1"
            >
              Course Code <span className="text-red-500">*</span>
            </label>
            <input
              id="create-course-code"
              ref={codeInputRef}
              type="text"
              value={courseCode}
              onChange={(e) => setCourseCode(e.target.value)}
              disabled={isSubmitting}
              required
              maxLength={50}
              className="block w-full rounded-lg border border-gray-300 px-3 py-2 text-sm shadow-sm focus:border-indigo-500 focus:outline-none focus:ring-2 focus:ring-indigo-500 disabled:bg-gray-100 disabled:cursor-not-allowed"
              placeholder="e.g. CS101"
            />
          </div>

          {/* Course name */}
          <div>
            <label
              htmlFor="create-course-name"
              className="block text-sm font-medium text-gray-700 mb-1"
            >
              Course Name <span className="text-red-500">*</span>
            </label>
            <input
              id="create-course-name"
              type="text"
              value={courseName}
              onChange={(e) => setCourseName(e.target.value)}
              disabled={isSubmitting}
              required
              maxLength={200}
              className="block w-full rounded-lg border border-gray-300 px-3 py-2 text-sm shadow-sm focus:border-indigo-500 focus:outline-none focus:ring-2 focus:ring-indigo-500 disabled:bg-gray-100 disabled:cursor-not-allowed"
              placeholder="e.g. Introduction to Software Engineering"
            />
          </div>

          {/* Term (optional) */}
          <div>
            <label
              htmlFor="create-course-term"
              className="block text-sm font-medium text-gray-700 mb-1"
            >
              Term <span className="text-gray-400 font-normal">(optional)</span>
            </label>
            <input
              id="create-course-term"
              type="text"
              value={term}
              onChange={(e) => setTerm(e.target.value)}
              disabled={isSubmitting}
              maxLength={100}
              className="block w-full rounded-lg border border-gray-300 px-3 py-2 text-sm shadow-sm focus:border-indigo-500 focus:outline-none focus:ring-2 focus:ring-indigo-500 disabled:bg-gray-100 disabled:cursor-not-allowed"
              placeholder="e.g. 2026 Spring"
            />
          </div>

          {/* Actions */}
          <div className="flex justify-end gap-3 pt-2">
            <button
              type="button"
              onClick={onCancel}
              disabled={isSubmitting}
              className="rounded-lg border border-gray-300 bg-white px-4 py-2 text-sm font-medium text-gray-700 shadow-sm hover:bg-gray-50 transition-colors disabled:cursor-not-allowed"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={isSubmitting || !courseCode.trim() || !courseName.trim()}
              className="inline-flex items-center gap-2 rounded-lg border border-transparent bg-indigo-600 px-4 py-2 text-sm font-semibold text-white shadow-sm hover:bg-indigo-700 transition-colors focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:ring-offset-2 disabled:bg-gray-300 disabled:cursor-not-allowed"
            >
              {isSubmitting && <Loader2 className="h-4 w-4 animate-spin" />}
              {isSubmitting ? 'Creating…' : 'Create Course'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};
