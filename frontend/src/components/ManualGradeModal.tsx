/**
 * @file ManualGradeModal.tsx
 * @brief Self-contained modal component for submitting an instructor manual grade (US-L).
 *
 * ## Responsibilities (SRP)
 * This component owns exactly one concern: collecting and submitting a manual
 * grade for a single student in a single activity.  It does **not** manage
 * activity lists, navigation, or score-log display — those belong to their
 * respective pages.
 *
 * ## SOLID notes
 * - **SRP** – one reason to change: the manual-grade form UX.
 * - **OCP** – the component is closed for modification but open for extension
 *   via its props interface (e.g. adding a `maxScore` prop for validation).
 * - **LSP** – not applicable (no class hierarchy).
 * - **ISP** – `ManualGradeModalProps` exposes only the fields this component
 *   actually needs; callers are not forced to supply unrelated data.
 * - **DIP** – the component depends on the `instructorApi` abstraction, not on
 *   a concrete HTTP library directly.
 */

import React, { useEffect, useRef, useState } from 'react';
import { AlertCircle, Loader2, PenLine, X } from 'lucide-react';
import { instructorApi } from '../api/instructorApi';

// ---------------------------------------------------------------------------
// Props
// ---------------------------------------------------------------------------

/**
 * @interface ManualGradeModalProps
 * @brief Public contract for the ManualGradeModal component.
 *
 * @property isOpen        Controls modal visibility.
 * @property studentEmail  E-mail of the student being graded (sent to backend).
 * @property studentName   Display name shown in the modal heading.
 * @property courseId      Course identifier required by the backend endpoint.
 * @property activityNo    Activity number required by the backend endpoint.
 * @property onSuccess     Callback invoked after a successful submission so the
 *                         parent can refresh its data.
 * @property onCancel      Callback invoked when the user dismisses the modal
 *                         without submitting.
 */
export interface ManualGradeModalProps {
  isOpen: boolean;
  studentEmail: string;
  studentName: string;
  courseId: string;
  activityNo: number;
  onSuccess: () => void;
  onCancel: () => void;
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

/**
 * @component ManualGradeModal
 * @brief Modal dialog for instructor manual grade entry.
 *
 * Renders a focused overlay with a numeric score field and an optional note
 * field.  Submission is disabled while a request is in flight.  All API
 * errors are surfaced inline without closing the modal so the instructor can
 * correct input and retry.
 *
 * Focus is trapped to the score input when the modal opens so keyboard users
 * do not need to tab through the rest of the page.
 *
 * @param props  See {@link ManualGradeModalProps}.
 */
export const ManualGradeModal: React.FC<ManualGradeModalProps> = ({
  isOpen,
  studentEmail,
  studentName,
  courseId,
  activityNo,
  onSuccess,
  onCancel,
}) => {
  const [score, setScore] = useState<string>('');
  const [note, setNote] = useState<string>('');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState<string>('');

  const scoreInputRef = useRef<HTMLInputElement>(null);

  // Reset form state whenever the modal opens for a (potentially different) student.
  useEffect(() => {
    if (isOpen) {
      setScore('');
      setNote('');
      setError('');
      // Defer focus until after the DOM has updated.
      const frame = requestAnimationFrame(() => scoreInputRef.current?.focus());
      return () => cancelAnimationFrame(frame);
    }
  }, [isOpen]);

  if (!isOpen) return null;

  /**
   * @brief Validates form fields and submits the manual grade to the backend.
   *
   * Blocks double-submission via `isSubmitting` flag.  Parses the score string
   * to a float; rejects non-numeric or negative values client-side to give
   * immediate feedback before an API round-trip.
   */
  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (isSubmitting) return;

    const parsedScore = parseFloat(score);
    if (isNaN(parsedScore) || parsedScore < 0) {
      setError('Score must be a non-negative number.');
      return;
    }

    try {
      setIsSubmitting(true);
      setError('');
      await instructorApi.submitManualGrade(courseId, activityNo, {
        studentEmail,
        score: parsedScore,
        note: note.trim(),
      });
      onSuccess();
    } catch (err: unknown) {
      const axiosMessage =
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

      setError(axiosMessage ?? (err instanceof Error ? err.message : 'Failed to submit grade.'));
    } finally {
      setIsSubmitting(false);
    }
  };

  /** @brief Closes the modal on backdrop click unless a submission is in flight. */
  const handleBackdropClick = () => {
    if (!isSubmitting) onCancel();
  };

  return (
    /* Backdrop */
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 backdrop-blur-sm"
      onClick={handleBackdropClick}
      role="dialog"
      aria-modal="true"
      aria-labelledby="manual-grade-title"
    >
      {/* Panel — stop clicks from bubbling to backdrop */}
      <div
        className="relative w-full max-w-md rounded-2xl bg-white shadow-2xl mx-4"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className="flex items-center justify-between px-6 pt-5 pb-4 border-b border-gray-100">
          <div className="flex items-center gap-2">
            <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-indigo-50 text-indigo-600">
              <PenLine className="h-4 w-4" />
            </div>
            <h2 id="manual-grade-title" className="text-base font-semibold text-gray-900">
              Manual Grade
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
        <form onSubmit={handleSubmit} className="px-6 py-5 space-y-5">
          {/* Student context */}
          <div className="rounded-lg bg-gray-50 border border-gray-200 px-4 py-3 text-sm text-gray-700">
            <span className="text-gray-500">Grading: </span>
            <span className="font-semibold">{studentName}</span>
            <span className="ml-1 text-gray-400 text-xs">({studentEmail})</span>
          </div>

          {/* Error banner */}
          {error && (
            <div className="flex items-start gap-2 rounded-lg border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-800">
              <AlertCircle className="h-4 w-4 mt-0.5 flex-shrink-0" />
              <span>{error}</span>
            </div>
          )}

          {/* Score field */}
          <div>
            <label
              htmlFor="manual-grade-score"
              className="block text-sm font-medium text-gray-700 mb-1"
            >
              Score <span className="text-red-500">*</span>
            </label>
            <input
              id="manual-grade-score"
              ref={scoreInputRef}
              type="number"
              min="0"
              step="1"
              value={score}
              onChange={(e) => setScore(e.target.value)}
              disabled={isSubmitting}
              required
              className="block w-full rounded-lg border border-gray-300 px-3 py-2 text-sm shadow-sm focus:border-indigo-500 focus:outline-none focus:ring-2 focus:ring-indigo-500 disabled:bg-gray-100 disabled:cursor-not-allowed"
              placeholder="e.g. 3"
            />
          </div>

          {/* Note field */}
          <div>
            <label
              htmlFor="manual-grade-note"
              className="block text-sm font-medium text-gray-700 mb-1"
            >
              Note <span className="text-gray-400 font-normal">(optional)</span>
            </label>
            <textarea
              id="manual-grade-note"
              rows={3}
              value={note}
              onChange={(e) => setNote(e.target.value)}
              disabled={isSubmitting}
              className="block w-full resize-none rounded-lg border border-gray-300 px-3 py-2 text-sm shadow-sm focus:border-indigo-500 focus:outline-none focus:ring-2 focus:ring-indigo-500 disabled:bg-gray-100 disabled:cursor-not-allowed"
              placeholder="Reason for manual override…"
            />
          </div>

          {/* Actions */}
          <div className="flex justify-end gap-3 pt-1">
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
              disabled={isSubmitting || score === ''}
              className="inline-flex items-center gap-2 rounded-lg border border-transparent bg-indigo-600 px-4 py-2 text-sm font-semibold text-white shadow-sm hover:bg-indigo-700 transition-colors focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:ring-offset-2 disabled:bg-gray-300 disabled:cursor-not-allowed"
            >
              {isSubmitting && <Loader2 className="h-4 w-4 animate-spin" />}
              {isSubmitting ? 'Submitting…' : 'Submit Grade'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};
