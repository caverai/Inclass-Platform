/**
 * @file EnrollStudentsModal.tsx
 * @brief Self-contained modal for enrolling students into a course.
 *
 * ## Responsibilities (SRP)
 * Collects a list of student emails (one per line, or comma-separated) and
 * calls the enrollment API.  Reports results inline: how many enrolled,
 * how many were already enrolled, and which emails were not found.
 *
 * ## SOLID notes
 * - **SRP**  – owns only the enroll-students form UX.
 * - **DIP**  – depends on `instructorApi` abstraction, not axios directly.
 */

import React, { useEffect, useRef, useState } from 'react';
import { AlertCircle, CheckCircle, Loader2, UserPlus, X } from 'lucide-react';
import { instructorApi } from '../api/instructorApi';
import type { EnrollmentResult } from '../types';

// ---------------------------------------------------------------------------
// Props
// ---------------------------------------------------------------------------

export interface EnrollStudentsModalProps {
  isOpen: boolean;
  courseId: string;
  /** Called after at least one student was successfully enrolled. */
  onSuccess: () => void;
  onCancel: () => void;
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export const EnrollStudentsModal: React.FC<EnrollStudentsModalProps> = ({
  isOpen,
  courseId,
  onSuccess,
  onCancel,
}) => {
  const [emailsRaw, setEmailsRaw] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState('');
  const [result, setResult] = useState<EnrollmentResult | null>(null);

  const textareaRef = useRef<HTMLTextAreaElement>(null);

  /** Reset state each time the modal opens. */
  useEffect(() => {
    if (isOpen) {
      setEmailsRaw('');
      setError('');
      setResult(null);
      const frame = requestAnimationFrame(() => textareaRef.current?.focus());
      return () => cancelAnimationFrame(frame);
    }
  }, [isOpen]);

  if (!isOpen) return null;

  /**
   * @brief Parses the raw textarea value into a cleaned list of emails.
   * Accepts newline-separated, comma-separated, or mixed formats.
   */
  const parseEmails = (raw: string): string[] => {
    return raw
      .split(/[\n,]+/)
      .map((e) => e.trim().toLowerCase())
      .filter((e) => e.length > 0);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (isSubmitting) return;

    const emails = parseEmails(emailsRaw);
    if (emails.length === 0) {
      setError('Please enter at least one student email.');
      return;
    }

    try {
      setIsSubmitting(true);
      setError('');
      setResult(null);

      const res = await instructorApi.enrollStudents(courseId, emails);
      setResult(res);

      if (res.enrolled.length > 0) {
        onSuccess(); // signal parent to refresh student count / list
      }
    } catch (err: unknown) {
      const axiosDetail =
        err &&
        typeof err === 'object' &&
        'response' in err &&
        (err as { response?: { data?: { detail?: unknown } } }).response?.data?.detail;

      setError(
        axiosDetail
          ? String(axiosDetail)
          : err instanceof Error
          ? err.message
          : 'Failed to enroll students.',
      );
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleBackdropClick = () => {
    if (!isSubmitting) onCancel();
  };

  const hasResult = result !== null;
  const totalEmails = parseEmails(emailsRaw).length;

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 backdrop-blur-sm"
      onClick={handleBackdropClick}
      role="dialog"
      aria-modal="true"
      aria-labelledby="enroll-students-title"
    >
      <div
        className="relative w-full max-w-lg rounded-2xl bg-white shadow-2xl mx-4"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className="flex items-center justify-between px-6 pt-5 pb-4 border-b border-gray-100">
          <div className="flex items-center gap-2">
            <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-indigo-50 text-indigo-600">
              <UserPlus className="h-4 w-4" />
            </div>
            <h2 id="enroll-students-title" className="text-base font-semibold text-gray-900">
              Enroll Students
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
        <div className="px-6 py-5 space-y-4">
          {/* Error banner */}
          {error && (
            <div className="flex items-start gap-2 rounded-lg border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-800">
              <AlertCircle className="h-4 w-4 mt-0.5 flex-shrink-0" />
              <span>{error}</span>
            </div>
          )}

          {/* Result panel (shown after submission) */}
          {hasResult && (
            <div className="rounded-lg border border-gray-200 bg-gray-50 p-4 space-y-2 text-sm">
              {result!.enrolled.length > 0 && (
                <div className="flex items-start gap-2 text-green-700">
                  <CheckCircle className="h-4 w-4 mt-0.5 flex-shrink-0" />
                  <span>
                    <span className="font-semibold">{result!.enrolled.length}</span> student(s) enrolled successfully.
                  </span>
                </div>
              )}
              {result!.alreadyEnrolled.length > 0 && (
                <div className="text-yellow-700">
                  <span className="font-semibold">{result!.alreadyEnrolled.length}</span> already enrolled:{' '}
                  <span className="text-xs">{result!.alreadyEnrolled.join(', ')}</span>
                </div>
              )}
              {result!.notFound.length > 0 && (
                <div className="text-red-700">
                  <span className="font-semibold">{result!.notFound.length}</span> not found (no student account):{' '}
                  <span className="text-xs">{result!.notFound.join(', ')}</span>
                </div>
              )}
            </div>
          )}

          {/* Email input — hide after successful submission to guide user to close */}
          {!hasResult && (
            <form onSubmit={handleSubmit} className="space-y-4">
              <div>
                <label
                  htmlFor="enroll-emails"
                  className="block text-sm font-medium text-gray-700 mb-1"
                >
                  Student Emails <span className="text-red-500">*</span>
                </label>
                <p className="text-xs text-gray-500 mb-2">
                  Enter one email per line, or separate with commas. Only registered student accounts will be enrolled.
                </p>
                <textarea
                  id="enroll-emails"
                  ref={textareaRef}
                  rows={6}
                  value={emailsRaw}
                  onChange={(e) => setEmailsRaw(e.target.value)}
                  disabled={isSubmitting}
                  className="block w-full rounded-lg border border-gray-300 px-3 py-2 text-sm shadow-sm focus:border-indigo-500 focus:outline-none focus:ring-2 focus:ring-indigo-500 disabled:bg-gray-100 disabled:cursor-not-allowed font-mono"
                  placeholder={'student1@school.edu\nstudent2@school.edu'}
                />
                {totalEmails > 0 && (
                  <p className="mt-1 text-xs text-gray-400">{totalEmails} email(s) detected</p>
                )}
              </div>

              <div className="flex justify-end gap-3">
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
                  disabled={isSubmitting || totalEmails === 0}
                  className="inline-flex items-center gap-2 rounded-lg border border-transparent bg-indigo-600 px-4 py-2 text-sm font-semibold text-white shadow-sm hover:bg-indigo-700 transition-colors focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:ring-offset-2 disabled:bg-gray-300 disabled:cursor-not-allowed"
                >
                  {isSubmitting && <Loader2 className="h-4 w-4 animate-spin" />}
                  {isSubmitting ? 'Enrolling…' : `Enroll ${totalEmails > 0 ? totalEmails : ''} Student(s)`}
                </button>
              </div>
            </form>
          )}

          {/* Post-result close button */}
          {hasResult && (
            <div className="flex justify-end">
              <button
                type="button"
                onClick={onCancel}
                className="rounded-lg border border-gray-300 bg-white px-4 py-2 text-sm font-medium text-gray-700 shadow-sm hover:bg-gray-50 transition-colors"
              >
                Close
              </button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
