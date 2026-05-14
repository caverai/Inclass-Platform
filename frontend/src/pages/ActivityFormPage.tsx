/**
 * @file ActivityFormPage.tsx
 * @brief Create / edit form for a single course activity.
 *
 * ## Responsibilities
 * - Create mode: collects activity number, text, and learning objectives,
 *   then calls `POST /instructor/activity/create`.
 * - Edit mode:   resolves the existing activity by UUID, pre-fills the form,
 *   then calls `PATCH /instructor/activity/{courseId}/{activityNo}`.
 *
 * All backend errors (400 validation, 403 not-authorized, 409 duplicate number)
 * are surfaced inline so the instructor can correct the input without losing work.
 *
 * ## SOLID notes
 * - **SRP** – owns only the activity form lifecycle.
 * - **DIP** – depends on `instructorApi` abstraction, not on axios directly.
 */

import React, { useState, useEffect } from 'react';
import { useParams, useNavigate, useLocation } from 'react-router-dom';
import { instructorApi } from '../api/instructorApi';
import type { Activity } from '../types';
import { AlertCircle, Plus, Trash2, ArrowLeft, Save } from 'lucide-react';

/**
 * @brief Extracts a human-readable error message from an unknown thrown value.
 *
 * Prefers the `detail` field from an Axios JSON response body (FastAPI format),
 * falls back to the Error message, then a generic string.
 *
 * @param err  The caught value from a try/catch block.
 * @returns    A non-empty string suitable for display in the UI.
 */
const extractErrorMessage = (err: unknown): string => {
  if (
    err &&
    typeof err === 'object' &&
    'response' in err &&
    err.response &&
    typeof err.response === 'object' &&
    'data' in err.response &&
    err.response.data &&
    typeof err.response.data === 'object' &&
    'detail' in err.response.data
  ) {
    return String((err.response.data as Record<string, unknown>).detail);
  }
  if (err instanceof Error) return err.message;
  return 'An unexpected error occurred.';
};

/**
 * @component ActivityFormPage
 * @brief Route-level component for creating or editing an activity.
 *
 * Determines mode from the URL pathname:
 * - `/instructor/courses/:courseId/activities/new`  → create mode
 * - `/instructor/activities/:activityId/edit`       → edit mode
 */
export const ActivityFormPage: React.FC = () => {
  const { courseId, activityId } = useParams<{ courseId?: string; activityId?: string }>();
  const navigate = useNavigate();
  const location = useLocation();
  const isEdit = location.pathname.includes('/edit');

  const [isLoading, setIsLoading] = useState(isEdit);
  const [isSaving, setIsSaving] = useState(false);
  const [saveError, setSaveError] = useState('');

  /**
   * Resolved activity kept in state so edit mode has courseId + activityNumber
   * available for the PATCH endpoint path parameters.
   */
  const [resolvedActivity, setResolvedActivity] = useState<Activity | null>(null);

  const [activityNumber, setActivityNumber] = useState<number>(1);
  const [text, setText] = useState('');
  const [learningObjectives, setLearningObjectives] = useState<string[]>(['']);

  // ---------------------------------------------------------------------------
  // Edit mode: fetch existing activity data
  // ---------------------------------------------------------------------------

  useEffect(() => {
    const fetchActivity = async () => {
      if (!isEdit || !activityId) return;
      try {
        // No single-activity GET endpoint exists yet, so we search across courses.
        const courses = await instructorApi.getCourses();
        let found = false;
        for (const course of courses) {
          const activities = await instructorApi.getCourseActivities(course.id);
          const act = activities.find((a) => a.id === activityId);
          if (act) {
            setResolvedActivity(act);
            setActivityNumber(act.activityNumber);
            setText(act.text);
            setLearningObjectives(act.learningObjectives.length > 0 ? act.learningObjectives : ['']);
            found = true;
            break;
          }
        }
        if (!found) {
          navigate(-1);
        }
      } catch (err) {
        setSaveError(extractErrorMessage(err));
      } finally {
        setIsLoading(false);
      }
    };
    void fetchActivity();
  }, [isEdit, activityId, navigate]);

  // ---------------------------------------------------------------------------
  // Objective field helpers
  // ---------------------------------------------------------------------------

  /** @brief Appends a blank objective input row. */
  const handleAddObjective = () => setLearningObjectives([...learningObjectives, '']);

  /** @brief Removes the objective row at the given index. */
  const handleRemoveObjective = (index: number) =>
    setLearningObjectives(learningObjectives.filter((_, i) => i !== index));

  /** @brief Updates the objective string at the given index. */
  const handleObjectiveChange = (index: number, val: string) => {
    const updated = [...learningObjectives];
    updated[index] = val;
    setLearningObjectives(updated);
  };

  // ---------------------------------------------------------------------------
  // Form submission
  // ---------------------------------------------------------------------------

  /**
   * @brief Validates the form and calls the appropriate API method.
   *
   * Surfaces backend errors inline rather than via `alert()` so the instructor
   * can read the message and correct their input without losing form state.
   */
  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setSaveError('');

    if (!text.trim()) {
      setSaveError('Activity text is required.');
      return;
    }

    const validObjectives = learningObjectives.filter((obj) => obj.trim() !== '');
    if (validObjectives.length === 0) {
      setSaveError('At least one learning objective is required.');
      return;
    }

    try {
      setIsSaving(true);

      if (isEdit && activityId && resolvedActivity) {
        // Edit mode — PATCH existing activity
        await instructorApi.updateActivityContent(
          resolvedActivity.courseId,
          resolvedActivity.activityNumber,
          { text, objectives: validObjectives },
        );
        navigate(-1);
      } else if (courseId) {
        // Create mode — POST new activity
        await instructorApi.createActivity(courseId, {
          activityNumber,
          text,
          learningObjectives: validObjectives,
        });
        navigate(`/instructor/courses/${courseId}`);
      } else {
        setSaveError('Course ID is missing. Please navigate from a course page.');
      }
    } catch (err) {
      setSaveError(extractErrorMessage(err));
    } finally {
      setIsSaving(false);
    }
  };

  // ---------------------------------------------------------------------------
  // Render
  // ---------------------------------------------------------------------------

  if (isLoading) return <div className="text-center py-10">Loading...</div>;

  return (
    <div className="max-w-3xl mx-auto">
      {/* Page header */}
      <div className="flex items-center mb-6">
        <button
          onClick={() => navigate(-1)}
          className="mr-4 p-2 text-gray-500 hover:text-gray-700 hover:bg-gray-100 rounded-full transition-colors"
        >
          <ArrowLeft className="w-5 h-5" />
        </button>
        <h1 className="text-2xl font-bold text-gray-900">
          {isEdit ? 'Edit Activity' : 'Create New Activity'}
        </h1>
      </div>

      <div className="bg-white shadow rounded-lg p-6">
        {/* Inline error banner */}
        {saveError && (
          <div className="mb-6 flex items-start gap-2 rounded-lg border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-800">
            <AlertCircle className="h-4 w-4 mt-0.5 flex-shrink-0" />
            <span>{saveError}</span>
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-6">
          {/* Activity number — hidden in edit mode (cannot change after creation) */}
          {!isEdit && (
            <div>
              <label className="block text-sm font-medium text-gray-700">Activity Number</label>
              <input
                type="number"
                min="1"
                value={activityNumber}
                onChange={(e) => setActivityNumber(parseInt(e.target.value) || 1)}
                className="mt-1 block w-32 rounded-md border-gray-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500 sm:text-sm p-2 border"
                required
              />
              <p className="mt-1 text-xs text-gray-400">Must be unique within the course.</p>
            </div>
          )}

          {/* Activity text */}
          <div>
            <label className="block text-sm font-medium text-gray-700">Activity Text</label>
            <textarea
              rows={4}
              value={text}
              onChange={(e) => setText(e.target.value)}
              className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500 sm:text-sm p-2 border"
              placeholder="Describe the activity..."
              required
            />
          </div>

          {/* Learning objectives */}
          <div>
            <div className="flex justify-between items-center mb-2">
              <label className="block text-sm font-medium text-gray-700">
                Learning Objectives{' '}
                <span className="text-xs text-gray-400 font-normal">(instructor only)</span>
              </label>
              <button
                type="button"
                onClick={handleAddObjective}
                className="inline-flex items-center text-sm text-indigo-600 hover:text-indigo-800"
              >
                <Plus className="w-4 h-4 mr-1" /> Add Objective
              </button>
            </div>

            <div className="space-y-3">
              {learningObjectives.map((objective, index) => (
                <div key={index} className="flex items-start">
                  <input
                    type="text"
                    value={objective}
                    onChange={(e) => handleObjectiveChange(index, e.target.value)}
                    className="flex-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500 sm:text-sm p-2 border"
                    placeholder={`Objective ${index + 1}`}
                    required={index === 0}
                  />
                  {learningObjectives.length > 1 && (
                    <button
                      type="button"
                      onClick={() => handleRemoveObjective(index)}
                      className="ml-2 p-2 text-red-500 hover:text-red-700 hover:bg-red-50 rounded"
                    >
                      <Trash2 className="w-5 h-5" />
                    </button>
                  )}
                </div>
              ))}
            </div>
          </div>

          {/* Form actions */}
          <div className="pt-4 flex justify-end gap-3">
            <button
              type="button"
              onClick={() => navigate(-1)}
              className="bg-white py-2 px-4 border border-gray-300 rounded-md shadow-sm text-sm font-medium text-gray-700 hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={isSaving}
              className="inline-flex justify-center items-center py-2 px-4 border border-transparent shadow-sm text-sm font-medium rounded-md text-white bg-indigo-600 hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500 disabled:opacity-50"
            >
              <Save className="w-4 h-4 mr-2" />
              {isSaving ? 'Saving...' : 'Save Activity'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};
