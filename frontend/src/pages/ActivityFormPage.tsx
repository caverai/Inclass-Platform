import React, { useState, useEffect } from 'react';
import { useParams, useNavigate, useLocation } from 'react-router-dom';
import { instructorApi } from '../api/instructorApi';
import type { Activity } from '../types';
import { Plus, Trash2, ArrowLeft, Save } from 'lucide-react';

export const ActivityFormPage: React.FC = () => {
  const { courseId, activityId } = useParams<{ courseId?: string; activityId?: string }>();
  const navigate = useNavigate();
  const location = useLocation();
  const isEdit = location.pathname.includes('/edit');

  const [isLoading, setIsLoading] = useState(isEdit);
  const [isSaving, setIsSaving] = useState(false);

  // Keep the resolved activity so we have courseId + activityNumber for the PATCH endpoint
  const [resolvedActivity, setResolvedActivity] = useState<Activity | null>(null);

  const [activityNumber, setActivityNumber] = useState<number>(1);
  const [text, setText] = useState('');
  const [learningObjectives, setLearningObjectives] = useState<string[]>(['']);

  useEffect(() => {
    const fetchActivity = async () => {
      if (isEdit && activityId) {
        try {
          // Since we don't have a getActivity endpoint yet, we fetch all course activities
          // In a real app we'd have a single endpoint or pass courseId
          const courses = await instructorApi.getCourses();
          let found = false;
          for (const course of courses) {
            const activities = await instructorApi.getCourseActivities(course.id);
            const act = activities.find(a => a.id === activityId);
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
            console.error('Activity not found');
            navigate(-1);
          }
        } catch (error) {
          console.error('Failed to fetch activity', error);
        } finally {
          setIsLoading(false);
        }
      }
    };
    fetchActivity();
  }, [isEdit, activityId, navigate]);

  const handleAddObjective = () => {
    setLearningObjectives([...learningObjectives, '']);
  };

  const handleRemoveObjective = (index: number) => {
    setLearningObjectives(learningObjectives.filter((_, i) => i !== index));
  };

  const handleObjectiveChange = (index: number, val: string) => {
    const newObjectives = [...learningObjectives];
    newObjectives[index] = val;
    setLearningObjectives(newObjectives);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!text.trim()) return alert('Activity text is required');
    
    const validObjectives = learningObjectives.filter(obj => obj.trim() !== '');
    if (validObjectives.length === 0) return alert('At least one learning objective is required');

    try {
      setIsSaving(true);
      if (isEdit && activityId && resolvedActivity) {
        await instructorApi.updateActivityContent(
          resolvedActivity.courseId,
          resolvedActivity.activityNumber,
          { text, objectives: validObjectives },
        );
        navigate(-1);
      } else if (courseId) {
        await instructorApi.createActivity(courseId, {
          activityNumber,
          text,
          learningObjectives: validObjectives
        });
        navigate(`/instructor/courses/${courseId}`);
      }
    } catch (error) {
      console.error('Failed to save activity', error);
      alert('Failed to save activity');
    } finally {
      setIsSaving(false);
    }
  };

  if (isLoading) return <div className="text-center py-10">Loading...</div>;

  return (
    <div className="max-w-3xl mx-auto">
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
        <form onSubmit={handleSubmit} className="space-y-6">
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
          </div>

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

          <div>
            <div className="flex justify-between items-center mb-2">
              <label className="block text-sm font-medium text-gray-700">Learning Objectives (Instructor Only)</label>
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

          <div className="pt-4 flex justify-end">
            <button
              type="button"
              onClick={() => navigate(-1)}
              className="bg-white py-2 px-4 border border-gray-300 rounded-md shadow-sm text-sm font-medium text-gray-700 hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500 mr-3"
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
