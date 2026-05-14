import React, { useEffect, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { instructorApi } from '../api/instructorApi';
import type { Activity, Course } from '../types';
import { StatusBadge } from '../components/StatusBadge';
import { ConfirmModal } from '../components/ConfirmModal';
import { Plus, Play, Square, RotateCcw, Edit, FileText, Trash2, Users } from 'lucide-react';

export const InstructorCoursePage: React.FC = () => {
  const { courseId } = useParams<{ courseId: string }>();
  const navigate = useNavigate();

  const [course, setCourse] = useState<Course | null>(null);
  const [activities, setActivities] = useState<Activity[]>([]);
  const [isLoading, setIsLoading] = useState(true);

  // Modal for start / end / reset
  const [actionModal, setActionModal] = useState<{
    isOpen: boolean;
    type: 'START' | 'END' | 'RESET' | null;
    activityId: string | null;
  }>({ isOpen: false, type: null, activityId: null });

  // Modal for activity deletion
  const [deleteModal, setDeleteModal] = useState<{
    isOpen: boolean;
    activityId: string | null;
    activityNo: number | null;
  }>({ isOpen: false, activityId: null, activityNo: null });

  const [isDeleting, setIsDeleting] = useState(false);

  const fetchData = async () => {
    if (!courseId) return;
    try {
      setIsLoading(true);
      const [coursesData, activitiesData] = await Promise.all([
        instructorApi.getCourses(),
        instructorApi.getCourseActivities(courseId),
      ]);
      const currentCourse = coursesData.find((c) => c.id === courseId);
      if (currentCourse) setCourse(currentCourse);
      setActivities(activitiesData.sort((a, b) => a.activityNumber - b.activityNumber));
    } catch (error) {
      console.error('Failed to fetch data', error);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, [courseId]);

  // --- Action modal (start / end / reset) ---

  const handleAction = async () => {
    const { type, activityId } = actionModal;
    if (!activityId || !type || !courseId) return;

    const activity = activities.find((a) => a.id === activityId);
    if (!activity) return;

    try {
      if (type === 'START') await instructorApi.startActivity(activityId, courseId, activity.activityNumber);
      if (type === 'END')   await instructorApi.endActivity(activityId, courseId, activity.activityNumber);
      if (type === 'RESET') await instructorApi.resetActivity(activityId, courseId, activity.activityNumber);
      await fetchData();
    } catch (error) {
      console.error(`Failed to ${type} activity`, error);
    } finally {
      setActionModal({ isOpen: false, type: null, activityId: null });
    }
  };

  const openActionModal = (type: 'START' | 'END' | 'RESET', activityId: string) => {
    setActionModal({ isOpen: true, type, activityId });
  };

  // --- Delete activity modal ---

  const handleDeleteActivity = async () => {
    if (!deleteModal.activityId || deleteModal.activityNo === null || !courseId) return;
    try {
      setIsDeleting(true);
      await instructorApi.deleteActivity(courseId, deleteModal.activityNo);
      setDeleteModal({ isOpen: false, activityId: null, activityNo: null });
      await fetchData();
    } catch (error) {
      console.error('Failed to delete activity', error);
    } finally {
      setIsDeleting(false);
    }
  };

  if (isLoading) return <div className="text-center py-10">Loading...</div>;
  if (!course) return <div className="text-center py-10">Course not found</div>;

  return (
    <div>
      {/* Page header */}
      <div className="flex justify-between items-center mb-6">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">{course.title}</h1>
          <p className="text-gray-500 mt-1">{course.description}</p>
        </div>
        <div className="flex items-center gap-2">
          {/* Students management button */}
          <button
            onClick={() => navigate(`/instructor/courses/${course.id}/students`)}
            className="inline-flex items-center px-3 py-2 border border-gray-300 text-sm font-medium rounded-md shadow-sm text-gray-700 bg-white hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500"
          >
            <Users className="w-4 h-4 mr-2" />
            Students
          </button>
          {/* Create activity button */}
          <button
            onClick={() => navigate(`/instructor/courses/${course.id}/activities/new`)}
            className="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md shadow-sm text-white bg-indigo-600 hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500"
          >
            <Plus className="w-4 h-4 mr-2" />
            Create Activity
          </button>
        </div>
      </div>

      {/* Activity list */}
      <div className="bg-white shadow overflow-hidden sm:rounded-md">
        <ul className="divide-y divide-gray-200">
          {activities.length === 0 ? (
            <li className="px-6 py-8 text-center text-gray-500">No activities created yet.</li>
          ) : (
            activities.map((activity) => (
              <li key={activity.id} className="px-6 py-4">
                <div className="flex items-center justify-between">
                  <div className="flex-1 min-w-0 pr-4">
                    <div className="flex items-center justify-between mb-2">
                      <p className="text-sm font-medium text-indigo-600 truncate">
                        Activity {activity.activityNumber}
                      </p>
                      <StatusBadge status={activity.status} />
                    </div>
                    <div className="mt-2">
                      <p className="text-sm text-gray-900 line-clamp-2">{activity.text}</p>
                    </div>
                    <div className="mt-2 text-xs text-gray-500">
                      {activity.learningObjectives.length} Learning Objective(s)
                    </div>
                  </div>

                  <div className="flex flex-col space-y-2 ml-4 flex-shrink-0">
                    {/* Edit / Logs / Delete row */}
                    <div className="flex space-x-2">
                      <button
                        onClick={() => navigate(`/instructor/activities/${activity.id}/edit`)}
                        className="inline-flex items-center px-2.5 py-1.5 border border-gray-300 shadow-sm text-xs font-medium rounded text-gray-700 bg-white hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500"
                        title="Edit"
                      >
                        <Edit className="w-4 h-4" />
                      </button>
                      <button
                        onClick={() => navigate(`/instructor/activities/${activity.id}/logs`)}
                        className="inline-flex items-center px-2.5 py-1.5 border border-gray-300 shadow-sm text-xs font-medium rounded text-gray-700 bg-white hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500"
                        title="Logs"
                      >
                        <FileText className="w-4 h-4" />
                      </button>
                      <button
                        onClick={() =>
                          setDeleteModal({
                            isOpen: true,
                            activityId: activity.id,
                            activityNo: activity.activityNumber,
                          })
                        }
                        className="inline-flex items-center px-2.5 py-1.5 border border-red-200 shadow-sm text-xs font-medium rounded text-red-600 bg-red-50 hover:bg-red-100 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-red-400"
                        title="Delete Activity"
                      >
                        <Trash2 className="w-4 h-4" />
                      </button>
                    </div>

                    {/* Start / End / Reset row */}
                    <div className="flex space-x-2">
                      {activity.status === 'NOT_STARTED' && (
                        <button
                          onClick={() => openActionModal('START', activity.id)}
                          className="inline-flex items-center px-2.5 py-1.5 border border-transparent shadow-sm text-xs font-medium rounded text-white bg-green-600 hover:bg-green-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-green-500"
                        >
                          <Play className="w-4 h-4 mr-1" /> Start
                        </button>
                      )}
                      {activity.status === 'ACTIVE' && (
                        <button
                          onClick={() => openActionModal('END', activity.id)}
                          className="inline-flex items-center px-2.5 py-1.5 border border-transparent shadow-sm text-xs font-medium rounded text-white bg-red-600 hover:bg-red-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-red-500"
                        >
                          <Square className="w-4 h-4 mr-1" /> End
                        </button>
                      )}
                      {(activity.status === 'ACTIVE' || activity.status === 'ENDED') && (
                        <button
                          onClick={() => openActionModal('RESET', activity.id)}
                          className="inline-flex items-center px-2.5 py-1.5 border border-transparent shadow-sm text-xs font-medium rounded text-indigo-700 bg-indigo-100 hover:bg-indigo-200 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500"
                        >
                          <RotateCcw className="w-4 h-4 mr-1" /> Reset
                        </button>
                      )}
                    </div>
                  </div>
                </div>
              </li>
            ))
          )}
        </ul>
      </div>

      {/* Start / End / Reset confirm modal */}
      <ConfirmModal
        isOpen={actionModal.isOpen}
        title={`${actionModal.type?.charAt(0)}${actionModal.type?.slice(1).toLowerCase()} Activity`}
        message={`Are you sure you want to ${actionModal.type?.toLowerCase()} this activity?`}
        onConfirm={handleAction}
        onCancel={() => setActionModal({ isOpen: false, type: null, activityId: null })}
        confirmStyle={actionModal.type === 'END' ? 'danger' : 'primary'}
      />

      {/* Delete activity confirm modal */}
      <ConfirmModal
        isOpen={deleteModal.isOpen}
        title="Delete Activity"
        message={`Are you sure you want to permanently delete Activity #${deleteModal.activityNo}? All student progress for this activity will also be deleted.`}
        confirmText={isDeleting ? 'Deleting…' : 'Delete'}
        confirmStyle="danger"
        onConfirm={handleDeleteActivity}
        onCancel={() => setDeleteModal({ isOpen: false, activityId: null, activityNo: null })}
      />
    </div>
  );
};
