import React, { useEffect, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { instructorApi } from '../api/instructorApi';
import type { Activity, Course } from '../types';
import { StatusBadge } from '../components/StatusBadge';
import { ConfirmModal } from '../components/ConfirmModal';
import { Plus, Play, Square, RotateCcw, Edit, FileText } from 'lucide-react';

export const InstructorCoursePage: React.FC = () => {
  const { courseId } = useParams<{ courseId: string }>();
  const navigate = useNavigate();
  
  const [course, setCourse] = useState<Course | null>(null);
  const [activities, setActivities] = useState<Activity[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  
  const [modalState, setModalState] = useState<{
    isOpen: boolean;
    type: 'START' | 'END' | 'RESET' | null;
    activityId: string | null;
  }>({ isOpen: false, type: null, activityId: null });

  const fetchData = async () => {
    if (!courseId) return;
    try {
      setIsLoading(true);
      const [coursesData, activitiesData] = await Promise.all([
        instructorApi.getCourses(),
        instructorApi.getCourseActivities(courseId)
      ]);
      const currentCourse = coursesData.find(c => c.id === courseId);
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

  const handleAction = async () => {
    const { type, activityId } = modalState;
    if (!activityId || !type || !courseId) return;

    const activity = activities.find(a => a.id === activityId);
    if (!activity) return;

    try {
      if (type === 'START') await instructorApi.startActivity(activityId, courseId, activity.activityNumber);
      if (type === 'END')   await instructorApi.endActivity(activityId, courseId, activity.activityNumber);
      if (type === 'RESET') await instructorApi.resetActivity(activityId, courseId, activity.activityNumber);

      await fetchData(); // refresh list
    } catch (error) {
      console.error(`Failed to ${type} activity`, error);
    } finally {
      setModalState({ isOpen: false, type: null, activityId: null });
    }
  };

  const openModal = (type: 'START' | 'END' | 'RESET', activityId: string) => {
    setModalState({ isOpen: true, type, activityId });
  };

  if (isLoading) return <div className="text-center py-10">Loading...</div>;
  if (!course) return <div className="text-center py-10">Course not found</div>;

  return (
    <div>
      <div className="flex justify-between items-center mb-6">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">{course.title}</h1>
          <p className="text-gray-500 mt-1">{course.description}</p>
        </div>
        <button
          onClick={() => navigate(`/instructor/courses/${course.id}/activities/new`)}
          className="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md shadow-sm text-white bg-indigo-600 hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500"
        >
          <Plus className="w-4 h-4 mr-2" />
          Create Activity
        </button>
      </div>

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
                    </div>
                    
                    <div className="flex space-x-2">
                      {activity.status === 'NOT_STARTED' && (
                        <button
                          onClick={() => openModal('START', activity.id)}
                          className="inline-flex items-center px-2.5 py-1.5 border border-transparent shadow-sm text-xs font-medium rounded text-white bg-green-600 hover:bg-green-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-green-500"
                        >
                          <Play className="w-4 h-4 mr-1" /> Start
                        </button>
                      )}
                      {activity.status === 'ACTIVE' && (
                        <button
                          onClick={() => openModal('END', activity.id)}
                          className="inline-flex items-center px-2.5 py-1.5 border border-transparent shadow-sm text-xs font-medium rounded text-white bg-red-600 hover:bg-red-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-red-500"
                        >
                          <Square className="w-4 h-4 mr-1" /> End
                        </button>
                      )}
                      {(activity.status === 'ACTIVE' || activity.status === 'ENDED') && (
                        <button
                          onClick={() => openModal('RESET', activity.id)}
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

      <ConfirmModal
        isOpen={modalState.isOpen}
        title={`${modalState.type?.charAt(0)}${modalState.type?.slice(1).toLowerCase()} Activity`}
        message={`Are you sure you want to ${modalState.type?.toLowerCase()} this activity?`}
        onConfirm={handleAction}
        onCancel={() => setModalState({ isOpen: false, type: null, activityId: null })}
        confirmStyle={modalState.type === 'END' ? 'danger' : 'primary'}
      />
    </div>
  );
};
