import React from 'react';
import type { Activity } from '../types';
import { StatusBadge } from './StatusBadge';

interface ActivityCardProps {
  activity: Activity;
  onClick: () => void;
}

export const ActivityCard: React.FC<ActivityCardProps> = ({ activity, onClick }) => {
  return (
    <div 
      className="bg-white border rounded-lg shadow-sm hover:shadow-md transition-shadow cursor-pointer p-5 flex flex-col"
      onClick={onClick}
    >
      <div className="flex justify-between items-start mb-3">
        <h3 className="text-lg font-semibold text-gray-900">Activity {activity.activityNumber}</h3>
        <StatusBadge status={activity.status} />
      </div>
      <p className="text-gray-600 text-sm flex-grow mb-4 line-clamp-3">{activity.text}</p>
      <div className="text-xs text-gray-500 mt-auto pt-3 border-t">
        {activity.learningObjectives.length} Learning Objective(s)
      </div>
    </div>
  );
};
