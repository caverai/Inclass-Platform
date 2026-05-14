import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { instructorApi } from '../api/instructorApi';
import type { Course } from '../types';
import { BookOpen } from 'lucide-react';

export const InstructorDashboard: React.FC = () => {
  const [courses, setCourses] = useState<Course[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const navigate = useNavigate();

  useEffect(() => {
    const fetchCourses = async () => {
      try {
        const data = await instructorApi.getCourses();
        setCourses(data);
      } catch (error) {
        console.error('Failed to fetch courses', error);
      } finally {
        setIsLoading(false);
      }
    };

    fetchCourses();
  }, []);

  if (isLoading) {
    return <div className="text-center py-10">Loading courses...</div>;
  }

  return (
    <div>
      <h1 className="text-2xl font-bold text-gray-900 mb-6">My Courses</h1>
      
      {courses.length === 0 ? (
        <div className="bg-white rounded-lg border border-gray-200 p-8 text-center text-gray-500">
          No courses assigned yet.
        </div>
      ) : (
        <div className="grid grid-cols-1 gap-6 sm:grid-cols-2 lg:grid-cols-3">
          {courses.map(course => (
            <div 
              key={course.id}
              onClick={() => navigate(`/instructor/courses/${course.id}`)}
              className="bg-white overflow-hidden shadow-sm rounded-lg border border-gray-200 cursor-pointer hover:shadow-md transition-shadow"
            >
              <div className="p-6">
                <div className="flex items-center">
                  <div className="flex-shrink-0 bg-indigo-100 rounded-md p-3">
                    <BookOpen className="h-6 w-6 text-indigo-600" />
                  </div>
                  <div className="ml-4">
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
    </div>
  );
};
