
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { Layout } from './components/Layout';
import { InstructorRoute, StudentRoute } from './components/ProtectedRoute';
import { LoginPage } from './pages/LoginPage';
import { StudentRegisterPage } from './pages/StudentRegisterPage';
import { StudentLoginPage } from './pages/StudentLoginPage';
import { InstructorDashboard } from './pages/InstructorDashboard';
import { InstructorCoursePage } from './pages/InstructorCoursePage';
import { ActivityFormPage } from './pages/ActivityFormPage';
import { ActivityLogsPage } from './pages/ActivityLogsPage';
import { CourseStudentsPage } from './pages/CourseStudentsPage';
import { StudentDashboard } from './pages/StudentDashboard';
import { StudentActivityPage } from './pages/StudentActivityPage';

function App() {
  return (
    <Router>
      <Routes>
        <Route path="/" element={<Navigate to="/student/login" replace />} />
        
        <Route element={<Layout />}>
          <Route path="/login" element={<Navigate to="/student/login" replace />} />
          <Route path="/student/login" element={<StudentLoginPage />} />
          <Route path="/student/register" element={<StudentRegisterPage />} />
          <Route path="/instructor/login" element={<LoginPage />} />
          
          <Route element={<InstructorRoute />}>
            <Route path="/instructor/dashboard" element={<InstructorDashboard />} />
            <Route path="/instructor/courses/:courseId" element={<InstructorCoursePage />} />
            <Route path="/instructor/courses/:courseId/activities/new" element={<ActivityFormPage />} />
            <Route path="/instructor/activities/:activityId/edit" element={<ActivityFormPage />} />
            <Route path="/instructor/activities/:activityId/logs" element={<ActivityLogsPage />} />
            <Route path="/instructor/courses/:courseId/students" element={<CourseStudentsPage />} />
          </Route>

          <Route element={<StudentRoute />}>
            <Route path="/student/dashboard" element={<StudentDashboard />} />
            <Route path="/student/activities/:activityId" element={<StudentActivityPage />} />
          </Route>
        </Route>
      </Routes>
    </Router>
  );
}

export default App;
