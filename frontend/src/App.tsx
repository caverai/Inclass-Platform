
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { Layout } from './components/Layout';
import { LoginPage } from './pages/LoginPage';
import { InstructorDashboard } from './pages/InstructorDashboard';
import { InstructorCoursePage } from './pages/InstructorCoursePage';
import { ActivityFormPage } from './pages/ActivityFormPage';
import { ActivityLogsPage } from './pages/ActivityLogsPage';

function App() {
  return (
    <Router>
      <Routes>
        <Route path="/" element={<Navigate to="/login" replace />} />
        
        <Route element={<Layout />}>
          <Route path="/login" element={<LoginPage />} />
          
          <Route path="/instructor/dashboard" element={<InstructorDashboard />} />
          <Route path="/instructor/courses/:courseId" element={<InstructorCoursePage />} />
          <Route path="/instructor/courses/:courseId/activities/new" element={<ActivityFormPage />} />
          <Route path="/instructor/activities/:activityId/edit" element={<ActivityFormPage />} />
          <Route path="/instructor/activities/:activityId/logs" element={<ActivityLogsPage />} />
        </Route>
      </Routes>
    </Router>
  );
}

export default App;
