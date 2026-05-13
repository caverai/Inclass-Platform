import React, { useEffect, useState } from 'react';
import { Navigate, Outlet } from 'react-router-dom';

type DemoRole = 'student' | 'instructor';
type RouteCheckStatus = 'checking' | 'ready';

interface ProtectedRouteProps {
  allowedRole: DemoRole;
}

const DASHBOARD_BY_ROLE: Record<DemoRole, string> = {
  student: '/student/dashboard',
  instructor: '/instructor/dashboard',
};

const normalizeDemoRole = (role: string | null): DemoRole | null => {
  if (role === 'student' || role === 'instructor') return role;
  return null;
};

export const ProtectedRoute: React.FC<ProtectedRouteProps> = ({ allowedRole }) => {
  const [status, setStatus] = useState<RouteCheckStatus>('checking');
  const [role, setRole] = useState<DemoRole | null>(null);

  useEffect(() => {
    setRole(normalizeDemoRole(localStorage.getItem('demo_role')));
    setStatus('ready');
  }, []);

  if (status === 'checking') {
    return <div className="min-h-screen flex items-center justify-center">Loading...</div>;
  }

  if (!role) {
    return <Navigate to="/login" replace />;
  }

  if (role !== allowedRole) {
    return <Navigate to={DASHBOARD_BY_ROLE[role]} replace />;
  }

  return <Outlet />;
};

export const StudentRoute: React.FC = () => <ProtectedRoute allowedRole="student" />;

export const InstructorRoute: React.FC = () => <ProtectedRoute allowedRole="instructor" />;
