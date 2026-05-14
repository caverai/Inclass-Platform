import React, { useEffect, useState } from 'react';
import { Navigate, Outlet } from 'react-router-dom';
import { getDemoRole, type DemoRole } from '../utils/demoAuth';

type RouteCheckStatus = 'checking' | 'ready';

interface ProtectedRouteProps {
  allowedRole: DemoRole;
}

const DASHBOARD_BY_ROLE: Record<DemoRole, string> = {
  student: '/student/dashboard',
  instructor: '/instructor/dashboard',
};

export const ProtectedRoute: React.FC<ProtectedRouteProps> = ({ allowedRole }) => {
  const [status, setStatus] = useState<RouteCheckStatus>('checking');
  const [role, setRole] = useState<DemoRole | null>(null);

  useEffect(() => {
    setRole(getDemoRole());
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
