import React, { useEffect, useState } from 'react';
import { Outlet, useNavigate, useLocation } from 'react-router-dom';
import { LogOut, BookOpen } from 'lucide-react';
import { authApi } from '../api/authApi';
import type { User } from '../types';

export const Layout: React.FC = () => {
  const navigate = useNavigate();
  const location = useLocation();
  const [user, setUser] = useState<User | null>(null);

  useEffect(() => {
    const fetchUser = async () => {
      try {
        const currentUser = await authApi.getMe();
        if (currentUser.role !== 'INSTRUCTOR' && location.pathname.startsWith('/instructor')) {
          navigate('/login');
        } else {
          setUser(currentUser);
        }
      } catch (err) {
        navigate('/login');
      }
    };
    
    if (location.pathname !== '/login') {
      fetchUser();
    }
  }, [navigate, location.pathname]);

  const handleLogout = () => {
    localStorage.removeItem('demo_token');
    localStorage.removeItem('demo_role');
    navigate('/login');
  };

  if (location.pathname === '/login') {
    return <Outlet />;
  }

  if (!user) {
    return <div className="min-h-screen flex items-center justify-center">Loading...</div>;
  }

  return (
    <div className="min-h-screen bg-gray-50 flex flex-col">
      <header className="bg-indigo-600 text-white shadow-md">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
          <div className="flex items-center space-x-3 cursor-pointer" onClick={() => navigate('/instructor/dashboard')}>
            <BookOpen className="w-6 h-6" />
            <span className="font-bold text-xl tracking-tight">InClass</span>
          </div>
          <div className="flex items-center space-x-4">
            <div className="flex flex-col items-end">
              <span className="text-sm font-medium">{user.name}</span>
              <span className="text-xs text-indigo-200">{user.role}</span>
            </div>
            <button 
              onClick={handleLogout}
              className="p-2 rounded-full hover:bg-indigo-700 transition-colors focus:outline-none focus:ring-2 focus:ring-white"
              title="Logout"
            >
              <LogOut className="w-5 h-5" />
            </button>
          </div>
        </div>
      </header>
      <main className="flex-grow max-w-7xl mx-auto w-full px-4 sm:px-6 lg:px-8 py-8">
        <Outlet />
      </main>
    </div>
  );
};
