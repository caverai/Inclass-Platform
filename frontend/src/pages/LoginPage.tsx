import React, { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { authApi } from '../api/authApi';
import { BookOpen, Lock, Mail } from 'lucide-react';
import { DEMO_ROLE_KEY, DEMO_USER_KEY } from '../utils/demoAuth';

export const LoginPage: React.FC = () => {
  const navigate = useNavigate();
  const [isLoading, setIsLoading] = useState(false);
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');

  const performAuth = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    
    if (!email || !password) {
      setError('Please fill in all required fields');
      return;
    }

    try {
      setIsLoading(true);
      const response = await authApi.login('INSTRUCTOR', email, password);
      
      localStorage.setItem('instructor_token', response.token);
      localStorage.setItem(DEMO_ROLE_KEY, 'instructor');
      
      const me = await authApi.getMe();
      localStorage.setItem(DEMO_USER_KEY, JSON.stringify(me));
      
      navigate('/instructor/dashboard');
    } catch (err: any) {
      const message = err.response?.data?.detail || err.message || 'Authentication failed';
      setError(message);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gray-50 flex flex-col justify-center py-12 sm:px-6 lg:px-8">
      <div className="sm:mx-auto sm:w-full sm:max-w-md">
        <div className="flex justify-center">
          <div className="bg-indigo-600 p-3 rounded-2xl shadow-xl transform transition-transform hover:scale-110">
            <BookOpen className="w-10 h-10 text-white" />
          </div>
        </div>
        <h2 className="mt-6 text-center text-4xl font-extrabold text-gray-900 tracking-tight">
          Instructor Portal
        </h2>
        <p className="mt-2 text-center text-sm text-gray-500 font-medium">
          Sign in to manage your courses
        </p>
      </div>

      <div className="mt-8 sm:mx-auto sm:w-full sm:max-w-md px-4">
        <div className="bg-white py-8 px-6 shadow-2xl sm:rounded-3xl border border-gray-100 backdrop-blur-sm bg-white/90">

          <form className="space-y-5" onSubmit={performAuth}>
            {error && (
              <div className="bg-red-50 border-l-4 border-red-500 p-4 rounded-r-lg animate-pulse">
                <p className="text-sm text-red-700 font-semibold">{error}</p>
              </div>
            )}

            <div>
              <label className="block text-sm font-bold text-gray-700 mb-1">Email address</label>
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                  <Mail className="h-5 w-5 text-gray-400" />
                </div>
                <input
                  type="email"
                  required
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  className="block w-full pl-10 pr-3 py-2.5 border border-gray-300 rounded-xl focus:ring-2 focus:ring-indigo-500 sm:text-sm transition-all"
                  placeholder="name@university.edu"
                />
              </div>
            </div>

            <div>
              <label className="block text-sm font-bold text-gray-700 mb-1">Password</label>
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                  <Lock className="h-5 w-5 text-gray-400" />
                </div>
                <input
                  type="password"
                  required
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="block w-full pl-10 pr-3 py-2.5 border border-gray-300 rounded-xl focus:ring-2 focus:ring-indigo-500 sm:text-sm transition-all"
                  placeholder="••••••••"
                />
              </div>
            </div>

            <button
              type="submit"
              disabled={isLoading}
              className="w-full flex justify-center items-center py-3 px-4 border border-transparent rounded-xl shadow-lg text-sm font-bold text-white bg-indigo-600 hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500 disabled:opacity-50 transition-all hover:shadow-indigo-200"
            >
              {isLoading ? 'Processing...' : 'Sign In'}
            </button>
          </form>

          <div className="mt-8 text-center">
            <Link
              to="/student/login"
              className="text-sm font-bold text-indigo-600 hover:text-indigo-800 transition-colors"
            >
              Are you a student? Sign in here
            </Link>
          </div>
        </div>
      </div>
    </div>
  );
};
