import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { authApi } from '../api/authApi';
import { BookOpen, GraduationCap, Lock, Mail, User as UserIcon, ShieldCheck } from 'lucide-react';
import type { Role } from '../types';

export const LoginPage: React.FC = () => {
  const navigate = useNavigate();
  const [isLoading, setIsLoading] = useState(false);
  const [isRegister, setIsRegister] = useState(false);
  const [selectedRole, setSelectedRole] = useState<Role>('STUDENT');
  
  const [email, setEmail] = useState('');
  const [name, setName] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');

  const performAuth = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    
    if (!email || !password || (isRegister && !name)) {
      setError('Please fill in all required fields');
      return;
    }

    try {
      setIsLoading(true);
      let response;
      
      if (isRegister) {
        response = await authApi.register(selectedRole, email, name, password);
      } else {
        response = await authApi.login(selectedRole, email, password);
      }
      
      localStorage.setItem('demo_token', response.token);
      localStorage.setItem('demo_role', selectedRole);
      
      if (selectedRole === 'INSTRUCTOR') {
        navigate('/instructor/dashboard');
      } else if (selectedRole === 'ADMIN') {
        alert('Admin dashboard coming soon');
      } else {
        alert('Student view not implemented in Task 1');
      }
    } catch (err: any) {
      setError(err.message || 'Authentication failed. Please try again.');
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
          InClass Platform
        </h2>
        <p className="mt-2 text-center text-sm text-gray-500 font-medium">
          {isRegister ? 'Create your account' : 'Sign in to your account'}
        </p>
      </div>

      <div className="mt-8 sm:mx-auto sm:w-full sm:max-w-md px-4">
        <div className="bg-white py-8 px-6 shadow-2xl sm:rounded-3xl border border-gray-100 backdrop-blur-sm bg-white/90">
          
          {/* Role Selection Tabs */}
          <div className="flex p-1 bg-gray-100 rounded-xl mb-8">
            <button
              onClick={() => setSelectedRole('STUDENT')}
              className={`flex-1 flex items-center justify-center py-2 px-1 text-sm font-semibold rounded-lg transition-all ${
                selectedRole === 'STUDENT' ? 'bg-white text-indigo-600 shadow-sm' : 'text-gray-500 hover:text-gray-700'
              }`}
            >
              <GraduationCap className="w-4 h-4 mr-2" />
              Student
            </button>
            <button
              onClick={() => setSelectedRole('INSTRUCTOR')}
              className={`flex-1 flex items-center justify-center py-2 px-1 text-sm font-semibold rounded-lg transition-all ${
                selectedRole === 'INSTRUCTOR' ? 'bg-white text-indigo-600 shadow-sm' : 'text-gray-500 hover:text-gray-700'
              }`}
            >
              <UserIcon className="w-4 h-4 mr-2" />
              Instructor
            </button>
            <button
              onClick={() => setSelectedRole('ADMIN')}
              className={`flex-1 flex items-center justify-center py-2 px-1 text-sm font-semibold rounded-lg transition-all ${
                selectedRole === 'ADMIN' ? 'bg-white text-indigo-600 shadow-sm' : 'text-gray-500 hover:text-gray-700'
              }`}
            >
              <ShieldCheck className="w-4 h-4 mr-2" />
              Admin
            </button>
          </div>

          <form className="space-y-5" onSubmit={performAuth}>
            {error && (
              <div className="bg-red-50 border-l-4 border-red-500 p-4 rounded-r-lg animate-pulse">
                <p className="text-sm text-red-700 font-semibold">{error}</p>
              </div>
            )}

            {isRegister && (
              <div>
                <label className="block text-sm font-bold text-gray-700 mb-1">Full Name</label>
                <div className="relative">
                  <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                    <UserIcon className="h-5 w-5 text-gray-400" />
                  </div>
                  <input
                    type="text"
                    required
                    value={name}
                    onChange={(e) => setName(e.target.value)}
                    className="block w-full pl-10 pr-3 py-2.5 border border-gray-300 rounded-xl focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm transition-all"
                    placeholder="John Doe"
                  />
                </div>
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
                  className="block w-full pl-10 pr-3 py-2.5 border border-gray-300 rounded-xl focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm transition-all"
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
                  className="block w-full pl-10 pr-3 py-2.5 border border-gray-300 rounded-xl focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm transition-all"
                  placeholder="••••••••"
                />
              </div>
            </div>

            <button
              type="submit"
              disabled={isLoading}
              className="w-full flex justify-center items-center py-3 px-4 border border-transparent rounded-xl shadow-lg text-sm font-bold text-white bg-indigo-600 hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500 disabled:opacity-50 transition-all hover:shadow-indigo-200"
            >
              {isLoading ? 'Processing...' : (isRegister ? 'Create Account' : 'Sign In')}
            </button>
          </form>

          <div className="mt-8 text-center">
            <button
              onClick={() => setIsRegister(!isRegister)}
              className="text-sm font-bold text-indigo-600 hover:text-indigo-800 transition-colors"
            >
              {isRegister ? 'Already have an account? Sign in' : "Don't have an account? Register now"}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
