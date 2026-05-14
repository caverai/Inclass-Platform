import React, { useCallback, useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { authApi } from '../api/authApi';
import { BookOpen } from 'lucide-react';
import { DEMO_ROLE_KEY, DEMO_USER_KEY } from '../utils/demoAuth';
import { GoogleSignInButton } from '../components/GoogleSignInButton';

export const LoginPage: React.FC = () => {
  const navigate = useNavigate();
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState('');

  const handleGoogleCredential = useCallback(async (credential: string) => {
    try {
      setIsLoading(true);
      const response = await authApi.googleSignIn('INSTRUCTOR', credential);

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
  }, [navigate]);

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

          <div className="space-y-5">
            {error && (
              <div className="bg-red-50 border-l-4 border-red-500 p-4 rounded-r-lg animate-pulse">
                <p className="text-sm text-red-700 font-semibold">{error}</p>
              </div>
            )}

            <p className="text-sm text-gray-600 text-center">
              Use your school Google account to sign in.
            </p>

            <div className={isLoading ? 'opacity-70 pointer-events-none' : ''}>
              <GoogleSignInButton onCredential={handleGoogleCredential} onError={setError} />
            </div>

            {isLoading && (
              <p className="text-sm text-gray-500 text-center">Signing you in...</p>
            )}
          </div>

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
