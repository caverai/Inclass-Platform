import React, { useCallback, useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { authApi } from '../api/authApi';
import { BookOpen } from 'lucide-react';
import { GoogleSignInButton } from '../components/GoogleSignInButton';
import { DEMO_ROLE_KEY, DEMO_USER_KEY } from '../utils/demoAuth';

export const StudentLoginPage: React.FC = () => {
  const navigate = useNavigate();
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState('');

  const handleGoogleCredential = useCallback(async (credential: string) => {
    try {
      setIsLoading(true);
      const { token } = await authApi.googleSignIn('STUDENT', credential);

      sessionStorage.setItem('student_token', token);
      sessionStorage.setItem(DEMO_ROLE_KEY, 'student');

      const me = await authApi.getMe();
      sessionStorage.setItem(DEMO_USER_KEY, JSON.stringify(me));

      navigate('/student/dashboard');
    } catch (err: any) {
      const message = err.response?.data?.detail || err.message || 'Login failed';
      setError(message);
    } finally {
      setIsLoading(false);
    }
  }, [navigate]);

  return (
    <div className="min-h-screen bg-gray-50 flex flex-col justify-center py-12 sm:px-6 lg:px-8">
      <div className="sm:mx-auto sm:w-full sm:max-w-md">
        <div className="flex justify-center">
          <div className="bg-indigo-600 p-3 rounded-2xl shadow-xl">
            <BookOpen className="w-10 h-10 text-white" />
          </div>
        </div>
        <h2 className="mt-6 text-center text-3xl font-extrabold text-gray-900">
          Student Login
        </h2>
        <p className="mt-2 text-center text-sm text-gray-600">
          Access your student portal
        </p>
      </div>

      <div className="mt-8 sm:mx-auto sm:w-full sm:max-w-md px-4">
        <div className="bg-white py-8 px-6 shadow-2xl sm:rounded-3xl border border-gray-100">
          <div className="space-y-5">
            {error && (
              <div className="bg-red-50 border-l-4 border-red-500 p-4 rounded-r-lg">
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

          <div className="mt-6 text-center space-y-2">
            <p className="text-sm text-gray-600">
              Don't have an account?{' '}
              <Link to="/student/register" className="font-bold text-indigo-600 hover:text-indigo-500">
                Register here
              </Link>
            </p>
            <p className="text-sm text-gray-500">
              Are you an instructor?{' '}
              <Link to="/instructor/login" className="font-semibold text-indigo-400 hover:text-indigo-500">
                Sign in here
              </Link>
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};
