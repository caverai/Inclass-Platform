/**
 * @file Layout.tsx
 * @brief Application shell component wrapping all authenticated routes.
 *
 * ## Responsibilities
 * - Renders the top navigation bar with the user's name and a logout button.
 * - Verifies the active session on every mount by calling `/auth/me`.
 * - Redirects to the login page **only on genuine auth failures (401/403)**.
 *   Network errors or server blips do NOT trigger a redirect so that an F5
 *   refresh does not log the user out unexpectedly.
 * - Pre-populates the user from `localStorage` (DEMO_USER_KEY) immediately so
 *   there is no blank-header flash while the `/auth/me` call is in flight.
 *
 * ## SOLID notes
 * - **SRP** – owns the shell layout and session validation only.
 * - **DIP** – depends on `authApi` abstraction, not on axios directly.
 */

import React, { useEffect, useState } from 'react';
import { Outlet, useNavigate, useLocation } from 'react-router-dom';
import { LogOut, BookOpen } from 'lucide-react';
import { authApi } from '../api/authApi';
import type { User } from '../types';
import { DEMO_ROLE_KEY, DEMO_USER_KEY } from '../utils/demoAuth';
import { isAxiosError } from 'axios';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const getRequiredRole = (path: string): User['role'] | null => {
  if (path.startsWith('/instructor')) return 'INSTRUCTOR';
  if (path.startsWith('/student')) return 'STUDENT';
  return null;
};

const getHomePath = (role: User['role']) => {
  if (role === 'INSTRUCTOR') return '/instructor/dashboard';
  if (role === 'STUDENT') return '/student/dashboard';
  return '/student/login';
};

/**
 * @brief Reads the cached user from localStorage without a network call.
 *
 * Used to populate the header immediately on mount / F5 so there is no
 * flash of an empty name while `/auth/me` is in flight.
 *
 * @returns The cached User object, or null if nothing is stored.
 */
const getCachedUser = (): User | null => {
  try {
    const raw = localStorage.getItem(DEMO_USER_KEY);
    if (!raw) return null;
    return JSON.parse(raw) as User;
  } catch {
    return null;
  }
};

/**
 * @brief Returns true if the Axios error indicates a genuine auth failure.
 *
 * Only 401 and 403 responses mean the token is invalid or expired.
 * Everything else (network timeout, 500, etc.) should NOT log the user out.
 *
 * @param err  The caught value from a try/catch block.
 */
const isAuthError = (err: unknown): boolean => {
  if (!isAxiosError(err)) return false;
  const status = err.response?.status;
  return status === 401 || status === 403;
};

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

/**
 * @component Layout
 * @brief Shell wrapper rendered around all non-public routes.
 *
 * Public paths (login / register pages) bypass the session check and render
 * their child via `<Outlet />` without the nav bar.
 */
export const Layout: React.FC = () => {
  const navigate = useNavigate();
  const location = useLocation();

  const publicPaths = ['/student/login', '/student/register', '/instructor/login', '/login'];
  const isPublicPath = publicPaths.includes(location.pathname);

  /**
   * Pre-populate from cache so the header renders immediately on F5.
   * Will be overwritten by the verified value returned from /auth/me.
   */
  const [user, setUser] = useState<User | null>(() => getCachedUser());

  useEffect(() => {
    if (isPublicPath) return;

    const verifySession = async () => {
      try {
        const currentUser = await authApi.getMe();

        // Persist fresh data so the next F5 pre-populates from an up-to-date value.
        localStorage.setItem(DEMO_USER_KEY, JSON.stringify(currentUser));
        setUser(currentUser);

        // Cross-role redirect: student trying to access /instructor/* etc.
        const requiredRole = getRequiredRole(location.pathname);
        if (requiredRole && currentUser.role !== requiredRole) {
          navigate(getHomePath(currentUser.role), { replace: true });
        }
      } catch (err) {
        if (isAuthError(err)) {
          // 401/403 — token is genuinely invalid or expired. Clear and redirect.
          localStorage.removeItem('instructor_token');
          localStorage.removeItem('student_token');
          localStorage.removeItem('demo_token');
          localStorage.removeItem(DEMO_ROLE_KEY);
          localStorage.removeItem(DEMO_USER_KEY);
          setUser(null);
          navigate('/student/login', { replace: true });
        }
        // Any other error (network, 5xx): keep cached user, do NOT redirect.
        // The user is very likely still authenticated; the server may be momentarily busy.
      }
    };

    void verifySession();
  }, [location.pathname, isPublicPath, navigate]);

  // Public pages bypass the shell entirely.
  if (isPublicPath) {
    return <Outlet />;
  }

  // Cache miss on first load (no prior login): show minimal loader.
  if (!user) {
    return (
      <div className="min-h-screen flex items-center justify-center text-gray-500">
        Loading…
      </div>
    );
  }

  const handleLogout = () => {
    localStorage.removeItem('instructor_token');
    localStorage.removeItem('student_token');
    localStorage.removeItem('demo_token');
    localStorage.removeItem(DEMO_ROLE_KEY);
    localStorage.removeItem(DEMO_USER_KEY);
    navigate('/student/login');
  };

  return (
    <div className="min-h-screen bg-gray-50 flex flex-col">
      <header className="bg-indigo-600 text-white shadow-md">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
          <div
            className="flex items-center space-x-3 cursor-pointer"
            onClick={() => navigate(getHomePath(user.role))}
          >
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
