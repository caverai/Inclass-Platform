
import type { Role, User } from '../types';
import { DEMO_ROLE_KEY, DEMO_USER_KEY } from '../utils/demoAuth';

const normalizeRole = (role: string | null): Role | null => {
  if (!role) return null;
  const normalized = role.toUpperCase();
  if (normalized === 'INSTRUCTOR' || normalized === 'STUDENT' || normalized === 'ADMIN') {
    return normalized;
  }
  return null;
};

const getStoredDemoUser = (): User | null => {
  const storedUser = localStorage.getItem(DEMO_USER_KEY);
  if (!storedUser) return null;

  try {
    const parsed = JSON.parse(storedUser) as Partial<User>;
    const role = normalizeRole(localStorage.getItem(DEMO_ROLE_KEY));
    if (!parsed.email || !parsed.name || !role) return null;

    return {
      id: parsed.id || (role === 'INSTRUCTOR' ? 'inst-1' : role === 'STUDENT' ? 'stu-1' : 'admin-1'),
      email: parsed.email,
      name: parsed.name,
      role,
    };
  } catch {
    return null;
  }
};

export const authApi = {
  login: async (role: Role, email?: string, password?: string) => {
    // Mock login for demo purposes
    return new Promise<{ token: string; user: User }>((resolve, reject) => {
      setTimeout(() => {
        // Simple mock validation
        if (password === 'error') {
          reject(new Error('Invalid credentials'));
          return;
        }

        resolve({
          token: 'mock-jwt-token',
          user: {
            id: `id-${Math.random()}`,
            email: email || `${role.toLowerCase()}@example.com`,
            name: role.charAt(0) + role.slice(1).toLowerCase() + ' User',
            role,
          },
        });
      }, 500);
    });
  },

  register: async (role: Role, email: string, name: string, _password?: string) => {
    return new Promise<{ token: string; user: User }>((resolve) => {
      setTimeout(() => {
        resolve({
          token: 'mock-jwt-token',
          user: {
            id: `id-${Math.random()}`,
            email: email,
            name: name,
            role,
          },
        });
      }, 800);
    });
  },

  getMe: async () => {
    // Return mock user based on role in token/localStorage
    return new Promise<User>((resolve, reject) => {
      setTimeout(() => {
        const storedDemoUser = getStoredDemoUser();
        if (storedDemoUser) {
          resolve(storedDemoUser);
          return;
        }

        const role = normalizeRole(localStorage.getItem(DEMO_ROLE_KEY));
        if (role) {
          resolve({
            id: role === 'INSTRUCTOR' ? 'inst-1' : role === 'STUDENT' ? 'stu-1' : 'admin-1',
            email: role === 'INSTRUCTOR' ? 'instructor@example.com' : role === 'STUDENT' ? 'student@example.com' : 'admin@example.com',
            name: role === 'INSTRUCTOR' ? 'Dr. Smith' : role === 'STUDENT' ? 'John Doe' : 'Admin User',
            role,
          });
        } else {
          reject(new Error('Not authenticated'));
        }
      }, 300);
    });
  },
};
