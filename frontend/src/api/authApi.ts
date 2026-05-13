
import type { User } from '../types';

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

  register: async (role: Role, email: string, name: string, password?: string) => {
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
        const role = localStorage.getItem('demo_role');
        if (role) {
          resolve({
            id: role === 'INSTRUCTOR' ? 'inst-1' : 'stu-1',
            email: role === 'INSTRUCTOR' ? 'instructor@example.com' : 'student@example.com',
            name: role === 'INSTRUCTOR' ? 'Dr. Smith' : 'John Doe',
            role: role as 'INSTRUCTOR' | 'STUDENT',
          });
        } else {
          reject(new Error('Not authenticated'));
        }
      }, 300);
    });
  },
};
