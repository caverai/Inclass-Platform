export type DemoRole = 'student' | 'instructor';

export const DEMO_ROLE_KEY = 'demo_role';
export const DEMO_USER_KEY = 'demo_user';

export const normalizeDemoRole = (role: string | null): DemoRole | null => {
  const normalized = role?.toLowerCase();
  if (normalized === 'student' || normalized === 'instructor') return normalized;
  return null;
};

export const getDemoRole = (): DemoRole | null => {
  return normalizeDemoRole(sessionStorage.getItem(DEMO_ROLE_KEY));
};

export const getDemoStudentEmail = (): string => {
  const storedUser = sessionStorage.getItem(DEMO_USER_KEY);

  if (storedUser) {
    try {
      const parsed = JSON.parse(storedUser) as { email?: unknown };
      if (typeof parsed.email === 'string' && parsed.email.trim()) {
        return parsed.email.trim().toLowerCase();
      }
    } catch {
      return 'student@example.com';
    }
  }

  return 'student@example.com';
};
