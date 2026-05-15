import axios from 'axios';

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || '';

export const apiClient = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

/**
 * Resolve the correct stored token based on the active role.
 * Instructor and student tokens are kept under separate keys so that
 * logging in as one role never clobbers the other's session.
 */
const getActiveToken = (): string | null => {
  const role = sessionStorage.getItem('demo_role');
  if (role === 'instructor') return sessionStorage.getItem('instructor_token');
  if (role === 'student')    return sessionStorage.getItem('student_token');
  // Fallback: legacy single-key token (handles any in-flight sessions)
  return sessionStorage.getItem('demo_token');
};

apiClient.interceptors.request.use((config) => {
  const token = getActiveToken();
  if (token && config.headers) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});
