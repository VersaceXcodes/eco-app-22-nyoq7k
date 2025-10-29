import { create } from 'zustand';
import { persist } from 'zustand/middleware';
import axios from 'axios';

// ====================
// == TYPE DEFINITIONS ==
// ====================

interface User {
  id: string;
  email: string;
  name: string;
  created_at: string;
}

interface Notification {
  id: string;
  type: 'success' | 'error' | 'info';
  message: string;
  timestamp: string;
}

interface AuthState {
  current_user: User | null;
  auth_token: string | null;
  authentication_status: {
    is_authenticated: boolean;
    is_loading: boolean;
  };
  error_message: string | null;
}

interface AppStore {
  auth_state: AuthState;
  notification_queue: Notification[];
  
  // Auth Actions
  login_user: (email: string, password: string) => Promise<void>;
  logout_user: () => void;
  register_user: (email: string, password: string, name: string) => Promise<void>;
  initialize_auth: () => Promise<void>;
  clear_auth_error: () => void;
  update_user_profile: (userData: Partial<User>) => void;
  
  // Notification Actions
  add_notification: (notification: Notification) => void;
  remove_notification: (id: string) => void;
}

// ====================
// === STORE IMPLEMENTATION ===
// ====================

export const useAppStore = create(
  persist<AppStore>(
    (set, get) => ({
      // Initial State
      auth_state: {
        current_user: null,
        auth_token: null,
        authentication_status: {
          is_authenticated: false,
          is_loading: true,
        },
        error_message: null,
      },
      notification_queue: [],
      
      // Auth Actions
      login_user: async (email: string, password: string) => {
        set((state) => ({
          auth_state: {
           ...state.auth_state,
            authentication_status: {
             ...state.auth_state.authentication_status,
              is_loading: true,
            },
            error_message: null,
          },
        }));

        try {
          const response = await axios.post(
            `${import.meta.env.VITE_API_BASE_URL || 'http://localhost:3000'}/api/auth/login`,
            { email, password },
            { headers: { 'Content-Type': 'application/json' } }
          );

          const { user, token } = response.data;

          set((state) => ({
            auth_state: {
              current_user: user,
              auth_token: token,
              authentication_status: {
                is_authenticated: true,
                is_loading: false,
              },
              error_message: null,
            },
          }));
        } catch (error: any) {
          const errorMessage = error.response?.data?.message || error.message || 'Login failed';
          
          set((state) => ({
            auth_state: {
             ...state.auth_state,
              current_user: null,
              auth_token: null,
              authentication_status: {
                is_authenticated: false,
                is_loading: false,
              },
              error_message: errorMessage,
            },
          }));
          throw new Error(errorMessage);
        }
      },

      logout_user: () => {
        set(() => ({
          auth_state: {
            current_user: null,
            auth_token: null,
            authentication_status: {
              is_authenticated: false,
              is_loading: false,
            },
            error_message: null,
          },
        }));
      },

      register_user: async (email: string, password: string, name: string) => {
        set((state) => ({
          auth_state: {
           ...state.auth_state,
            authentication_status: {
             ...state.auth_state.authentication_status,
              is_loading: true,
            },
            error_message: null,
          },
        }));

        try {
          const response = await axios.post(
            `${import.meta.env.VITE_API_BASE_URL || 'http://localhost:3000'}/api/auth/register`,
            { email, password, name },
            { headers: { 'Content-Type': 'application/json' } }
          );

          const { user, token } = response.data;

          set((state) => ({
            auth_state: {
              current_user: user,
              auth_token: token,
              authentication_status: {
                is_authenticated: true,
                is_loading: false,
              },
              error_message: null,
            },
          }));
          return { user, token };
        } catch (error: any) {
          const errorMessage = error.response?.data?.message || error.message || 'Registration failed';
          
          set((state) => ({
            auth_state: {
             ...state.auth_state,
              current_user: null,
              auth_token: null,
              authentication_status: {
                is_authenticated: false,
                is_loading: false,
              },
              error_message: errorMessage,
            },
          }));
          throw new Error(errorMessage);
        }
      },

      initialize_auth: async () => {
        const { auth_state } = get();
        const token = auth_state.auth_token;

        if (!token) {
          set((state) => ({
            auth_state: {
             ...state.auth_state,
              authentication_status: {
               ...state.auth_state.authentication_status,
                is_loading: false,
              },
            },
          }));
          return;
        }

        try {
          const response = await axios.get(
            `${import.meta.env.VITE_API_BASE_URL || 'http://localhost:3000'}/api/auth/verify`,
            { headers: { Authorization: `Bearer ${token}` } }
          );

          const { user } = response.data;

          set((state) => ({
            auth_state: {
              current_user: user,
              auth_token: token,
              authentication_status: {
                is_authenticated: true,
                is_loading: false,
              },
              error_message: null,
            },
          }));
        } catch (error) {
          set((state) => ({
            auth_state: {
              current_user: null,
              auth_token: null,
              authentication_status: {
                is_authenticated: false,
                is_loading: false,
              },
              error_message: null,
            },
          }));
        }
      },

      clear_auth_error: () => {
        set((state) => ({
          auth_state: {
           ...state.auth_state,
            error_message: null,
          },
        }));
      },

      update_user_profile: (userData: Partial<User>) => {
        set(() => ({
          auth_state: {
           ...get().auth_state,
            current_user: get().auth_state.current_user
             ? {...get().auth_state.current_user,...userData }
              : null,
          },
        }));
      },

      // Notification Actions
      add_notification: (notification: Notification) => {
        set((state) => ({
          notification_queue: [...state.notification_queue, notification],
        }));
      },

      remove_notification: (id: string) => {
        set((state) => ({
          notification_queue: state.notification_queue.filter((n) => n.id!== id),
        }));
      },
    }),
    {
      name: 'app-store',
      partialize: (state) => ({
        auth_state: {
          current_user: state.auth_state.current_user,
          auth_token: state.auth_state.auth_token,
          authentication_status: {
            is_authenticated: state.auth_state.authentication_status.is_authenticated,
            is_loading: false,
          },
          error_message: null,
        },
      }),
    }
  )
);

// Export types for component usage
export type { User, Notification, AuthState, AppStore };