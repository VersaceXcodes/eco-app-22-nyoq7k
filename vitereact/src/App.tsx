import React, { useEffect } from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { useAppStore } from '@/store/main';

// Import views based on provided structure
import UV_Login from '@/components/views/UV_Login';
import UV_Dashboard from '@/components/views/UV_Dashboard';

// Initialize QueryClient with default options
const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 5 * 60 * 1000, // 5 minutes
      retry: 1,
    },
  },
});

// Loading spinner component
const LoadingSpinner: React.FC = () => (
  <div className="min-h-screen flex items-center justify-center bg-gray-50">
    <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600"></div>
  </div>
);

// Protected route component
const ProtectedRoute: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  // Use individual selectors to prevent infinite loops
  const isAuthenticated = useAppStore(state => state.auth_state.authentication_status.is_authenticated);
  const isLoading = useAppStore(state => state.auth_state.authentication_status.is_loading);
  
  if (isLoading) {
    return <LoadingSpinner />;
  }
  
  if (!isAuthenticated) {
    return <Navigate to="/login" replace />;
  }
  
  return <>{children}</>;
};

// Main App component
const App: React.FC = () => {
  // Destructure only necessary store values
  const isLoading = useAppStore(state => state.auth_state.authentication_status.is_loading);
  const initializeAuth = useAppStore(state => state.initialize_auth);
  
  // Initialize authentication on mount
  useEffect(() => {
    initializeAuth();
  }, [initializeAuth]);
  
  // Show loading spinner during initial auth check
  if (isLoading) {
    return <LoadingSpinner />;
  }

  return (
    <Router>
      <QueryClientProvider client={queryClient}>
        <div className="App min-h-screen flex flex-col bg-gray-50">
          <main className="flex-1">
            <Routes>
              {/* Public Routes */}
              <Route 
                path="/login" 
                element={
                  <UV_Login />
                } 
              />
              
              {/* Protected Routes */}
              <Route 
                path="/dashboard" 
                element={
                  <ProtectedRoute>
                    <UV_Dashboard />
                  </ProtectedRoute>
                } 
              />
              
              {/* Catch-all route redirects to dashboard */}
              <Route path="*" element={<Navigate to="/dashboard" replace />} />
            </Routes>
          </main>
        </div>
      </QueryClientProvider>
    </Router>
  );
};

export default App;