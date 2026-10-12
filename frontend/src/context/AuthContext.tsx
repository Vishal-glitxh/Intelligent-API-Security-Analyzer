import React, { createContext, useContext, useState, useEffect } from 'react';

interface AuthContextType {
  apiKey: string;
  setApiKey: (key: string) => void;
  isAuthenticated: boolean;
  isConfigModalOpen: boolean;
  setIsConfigModalOpen: (open: boolean) => void;
  getAuthHeaders: () => Record<string, string>;
  clearAuth: () => void;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  // We keep in-memory credential state as required by security guidelines
  // But also check if dev token is present in window or sessionStorage if explicitly chosen
  const [apiKey, setApiKeyState] = useState<string>(() => {
    return sessionStorage.getItem('analyzer_session_api_key') || '';
  });
  const [isConfigModalOpen, setIsConfigModalOpen] = useState(false);

  const setApiKey = (key: string) => {
    const trimmed = key.trim();
    setApiKeyState(trimmed);
    if (trimmed) {
      sessionStorage.setItem('analyzer_session_api_key', trimmed);
    } else {
      sessionStorage.removeItem('analyzer_session_api_key');
    }
  };

  const clearAuth = () => {
    setApiKeyState('');
    sessionStorage.removeItem('analyzer_session_api_key');
  };

  const getAuthHeaders = (): Record<string, string> => {
    if (!apiKey) return {};
    return {
      'X-API-Key': apiKey,
      'Authorization': `Bearer ${apiKey}`,
    };
  };

  // Auto prompt if no key set
  useEffect(() => {
    if (!apiKey) {
      // Don't pop up immediately on first load, let user see the dashboard first
    }
  }, [apiKey]);

  return (
    <AuthContext.Provider
      value={{
        apiKey,
        setApiKey,
        isAuthenticated: Boolean(apiKey),
        isConfigModalOpen,
        setIsConfigModalOpen,
        getAuthHeaders,
        clearAuth,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = (): AuthContextType => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};
