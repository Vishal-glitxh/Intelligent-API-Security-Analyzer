import React, { useState, useEffect } from 'react';
import { api } from '../services/api';
import { AuthContext } from './auth-context';

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  // We keep in-memory credential state as required by security guidelines
  // But also check if dev token is present in window or sessionStorage if explicitly chosen
  const [apiKey, setApiKeyState] = useState<string>(() => {
    return sessionStorage.getItem('analyzer_session_api_key') || '';
  });
  const [isConfigModalOpen, setIsConfigModalOpen] = useState(false);
  const [localDevelopmentAccess, setLocalDevelopmentAccess] = useState(false);

  useEffect(() => {
    if (apiKey) return;
    let active = true;
    void api.getAuthSession().then((session) => {
      if (active) setLocalDevelopmentAccess(session.auth_mode === 'local-development');
    }).catch(() => {
      if (active) setLocalDevelopmentAccess(false);
    });
    return () => { active = false; };
  }, [apiKey]);

  const setApiKey = (key: string) => {
    const trimmed = key.trim();
    setApiKeyState(trimmed);
    setLocalDevelopmentAccess(false);
    if (trimmed) {
      sessionStorage.setItem('analyzer_session_api_key', trimmed);
    } else {
      sessionStorage.removeItem('analyzer_session_api_key');
    }
  };

  const clearAuth = () => {
    setApiKeyState('');
    setLocalDevelopmentAccess(false);
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
        isAuthenticated: Boolean(apiKey) || localDevelopmentAccess,
        localDevelopmentAccess,
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
