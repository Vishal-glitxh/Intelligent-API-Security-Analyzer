import { createContext } from 'react';

export interface AuthContextType {
  apiKey: string;
  setApiKey: (key: string) => void;
  isAuthenticated: boolean;
  localDevelopmentAccess: boolean;
  isConfigModalOpen: boolean;
  setIsConfigModalOpen: (open: boolean) => void;
  getAuthHeaders: () => Record<string, string>;
  clearAuth: () => void;
}

export const AuthContext = createContext<AuthContextType | undefined>(undefined);
