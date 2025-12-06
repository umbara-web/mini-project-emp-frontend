'use client';
import { createContext, useContext, useEffect, useState } from 'react';

type User = {
  id: string;
  name: string;
  role: 'customer' | 'organizer';
  points: number;
  referenceCode: string;
};

const mockUser: User = {
  id: 'user-1',
  name: 'Demo User',
  role: 'customer',
  points: 20000,
  referenceCode: 'REF-ABC123',
};

const AuthContext = createContext<{
  user: User | null;
  login: (u?: Partial<User>) => void;
  logout: () => void;
}>({
  user: null,
  login: () => {},
  logout: () => {},
});

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<User | null>(null);

  useEffect(() => {
    // in dev mode, keep a mocked logged-in user for quicker demos
    setUser(mockUser);
  }, []);

  function login(u?: Partial<User>) {
    setUser({ ...mockUser, ...u } as User);
  }
  function logout() {
    setUser(null);
  }

  return (
    <AuthContext.Provider value={{ user, login, logout }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  return useContext(AuthContext);
}
