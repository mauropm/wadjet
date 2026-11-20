import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
} from 'react';
import { authApi, clearToken, setToken } from '@/api/client';
import type { User } from '@/lib/types';

interface AuthState {
  user: User | null;
  booting: boolean;
  login: (email: string, password: string) => Promise<void>;
  register: (email: string, name: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
}

const Ctx = createContext<AuthState | null>(null);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [booting, setBooting] = useState<boolean>(true);

  useEffect(() => {
    let cancelled = false;
    // Always probe /auth/me, token or not: the SERVER is the authority on
    // who is authenticated. That is what makes development no-login mode
    // (WADJET_DEV_NO_LOGIN, `make dev`) work — an unauthenticated probe
    // resolves to the bootstrap admin there. In normal deployments the
    // tokenless probe just 401s and the router shows the login page, one
    // cheap request the way it already was.
    authApi
      .me()
      .then((u) => {
        if (!cancelled) setUser(u);
      })
      .catch(() => {
        if (!cancelled) {
          clearToken();
          setUser(null);
        }
      })
      .finally(() => {
        if (!cancelled) setBooting(false);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const login = useCallback(async (email: string, password: string) => {
    const res = await authApi.login(email, password);
    setToken(res.token);
    setUser(res.user);
  }, []);

  const register = useCallback(async (email: string, name: string, password: string) => {
    await authApi.register(email, name, password);
    // Registration does not return a token — sign straight in.
    const res = await authApi.login(email, password);
    setToken(res.token);
    setUser(res.user);
  }, []);

  const logout = useCallback(async () => {
    try {
      await authApi.logout();
    } catch {
      /* best-effort */
    }
    clearToken();
    setUser(null);
  }, []);

  const value = useMemo(
    () => ({ user, booting, login, register, logout }),
    [user, booting, login, register, logout],
  );

  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useAuth(): AuthState {
  const ctx = useContext(Ctx);
  if (!ctx) throw new Error('useAuth must be used within AuthProvider');
  return ctx;
}
