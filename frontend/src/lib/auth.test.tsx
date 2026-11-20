// @vitest-environment jsdom
import { render, screen, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';

// vi.mock is hoisted above these declarations — share the fakes via vi.hoisted.
const { me, getToken } = vi.hoisted(() => ({
  me: vi.fn(),
  getToken: vi.fn((): string | null => null),
}));

vi.mock('@/api/client', () => ({
  authApi: { me, login: vi.fn(), register: vi.fn(), logout: vi.fn() },
  getToken: () => getToken(),
  setToken: vi.fn(),
  clearToken: vi.fn(),
}));

import { AuthProvider, useAuth } from './auth';
import type { User } from '@/lib/types';

const admin: User = {
  id: '11111111-1111-1111-1111-111111111111',
  email: 'admin@wadjet.local',
  name: 'Administrator',
  role: 'admin',
  created_at: '2026-01-01T00:00:00Z',
};

function Probe() {
  const { user, booting } = useAuth();
  if (booting) return <div>BOOTING</div>;
  return <div>{user ? `USER:${user.email}` : 'ANON'}</div>;
}

beforeEach(() => {
  me.mockReset();
  getToken.mockReset();
  getToken.mockReturnValue(null);
});

// Regression: the SPA must NOT short-circuit to the login page when no
// token is stored. It always probes /auth/me and lets the SERVER decide —
// that is what makes `make dev` (WADJET_DEV_NO_LOGIN) open straight to the
// dashboard: a tokenless probe returns the bootstrap admin. An earlier
// version skipped the probe without a token and always showed /login.
describe('AuthProvider boot', () => {
  it('probes /auth/me even without a stored token', async () => {
    me.mockResolvedValue(admin);
    render(
      <AuthProvider>
        <Probe />
      </AuthProvider>,
    );
    await waitFor(() => expect(screen.getByText('USER:admin@wadjet.local')).toBeDefined());
    expect(me).toHaveBeenCalledTimes(1);
  });

  it('falls back to the login principal (null) when the probe 401s', async () => {
    me.mockRejectedValue(new Error('401'));
    render(
      <AuthProvider>
        <Probe />
      </AuthProvider>,
    );
    await waitFor(() => expect(screen.getByText('ANON')).toBeDefined());
    expect(me).toHaveBeenCalledTimes(1);
  });
});
