// Typed fetch wrapper for the WADJET REST API.
// Base '/api/v1' (vite proxies /api → http://localhost:8080).
// Token: localStorage('wadjet_token'). Auto-logout on 401.
//
// NOTE: the Go server decodes request bodies with DisallowUnknownFields(),
// so request payloads must contain ONLY contract fields (see lib/types.ts).

import type {
  Asset,
  AssetCreateInput,
  AssetObservation,
  AuditLog,
  CloneInput,
  Finding,
  FindingObservation,
  FindingStatusHistory,
  FindingStatusInput,
  ListResponse,
  LoginResponse,
  ProfileInput,
  Project,
  ProjectCreateInput,
  ProjectTarget,
  ProjectUpdateInput,
  Report,
  ScanCreateInput,
  ScanProfile,
  ScanSession,
  ScannerRecord,
  TargetCreateInput,
  TargetUpdateInput,
  User,
} from '@/lib/types';
import { qs } from '@/lib/utils';

export const TOKEN_KEY = 'wadjet_token';
const BASE = '/api/v1';

export class ApiError extends Error {
  status: number;
  constructor(message: string, status: number) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
  }
}

export function getToken(): string | null {
  try {
    return localStorage.getItem(TOKEN_KEY);
  } catch {
    return null;
  }
}

export function setToken(token: string): void {
  try {
    localStorage.setItem(TOKEN_KEY, token);
  } catch {
    /* storage unavailable */
  }
}

export function clearToken(): void {
  try {
    localStorage.removeItem(TOKEN_KEY);
  } catch {
    /* noop */
  }
}

function forceLogout(): void {
  clearToken();
  if (!window.location.pathname.startsWith('/login')) {
    window.location.assign('/login');
  }
}

/** Strip undefined keys so we never send fields the server doesn't know. */
function cleanBody<T>(body: T): T {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(body as Record<string, unknown>)) {
    if (v !== undefined) out[k] = v;
  }
  return out as T;
}

async function request<T>(
  method: string,
  path: string,
  body?: unknown,
  opts: { silent401?: boolean } = {},
): Promise<T> {
  const headers: Record<string, string> = { Accept: 'application/json' };
  const token = getToken();
  if (token) headers.Authorization = `Bearer ${token}`;
  if (body !== undefined) headers['Content-Type'] = 'application/json';

  let res: Response;
  try {
    res = await fetch(`${BASE}${path}`, {
      method,
      headers,
      body: body !== undefined ? JSON.stringify(body) : undefined,
      credentials: 'same-origin',
    });
  } catch {
    throw new ApiError('Cannot reach the WADJET API. Is the server running?', 0);
  }

  if (res.status === 401 && !opts.silent401) {
    forceLogout();
    throw new ApiError('Session expired — please sign in again.', 401);
  }

  if (res.status === 204) return undefined as T;

  const text = await res.text();
  let data: unknown = null;
  if (text) {
    try {
      data = JSON.parse(text);
    } catch {
      data = null;
    }
  }

  if (!res.ok) {
    const msg =
      (data as { error?: { message?: string } } | null)?.error?.message ||
      (typeof data === 'string' && data ? data : '') ||
      `${res.status} ${res.statusText || 'request failed'}`;
    throw new ApiError(msg, res.status);
  }

  return data as T;
}

const get = <T>(path: string, opts?: { silent401?: boolean }) =>
  request<T>('GET', path, undefined, opts);
const post = <T>(path: string, body?: unknown) => request<T>('POST', path, body ?? {});
const put = <T>(path: string, body?: unknown) => request<T>('PUT', path, body ?? {});
const del = <T>(path: string) => request<T>('DELETE', path);

// ── Auth ────────────────────────────────────────────────────────────────────

export const authApi = {
  login: (email: string, password: string) =>
    post<LoginResponse>('/auth/login', { email, password }),
  register: (email: string, name: string, password: string) =>
    post<User>('/auth/register', { email, name, password }),
  logout: () => post<{ status: string }>('/auth/logout'),
  me: () => get<User>('/auth/me', { silent401: true }),
};

// ── Projects & targets ──────────────────────────────────────────────────────

export const projectsApi = {
  list: () => get<ListResponse<Project>>('/projects'),
  get: (id: string) => get<Project>(`/projects/${id}`),
  create: (input: ProjectCreateInput) => post<Project>('/projects', cleanBody(input)),
  update: (id: string, input: ProjectUpdateInput) =>
    put<Project>(`/projects/${id}`, cleanBody(input)),
  remove: (id: string) => del<void>(`/projects/${id}`),
  archive: (id: string) => post<Project>(`/projects/${id}/archive`),
  clone: (id: string, input: CloneInput) => {
    // Backend contract: {name, description?, copy?: {settings, targets, ...}}
    const { name, description, ...flat } = input as CloneInput & {
      description?: string;
    };
    const copy = Object.fromEntries(
      Object.entries(flat)
        .filter(([k]) => k.startsWith('copy_'))
        .map(([k, v]) => [k.replace(/^copy_/, ''), v]),
    );
    return post<Project>(
      `/projects/${id}/clone`,
      cleanBody({ name, description, copy: Object.keys(copy).length ? copy : undefined }),
    );
  },

  listTargets: (projectId: string) =>
    get<ListResponse<ProjectTarget>>(`/projects/${projectId}/targets`),
  createTarget: (projectId: string, input: TargetCreateInput) =>
    post<ProjectTarget>(`/projects/${projectId}/targets`, cleanBody(input)),
  updateTarget: (id: string, input: TargetUpdateInput) =>
    put<ProjectTarget>(`/targets/${id}`, cleanBody(input)),
  deleteTarget: (id: string) => del<void>(`/targets/${id}`),

  // Assets
  listAssets: (projectId: string) =>
    get<ListResponse<Asset>>(`/projects/${projectId}/assets`),
  createAsset: (projectId: string, input: AssetCreateInput) =>
    post<Asset>(`/projects/${projectId}/assets`, cleanBody(input)),

  // Profiles
  listProfiles: (projectId: string) =>
    get<ListResponse<ScanProfile>>(`/projects/${projectId}/profiles`),
  createProfile: (projectId: string, input: ProfileInput) =>
    post<ScanProfile>(`/projects/${projectId}/profiles`, cleanBody(input)),
  updateProfile: (id: string, input: ProfileInput) =>
    put<ScanProfile>(`/profiles/${id}`, cleanBody(input)),
  deleteProfile: (id: string) => del<void>(`/profiles/${id}`),

  // Scans
  listScans: (projectId: string) => get<ListResponse<ScanSession>>(`/projects/${projectId}/scans`),
  createScan: (projectId: string, input: ScanCreateInput) =>
    post<ScanSession>(`/projects/${projectId}/scans`, cleanBody(input)),

  // Findings
  listFindings: (projectId: string, filters: Record<string, string | number | undefined> = {}) =>
    get<ListResponse<Finding>>(`/projects/${projectId}/findings${qs(filters)}`),

  // Reports
  generateScanReport: (projectId: string, sessionId: string) =>
    post<Report>(`/projects/${projectId}/reports/scan`, { session_id: sessionId }),
  generateFindingsReport: (projectId: string, type: 'findings_consolidated' | 'findings_zip') =>
    post<Report>(`/projects/${projectId}/reports/findings`, { type }),
};

// ── Assets (top-level) ──────────────────────────────────────────────────────

export const assetsApi = {
  get: (id: string) => get<Asset>(`/assets/${id}`),
  update: (id: string, input: Partial<AssetCreateInput>) =>
    put<Asset>(`/assets/${id}`, cleanBody(input)),
  remove: (id: string) => del<void>(`/assets/${id}`),
  history: (id: string) => get<ListResponse<AssetObservation>>(`/assets/${id}/history`),
};

// ── Findings (top-level) ────────────────────────────────────────────────────

export const findingsApi = {
  get: (id: string) => get<Finding>(`/findings/${id}`),
  setStatus: (id: string, input: FindingStatusInput) =>
    put<Finding>(`/findings/${id}/status`, cleanBody(input)),
  history: (id: string) =>
    get<ListResponse<FindingStatusHistory>>(`/findings/${id}/history`),
  /** Not in CONTRACTS.md §4 yet — callers must tolerate 404. */
  observations: (id: string) =>
    get<ListResponse<FindingObservation>>(`/findings/${id}/observations`),
  generateReport: (id: string) => post<Report>(`/findings/${id}/report`),
};

// ── Scans ───────────────────────────────────────────────────────────────────

export const scansApi = {
  get: (id: string) => get<ScanSession>(`/scans/${id}`),
  start: (id: string) => post<ScanSession>(`/scans/${id}/start`),
  cancel: (id: string) => post<ScanSession>(`/scans/${id}/cancel`),
};

// ── Scanners ────────────────────────────────────────────────────────────────

export const scannersApi = {
  list: () => get<ListResponse<ScannerRecord>>('/scanners'),
  get: (id: string) => get<ScannerRecord>(`/scanners/${id}`),
  setEnabled: (id: string, enabled: boolean) =>
    put<ScannerRecord>(`/scanners/${id}/enabled`, { enabled }),
};

// ── Reports ─────────────────────────────────────────────────────────────────

export const reportsApi = {
  list: (projectId?: string) =>
    get<ListResponse<Report>>(`/reports${projectId ? qs({ project_id: projectId }) : ''}`),
  get: (id: string) => get<Report>(`/reports/${id}`),
  download: async (id: string, fallbackName = 'wadjet-report.pdf'): Promise<void> => {
    const token = getToken();
    const res = await fetch(`${BASE}/reports/${id}/download`, {
      headers: token ? { Authorization: `Bearer ${token}` } : undefined,
      credentials: 'same-origin',
    });
    if (!res.ok) throw new ApiError('Download failed', res.status);
    const blob = await res.blob();
    const cd = res.headers.get('Content-Disposition') ?? '';
    const m = cd.match(/filename="?([^";]+)"?/i);
    const name = m?.[1] ?? (blob.type.includes('zip') ? fallbackName.replace(/\.pdf$/, '.zip') : fallbackName);
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = name;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  },
};

// ── Audit (optional endpoint) ───────────────────────────────────────────────

export const auditApi = {
  list: () => get<ListResponse<AuditLog>>('/audit'),
};

/**
 * Lenient list unwrap: accepts the contract `{items,total}` envelope or a
 * bare array (defensive against handler drift).
 */
export function unwrap<T>(r: ListResponse<T> | T[] | null | undefined): T[] {
  if (!r) return [];
  if (Array.isArray(r)) return r;
  return r.items ?? [];
}
