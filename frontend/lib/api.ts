import axios from 'axios';

// withCredentials: true means the browser sends/receives the httpOnly cookies
// (access_token / refresh_token) that auth-service sets. This is why CORS on
// every backend must set credentials:true and echo the exact origin.
export const authApi = axios.create({
  baseURL:
    process.env.NEXT_PUBLIC_AUTH_API_URL ||
    process.env.NEXT_PUBLIC_AUTH_URL ||
    // Production fallback — used when env vars aren't set on Vercel.
    // Set NEXT_PUBLIC_AUTH_API_URL in Vercel dashboard to override.
    (typeof window !== 'undefined' && window.location.hostname !== 'localhost'
      ? 'https://patchline-auth.onrender.com'
      : 'http://localhost:5000'),
  withCredentials: true,
});

export const mainApi = axios.create({
  baseURL:
    process.env.NEXT_PUBLIC_MAIN_API_URL ||
    process.env.NEXT_PUBLIC_API_URL ||
    (typeof window !== 'undefined' && window.location.hostname !== 'localhost'
      ? 'https://patchline-ai-uv72.onrender.com'
      : 'http://localhost:5001'),
  withCredentials: true,
});

// Resolve the main-service base URL at runtime (same logic as mainApi above).
const MAIN_API_BASE =
  process.env.NEXT_PUBLIC_MAIN_API_URL ||
  process.env.NEXT_PUBLIC_API_URL ||
  (typeof window !== 'undefined' && window.location.hostname !== 'localhost'
    ? 'https://patchline-ai-uv72.onrender.com'
    : 'http://localhost:5001');

// AI + file endpoints are reached THROUGH the main backend's proxy
// (/api/proxy/...), so the browser only ever talks to two hosts: auth-service
// and main-service. Swap to a direct ai-storage URL later if you want the
// frontend to bypass the gateway for large file uploads.
export const aiApi = {
  chat: (payload: { messages: { role: string; content: string }[] }) =>
    mainApi.post('/api/proxy/api/ai/chat', payload),
  analyze: (payload: { input: string; instructions?: string }) =>
    mainApi.post('/api/proxy/api/ai/analyze', payload),
};

export const filesApi = {
  upload: (file: File) => {
    const form = new FormData();
    form.append('file', file);
    return mainApi.post('/api/proxy/api/files/upload', form, {
      headers: { 'content-type': 'multipart/form-data' },
    });
  },
  list: () => mainApi.get('/api/proxy/api/files'),
};

// ---------------------------------------------------------------------------
// Token store — localStorage-backed so the token survives page refreshes.
// ---------------------------------------------------------------------------
// In production, auth-service and main-service are on different domains.
// Browsers block cross-domain httpOnly cookies, so the access_token cookie
// set by auth-service is never forwarded to main-service. Auth-service
// returns the accessToken in the JSON response body as well, so we persist
// it in localStorage and inject it as Authorization: Bearer on every request.
const TOKEN_KEY = 'pl_access_token';

function _readStoredToken(): string | null {
  if (typeof window === 'undefined') return null;
  try { return localStorage.getItem(TOKEN_KEY); } catch { return null; }
}

let _accessToken: string | null = _readStoredToken();

export function setAccessToken(token: string | null) {
  _accessToken = token;
  if (typeof window !== 'undefined') {
    try {
      if (token) { localStorage.setItem(TOKEN_KEY, token); }
      else { localStorage.removeItem(TOKEN_KEY); }
    } catch { /* storage blocked (private mode, quota) — silent */ }
  }
}

export function clearAccessToken() {
  setAccessToken(null);
}

// Helper used by both request interceptors below.
function _injectBearer(config: any): any {
  const token = _accessToken || _readStoredToken();
  if (token) {
    config.headers = config.headers ?? {};
    config.headers['Authorization'] = `Bearer ${token}`;
  }
  return config;
}

// Inject Bearer token into every mainApi request.
mainApi.interceptors.request.use(_injectBearer);

// Also inject into authApi — cross-domain browsers block the httpOnly cookie
// from being sent to auth-service from a different origin (Vercel → Render).
// Including the Bearer header ensures /api/auth/me and /api/auth/refresh work
// when cookies are not forwarded.
authApi.interceptors.request.use(_injectBearer);

let refreshing: Promise<unknown> | null = null;

// One shared 401 interceptor: on the first 401, try /refresh once and replay
// the original request. Avoids a stampede of parallel refresh calls.
mainApi.interceptors.response.use(
  (res) => res,
  async (error) => {
    const original = error.config;
    if (error.response?.status === 401 && !original._retry) {
      original._retry = true;
      try {
        refreshing = refreshing || authApi.post('/api/auth/refresh');
        const refreshRes = await refreshing as any;
        refreshing = null;
        if (refreshRes?.data?.accessToken) {
          setAccessToken(refreshRes.data.accessToken);
          original.headers = original.headers ?? {};
          original.headers['Authorization'] = `Bearer ${refreshRes.data.accessToken}`;
        }
        return mainApi(original);
      } catch (refreshErr) {
        refreshing = null;
        clearAccessToken();
        return Promise.reject(refreshErr);
      }
    }
    return Promise.reject(error);
  }
);

authApi.interceptors.response.use(
  (res) => res,
  async (error) => {
    const original = error.config;
    const isRefreshCall = typeof original?.url === 'string' && original.url.includes('/api/auth/refresh');
    if (error.response?.status === 401 && !original._retry && !isRefreshCall) {
      original._retry = true;
      try {
        refreshing = refreshing || authApi.post('/api/auth/refresh');
        const refreshRes = await refreshing as any;
        refreshing = null;
        if (refreshRes?.data?.accessToken) {
          setAccessToken(refreshRes.data.accessToken);
          original.headers = original.headers ?? {};
          original.headers['Authorization'] = `Bearer ${refreshRes.data.accessToken}`;
        }
        return authApi(original);
      } catch (refreshErr) {
        refreshing = null;
        clearAccessToken();
        return Promise.reject(refreshErr);
      }
    }
    return Promise.reject(error);
  }
);

export const jiraApi = {
  status: () => mainApi.get('/api/jira/status'),
  // Fetches the Atlassian OAuth consent URL via axios (which sends the
  // Authorization: Bearer header) then the caller navigates to it.
  // In cross-domain production a direct browser navigation to /oauth/start
  // carries no cookie/header, so the backend gets NO_TOKEN.
  connect: (returnTo?: string) =>
    mainApi.get('/api/jira/oauth/start-url', { params: returnTo ? { redirect: returnTo } : {} }),
  disconnect: () => mainApi.delete('/api/jira/disconnect'),
  createIssue: (payload: { summary: string; description: string; issueType?: string }) =>
    mainApi.post('/api/jira/issues', payload),
  getIssue: (key: string) => mainApi.get(`/api/jira/issues/${encodeURIComponent(key)}`),
};

export const githubApi = {
  status: () => mainApi.get('/api/github/status'),
  // Fetches the GitHub OAuth consent URL via axios (which sends the
  // Authorization: Bearer header) then the caller navigates to it.
  connect: (returnTo?: string) =>
    mainApi.get('/api/github/oauth/start-url', { params: returnTo ? { redirect: returnTo } : {} }),
  disconnect: () => mainApi.delete('/api/github/disconnect'),
  listRepos: () => mainApi.get('/api/github/repos'),
  createIssue: (payload: { owner: string; repo: string; title: string; body?: string }) =>
    mainApi.post('/api/github/issues', payload),

  // Continuous scanning (watch a repo -> push webhook -> auto-rescan).
  listWatched: () => mainApi.get('/api/github/watched'),
  watchRepo: (payload: { repoOwner: string; repoName: string; branch?: string }) =>
    mainApi.post('/api/github/watched', payload),
  unwatchRepo: (repositoryId: string) =>
    mainApi.delete(`/api/github/watched/${encodeURIComponent(repositoryId)}`),
  updateRepoSettings: (repositoryId: string, payload: { autoRescan: boolean }) =>
    mainApi.patch(`/api/github/watched/${encodeURIComponent(repositoryId)}/settings`, payload),
};

export const scannerApi = {
  scan: (payload: { repoOwner: string; repoName: string; branch?: string }) =>
    mainApi.post('/api/scanner/scan', payload),
  status: (scanId: string) =>
    mainApi.get(`/api/scanner/status/${scanId}`),
  approveAndFix: (payload: { scanId: string; findingId: string }) =>
    mainApi.post('/api/scanner/approve-fix', payload),
  history: (limit = 20) =>
    mainApi.get(`/api/scanner/history?limit=${limit}`),
  // Live AI provider health — Featherless primary / Azure OpenAI fallback
  aiProviderStatus: () =>
    mainApi.get('/api/scanner/ai-provider-status'),
  // Dashboard aggregation — real Mongo+ES data, no hardcoded numbers
  dashboardStats: () =>
    mainApi.get('/api/proxy/api/v1/dashboard/stats'),
};


// Used right after login/register to decide whether to route the person
// into the onboarding wizard (GitHub + Jira not connected yet) or straight
// to the dashboard. Failures are treated as "not connected" — an integration
// being briefly unreachable shouldn't block someone who already connected it
// on a previous visit; getting redirected to onboarding again is a minor
// inconvenience they can skip through, not a lockout.
export async function getConnectionStatus() {
  const [githubRes, jiraRes] = await Promise.allSettled([githubApi.status(), jiraApi.status()]);
  return {
    githubConnected: githubRes.status === 'fulfilled' && !!githubRes.value.data?.connected,
    jiraConnected: jiraRes.status === 'fulfilled' && !!jiraRes.value.data?.connected,
  };
}



export interface AuthUser {
  id: string;
  name: string;
  email: string;
  role: 'user' | 'admin';
}
