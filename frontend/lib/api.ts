import axios from 'axios';

// withCredentials: true means the browser sends/receives the httpOnly cookies
// (access_token / refresh_token) that auth-service sets. This is why CORS on
// every backend must set credentials:true and echo the exact origin.
export const authApi = axios.create({
  baseURL: process.env.NEXT_PUBLIC_AUTH_API_URL || process.env.NEXT_PUBLIC_AUTH_URL || 'http://localhost:5000',
  withCredentials: true,
});

export const mainApi = axios.create({
  baseURL: process.env.NEXT_PUBLIC_MAIN_API_URL || process.env.NEXT_PUBLIC_API_URL || 'http://localhost:5001',
  withCredentials: true,
});

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
// In-memory token store
// ---------------------------------------------------------------------------
// In production, auth-service and main-service are on different domains.
// The browser will send the httpOnly access_token cookie back to auth-service
// requests only — NOT to main-service (cross-domain cookies are blocked).
// Auth-service already returns the accessToken in the JSON response body, so
// we store it here and inject it as an Authorization: Bearer header on every
// mainApi request. On localhost the cookie also works, so this is strictly
// additive and doesn't break anything.
let _accessToken: string | null = null;

export function setAccessToken(token: string | null) {
  _accessToken = token;
}

export function clearAccessToken() {
  _accessToken = null;
}

// Inject Bearer token into every mainApi request.
mainApi.interceptors.request.use((config) => {
  if (_accessToken) {
    config.headers = config.headers ?? {};
    config.headers['Authorization'] = `Bearer ${_accessToken}`;
  }
  return config;
});

let refreshing: Promise<unknown> | null = null;

// One shared 401 interceptor: on the first 401, try /refresh once and replay
// the original request. Avoids a stampede of parallel refresh calls. Shared
// `refreshing` promise below is deliberately reused by BOTH interceptors
// (mainApi's and authApi's) so a 401 from either client triggers at most one
// concurrent refresh call, not two racing ones.
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
        // Store the new access token so subsequent mainApi calls include it.
        if (refreshRes?.data?.accessToken) setAccessToken(refreshRes.data.accessToken);
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

// Same idea for direct authApi calls (e.g. AuthContext's `/api/auth/me` on
// mount). Previously ONLY mainApi had this interceptor, so a call like
// `/api/auth/me` made after the 15-minute access token expired would just
// fail with 401 and never retry — from the user's perspective the account
// looked logged out / showed an "invalid token" error, even though the
// refresh_token cookie was still valid. `isRefreshCall` guards against
// infinite recursion when the /refresh call itself comes back 401 (i.e. the
// refresh token is also expired or revoked) — in that case we give up and
// let the caller treat the session as logged out.
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
        if (refreshRes?.data?.accessToken) setAccessToken(refreshRes.data.accessToken);
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
  // Full-page navigation, not an axios call — the user needs to actually see
  // and approve Atlassian's consent screen, which an XHR redirect can't show.
  // `returnTo` lets a caller (e.g. the onboarding wizard) get sent back to a
  // specific in-app page instead of always landing on /jira.
  connectUrl: (returnTo?: string) =>
    `${process.env.NEXT_PUBLIC_MAIN_API_URL || 'http://localhost:5001'}/api/jira/oauth/start${returnTo ? `?redirect=${encodeURIComponent(returnTo)}` : ''
    }`,
  disconnect: () => mainApi.delete('/api/jira/disconnect'),
  createIssue: (payload: { summary: string; description: string; issueType?: string }) =>
    mainApi.post('/api/jira/issues', payload),
  getIssue: (key: string) => mainApi.get(`/api/jira/issues/${encodeURIComponent(key)}`),
};

export const githubApi = {
  status: () => mainApi.get('/api/github/status'),
  connectUrl: (returnTo?: string) =>
    `${process.env.NEXT_PUBLIC_MAIN_API_URL || 'http://localhost:5001'}/api/github/oauth/start${returnTo ? `?redirect=${encodeURIComponent(returnTo)}` : ''
    }`,
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
