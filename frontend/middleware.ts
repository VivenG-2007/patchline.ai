import { NextRequest, NextResponse } from 'next/server';
import { jwtVerify, importSPKI } from 'jose';

// Runs at the edge before /dashboard and /upload render. This is a UX
// short-circuit (fast redirect to /login for an obviously missing/expired
// cookie) — it is NOT a substitute for each backend verifying the token
// itself, which they all still do independently.
const PROTECTED_PREFIXES = ['/dashboard', '/upload', '/jira', '/github', '/scanner', '/onboarding'];

// Same origin lib/api.ts uses for the browser-side axios client — reused
// here so the edge and the client agree on where auth-service lives.
const AUTH_API_URL = process.env.NEXT_PUBLIC_AUTH_API_URL || 'http://localhost:5000';

function decodeKey(base64Value: string | undefined) {
  if (!base64Value) return null;
  try {
    return Buffer.from(base64Value, 'base64').toString('utf8');
  } catch {
    return null;
  }
}

async function isValidAccessToken(token: string, publicKeyPem: string): Promise<boolean> {
  try {
    const key = await importSPKI(publicKeyPem, 'RS256');
    await jwtVerify(token, key, {
      issuer: process.env.JWT_ISSUER || 'hackathon-auth-service',
      audience: process.env.JWT_AUDIENCE || 'patchline',
    });
    return true;
  } catch {
    return false;
  }
}

// BUG THIS FIXES: the access_token cookie is only valid for 15 minutes
// (JWT_ACCESS_EXPIRES_IN). Previously, the moment it expired, this
// middleware redirected straight to /login — even though the much
// longer-lived refresh_token cookie was still sitting right there and
// perfectly valid. The client-side axios interceptor in lib/api.ts *does*
// silently refresh on a 401 from an API call, but it never got a chance to
// run here, because a page navigation never goes through axios — it hits
// this middleware directly. Net effect: anyone who stayed on a protected
// page (or came back to one) more than ~15 minutes after logging in got
// bounced to /login and told their session was invalid, despite having a
// perfectly good refresh token.
//
// Fix: before redirecting, try exchanging the refresh_token for a new
// access_token/refresh_token pair server-side (same call lib/api.ts's
// interceptor makes), and forward whatever Set-Cookie headers auth-service
// returns onto the response. Only redirect to /login if that also fails
// (refresh token itself missing, expired, or revoked).
async function tryRefresh(req: NextRequest): Promise<string[] | null> {
  const refreshToken = req.cookies.get('refresh_token')?.value;
  if (!refreshToken) return null;

  try {
    const res = await fetch(`${AUTH_API_URL}/api/auth/refresh`, {
      method: 'POST',
      headers: { cookie: `refresh_token=${refreshToken}` },
      // Never let a slow/unreachable auth-service hang page navigation —
      // fail fast to the /login redirect instead.
      signal: AbortSignal.timeout(5000),
    });
    if (!res.ok) return null;

    // getSetCookie() is the correct way to read multiple Set-Cookie headers
    // (a plain .get('set-cookie') collapses them into one comma-joined
    // string per the Headers spec, which breaks on cookies with commas in
    // e.g. their Expires attribute). Supported by the Next.js edge runtime.
    const setCookies = res.headers.getSetCookie?.() ?? [];
    return setCookies.length > 0 ? setCookies : null;
  } catch {
    return null;
  }
}

export async function middleware(req: NextRequest) {
  const isProtected = PROTECTED_PREFIXES.some((p) => req.nextUrl.pathname.startsWith(p));
  if (!isProtected) return NextResponse.next();

  const token = req.cookies.get('access_token')?.value;
  const publicKeyPem = decodeKey(process.env.JWT_PUBLIC_KEY_BASE64);

  if (token && publicKeyPem) {
    if (await isValidAccessToken(token, publicKeyPem)) {
      return NextResponse.next();
    }
  } else if (token && !publicKeyPem) {
    // Key not configured for this deployment — fall back to letting the
    // client-side AuthContext + backend 401s handle protection instead of
    // hard-blocking every request.
    return NextResponse.next();
  }

  // Access token missing, or present but invalid/expired — try to refresh
  // before giving up on the session.
  const setCookieHeaders = await tryRefresh(req);
  if (setCookieHeaders) {
    const response = NextResponse.next();
    for (const cookie of setCookieHeaders) {
      response.headers.append('set-cookie', cookie);
    }
    return response;
  }

  return NextResponse.redirect(new URL('/login', req.url));
}

export const config = {
  matcher: ['/dashboard/:path*', '/upload/:path*', '/jira/:path*', '/github/:path*', '/scanner/:path*', '/onboarding/:path*'],
};
