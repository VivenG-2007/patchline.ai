import hmac
from typing import Optional

import jwt
from fastapi import Cookie, Header, HTTPException, Request, status

from app.config import get_settings


class CurrentUser:
    def __init__(self, user_id: str, role: Optional[str] = None):
        self.id = user_id
        self.role = role


def _extract_token(authorization: Optional[str], access_token_cookie: Optional[str]) -> Optional[str]:
    if authorization and authorization.startswith("Bearer "):
        return authorization[7:]
    if access_token_cookie:
        return access_token_cookie
    return None


def _verify(token: str) -> dict:
    settings = get_settings()
    if not settings.jwt_public_key:
        raise HTTPException(status_code=500, detail="JWT public key not configured on this service")
    decode_kwargs = dict(algorithms=["RS256"], issuer=settings.jwt_issuer, audience=settings.jwt_audience)
    try:
        payload = jwt.decode(token, settings.jwt_public_key, **decode_kwargs)
    except jwt.PyJWTError as current_key_exc:
        # Fall back to the pre-rotation key if one is configured (see
        # config.py) — same dual-key handover window as the two Node
        # services, so rotating JWT_KID on auth-service doesn't instantly
        # invalidate every token this service verifies locally.
        if not settings.jwt_previous_public_key:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token") from current_key_exc
        try:
            payload = jwt.decode(token, settings.jwt_previous_public_key, **decode_kwargs)
        except jwt.PyJWTError:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token") from current_key_exc
    if payload.get("type") != "access":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Wrong token type")
    return payload


# Same local-verification pattern as the Node services: this service checks
# the JWT signature itself with auth-service's PUBLIC key. No network call to
# auth-service happens here, whether the request arrived directly from the
# frontend or via main-service's proxy.
async def require_auth(
    request: Request,
    authorization: Optional[str] = Header(default=None),
    access_token: Optional[str] = Cookie(default=None),
) -> CurrentUser:
    token = _extract_token(authorization, access_token)
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing access token")
    payload = _verify(token)
    user = CurrentUser(user_id=payload["sub"], role=payload.get("role"))
    request.state.user_id = user.id
    return user


# Same local-verification pattern as require_auth, but tolerates a request
# that has no live browser JWT at all — used by /scan, which can be invoked
# two ways:
#   1. a real user's browser session (Authorization / access_token cookie)
#   2. main-service's BullMQ worker, running a webhook-triggered rescan with
#      no browser involved (see workers/scannerWorkers.js#upstreamHeaders)
#
# In case 2, main-service asserts the watched repo's owner via the
# X-System-User-Id header, which is only trusted when the shared
# X-Internal-Service-Token is also present and valid — this route already
# sits behind require_internal_service_token as a router-level dependency,
# but the check is repeated here defensively since this function could be
# reused directly on a route that doesn't have that dependency.
async def require_auth_optional(
    request: Request,
    authorization: Optional[str] = Header(default=None),
    access_token: Optional[str] = Cookie(default=None),
    x_system_user_id: Optional[str] = Header(default=None),
    x_internal_service_token: Optional[str] = Header(default=None),
) -> CurrentUser:
    token = _extract_token(authorization, access_token)
    if token:
        payload = _verify(token)
        user = CurrentUser(user_id=payload["sub"], role=payload.get("role"))
        request.state.user_id = user.id
        return user

    settings = get_settings()
    if (
        x_system_user_id
        and settings.internal_service_token
        and x_internal_service_token
        and hmac.compare_digest(x_internal_service_token, settings.internal_service_token)
    ):
        request.state.user_id = x_system_user_id
        return CurrentUser(user_id=x_system_user_id, role="system")

    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing access token")


# Defense-in-depth for routes that also expect to be reached only through
# main-service's gateway (see docs/security.md — "Internal service secret"
# layer). main-service's proxyController already sends this header on every
# forwarded call; this just verifies it server-side instead of leaving the
# setting unused. If INTERNAL_SERVICE_TOKEN is unset (e.g. local dev without
# it configured), the check is skipped rather than locking the service out.
async def require_internal_service_token(
    x_internal_service_token: Optional[str] = Header(default=None),
) -> None:
    settings = get_settings()
    if not settings.internal_service_token:
        return
    if not x_internal_service_token or not hmac.compare_digest(
        x_internal_service_token, settings.internal_service_token
    ):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Missing or invalid internal service token")
