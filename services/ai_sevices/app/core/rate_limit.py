from slowapi import Limiter
from slowapi.util import get_remote_address

from app.config import get_settings

settings = get_settings()

# Redis-backed storage (via the `limits` library slowapi wraps) so limits
# are shared across every replica of this service instead of reset per
# instance — same reasoning as main-service's rate-limit-redis store and
# auth-service's (see docs/production-readiness.md, "in-memory rate
# limiting" gap). Reuses REDIS_URL, which this service already connects to
# for scan/fix state (see core/redis_client.py), so there's no new
# infrastructure dependency — just no longer defaulting to slowapi's
# in-memory counter.
#
# Keyed by remote address by default. For per-user limits, swap the key_func
# to pull `request.state.user_id` (set by require_auth) once auth has run —
# left as remote-address here so limits still apply to unauthenticated routes.
limiter = Limiter(key_func=get_remote_address, storage_uri=settings.redis_url)
