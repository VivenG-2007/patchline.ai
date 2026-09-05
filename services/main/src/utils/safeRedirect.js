// The onboarding wizard (and anything else that kicks off an OAuth flow)
// needs the callback to come back to a specific in-app page, not always the
// integration's own status page. That path travels through Redis alongside
// the CSRF state and back out through a query param main-service doesn't
// otherwise control — so it must be validated as a same-app relative path,
// never followed as-is, or an attacker could craft a redirect link that
// carries a stolen `code` off to an external host.
function sanitizeReturnTo(raw, fallback) {
  if (typeof raw !== 'string') return fallback;
  // Must be a single leading slash: reject protocol-relative ("//evil.com"),
  // absolute URLs ("https://evil.com"), and anything without a leading slash.
  if (!raw.startsWith('/') || raw.startsWith('//')) return fallback;
  if (raw.length > 200) return fallback;
  return raw;
}

module.exports = { sanitizeReturnTo };
