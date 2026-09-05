const crypto = require('crypto');
const redis = require('../config/redis');

const STATE_TTL_SECONDS = 5 * 60; // any OAuth consent flow should complete within 5 minutes

// Shared CSRF-state helper for every OAuth integration (Jira, GitHub, ...).
// Binds a one-time random value to the app user who initiated the flow, in
// Redis rather than instance memory — required for the flow to work when
// /oauth/start and /oauth/callback land on different backend instances
// behind a load balancer (see docs/architecture.md on statelessness).
function keyFor(provider, state) {
  return `oauth:state:${provider}:${state}`;
}

async function createState(provider, userId, returnTo) {
  const state = crypto.randomBytes(24).toString('hex');
  // Store as JSON so callers can round-trip an optional "come back here"
  // path (e.g. the onboarding wizard) alongside the userId this state is
  // bound to. Kept backward compatible: consumeState handles both shapes.
  await redis.set(keyFor(provider, state), JSON.stringify({ userId, returnTo: returnTo || null }), 'EX', STATE_TTL_SECONDS);
  return state;
}

// Consumes (one-time use) the state value — returns { userId, returnTo }, or
// null if it's missing/expired/already used.
async function consumeState(provider, state) {
  const key = keyFor(provider, state);
  const raw = await redis.get(key);
  if (!raw) return null;
  await redis.del(key);
  try {
    const parsed = JSON.parse(raw);
    if (parsed && typeof parsed === 'object' && parsed.userId) return parsed;
  } catch {
    // Fall through — pre-existing states stored before this change were a
    // bare userId string, not JSON.
  }
  return { userId: raw, returnTo: null };
}

module.exports = { createState, consumeState };
