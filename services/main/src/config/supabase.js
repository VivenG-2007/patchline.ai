const { createClient } = require('@supabase/supabase-js');
const env = require('./env');
const logger = require('./logger');

let client = null;

// Server-side client using the service-role key: bypasses RLS, so it must
// only ever run in this backend, never be shipped to the frontend.
function getSupabase() {
  if (!env.supabase.url || !env.supabase.serviceRoleKey) {
    logger.warn('Supabase not configured — SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY missing');
    return null;
  }
  if (!client) {
    client = createClient(env.supabase.url, env.supabase.serviceRoleKey, {
      auth: { persistSession: false, autoRefreshToken: false },
    });
  }
  return client;
}

module.exports = { getSupabase };
