const { getSupabase } = require('../config/supabase');
const { encrypt, decrypt } = require('../utils/crypto');

// Persists one Jira OAuth connection per app user in Supabase. Access +
// refresh tokens are encrypted at rest (see utils/crypto.js) — Supabase's
// service-role key already bypasses RLS for this table, so encryption is the
// second layer protecting these credentials specifically, since a leaked DB
// dump alone wouldn't be enough to impersonate a user's Jira session.
//
// Expected table (create once in Supabase SQL editor):
//   create table jira_connections (
//     user_id text primary key,
//     cloud_id text not null,
//     site_url text,
//     site_name text,
//     access_token text not null,
//     refresh_token text not null,
//     expires_at timestamptz not null,
//     created_at timestamptz default now(),
//     updated_at timestamptz default now()
//   );

function table() {
  const supabase = getSupabase();
  if (!supabase) {
    const err = new Error('Supabase not configured — required for storing Jira OAuth tokens');
    err.status = 503;
    throw err;
  }
  return supabase.from('jira_connections');
}

async function getConnection(userId) {
  const { data, error } = await table().select('*').eq('user_id', userId).maybeSingle();
  if (error) throw Object.assign(new Error(error.message), { status: 500 });
  if (!data) return null;
  return {
    userId: data.user_id,
    cloudId: data.cloud_id,
    siteUrl: data.site_url,
    siteName: data.site_name,
    accessToken: decrypt(data.access_token),
    refreshToken: decrypt(data.refresh_token),
    expiresAt: new Date(data.expires_at),
  };
}

async function upsertConnection({ userId, cloudId, siteUrl, siteName, accessToken, refreshToken, expiresAt }) {
  const { error } = await table().upsert(
    {
      user_id: userId,
      cloud_id: cloudId,
      site_url: siteUrl,
      site_name: siteName,
      access_token: encrypt(accessToken),
      refresh_token: encrypt(refreshToken),
      expires_at: expiresAt.toISOString(),
      updated_at: new Date().toISOString(),
    },
    { onConflict: 'user_id' }
  );
  if (error) throw Object.assign(new Error(error.message), { status: 500 });
}

async function deleteConnection(userId) {
  const { error } = await table().delete().eq('user_id', userId);
  if (error) throw Object.assign(new Error(error.message), { status: 500 });
}

module.exports = { getConnection, upsertConnection, deleteConnection };
