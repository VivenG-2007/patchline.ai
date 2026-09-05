const { getSupabase } = require('../config/supabase');
const { encrypt, decrypt } = require('../utils/crypto');

// Persists one GitHub OAuth connection per app user in Supabase, encrypted
// at rest with the same shared key as Jira's tokens (utils/crypto.js).
//
// Expected table (create once in Supabase SQL editor):
//   create table github_connections (
//     user_id text primary key,
//     github_user_id bigint not null,
//     username text not null,
//     avatar_url text,
//     access_token text not null,
//     scopes text,
//     created_at timestamptz default now(),
//     updated_at timestamptz default now()
//   );

function table() {
  const supabase = getSupabase();
  if (!supabase) {
    const err = new Error('Supabase not configured — required for storing GitHub OAuth tokens');
    err.status = 503;
    throw err;
  }
  return supabase.from('github_connections');
}

async function getConnection(userId) {
  const { data, error } = await table().select('*').eq('user_id', userId).maybeSingle();
  if (error) throw Object.assign(new Error(error.message), { status: 500 });
  if (!data) return null;
  return {
    userId: data.user_id,
    githubUserId: data.github_user_id,
    username: data.username,
    avatarUrl: data.avatar_url,
    accessToken: decrypt(data.access_token),
    scopes: data.scopes,
  };
}

async function upsertConnection({ userId, githubUserId, username, avatarUrl, accessToken, scopes }) {
  const { error } = await table().upsert(
    {
      user_id: userId,
      github_user_id: githubUserId,
      username,
      avatar_url: avatarUrl,
      access_token: encrypt(accessToken),
      scopes,
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
