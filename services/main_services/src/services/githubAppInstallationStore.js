const { getSupabase } = require('../config/supabase');

// Persists which GitHub App installations exist and which app user connected
// each one — populated by the `installation` webhook event (see
// githubController.js#handleWebhook's 'installation' branch), not by a
// user-facing OAuth callback the way githubTokenStore.js is. A GitHub App
// installation isn't "one user's token" the way classic OAuth is — it's
// "this org/account granted the App access to these repos" — so what we
// store is the mapping, not a per-user secret (there IS no long-lived
// secret to store here; installation access tokens are minted on demand and
// cached in Redis, see config/githubApp.js).
//
// Expected table (create once in Supabase SQL editor):
//   create table github_app_installations (
//     installation_id bigint primary key,
//     account_login text not null,
//     account_type text not null,        -- 'User' | 'Organization'
//     connected_by_user_id text,         -- who was mid-install-flow when GitHub redirected back, if known
//     repository_selection text,         -- 'all' | 'selected'
//     created_at timestamptz default now(),
//     updated_at timestamptz default now()
//   );

function table() {
  const supabase = getSupabase();
  if (!supabase) {
    const err = new Error('Supabase not configured — required for storing GitHub App installations');
    err.status = 503;
    throw err;
  }
  return supabase.from('github_app_installations');
}

async function upsertInstallation({ installationId, accountLogin, accountType, connectedByUserId, repositorySelection }) {
  const { error } = await table().upsert(
    {
      installation_id: installationId,
      account_login: accountLogin,
      account_type: accountType,
      connected_by_user_id: connectedByUserId || null,
      repository_selection: repositorySelection || null,
      updated_at: new Date().toISOString(),
    },
    { onConflict: 'installation_id' }
  );
  if (error) throw Object.assign(new Error(error.message), { status: 500 });
}

async function getInstallationByAccount(accountLogin) {
  const { data, error } = await table().select('*').eq('account_login', accountLogin).maybeSingle();
  if (error) throw Object.assign(new Error(error.message), { status: 500 });
  return data ? _fromRow(data) : null;
}

async function getInstallationById(installationId) {
  const { data, error } = await table().select('*').eq('installation_id', installationId).maybeSingle();
  if (error) throw Object.assign(new Error(error.message), { status: 500 });
  return data ? _fromRow(data) : null;
}

async function deleteInstallation(installationId) {
  const { error } = await table().delete().eq('installation_id', installationId);
  if (error) throw Object.assign(new Error(error.message), { status: 500 });
}

function _fromRow(data) {
  return {
    installationId: data.installation_id,
    accountLogin: data.account_login,
    accountType: data.account_type,
    connectedByUserId: data.connected_by_user_id,
    repositorySelection: data.repository_selection,
  };
}

module.exports = { upsertInstallation, getInstallationByAccount, getInstallationById, deleteInstallation };
